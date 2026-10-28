"""Evaluasi v3: holdout terkunci, flow Langflow sungguhan, N kali per kasus.

    python eval_v3.py                    # memanggil Langflow (.env: LANGFLOW_RUN_URL, LANGFLOW_API_KEY, MODEL_NAME)
    python eval_v3.py --runs 5 --delay 2
    python eval_v3.py --dry-run          # tanpa jaringan: komponen lokal + LLM tiruan (angka TIRUAN)

Dari SATU output hybrid per run diambil tiga mode:
  aturan = layer1_score, LLM = bobot temuan L2 (0 jika LLM menilai aman), hybrid = risk_score.
Run dengan LLM gagal tidak dihitung di mode LLM (dihitung terpisah); hybrid saat itu memakai aturan saja.

Hasil: eval/results/eval_v3_<waktu>.json (data mentah per run, tanpa teks deskripsi) dan .md (ringkasan + Batasan).
"""
import argparse
import datetime
import json
import math
import os
import random
import re
import statistics
import sys
import time

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

import build_component
from lock_holdout import DEFAULT_HOLDOUT, SOURCES, HoldoutError, load_locked_holdout, sha256_file

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(HERE, "eval", "results")
THRESHOLDS = (20, 50)
MODES = ("aturan", "llm", "hybrid")
COMBINE = re.compile(r"aturan (\d+) \+ LLM (\d+) -> akhir (\d+)")


# ------------------------------------------------------------------ membaca satu output hybrid
def _int_or_none(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def scores_from_result(raw: dict) -> dict:
    """Skor tiga mode + status LLM dari satu output komponen (dict JSON atau hasil parse report_text)."""
    steps = {s.get("step"): s for s in raw.get("trace") or [] if isinstance(s, dict)}
    llm_step = steps.get("llm", {})
    findings = [f for f in raw.get("findings") or [] if isinstance(f, dict)]
    combine = COMBINE.search(str(steps.get("combine", {}).get("detail", "")))

    if raw.get("llm_layer_used") is False or llm_step.get("status") == "skip":
        llm_status = "tidak_terhubung"
    elif (any(f.get("category") == "llm_unavailable" for f in findings)
          or str(llm_step.get("detail", "")).startswith("gagal")):
        llm_status = "gagal"
    else:
        llm_status = "ok"

    rule = _int_or_none(raw.get("layer1_score"))
    if rule is None and combine:
        rule = int(combine.group(1))

    llm = None
    if llm_status == "ok":
        l2 = [f for f in findings if f.get("rule_id") == "L2"]
        if any("weight" in f for f in l2):
            llm = max((_int_or_none(f.get("weight")) or 0 for f in l2), default=0)
        elif combine:
            llm = int(combine.group(2))
        elif not l2:
            llm = 0

    return {
        "aturan": rule,
        "llm": llm,
        "hybrid": _int_or_none(raw.get("risk_score")),
        "llm_status": llm_status,
        "needs_human_review": bool(raw.get("needs_human_review")),
        "total_ms": raw.get("total_ms") if isinstance(raw.get("total_ms"), (int, float)) else None,
    }


# ------------------------------------------------------------------ mesin pemanggil
def langflow_caller(url, api_key, timeout):
    import requests
    from console_core import build_audit_request, extract_result_from_response

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["x-api-key"] = api_key

    def call(case, _run):
        payload = {"input_value": build_audit_request(case["tool_name"], case["description"]),
                   "input_type": "chat", "output_type": "chat"}
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code}")
        raw = extract_result_from_response(resp.json())
        if raw is None:
            raise RuntimeError("hasil audit tidak ditemukan di respons Langflow")
        return raw
    return call


def dry_run_caller():
    """Komponen hasil build + LLM tiruan acak (benih tetap per kasus dan run). Angka yang keluar TIRUAN."""
    from component_harness import FakeLLM, load, run
    comp = load(os.path.join(HERE, build_component.OUTPUT), "wg_eval_dry")

    def call(case, run_no):
        rng = random.Random(f"{case['id']}:{run_no}")
        weights = (15, 25, 60) if case["label"] == "malicious" else (80, 15, 5)

        def reply(_messages):
            if rng.random() < 0.08:
                return "maaf, tidak bisa menilai"            # meniru keluaran LLM yang tidak valid
            verdict = rng.choices(("safe", "suspicious", "malicious"), weights=weights)[0]
            quote = " ".join(case["description"].split()[:6])
            return json.dumps({"verdict": verdict, "confidence": round(rng.uniform(0.5, 1.0), 2),
                               "categories": [] if verdict == "safe" else ["other"],
                               "evidence": [] if verdict == "safe" else [quote], "reasoning": "tiruan"})
        return run(comp, case["tool_name"], case["description"], FakeLLM(reply))
    return call


def call_with_retry(call, case, run_no, retries, delay):
    last = None
    for attempt in range(retries + 1):
        t = time.perf_counter()
        try:
            raw = call(case, run_no)
            return raw, (time.perf_counter() - t) * 1000, None
        except Exception as e:  # jaringan, HTTP, format: dicoba ulang lalu dicatat
            last = f"{type(e).__name__}: {str(e)[:160]}"
            if attempt < retries:
                time.sleep(delay * (2 ** attempt))
    return None, None, last


# ------------------------------------------------------------------ statistik
def pct(values, q):
    """Persentil nearest-rank (q dalam 0..100). None jika kosong."""
    if not values:
        return None
    s = sorted(values)
    return s[max(0, math.ceil(q / 100 * len(s)) - 1)]


def rate(hits, n):
    return None if n == 0 else hits / n


def mode_metrics(records, mode, runs):
    rows = [r for r in records if r["ok"] and r[mode] is not None]
    out = {"n_runs_used": len(rows), "n_runs_excluded": sum(r["ok"] for r in records) - len(rows), "thresholds": {}}
    for t in THRESHOLDS:
        mal = [r for r in rows if r["label"] == "malicious"]
        cln = [r for r in rows if r["label"] == "clean"]
        per_run = []
        for k in range(runs):
            mk = [r for r in mal if r["run"] == k]
            ck = [r for r in cln if r["run"] == k]
            per_run.append({"run": k,
                            "recall": rate(sum(r[mode] >= t for r in mk), len(mk)),
                            "fpr": rate(sum(r[mode] >= t for r in ck), len(ck))})
        by_case = {}
        for r in rows:
            by_case.setdefault(r["id"], set()).add(r[mode] >= t)
        out["thresholds"][str(t)] = {
            "recall": rate(sum(r[mode] >= t for r in mal), len(mal)),
            "fpr": rate(sum(r[mode] >= t for r in cln), len(cln)),
            "n_malicious_runs": len(mal), "n_clean_runs": len(cln),
            "per_run": per_run,
            "unstable_cases": sorted(cid for cid, v in by_case.items() if len(v) > 1),
        }
    clean_scores = [r[mode] for r in rows if r["label"] == "clean"]
    out["clean_scores"] = {
        "n": len(clean_scores), "min": min(clean_scores, default=None), "median": pct(clean_scores, 50),
        "p90": pct(clean_scores, 90), "max": max(clean_scores, default=None),
        "bins": {"0": sum(s == 0 for s in clean_scores), "1-19": sum(0 < s < 20 for s in clean_scores),
                 "20-49": sum(20 <= s < 50 for s in clean_scores), "50-100": sum(s >= 50 for s in clean_scores)},
    }
    spread = {}
    for r in rows:
        spread.setdefault(r["id"], []).append(r[mode])
    multi = [v for v in spread.values() if len(v) > 1]
    out["score_variation"] = {
        "cases_with_2plus_runs": len(multi),
        "mean_stdev": round(statistics.mean(statistics.pstdev(v) for v in multi), 2) if multi else None,
        "max_range": max((max(v) - min(v) for v in multi), default=None),
        "cases_with_any_change": sum(len(set(v)) > 1 for v in multi),
    }
    return out


def summarize(records, runs):
    ok = [r for r in records if r["ok"]]
    total = [r["total_ms"] for r in ok if r["total_ms"] is not None]
    rt = [r["roundtrip_ms"] for r in ok]
    by_source = {}
    for src in [s for s in SOURCES if any(r["source"] == s for r in records)]:
        rows = [r for r in records if r["source"] == src]
        by_source[src] = {
            "n_malicious": len({r["id"] for r in rows if r["label"] == "malicious"}),
            "n_clean": len({r["id"] for r in rows if r["label"] == "clean"}),
            "modes": {m: mode_metrics(rows, m, runs) for m in MODES},
        }
    return {
        "modes": {m: mode_metrics(records, m, runs) for m in MODES},
        "by_source": by_source,
        "timing_ms": {
            "total_ms": {"n": len(total), "median": pct(total, 50), "p90": pct(total, 90)},
            "roundtrip_ms": {"n": len(rt), "median": pct(rt, 50), "p90": pct(rt, 90)},
        },
        "failures": {
            "request_failed": sum(not r["ok"] for r in records),
            "llm_failed": sum(r["llm_status"] == "gagal" for r in ok),
            "llm_not_connected": sum(r["llm_status"] == "tidak_terhubung" for r in ok),
            "needs_human_review": sum(r["needs_human_review"] for r in ok),
        },
    }


# ------------------------------------------------------------------ laporan
def _fmt(v, as_pct=True):
    if v is None:
        return "-"
    return f"{v * 100:.1f}%" if as_pct else (f"{v:.1f}" if isinstance(v, float) else str(v))


def _range(per_run, key):
    vals = [p[key] for p in per_run if p[key] is not None]
    if not vals:
        return "-"
    return f"{_fmt(min(vals))} - {_fmt(max(vals))} (sd {statistics.pstdev(vals) * 100:.1f} poin)"


def render_markdown(meta, summary, limitations):
    L = []
    title = "Evaluasi v3 WhisperGuard" + (" - DRY RUN (ANGKA TIRUAN)" if meta["dry_run"] else "")
    L += [f"# {title}", ""]
    if meta["dry_run"]:
        L += ["> **DRY RUN.** LLM diganti tiruan acak. Angka di bawah hanya menguji jalannya skrip, "
              "**bukan** hasil evaluasi dan tidak boleh dikutip.", ""]
    L += ["## Setup", "",
          f"- Waktu (UTC): {meta['started_utc']}",
          f"- Holdout: `{meta['holdout_file']}` ({meta['n_cases']} kasus: {meta['labels']}; sumber: {meta['sources']})",
          f"- SHA-256 holdout: `{meta['holdout_sha256']}` (dikunci {meta['locked_at_utc']} UTC)",
          f"- Run per kasus: {meta['runs']}, jeda {meta['delay_s']} dtk, retry {meta['retries']}",
          f"- Model (dinyatakan operator lewat MODEL_NAME): `{meta['model_name']}`",
          f"- Komponen lokal: `{meta['component_file']}` SHA-256 `{meta['component_sha256']}`", ""]

    for t in THRESHOLDS:
        L += [f"## Ambang skor >= {t}", "",
              "| Mode | Recall | False positive rate | Recall antar-run (min-maks) | FPR antar-run (min-maks) "
              "| Kasus tidak stabil | Run dipakai |",
              "|---|---|---|---|---|---|---|"]
        for m in MODES:
            mm = summary["modes"][m]
            th = mm["thresholds"][str(t)]
            L.append(f"| {m} | {_fmt(th['recall'])} | {_fmt(th['fpr'])} | {_range(th['per_run'], 'recall')} "
                     f"| {_range(th['per_run'], 'fpr')} | {len(th['unstable_cases'])} | {mm['n_runs_used']} |")
        L.append("")

    L += ["## Hasil per sumber", "",
          "Setiap sumber dihitung terpisah. Recall '-' = sumber itu tidak punya kasus malicious; "
          "FPR '-' = tidak punya kasus clean.", "",
          "| Sumber | Kasus (malicious/clean) | Mode | Recall >= 20 | FPR >= 20 | Recall >= 50 | FPR >= 50 | Run dipakai |",
          "|---|---|---|---|---|---|---|---|"]
    for src, bs in summary["by_source"].items():
        for m in MODES:
            mm = bs["modes"][m]
            t20, t50 = mm["thresholds"]["20"], mm["thresholds"]["50"]
            L.append(f"| {src} | {bs['n_malicious']}/{bs['n_clean']} | {m} | {_fmt(t20['recall'])} | {_fmt(t20['fpr'])} "
                     f"| {_fmt(t50['recall'])} | {_fmt(t50['fpr'])} | {mm['n_runs_used']} |")
    L.append("")

    L += ["## Distribusi skor kasus bersih", "",
          "| Mode | n | min | median | p90 | maks | 0 | 1-19 | 20-49 | 50-100 |", "|---|---|---|---|---|---|---|---|---|---|"]
    for m in MODES:
        c = summary["modes"][m]["clean_scores"]
        b = c["bins"]
        L.append(f"| {m} | {c['n']} | {_fmt(c['min'], False)} | {_fmt(c['median'], False)} | {_fmt(c['p90'], False)} "
                 f"| {_fmt(c['max'], False)} | {b['0']} | {b['1-19']} | {b['20-49']} | {b['50-100']} |")
    L += ["", "## Variasi skor antar-run (per kasus)", "",
          "| Mode | Kasus >=2 run | Rata-rata simpangan baku | Rentang terbesar | Kasus yang skornya berubah |",
          "|---|---|---|---|---|"]
    for m in MODES:
        v = summary["modes"][m]["score_variation"]
        L.append(f"| {m} | {v['cases_with_2plus_runs']} | {_fmt(v['mean_stdev'], False)} | {_fmt(v['max_range'], False)} "
                 f"| {v['cases_with_any_change']} |")
    tm = summary["timing_ms"]
    f = summary["failures"]
    L += ["", "## Waktu per audit (ms)", "",
          "| Ukuran | n | Median | p90 |", "|---|---|---|---|",
          f"| total_ms (di dalam komponen) | {tm['total_ms']['n']} | {_fmt(tm['total_ms']['median'], False)} "
          f"| {_fmt(tm['total_ms']['p90'], False)} |",
          f"| round-trip (skrip -> Langflow -> skrip) | {tm['roundtrip_ms']['n']} | "
          f"{_fmt(tm['roundtrip_ms']['median'], False)} | {_fmt(tm['roundtrip_ms']['p90'], False)} |",
          "", "## Kegagalan", "",
          f"- Permintaan gagal setelah retry: {f['request_failed']}",
          f"- LLM gagal (keluaran tidak valid/error, fail-safe ke aturan): {f['llm_failed']}",
          f"- LLM tidak terhubung di flow: {f['llm_not_connected']}",
          f"- Run yang ditandai perlu tinjauan manusia: {f['needs_human_review']}",
          "", "## Batasan", ""]
    L += [f"- {x}" for x in limitations]
    return "\n".join(L) + "\n"


def limitations_for(meta, summary, runs_log_warning):
    out = []
    if meta["dry_run"]:
        out.append("DRY RUN: lapisan LLM diganti tiruan acak. Tidak ada angka di laporan ini yang mencerminkan kinerja.")
    out += [
        f"Holdout hanya {meta['n_cases']} kasus ({meta['labels']}). Dengan n sekecil ini, selisih beberapa kasus "
        "menggeser recall/FPR puluhan poin persen; angka bukan perkiraan kinerja populasi.",
        f"Komposisi sumber: {meta['sources']}. Kasus buatan tim dibuat oleh pihak yang juga menulis aturan, "
        "sehingga cenderung lebih mudah dideteksi daripada serangan nyata.",
        "Skor mode LLM = bobot temuan L2 setelah grounding (bukti wajib ada di deskripsi, tanpa bukti maks 30) "
        "dan skala keyakinan, bukan verdict mentah LLM. Run dengan LLM gagal tidak dihitung di mode LLM.",
        "Mode aturan dan LLM diambil dari output hybrid yang sama, bukan dari flow terpisah.",
        "MODEL_NAME adalah model yang dinyatakan operator. Skrip ini tidak bisa memastikan flow Langflow "
        "benar-benar memakai model itu, dan tidak bisa memastikan komponen di Langflow sama dengan berkas lokal "
        f"`{meta['component_file']}`.",
        "Round-trip mencakup jaringan dan overhead Langflow; total_ms hanya waktu di dalam komponen.",
        "Yang diaudit hanya nama dan deskripsi tool. Serangan lewat inputSchema, nilai default, atau output tool "
        "tidak tercakup.",
    ]
    if "sintetis-llm" in summary["by_source"]:
        out.append("Kasus sintetis-llm dibuat dengan bantuan LLM, bukan oleh pengguna nyata (model dan riwayat revisi: "
                   "eval/holdout_v3/README.md). Hasil sumber ini tidak mewakili serangan dari penyerang sungguhan.")
    missing = [s for s in ("penguji", "publik") if f"{s} 0" in meta["sources"]]
    if missing:
        out.append(f"Belum ada kasus dari sumber: {', '.join(missing)}. Tanpa data independen, angka ini belum "
                   "menunjukkan kinerja pada serangan yang tidak dikenal penulis aturan.")
    if runs_log_warning:
        out.append(runs_log_warning)
    if summary["failures"]["request_failed"]:
        out.append(f"{summary['failures']['request_failed']} run gagal dipanggil dan tidak masuk perhitungan.")
    return out


# ------------------------------------------------------------------ catatan run holdout
def check_runs_log(holdout_path, component_sha):
    """Peringatan jika komponen berubah sejak evaluasi holdout pertama (holdout terbakar)."""
    path = os.path.join(os.path.dirname(os.path.abspath(holdout_path)), "RUNS.txt")
    if not os.path.exists(path):
        return path, None
    with open(path, encoding="utf-8") as f:
        shas = {line.split("|")[1].strip() for line in f if line.count("|") >= 3}
    if shas and component_sha not in shas:
        return path, ("Komponen berbeda dari evaluasi holdout sebelumnya (lihat RUNS.txt). Jika aturan/prompt "
                      "diubah setelah melihat hasil holdout ini, holdout ini sudah terbakar dan angkanya optimistis.")
    return path, None


def main(argv=None):
    p = argparse.ArgumentParser(description="Evaluasi v3 WhisperGuard pada holdout terkunci.")
    p.add_argument("--holdout", default=DEFAULT_HOLDOUT)
    p.add_argument("--runs", type=int, default=5, help="jumlah run per kasus (default 5)")
    p.add_argument("--delay", type=float, default=1.0, help="jeda antar-panggilan dalam detik (default 1)")
    p.add_argument("--retries", type=int, default=3, help="percobaan ulang saat gagal (default 3)")
    p.add_argument("--timeout", type=float, default=120, help="batas waktu satu panggilan (detik)")
    p.add_argument("--dry-run", action="store_true", help="tanpa jaringan: komponen lokal + LLM tiruan")
    p.add_argument("--out", default=RESULTS_DIR)
    args = p.parse_args(argv)
    if args.runs < 1:
        p.error("--runs minimal 1")

    try:
        cases, lock = load_locked_holdout(args.holdout)
    except HoldoutError as e:
        print(f"Ditolak: {e}", file=sys.stderr)
        return 2

    if args.dry_run:
        model, call, delay = "dry-run (LLM tiruan)", dry_run_caller(), 0.0
    else:
        url = os.getenv("LANGFLOW_RUN_URL", "").strip()
        model = os.getenv("MODEL_NAME", "").strip()
        if not url or url.startswith("ISI_"):
            print("Ditolak: LANGFLOW_RUN_URL belum diisi di .env.", file=sys.stderr)
            return 2
        if not model or model.startswith("ISI_") or "latest" in model.lower():
            print("Ditolak: isi MODEL_NAME di .env dengan versi model yang dipin (bukan alias 'latest').",
                  file=sys.stderr)
            return 2
        call, delay = langflow_caller(url, os.getenv("LANGFLOW_API_KEY", "").strip(), args.timeout), args.delay

    comp_file = build_component.OUTPUT
    comp_sha = sha256_file(os.path.join(HERE, comp_file))
    runs_log, runs_warning = check_runs_log(args.holdout, comp_sha)
    started = datetime.datetime.now(datetime.timezone.utc)

    records = []
    total = len(cases) * args.runs
    for k in range(args.runs):
        for case in cases:
            raw, rt_ms, err = call_with_retry(call, case, k, args.retries, max(delay, 0.5) if not args.dry_run else 0)
            rec = {"id": case["id"], "source": case["source"], "label": case["label"], "run": k,
                   "ok": raw is not None, "error": err, "roundtrip_ms": round(rt_ms, 1) if rt_ms else None}
            rec.update(scores_from_result(raw) if raw is not None else
                       {"aturan": None, "llm": None, "hybrid": None, "llm_status": "-",
                        "needs_human_review": False, "total_ms": None})
            if rec["ok"] and rec["hybrid"] is None:
                rec["ok"], rec["error"] = False, "risk_score tidak ada di hasil"
            records.append(rec)
            print(f"\r{len(records)}/{total} run", end="", flush=True)
            if delay:
                time.sleep(delay)
    print()

    count = lambda key, vals: ", ".join(f"{v} {sum(c[key] == v for c in cases)}" for v in vals)  # noqa: E731
    meta = {
        "dry_run": args.dry_run, "started_utc": started.strftime("%Y-%m-%d %H:%M:%S"),
        "holdout_file": os.path.relpath(args.holdout, HERE).replace(os.sep, "/"),
        "holdout_sha256": lock["sha256"], "locked_at_utc": lock.get("locked_at_utc", "?"),
        "n_cases": len(cases), "labels": count("label", ("malicious", "clean")),
        "sources": count("source", SOURCES),
        "runs": args.runs, "delay_s": delay, "retries": args.retries, "model_name": model,
        "component_file": comp_file, "component_sha256": comp_sha,
    }
    summary = summarize(records, args.runs)
    limitations = limitations_for(meta, summary, runs_warning)

    os.makedirs(args.out, exist_ok=True)
    stem = os.path.join(args.out, f"eval_v3_{started.strftime('%Y%m%d_%H%M%S')}" + ("_dryrun" if args.dry_run else ""))
    with open(stem + ".json", "w", encoding="utf-8") as f:
        json.dump({"meta": meta, "summary": summary, "limitations": limitations, "records": records},
                  f, indent=2, ensure_ascii=False)
    with open(stem + ".md", "w", encoding="utf-8", newline="\n") as f:
        f.write(render_markdown(meta, summary, limitations))
    if not args.dry_run:
        with open(runs_log, "a", encoding="utf-8", newline="\n") as f:
            f.write(f"{meta['started_utc']} | {comp_sha} | {model} | runs={args.runs} | "
                    f"{os.path.basename(stem)}.json\n")
    print(f"OK: {stem}.json dan {stem}.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
