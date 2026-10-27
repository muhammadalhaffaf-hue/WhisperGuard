"""
WhisperGuard Console - logika inti (tanpa tampilan).

Dipisah dari console_app.py supaya bisa diuji tanpa Streamlit.
Isi:
- memanggil flow audit di Langflow lewat API (mesin yang sama dengan yang dipakai Bob)
- cadangan lapisan 1 lokal (auditor.py) jika Langflow tidak bisa dihubungi
- jejak eksekusi (trace): dibaca dari komponen v2.1, atau dibuat sendiri pada mode lokal
- deteksi rug pull: membandingkan deskripsi dengan versi terakhir yang DISETUJUI manusia
- penyimpanan riwayat audit dan keputusan manusia di SQLite (append-only), per organisasi
- hak akses per peran (developer, peninjau, admin) yang diperiksa di setiap fungsi data

Prinsip keamanan:
- Nama dan deskripsi tool adalah DATA TIDAK DIPERCAYA. Kutipan bukti selalu dinetralkan.
- Yang dikirim ke Langflow (dan LLM di dalamnya) hanya nama dan deskripsi tool.
- Keputusan manusia tidak pernah dihapus atau diubah; keputusan baru menambah baris baru.
- Data satu organisasi tidak pernah terlihat atau bisa diputuskan oleh akun organisasi lain.
"""
import datetime
import difflib
import hashlib
import html
import json
import os
import re
import sqlite3
import time
import unicodedata

import requests

LEVELS = ("LOW", "MEDIUM", "HIGH")
DECISIONS = ("Setujui", "Karantina", "Perlu revisi")
PENDING = "Menunggu keputusan"
MIN_NOTE_HIGH_APPROVAL = 20

# Jejak eksekusi
STEP_ORDER = ("input", "hidden", "rules", "llm", "grounding", "combine", "drift", "human")
STEP_SHORT = {  # label kotak diagram (\\n = baris baru di Graphviz)
    "input": "Input", "hidden": "Karakter\\ntersembunyi", "rules": "Aturan\\npola",
    "llm": "Lapisan\\nLLM", "grounding": "Verifikasi\\nbukti", "combine": "Gabung\\nskor",
    "drift": "Cek\\nperubahan", "human": "Keputusan\\nmanusia",
}
STATUSES = ("ok", "warn", "fail", "skip", "pending")

# Deteksi rug pull
DRIFT_NEW, DRIFT_SAME, DRIFT_CHANGED = "BARU", "SAMA", "BERUBAH"


# ------------------------------------------------------------------ util
def now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _is_invisible(ch) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F or unicodedata.category(ch) == "Cf"


def neutralize(text, limit=300) -> str:
    """Buang karakter tak terlihat/kontrol, nonaktifkan < >, ringkas spasi, batasi panjang."""
    out = []
    for ch in str(text if text is not None else ""):
        if _is_invisible(ch) or unicodedata.category(ch) == "Cc":
            if ch not in "\n\t":
                continue
        out.append({"<": "‹", ">": "›"}.get(ch, ch))
    s = " ".join("".join(out).split())
    return s if len(s) <= limit else s[:limit] + "..."


def count_invisible(text) -> int:
    return sum(1 for ch in str(text or "") if _is_invisible(ch))


def reveal_invisible(text) -> str:
    """Tampilkan karakter tak terlihat sebagai penanda yang terlihat, mis. ⟦U+200B⟧."""
    return "".join(f"⟦U+{ord(ch):04X}⟧" if _is_invisible(ch) else ch for ch in str(text or ""))


# ------------------------------------------------------------------ Mode Sinar-X
# Membandingkan yang dilihat manusia dengan yang dibaca AI. Hanya untuk tampilan: tidak mengubah
# skor atau temuan. Semua teks dari deskripsi di-escape (html.escape) sebelum masuk HTML, dan
# hasilnya dirender dengan st.html (tanpa pemrosesan Markdown).
TAG_PRINTABLE = range(0xE0020, 0xE007F)  # U+E0020..U+E007E -> ASCII 0x20..0x7E
MIN_EVIDENCE_LEN = 4


def _is_tag_printable(ch) -> bool:
    return ord(ch) in TAG_PRINTABLE


def hidden_tag_messages(text) -> list:
    """Terjemahkan rangkaian karakter Unicode tag (U+E0020-U+E007E) ke ASCII: chr(cp - 0xE0000).
    Setiap rangkaian berurutan menjadi satu pesan."""
    messages, run = [], []
    for ch in str(text or ""):
        if _is_tag_printable(ch):
            run.append(chr(ord(ch) - 0xE0000))
        elif run:
            messages.append("".join(run)); run = []
    if run:
        messages.append("".join(run))
    return messages


def _visible_projection(text):
    """Teks seperti setelah neutralize() (tanpa batas panjang), plus posisi asal tiap karakternya.
    Dipakai untuk mencocokkan kutipan bukti (yang sudah dinetralkan) ke deskripsi asli."""
    chars, origin, prev_space = [], [], False
    for i, ch in enumerate(text):
        if _is_invisible(ch) or (unicodedata.category(ch) == "Cc" and ch not in "\n\t"):
            continue
        if ch.isspace():
            if prev_space or not chars:
                continue
            chars.append(" "); origin.append(i); prev_space = True
            continue
        prev_space = False
        chars.append({"<": "‹", ">": "›"}.get(ch, ch)); origin.append(i)
    return "".join(chars), origin


def evidence_spans(description, findings) -> list:
    """Rentang (awal, akhir) di deskripsi asli untuk kutipan bukti yang TERVERIFIKASI, yaitu benar-benar
    ada di deskripsi. Kutipan yang tidak ditemukan (misalnya karangan LLM) tidak disorot."""
    text = str(description or "")
    proj, origin = _visible_projection(text)
    spans = []
    for f in findings or []:
        quote = str(f.get("bukti", "") if isinstance(f, dict) else "").strip()
        if quote.endswith("..."):
            quote = quote[:-3].rstrip()
        if len(quote) < MIN_EVIDENCE_LEN:
            continue
        start = proj.find(quote)
        while start != -1:
            end = start + len(quote) - 1
            spans.append((origin[start], origin[end] + 1))
            start = proj.find(quote, start + 1)
    return sorted(set(spans))


def human_view_html(description) -> str:
    """Kolom 'Yang dilihat manusia': deskripsi apa adanya (di-escape). Karakter tak terlihat tetap
    tak terlihat, sama seperti di layar pengguna."""
    return html.escape(str(description or ""), quote=True)


def ai_view_html(description, findings) -> str:
    """Kolom 'Yang dibaca AI': karakter tak terlihat menjadi penanda, pesan Unicode tag diterjemahkan,
    kutipan bukti terverifikasi disorot. Setiap potongan teks dari deskripsi di-escape."""
    text = str(description or "")
    marked = [False] * len(text)
    for start, end in evidence_spans(text, findings):
        for i in range(start, end):
            marked[i] = True
    out, in_mark, i = [], False, 0
    while i < len(text):
        if marked[i] != in_mark:
            out.append("<mark class='wg-xr-ev'>" if marked[i] else "</mark>")
            in_mark = marked[i]
        ch = text[i]
        if _is_tag_printable(ch):
            j = i
            while j < len(text) and _is_tag_printable(text[j]) and marked[j] == marked[i]:
                j += 1
            decoded = "".join(chr(ord(c) - 0xE0000) for c in text[i:j])
            out.append(f"<span class='wg-xr-tag'>⟦Pesan tersembunyi: {html.escape(decoded, quote=True)}⟧</span>")
            i = j
            continue
        if _is_invisible(ch):
            out.append(f"<span class='wg-xr-mark'>⟦U+{ord(ch):04X}⟧</span>")
        else:
            out.append(html.escape(ch, quote=True))
        i += 1
    if in_mark:
        out.append("</mark>")
    return "".join(out)


def xray(description, findings) -> dict:
    """Semua bahan Mode Sinar-X untuk satu deskripsi."""
    return {
        "human_html": human_view_html(description),
        "ai_html": ai_view_html(description, findings),
        "messages": hidden_tag_messages(description),
        "invisible": count_invisible(description),
        "evidence_count": len(evidence_spans(description, findings)),
    }


def fingerprint(description) -> str:
    """Sidik jari deskripsi. Ketat: perubahan satu karakter (termasuk tak terlihat) mengubah hasil."""
    text = str(description or "").replace("\r\n", "\n").strip()
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def word_diff(old, new) -> str:
    """Perbandingan kata: [-dihapus-] dan {+ditambah+}. Teks polos, karakter tersembunyi ditampakkan."""
    a = re.split(r"(\s+)", reveal_invisible(old))
    b = re.split(r"(\s+)", reveal_invisible(new))
    out = []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
        if op == "equal":
            out.append("".join(a[i1:i2]))
        if op in ("delete", "replace"):
            out.append("[-" + "".join(a[i1:i2]) + "-]")
        if op in ("insert", "replace"):
            out.append("{+" + "".join(b[j1:j2]) + "+}")
    return "".join(out)


def build_audit_request(tool_name: str, description: str) -> str:
    """Format teks yang dikenali kolom Audit Request di komponen WhisperGuard."""
    return f"tool_name: {tool_name.strip()}\ntool_description: {description.strip()}"


# ------------------------------------------------------------------ normalisasi hasil
def _to_int(v, default=0):
    try:
        return int(float(v))
    except Exception:
        return default


def _to_float_or_none(v):
    try:
        return round(float(v), 1)
    except Exception:
        return None


def _to_bool(v):
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "1", "yes", "ya")


def normalize_trace(raw):
    steps = []
    if not isinstance(raw, list):
        return steps
    for s in raw:
        if not isinstance(s, dict):
            continue
        step = str(s.get("step", ""))
        if step not in STEP_ORDER:
            continue
        status = str(s.get("status", "")).lower()
        steps.append({
            "step": step,
            "label": neutralize(s.get("label", step), 80),
            "status": status if status in STATUSES else "warn",
            "detail": neutralize(s.get("detail", ""), 220),
            "ms": _to_float_or_none(s.get("ms")),
        })
    return steps


def normalize_result(raw: dict, source: str) -> dict:
    """Ubah hasil (dari Langflow atau lokal) menjadi bentuk baku yang aman ditampilkan."""
    level = str(raw.get("risk_level", "")).strip().upper()
    score = max(0, min(100, _to_int(raw.get("risk_score"), 0)))
    if level not in LEVELS:
        level = "HIGH" if score >= 50 else "MEDIUM" if score >= 20 else "LOW"
        forced_review = True
    else:
        forced_review = False

    findings = []
    for f in raw.get("findings") or []:
        if not isinstance(f, dict):
            continue
        findings.append({
            "rule_id": neutralize(f.get("rule_id", "?"), 12),
            "kategori": neutralize(f.get("category", f.get("kategori", "")), 40),
            "bobot": _to_int(f.get("weight", f.get("bobot")), 0),
            "penjelasan": neutralize(f.get("explanation", f.get("penjelasan", "")), 300),
            "bukti": neutralize(f.get("evidence", f.get("bukti", "")), 160),
        })

    return {
        "risk_level": level,
        "risk_score": score,
        "layer1_score": _to_int(raw.get("layer1_score"), score),
        "llm_layer_used": _to_bool(raw.get("llm_layer_used", False)),
        "needs_human_review": _to_bool(raw.get("needs_human_review", False)) or forced_review,
        "recommendation": neutralize(raw.get("recommendation", ""), 400),
        "findings": findings,
        "trace": normalize_trace(raw.get("trace")),
        "source": source,
    }


# ------------------------------------------------------------------ membaca respons Langflow
def _find_result_dict(obj, depth=0):
    """Cari dict yang punya risk_level dan risk_score di mana pun di dalam respons."""
    if depth > 15:
        return None
    if isinstance(obj, dict):
        if "risk_level" in obj and "risk_score" in obj:
            return obj
        for v in obj.values():
            r = _find_result_dict(v, depth + 1)
            if r is not None:
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = _find_result_dict(v, depth + 1)
            if r is not None:
                return r
    elif isinstance(obj, str) and "risk_level" in obj:
        m = re.search(r"\{.*\}", obj, re.S)
        if m:
            try:
                return _find_result_dict(json.loads(m.group(0)), depth + 1)
            except Exception:
                return None
    return None


def _iter_strings(obj, depth=0):
    if depth > 15:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_strings(v, depth + 1)


TRACE_LINE = re.compile(r"^~ (\w+)\|(\w+)\|([\d.]*)\|([^|\n]*)\|(.*)$", re.M)


def _parse_report_text(text: str):
    """Cadangan: baca teks 'LAPORAN AUDIT WHISPERGUARD' jika Chat Output hanya mengirim teks."""
    m = re.search(r"Level risiko:\s*(LOW|MEDIUM|HIGH)\s*\(skor\s*(\d+)", text)
    if not m:
        return None
    findings = []
    for fm in re.finditer(r"^- \[([^\]]+)\]\s*(.*?)\s*\|\s*bukti:\s*(.*)$", text, re.M):
        findings.append({"rule_id": fm.group(1), "explanation": fm.group(2), "evidence": fm.group(3)})
    rec = re.search(r"^Rekomendasi:\s*(.*)$", text, re.M)
    trace = [{"step": t[0], "status": t[1], "ms": t[2] or None, "label": t[3], "detail": t[4]}
             for t in TRACE_LINE.findall(text)]
    return {
        "risk_level": m.group(1),
        "risk_score": int(m.group(2)),
        "findings": findings,
        "recommendation": rec.group(1) if rec else "",
        "needs_human_review": "tinjauan manusia" in text.lower(),
        "llm_layer_used": any(f["rule_id"] == "L2" for f in findings),
        "trace": trace,
    }


def extract_result_from_response(data):
    """Kembalikan dict hasil audit dari respons Langflow, atau None jika tidak ditemukan."""
    found = _find_result_dict(data)
    if found is not None:
        return found
    for s in _iter_strings(data):
        if "Level risiko:" in s:
            parsed = _parse_report_text(s)
            if parsed:
                return parsed
    return None


# ------------------------------------------------------------------ mesin audit
class AuditEngineError(Exception):
    pass


def audit_via_langflow(tool_name, description, run_url, api_key, timeout=90):
    if not run_url:
        raise AuditEngineError("LANGFLOW_RUN_URL belum diisi di file .env.")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["x-api-key"] = api_key
    payload = {
        "input_value": build_audit_request(tool_name, description),
        "input_type": "chat",
        "output_type": "chat",
    }
    try:
        resp = requests.post(run_url, headers=headers, json=payload, timeout=timeout)
    except requests.RequestException as e:
        raise AuditEngineError(f"Tidak bisa menghubungi Langflow ({type(e).__name__}). "
                               "Pastikan Langflow sedang berjalan.") from None
    if resp.status_code != 200:
        raise AuditEngineError(f"Langflow membalas HTTP {resp.status_code}: {neutralize(resp.text, 200)}")
    try:
        data = resp.json()
    except Exception:
        raise AuditEngineError("Balasan Langflow bukan JSON.") from None
    raw = extract_result_from_response(data)
    if raw is None:
        raise AuditEngineError("Hasil audit tidak ditemukan di balasan Langflow. "
                               "Periksa apakah flow yang dipanggil benar.")
    return normalize_result(raw, "Langflow (aturan + LLM)")


def audit_local(tool_name, description, llm_reason="dilewati: mode lokal (aturan saja)"):
    """Lapisan 1 saja, dengan kode dan jejak yang sama persis dengan komponen Langflow
    (auditor.audit_tool + hybrid.build_trace). Selalu ditandai perlu tinjauan manusia
    karena lapisan LLM tidak dipakai."""
    try:
        from auditor import audit_tool
        from hybrid import build_trace
    except Exception:
        raise AuditEngineError("auditor.py / hybrid.py tidak ditemukan. Letakkan console_app.py di folder "
                               "yang sama dengan auditor.py dan hybrid.py.") from None
    t = time.perf_counter()
    base = audit_tool(tool_name, description)
    rules_ms = (time.perf_counter() - t) * 1000
    base.needs_human_review = True
    r = base.to_dict()
    r["layer1_score"] = r.get("risk_score", 0)
    r["llm_layer_used"] = False
    r["needs_human_review"] = True
    res = normalize_result(r, "Lokal (aturan saja)")
    trace = build_trace(description, base, base, False, {}, None, rules_ms, "Console")
    for step in trace:
        if step["step"] == "llm":
            step["detail"] = llm_reason
        elif step["step"] == "human":
            step["detail"] = "keputusan akhir oleh manusia; WAJIB ditinjau: lapisan LLM tidak dipakai"
    res["trace"] = normalize_trace(trace)
    return res


def run_audit(tool_name, description, mode, run_url, api_key):
    """mode: 'langflow' atau 'local'. Mengembalikan (hasil, peringatan_atau_None).
    Jika Langflow gagal, otomatis memakai lapisan 1 lokal (fail-safe)."""
    if mode == "langflow":
        try:
            return audit_via_langflow(tool_name, description, run_url, api_key), None
        except AuditEngineError as e:
            res = audit_local(tool_name, description, llm_reason="dilewati: Langflow gagal dihubungi")
            res["source"] = "Lokal (cadangan, Langflow gagal)"
            return res, str(e)
    return audit_local(tool_name, description), None


# ------------------------------------------------------------------ penyimpanan
# Setiap baris audit dan keputusan milik satu organisasi (org_id). Semua fungsi data di bawah
# menerima `actor` (akun yang login) dan memfilter berdasarkan organisasi akun itu, dibaca ulang
# dari database. Tampilan boleh menyembunyikan tombol, tetapi pemeriksaan sebenarnya ada di sini.
SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_utc TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    description TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    layer1_score INTEGER,
    llm_layer_used INTEGER,
    needs_human_review INTEGER,
    recommendation TEXT,
    findings_json TEXT,
    source TEXT
);
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER NOT NULL REFERENCES audits(id),
    decided_utc TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    decision TEXT NOT NULL,
    note TEXT
);
CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    created_utc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL REFERENCES organizations(id),
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('developer', 'peninjau', 'admin')),
    active INTEGER NOT NULL DEFAULT 1,
    password_hash TEXT NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until REAL NOT NULL DEFAULT 0,
    created_utc TEXT NOT NULL,
    last_login_utc TEXT
);
CREATE TABLE IF NOT EXISTS activity_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_utc TEXT NOT NULL,
    org_id INTEGER,
    actor_user_id INTEGER,
    target_user_id INTEGER,
    username TEXT,
    event TEXT NOT NULL,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_activity_org ON activity_log(org_id, id);
"""
# Kolom tambahan. Ditambahkan otomatis ke database lama tanpa menghapus data.
NEW_AUDIT_COLUMNS = {
    "server": "TEXT DEFAULT ''",
    "desc_hash": "TEXT",
    "drift_status": "TEXT",
    "baseline_id": "INTEGER",
    "trace_json": "TEXT",
    "org_id": "INTEGER",
    "created_by_user_id": "INTEGER",
    "created_by": "TEXT",
}
NEW_DECISION_COLUMNS = {
    "org_id": "INTEGER",
    "user_id": "INTEGER",
}
DEFAULT_ORG_NAME = "Organisasi utama"

# Peran dan hak akses. Dipakai oleh semua fungsi data, bukan hanya tampilan.
ROLES = ("developer", "peninjau", "admin")
ROLE_LABEL = {"developer": "Developer", "peninjau": "Peninjau", "admin": "Admin"}
PERMISSIONS = {
    "developer": {"audit", "history"},
    "peninjau": {"audit", "history", "decide"},
    "admin": {"audit", "history", "decide", "manage_users"},
}


class AccessDenied(PermissionError):
    """Akun tidak boleh melakukan aksi ini, atau data tidak ada di organisasinya."""


def can(role, permission) -> bool:
    return permission in PERMISSIONS.get(role, set())


def _add_missing_columns(con, table, columns):
    existing = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
    for col, decl in columns.items():
        if col not in existing:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")


def connect(db_path):
    con = sqlite3.connect(db_path, timeout=10)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    _add_missing_columns(con, "audits", NEW_AUDIT_COLUMNS)
    _add_missing_columns(con, "decisions", NEW_DECISION_COLUMNS)
    _migrate_orphans(con)
    return con


def _migrate_orphans(con):
    """Audit dari database lama (tanpa org_id) masuk ke organisasi pertama. Tidak ada data yang dihapus."""
    orphans = con.execute("SELECT COUNT(*) FROM audits WHERE org_id IS NULL").fetchone()[0]
    orphan_dec = con.execute("SELECT COUNT(*) FROM decisions WHERE org_id IS NULL").fetchone()[0]
    if not orphans and not orphan_dec:
        return
    row = con.execute("SELECT id FROM organizations ORDER BY id LIMIT 1").fetchone()
    org_id = row[0] if row else con.execute(
        "INSERT INTO organizations (name, created_utc) VALUES (?, ?)", (DEFAULT_ORG_NAME, now_utc())).lastrowid
    con.execute("UPDATE audits SET org_id = ? WHERE org_id IS NULL", (org_id,))
    con.execute("UPDATE decisions SET org_id = (SELECT a.org_id FROM audits a WHERE a.id = decisions.audit_id) "
                "WHERE org_id IS NULL")
    con.execute("UPDATE decisions SET org_id = ? WHERE org_id IS NULL", (org_id,))
    con.commit()


def resolve_actor(con, actor, permission=None):
    """Baca ulang akun dari database. Akun yang dinonaktifkan, terhapus, atau masih memakai password
    sementara tidak boleh mengakses data, walaupun sesinya masih terbuka."""
    uid = actor.get("id") if isinstance(actor, dict) else None
    row = con.execute("SELECT id, org_id, username, display_name, role, active, must_change_password "
                      "FROM users WHERE id = ?", (uid,)).fetchone() if uid is not None else None
    if row is None or not row["active"]:
        raise AccessDenied("Sesi tidak berlaku. Silakan masuk lagi.")
    if row["must_change_password"]:
        raise AccessDenied("Ganti password sementara terlebih dahulu.")
    if permission and not can(row["role"], permission):
        raise AccessDenied("Peran akun ini tidak diizinkan melakukan aksi tersebut.")
    return dict(row)


def find_baseline(db_path, actor, server, tool_name):
    """Audit terbaru untuk (server, tool) di organisasi akun yang keputusan TERAKHIR-nya 'Setujui'."""
    with connect(db_path) as con:
        me = resolve_actor(con, actor, "audit")
        row = con.execute(
            "SELECT a.* FROM audits a WHERE a.org_id = ? AND COALESCE(a.server, '') = ? AND a.tool_name = ? AND "
            "(SELECT d.decision FROM decisions d WHERE d.audit_id = a.id ORDER BY d.id DESC LIMIT 1) = 'Setujui' "
            "ORDER BY a.id DESC LIMIT 1", (me["org_id"], (server or "").strip(), tool_name.strip())).fetchone()
    return dict(row) if row else None


def check_drift(db_path, actor, server, tool_name, description):
    base = find_baseline(db_path, actor, server, tool_name)
    if base is None:
        return {"status": DRIFT_NEW, "baseline_id": None, "baseline_utc": None}
    same = fingerprint(base["description"]) == fingerprint(description)
    return {"status": DRIFT_SAME if same else DRIFT_CHANGED,
            "baseline_id": base["id"], "baseline_utc": base["created_utc"]}


def apply_drift(result, drift):
    """Tambahkan hasil cek perubahan ke hasil audit. Perubahan sejak disetujui = wajib tinjau ulang.
    Skor risiko TIDAK diubah: perubahan bukan bukti serangan, tetapi persetujuan lama tidak berlaku lagi."""
    result["drift"] = drift
    status = drift["status"]
    if status == DRIFT_NEW:
        step = {"status": "ok", "detail": "belum ada versi yang disetujui untuk tool ini"}
    elif status == DRIFT_SAME:
        step = {"status": "ok", "detail": f"sama persis dengan versi yang disetujui (audit #{drift['baseline_id']})"}
    else:
        step = {"status": "fail",
                "detail": f"deskripsi BERUBAH sejak disetujui (audit #{drift['baseline_id']}); persetujuan lama "
                          "tidak berlaku, wajib tinjau ulang"}
        result["needs_human_review"] = True
        result["findings"].append({
            "rule_id": "D01", "kategori": "description_drift", "bobot": 0,
            "penjelasan": "Deskripsi berbeda dari versi yang sudah disetujui manusia (indikasi rug pull). "
                          "Persetujuan lama tidak berlaku.",
            "bukti": f"bandingkan dengan audit #{drift['baseline_id']}"})
        result["recommendation"] = (result["recommendation"] + " Deskripsi berubah sejak disetujui: "
                                    "tinjau ulang perbedaannya sebelum tool dipakai lagi.").strip()
    if result.get("trace"):
        trace = [s for s in result["trace"] if s["step"] != "drift"]
        idx = next((i for i, s in enumerate(trace) if s["step"] == "human"), len(trace))
        trace.insert(idx, {"step": "drift", "label": "Cek perubahan sejak disetujui (Console)",
                           "status": step["status"], "detail": step["detail"], "ms": None})
        if status == DRIFT_CHANGED:
            for s in trace:
                if s["step"] == "human" and "WAJIB" not in s["detail"]:
                    s["detail"] += "; WAJIB ditinjau: deskripsi berubah sejak disetujui"
        result["trace"] = trace
    return result


def save_audit(db_path, actor, tool_name, description, result, server="") -> int:
    """Simpan audit di organisasi akun, beserta siapa yang menjalankannya."""
    drift = result.get("drift") or {}
    with connect(db_path) as con:
        me = resolve_actor(con, actor, "audit")
        cur = con.execute(
            "INSERT INTO audits (created_utc, tool_name, description, risk_level, risk_score, layer1_score, "
            "llm_layer_used, needs_human_review, recommendation, findings_json, source, "
            "server, desc_hash, drift_status, baseline_id, trace_json, org_id, created_by_user_id, created_by) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (now_utc(), tool_name.strip(), description, result["risk_level"], result["risk_score"],
             result["layer1_score"], int(result["llm_layer_used"]), int(result["needs_human_review"]),
             result["recommendation"], json.dumps(result["findings"], ensure_ascii=False), result["source"],
             (server or "").strip(), fingerprint(description), drift.get("status"), drift.get("baseline_id"),
             json.dumps(result.get("trace") or [], ensure_ascii=False),
             me["org_id"], me["id"], me["display_name"]))
        return cur.lastrowid


def validate_decision(level, decision, note, confirmed, drift_status=None):
    """Kembalikan daftar pesan kesalahan. Kosong berarti keputusan boleh disimpan."""
    errors = []
    if decision not in DECISIONS:
        errors.append("Pilih salah satu keputusan.")
    if not confirmed:
        errors.append("Centang pernyataan bahwa kamu sudah membaca deskripsi dan temuan.")
    note = (note or "").strip()
    if decision == "Setujui" and level == "HIGH" and len(note) < MIN_NOTE_HIGH_APPROVAL:
        errors.append(f"Menyetujui tool HIGH wajib disertai alasan minimal {MIN_NOTE_HIGH_APPROVAL} karakter.")
    elif decision == "Setujui" and drift_status == DRIFT_CHANGED and len(note) < MIN_NOTE_HIGH_APPROVAL:
        errors.append("Deskripsi berubah sejak disetujui. Menyetujui versi baru wajib disertai alasan "
                      f"minimal {MIN_NOTE_HIGH_APPROVAL} karakter.")
    elif decision == "Setujui" and level == "MEDIUM" and not note:
        errors.append("Menyetujui tool MEDIUM wajib disertai alasan.")
    return errors


def decide(db_path, actor, audit_id, decision, note, confirmed):
    """Simpan keputusan atas nama akun yang login. Level dan status perubahan dibaca dari database,
    bukan dari tampilan. Kembalikan daftar kesalahan validasi (kosong = tersimpan).
    AccessDenied jika peran tidak boleh memutuskan atau audit bukan milik organisasi akun."""
    with connect(db_path) as con:
        me = resolve_actor(con, actor, "decide")
        audit = con.execute("SELECT id, risk_level, drift_status FROM audits WHERE id = ? AND org_id = ?",
                            (audit_id, me["org_id"])).fetchone()
        if audit is None:
            raise AccessDenied("Audit tidak ditemukan.")
        errors = validate_decision(audit["risk_level"], decision, note, confirmed, audit["drift_status"])
        if errors:
            return errors
        con.execute("INSERT INTO decisions (audit_id, decided_utc, reviewer, decision, note, org_id, user_id) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (audit["id"], now_utc(), me["display_name"], decision, (note or "").strip(),
                     me["org_id"], me["id"]))
    return []


def _row_to_audit(r):
    d = dict(r)
    d["findings"] = json.loads(d.pop("findings_json") or "[]")
    d["trace"] = normalize_trace(json.loads(d.pop("trace_json", None) or "[]"))
    d["server"] = d.get("server") or ""
    d["created_by"] = d.get("created_by") or ""
    if "status" in d:
        d["status"] = d["status"] or PENDING
    return d


def load_audits(db_path, actor):
    """Audit organisasi akun (terbaru dulu) beserta status keputusan terakhir."""
    with connect(db_path) as con:
        me = resolve_actor(con, actor, "history")
        rows = con.execute(
            "SELECT a.*, "
            "(SELECT d.decision FROM decisions d WHERE d.audit_id = a.id ORDER BY d.id DESC LIMIT 1) AS status, "
            "(SELECT d.reviewer FROM decisions d WHERE d.audit_id = a.id ORDER BY d.id DESC LIMIT 1) AS reviewer "
            "FROM audits a WHERE a.org_id = ? ORDER BY a.id DESC", (me["org_id"],)).fetchall()
    return [_row_to_audit(r) for r in rows]


def get_audit(db_path, actor, audit_id):
    """Satu audit, hanya jika milik organisasi akun. Selain itu None."""
    with connect(db_path) as con:
        me = resolve_actor(con, actor, "history")
        r = con.execute("SELECT * FROM audits WHERE id = ? AND org_id = ?", (audit_id, me["org_id"])).fetchone()
    return _row_to_audit(r) if r else None


def load_decisions(db_path, actor, audit_id=None):
    with connect(db_path) as con:
        me = resolve_actor(con, actor, "history")
        if audit_id is None:
            rows = con.execute(
                "SELECT d.*, a.tool_name, a.risk_level FROM decisions d JOIN audits a ON a.id = d.audit_id "
                "WHERE d.org_id = ? ORDER BY d.id DESC", (me["org_id"],)).fetchall()
        else:
            rows = con.execute("SELECT * FROM decisions WHERE audit_id = ? AND org_id = ? ORDER BY id DESC",
                               (audit_id, me["org_id"])).fetchall()
    return [dict(r) for r in rows]


def org_summary(db_path, actor):
    """Ringkasan angka untuk Beranda: hanya organisasi akun."""
    audits = load_audits(db_path, actor)
    with connect(db_path) as con:
        me = resolve_actor(con, actor)
        org = con.execute("SELECT name FROM organizations WHERE id = ?", (me["org_id"],)).fetchone()
        users = con.execute("SELECT COUNT(*) FROM users WHERE org_id = ? AND active = 1",
                            (me["org_id"],)).fetchone()[0]
    return {
        "org_name": org["name"] if org else "-",
        "total": len(audits),
        "levels": {lv: sum(a["risk_level"] == lv for a in audits) for lv in LEVELS},
        "pending": sum(a["status"] == PENDING for a in audits),
        "changed": sum(a["drift_status"] == DRIFT_CHANGED and a["status"] == PENDING for a in audits),
        "active_users": users,
    }


# ------------------------------------------------------------------ Peta Risiko
# Organisasi -> server MCP -> tool, memakai audit TERBARU per (server, nama tool) di organisasi akun.
# Hanya membaca; tidak mengubah logika audit. Nama server dan tool adalah data tidak dipercaya:
# ID node DOT selalu buatan sistem (o1, s1, t1, ...), nama hanya muncul di label yang di-escape.
NO_SERVER = "(tanpa server)"
MAP_MAX_TOOLS = 60
DOT_LABEL_MAX = 40
STATUS_SHORT = {PENDING: "Menunggu", "Setujui": "Setujui", "Karantina": "Karantina", "Perlu revisi": "Perlu revisi"}
MAP_COLORS = {  # (isi, tepi) dari palet lembar
    "LOW": ("#cfe5d8", "#1f7a4d"), "MEDIUM": ("#f6e2a6", "#9a6412"), "HIGH": ("#f3cdc8", "#b42318"),
}


def _level_rank(level):
    return LEVELS.index(level) if level in LEVELS else 0


def latest_tools(db_path, actor):
    """Satu baris per (server, nama tool): audit terbaru di organisasi akun."""
    seen, tools = set(), []
    for a in load_audits(db_path, actor):  # terbaru dulu
        key = ((a["server"] or "").strip(), a["tool_name"].strip())
        if key in seen:
            continue
        seen.add(key)
        tools.append({
            "audit_id": a["id"], "server": key[0] or NO_SERVER, "has_server": bool(key[0]),
            "tool_name": key[1], "risk_level": a["risk_level"] if a["risk_level"] in LEVELS else "LOW",
            "risk_score": a["risk_score"], "drift_status": a["drift_status"] or "", "status": a["status"],
            "created_utc": a["created_utc"], "created_by": a["created_by"],
        })
    return tools


def filter_tools(tools, levels=None, statuses=None):
    return [t for t in tools if (levels is None or t["risk_level"] in levels)
            and (statuses is None or t["status"] in statuses)]


def group_servers(tools):
    """Server beserta tool-nya. Level server = level tool terburuk di dalamnya."""
    servers = {}
    for t in tools:
        s = servers.setdefault(t["server"], {"server": t["server"], "has_server": t["has_server"],
                                             "tools": [], "risk_level": "LOW"})
        s["tools"].append(t)
        if _level_rank(t["risk_level"]) > _level_rank(s["risk_level"]):
            s["risk_level"] = t["risk_level"]
    # tanpa server di akhir, sisanya urut nama
    return sorted(servers.values(), key=lambda s: (not s["has_server"], s["server"].lower()))


def map_summary(tools):
    return {
        "servers": len({t["server"] for t in tools}),
        "tools": len(tools),
        "high": sum(t["risk_level"] == "HIGH" for t in tools),
        "changed": sum(t["drift_status"] == DRIFT_CHANGED for t in tools),
        "pending": sum(t["status"] == PENDING for t in tools),
    }


def dot_label(text, limit=DOT_LABEL_MAX) -> str:
    """Label DOT yang aman untuk teks tidak dipercaya: buang karakter tak terlihat/kontrol, ubah baris baru
    jadi spasi, potong maks `limit` karakter, lalu escape backslash dan tanda kutip; < > diganti ‹ ›."""
    cleaned = []
    for ch in str(text if text is not None else ""):
        if _is_invisible(ch) or unicodedata.category(ch) in ("Cc", "Zl", "Zp"):
            cleaned.append(" " if ch in "\r\n\t  " else "")
            continue
        cleaned.append(ch)
    s = " ".join("".join(cleaned).split())
    if len(s) > limit:
        s = s[: limit - 1] + "…"
    return (s.replace("\\", "\\\\").replace('"', '\\"').replace("<", "‹").replace(">", "›"))


def risk_map_dot(org_name, servers) -> str:
    """Kode DOT untuk peta risiko. Teks dari data hanya lewat dot_label(); baris baru di label dari sistem."""
    lines = [
        "digraph PetaRisiko {",
        'graph [rankdir=LR, bgcolor="transparent", nodesep=0.18, ranksep=0.55, pad=0.2];',
        'node [shape=box, style="rounded,filled", fontname="Public Sans", fontsize=11, margin="0.14,0.06", '
        'color="#cfd6da", fillcolor="#ffffff", fontcolor="#20262d", penwidth=1.2];',
        'edge [color="#8d99a3", arrowsize=0.55, penwidth=1];',
        f'o1 [label="{dot_label(org_name)}", fillcolor="#0f6e74", color="#0f6e74", fontcolor="#ffffff", '
        'fontsize=12];',
    ]
    t_index = 0
    for s_index, s in enumerate(servers, start=1):
        fill, edge = MAP_COLORS[s["risk_level"]]
        sid = f"s{s_index}"
        lines.append(f'{sid} [label="{dot_label(s["server"])}\\n{s["risk_level"]} · {len(s["tools"])} tool", '
                     f'fillcolor="{fill}", color="{edge}"];')
        lines.append(f"o1 -> {sid};")
        for t in s["tools"]:
            t_index += 1
            tid = f"t{t_index}"
            fill, edge = MAP_COLORS[t["risk_level"]]
            changed = t["drift_status"] == DRIFT_CHANGED
            status = STATUS_SHORT.get(t["status"], "Menunggu")
            extra = " · BERUBAH" if changed else ""
            style = "rounded,filled,dashed" if changed else "rounded,filled"
            lines.append(f'{tid} [label="{dot_label(t["tool_name"])}\\n{t["risk_level"]} {int(t["risk_score"])} · '
                         f'{status}{extra}", fillcolor="{fill}", color="{edge}", style="{style}", '
                         f'penwidth={2.2 if changed else 1.2}];')
            lines.append(f"{sid} -> {tid};")
    lines.append("}")
    return "\n".join(lines)


def env(name, default=""):
    return (os.getenv(name) or default).strip()
