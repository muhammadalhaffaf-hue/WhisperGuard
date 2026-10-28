"""Mengunci holdout evaluasi WhisperGuard dengan hash SHA-256.

    python lock_holdout.py                       # kunci eval/holdout_v3/holdout.jsonl
    python lock_holdout.py --check               # hanya periksa apakah holdout masih cocok dengan kunci

Aturan main holdout:
- Holdout dikunci SEBELUM aturan/prompt disetel ulang. Setelah evaluasi pertama dijalankan,
  aturan dan prompt tidak boleh diubah berdasarkan hasilnya.
- Kunci tidak bisa ditimpa. Holdout yang sudah dipakai untuk menyetel dianggap "terbakar":
  buat folder holdout baru (mis. holdout_v4) daripada mengunci ulang yang lama.
- eval_v3.py menolak jalan jika isi holdout tidak cocok dengan hash di HOLDOUT_LOCK.txt.

Format holdout.jsonl: satu objek JSON per baris dengan kolom
  id (unik), source (penguji | tim | publik | sintetis-llm), label (malicious | clean), tool_name, description.
"""
import argparse
import datetime
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_HOLDOUT = os.path.join(HERE, "eval", "holdout_v3", "holdout.jsonl")
LOCK_NAME = "HOLDOUT_LOCK.txt"
SOURCES = ("penguji", "tim", "publik", "sintetis-llm")
LABELS = ("malicious", "clean")
REQUIRED = ("id", "source", "label", "tool_name", "description")


class HoldoutError(Exception):
    pass


def lock_path(holdout_path):
    return os.path.join(os.path.dirname(os.path.abspath(holdout_path)), LOCK_NAME)


def read_normalized(path) -> str:
    """Isi berkas dengan akhir baris LF, supaya hash tidak berubah karena konversi CRLF oleh git/editor."""
    with open(path, encoding="utf-8", newline="") as f:
        return f.read().replace("\r\n", "\n")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path) -> str:
    return sha256_text(read_normalized(path))


def parse_holdout(text: str) -> list:
    """Validasi ketat. Mengembalikan daftar kasus atau melempar HoldoutError dengan nomor baris."""
    cases, seen, errors = [], set(), []
    for no, line in enumerate(text.split("\n"), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"baris {no}: bukan JSON valid ({e.msg})")
            continue
        if not isinstance(obj, dict):
            errors.append(f"baris {no}: harus objek JSON")
            continue
        missing = [k for k in REQUIRED if not isinstance(obj.get(k), str) or not obj[k].strip()]
        if missing:
            errors.append(f"baris {no}: kolom kosong/hilang: {', '.join(missing)}")
            continue
        if obj["source"] not in SOURCES:
            errors.append(f"baris {no}: source harus salah satu dari {SOURCES}")
        if obj["label"] not in LABELS:
            errors.append(f"baris {no}: label harus salah satu dari {LABELS}")
        if obj["id"] in seen:
            errors.append(f"baris {no}: id '{obj['id']}' ganda")
        seen.add(obj["id"])
        cases.append(obj)
    if errors:
        raise HoldoutError("Holdout tidak valid:\n  " + "\n  ".join(errors))
    if not cases:
        raise HoldoutError("Holdout kosong. Isi kasus dulu sebelum dikunci.")
    labels = {c["label"] for c in cases}
    if labels != set(LABELS):
        raise HoldoutError("Holdout harus berisi kasus malicious DAN clean (untuk recall dan false positive rate).")
    return cases


def read_lock(path) -> dict:
    lock = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if ":" in line and not line.startswith("#"):
                k, v = line.split(":", 1)
                lock[k.strip()] = v.strip()
    if len(lock.get("sha256", "")) != 64:
        raise HoldoutError(f"{path} rusak: baris sha256 tidak ditemukan.")
    return lock


def load_locked_holdout(holdout_path=DEFAULT_HOLDOUT):
    """Untuk evaluasi: kembalikan (kasus, isi_kunci). Melempar HoldoutError jika belum dikunci atau hash beda."""
    lp = lock_path(holdout_path)
    if not os.path.exists(holdout_path):
        raise HoldoutError(f"Holdout tidak ditemukan: {holdout_path}")
    if not os.path.exists(lp):
        raise HoldoutError(f"Holdout belum dikunci ({LOCK_NAME} tidak ada). Jalankan: python lock_holdout.py")
    lock = read_lock(lp)
    actual = sha256_file(holdout_path)
    if actual != lock["sha256"]:
        raise HoldoutError(f"Hash holdout TIDAK cocok dengan {LOCK_NAME}: isi holdout berubah setelah dikunci.\n"
                           f"  terkunci: {lock['sha256']}\n  sekarang: {actual}")
    return parse_holdout(read_normalized(holdout_path)), lock


def component_fingerprint():
    """Hash berkas komponen hasil build, dicatat di kunci agar perubahan aturan setelah penguncian terlihat."""
    import build_component
    path = os.path.join(HERE, build_component.OUTPUT)
    return build_component.OUTPUT, (sha256_file(path) if os.path.exists(path) else "(tidak ada)")


def write_lock(holdout_path):
    lp = lock_path(holdout_path)
    if os.path.exists(lp):
        raise HoldoutError(f"{lp} sudah ada. Kunci tidak ditimpa. Holdout yang sudah dipakai menyetel aturan "
                           "dianggap terbakar: buat folder holdout baru.")
    text = read_normalized(holdout_path)
    cases = parse_holdout(text)
    count = lambda key, val: sum(c[key] == val for c in cases)  # noqa: E731
    comp_name, comp_hash = component_fingerprint()
    rel = os.path.relpath(holdout_path, HERE).replace(os.sep, "/")
    lines = [
        "# WhisperGuard - kunci holdout. JANGAN diedit manual.",
        "# Setelah evaluasi pertama dijalankan, aturan/prompt tidak boleh diubah berdasarkan hasilnya.",
        f"file: {rel}",
        f"sha256: {sha256_text(text)}",
        f"cases: {len(cases)}",
        "labels: " + ", ".join(f"{lb} {count('label', lb)}" for lb in LABELS),
        "sources: " + ", ".join(f"{s} {count('source', s)}" for s in SOURCES),
        f"locked_at_utc: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
        f"component_file: {comp_name}",
        f"component_sha256: {comp_hash}",
    ]
    with open(lp, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    return lp, cases


def main(argv=None):
    p = argparse.ArgumentParser(description="Kunci holdout evaluasi WhisperGuard (SHA-256).")
    p.add_argument("--holdout", default=DEFAULT_HOLDOUT, help="lokasi holdout.jsonl")
    p.add_argument("--check", action="store_true", help="hanya periksa kecocokan dengan kunci")
    args = p.parse_args(argv)
    try:
        if args.check:
            cases, lock = load_locked_holdout(args.holdout)
            print(f"OK: holdout cocok dengan kunci ({len(cases)} kasus, dikunci {lock.get('locked_at_utc')} UTC).")
        else:
            lp, cases = write_lock(args.holdout)
            print(f"OK: {len(cases)} kasus dikunci di {lp}")
    except HoldoutError as e:
        print(f"Gagal: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
