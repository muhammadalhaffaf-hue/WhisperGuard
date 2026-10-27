"""Membangun komponen Langflow WhisperGuard: satu berkas mandiri untuk ditempel ke Custom Component.

Sumber kebenaran (edit hanya di sini):
  auditor.py        lapisan 1, aturan deterministik
  hybrid.py         lapisan 2 (LLM) + penggabungan skor + jejak eksekusi
  component_part.py kelas komponen Langflow

Jalankan setelah mengubah salah satu sumber:  python build_component.py
test_sync.py gagal jika berkas komponen tidak sama dengan hasil build.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUTPUT = "whisperguard_component_v2_2.py"
HYBRID_MARKER = "# ---- BUILD: semua baris di bawah ini disalin apa adanya ke komponen ----\n"


def _read(name):
    with open(os.path.join(HERE, name), encoding="utf-8", newline="") as f:
        return f.read().replace("\r\n", "\n")


def build() -> str:
    """Rangkai ketiga sumber menjadi teks komponen (akhir baris LF)."""
    aud = _read("auditor.py").split('if __name__ == "__main__":')[0].rstrip("\n") + "\n"
    hyb = _read("hybrid.py").split(HYBRID_MARKER, 1)[1].rstrip("\n") + "\n"
    comp = _read("component_part.py").rstrip("\n") + "\n"
    return aud + "\n\n" + hyb + "\n\n" + comp


if __name__ == "__main__":
    with open(os.path.join(HERE, OUTPUT), "w", encoding="utf-8", newline="\n") as f:
        f.write(build())
    print(f"OK: {OUTPUT} dibangun")
