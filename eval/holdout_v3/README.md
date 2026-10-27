# Holdout v3

Set uji yang dikunci **sebelum** aturan atau prompt disetel ulang. Hasilnya hanya untuk mengukur,
bukan untuk menyetel aturan.

## Format `holdout.jsonl`

Satu objek JSON per baris:

```json
{"id": "P-001", "source": "penguji", "label": "malicious", "tool_name": "...", "description": "..."}
```

| Kolom | Nilai |
|---|---|
| `id` | unik, mis. `P-001` (penguji), `T-001` (tim), `X-001` (publik) |
| `source` | `penguji` (dari user validation), `tim`, atau `publik` (dataset independen, mis. MCPTox) |
| `label` | `malicious` atau `clean` |
| `tool_name`, `description` | persis seperti yang diterima agent |

Kasus `publik` wajib mencatat asal datanya di tabel di bawah. Kasus `penguji` diisi dari user validation,
tidak dikarang.

## Urutan kerja

1. Isi `holdout.jsonl`. Status sekarang: **[ISI] kasus penguji, tim, dan publik belum ada.**
2. Kunci: `python lock_holdout.py` (menulis `HOLDOUT_LOCK.txt`, tidak bisa ditimpa).
3. Evaluasi: `python eval_v3.py` (menolak jalan jika hash berubah).
4. Setelah evaluasi pertama, aturan/prompt tidak diubah berdasarkan hasil holdout ini.
   Jika tetap diubah, holdout ini terbakar: buat `holdout_v4`.

## Asal data publik

| Sumber | Versi / tanggal unduh | Lisensi | Cara memilih sampel |
|---|---|---|---|
| [ISI] | [ISI] | [ISI] | [ISI] |
