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
| `id` | unik, mis. `P-001` (penguji), `T-001` (tim), `X-001` (publik), `s-01` (sintetis-llm) |
| `source` | `penguji` (dari user validation), `tim`, `publik` (dataset independen, mis. MCPTox), atau `sintetis-llm` |
| `label` | `malicious` atau `clean` |
| `tool_name`, `description` | persis seperti yang diterima agent |

Kasus `publik` wajib mencatat asal datanya di tabel di bawah. Kasus `penguji` diisi dari user validation,
tidak dikarang.

## Kasus sintetis-llm

Kasus sintetis-llm (s-01 s.d. s-12) dibuat dengan bantuan LLM Gemini 3.1 Pro bukan oleh pengguna nyata.
Versi pertama memakai penanda eksplisit '[Perintah Tersembunyi]'; versi ini direvisi menjadi serangan halus
sebelum holdout dikunci. Tim tidak melihat hasil audit kasus ini sebelum dikunci.

`eval_v3.py` melaporkan hasil setiap sumber secara terpisah (bagian "Hasil per sumber"), jadi angka sumber
ini tidak tercampur dengan sumber lain.

## Urutan kerja

1. Isi `holdout.jsonl`. Status sekarang (33 kasus, belum dikunci):
   - `sintetis-llm`: s-01 sampai s-12 (6 clean, 6 malicious)
   - `tim`: t-01 sampai t-06 (3 malicious halus tanpa penanda eksplisit, 3 clean)
   - `publik`: x-01 sampai x-15 (15 clean, deskripsi tool asli)
   - **[ISI] kasus penguji belum ada.** Kasus publik malicious belum ada (lihat di bawah).
2. Kunci: `python lock_holdout.py` (menulis `HOLDOUT_LOCK.txt`, tidak bisa ditimpa).
3. Evaluasi: `python eval_v3.py` (menolak jalan jika hash berubah).
4. Setelah evaluasi pertama, aturan/prompt tidak diubah berdasarkan hasil holdout ini.
   Jika tetap diubah, holdout ini terbakar: buat `holdout_v4`.

## Asal data publik

| Sumber | Versi / tanggal unduh | Lisensi | Cara memilih sampel |
|---|---|---|---|
| [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers), server `time`, `fetch`, `git` (kasus x-01 sampai x-15, semua `clean`) | commit `ef9808f71090d0db3eda99e2af2ba78f1086f4fb`, diunduh 2026-10-28 | Apache-2.0 (sebagian kontribusi lama MIT), lihat `LICENSE` di repo | Semua tool dari ketiga server diambil tanpa seleksi (2 + 1 + 12). `name` dan `description` disalin otomatis dari argumen `@server.tool(...)` di `src/<server>/src/mcp_server_<server>/server.py`, tanpa diubah. Deskripsi parameter (inputSchema) tidak diambil. |

Catatan:
- `fetch` (x-03) adalah tool resmi yang deskripsinya berisi kalimat berbentuk instruksi ke model
  ("this tool now grants you internet access ..."). Kasus ini dibiarkan sebagai uji false positive yang sulit.
- Nama `read_text_file` pernah dipakai di set dev `eval_v2.py` untuk kasus jahat buatan; tidak ada nama atau
  deskripsi dari x-01 sampai x-15 yang dipakai di set dev.
- **Kasus publik malicious belum ada.** Yang sudah diperiksa:
  - MCPTox (arXiv:2508.14925): data di `anonymous.4open.science/r/AAAI26-7C02`, tanpa berkas LICENSE.
  - `invariantlabs-ai/mcp-injection-experiments`: tanpa lisensi; contohnya (`add` + `<IMPORTANT>`) juga mirip
    kasus dev.

  Tanpa lisensi, izin pakai ulang tidak jelas. [ISI] tambahkan setelah ada izin atau lisensi yang jelas.
