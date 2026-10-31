# WhisperGuard

AI security co-pilot untuk memeriksa **integritas nama dan deskripsi tool MCP** (deteksi *tool poisoning*),
dibangun dengan IBM Bob + Langflow + MCP untuk Hacktiv8 Hackathon National (IBM SkillsBuild).

**Tautan cepat**

- Dokumentasi teknis: [docs/TECHNICAL_DOCUMENTATION.md](docs/TECHNICAL_DOCUMENTATION.md)
- Validasi pengguna: [docs/user_validation/RINGKASAN_USER_VALIDATION.md](docs/user_validation/RINGKASAN_USER_VALIDATION.md)
- Hasil evaluasi holdout v3: [eval/results/eval_v3_20261028_045128.md](eval/results/eval_v3_20261028_045128.md)
- Video demo: [ISI link]
- Video pitching: [ISI link]

## Masalah
Agent seperti IBM Bob memilih dan memercayai tool hanya dari **nama dan deskripsinya**. Deskripsi yang disisipi
instruksi tersembunyi dapat membuat agent menjalankan aksi yang tidak diminta pengguna (MCP Tool Poisoning).

## Cara Kerja

```
Pengguna (chat) -> IBM Bob -> MCP -> Langflow
tool 1: audit_tool_description_integrity   (lapisan aturan + lapisan LLM -> skor, level, bukti)
tool 2: record_audit_findings              (Google Sheets + Google Docs + Gmail DRAFT)
```

- **Lapisan 1 (aturan deterministik, R01–R13):** memeriksa karakter tak terlihat, markup tersembunyi, perintah
  menyembunyikan sesuatu dari pengguna, akses kredensial, eksfiltrasi, override instruksi, blob base64,
  homoglyph, permintaan data pengguna, dan konvensi penamaan.
- **Lapisan 2 (LLM terisolasi):** menilai maksud deskripsi.
  - Hanya bisa **menaikkan** skor.
  - Kutipan bukti dari LLM harus ada di deskripsi asli.
  - Jika LLM gagal, sistem tetap memakai lapisan 1 dan meminta tinjauan manusia.
- **Aksi:** hasil dicatat ke risk register. Email hanya dibuat sebagai **draft**, sehingga keputusan tetap di
  tangan manusia.
- **Mitigasi injeksi lanjutan:** output dibaca agent lain, jadi kutipan bukti dinetralkan dulu: karakter tak
  terlihat dibuang, tanda `< >` dinonaktifkan, dan panjang dibatasi.

## Console

UI Streamlit lokal untuk staf keamanan/TI. Jalur utama pengguna tetap IBM Bob, sedangkan Console menjadi ruang
kendali manusia. Fiturnya:

- **Login berperan:** developer, peninjau, dan admin, dengan data terpisah per organisasi. Hak akses diperiksa
  di fungsi data, tidak hanya disembunyikan di tampilan.
- **Jejak eksekusi:** langkah audit ditampilkan sebagai diagram yang bisa diputar ulang.
- **Mode Sinar-X:** membandingkan yang dilihat manusia dengan yang dibaca AI. Karakter tak terlihat ditampakkan
  dan kutipan bukti disorot.
- **Peta Risiko:** diagram server → tool dari audit terbaru tiap tool.
- **Deteksi rug pull (D01):** muncul jika deskripsi berubah setelah disetujui. Persetujuan lama tidak berlaku
  dan tool wajib ditinjau ulang.
- **Keputusan tercatat:** Setujui, Karantina, atau Perlu revisi, dicatat atas nama akun. Menyetujui tool
  berisiko wajib disertai alasan.

Menjalankan:

```bash
pip install -r requirements_console.txt
copy .env.example .env            # isi LANGFLOW_RUN_URL, LANGFLOW_API_KEY, MODEL_NAME
python manage_users.py create-admin
streamlit run console_app.py
```

Panduan lengkap: [PANDUAN_CONSOLE.md](PANDUAN_CONSOLE.md).

## Struktur Repo

| Berkas / Folder | Fungsi |
|---|---|
| `auditor.py` | Sumber: mesin aturan (lapisan 1) dan skor risiko |
| `hybrid.py` | Sumber: lapisan LLM, penggabungan skor (hanya naik), jejak eksekusi |
| `component_part.py` | Sumber: kelas komponen Langflow dan sanitasi output |
| `build_component.py` | Merangkai tiga sumber di atas menjadi berkas komponen |
| `whisperguard_component_v2_2.py` | Custom Component Langflow (hasil build, jangan diedit langsung) |
| `whisperguard_component_v2_1.py` | Versi sebelumnya, acuan uji regresi |
| `component_harness.py` | Menjalankan komponen tanpa Langflow (untuk tes) |
| `console_app.py` | Console: tampilan Streamlit |
| `console_core.py` | Console: panggilan Langflow, cadangan lokal, jejak, rug pull, database, hak akses, peta risiko |
| `console_auth.py` | Console: akun, hash password scrypt, penguncian login, sesi, log aktivitas |
| `manage_users.py` | CLI akun dan organisasi (admin pertama dibuat di sini) |
| `requirements_console.txt` | Dependensi Console |
| `eval/holdout_v3/`, `lock_holdout.py` | Holdout evaluasi + kunci SHA-256 (evaluasi menolak jalan jika isi berubah) |
| `eval_v3.py` | Evaluasi pada flow Langflow sungguhan, N run per kasus, tiga mode (aturan/LLM/hybrid) |
| `eval/results/` | Laporan evaluasi (.json + .md) |
| `eval/holdout_v4_kandidat/` | Kasus dari validasi pengguna untuk holdout berikutnya (belum dikunci) |
| `eval.py`, `eval_v2.py` | Set uji pengembangan lama |
| `test_*.py` | Tujuh berkas tes (lihat [Menjalankan Tes](#menjalankan-tes)) |
| `flows/` | Ekspor flow Langflow **tanpa API key** |
| `docs/` | Dokumentasi teknis dan validasi pengguna |
| `test/` | Kasus uji Playground, prompt LLM, panduan flow aksi |
| `bukti/` | Tangkapan layar bukti pengujian dan integrasi |

## Bukti Pengujian & Hasil Integrasi

| Eksekusi dua flow dari IBM Bob | Hasil audit LOW: tidak ada aksi |
| --- | --- |
| ![IBM Bob menjalankan audit lalu record_audit_findings](bukti/ibmbob_running_2flow.png) | ![Audit LOW, flow aksi membalas No action needed](bukti/uji_low.png) |

| Risk Register di Google Sheets | Laporan audit di Google Docs |
| --- | --- |
| ![Baris HIGH tercatat di Risk Register](bukti/spreadsheet_high.png) | ![Laporan audit HIGH di Google Docs](bukti/docs_high.png) |

### Akses Google Workspace (akun uji)

| Sheets | Docs | Gmail (draft) |
| --- | --- | --- |
| ![Akses Google Sheets](bukti/akses_spreadsheet.png) | ![Akses Google Docs](bukti/akses_doc.png) | ![Akses Gmail draft](bukti/akses_gmail.png) |

## Menjalankan Tes

Semua tes berjalan tanpa jaringan: Langflow dan LLM ditiru.

| Berkas | Yang diuji |
|---|---|
| `test_hybrid.py` | Properti keamanan lapisan LLM: hanya menaikkan skor, grounding, fail-safe, nonce, tanda kutip tipografis |
| `test_component.py` | Komponen Langflow v2.2 tanpa Langflow, termasuk regresi terhadap v2.1 |
| `test_sync.py` | Komponen hasil build identik dengan `auditor.py` + `hybrid.py` |
| `test_sanitization.py` | Output bebas karakter tak terlihat, tanpa `< >` aktif, terpotong sesuai batas |
| `test_eval_v3.py` | Penguncian holdout dan skrip evaluasi |
| `test_console.py` | Logika Console: peran, isolasi organisasi, password, rug pull, Sinar-X, Peta Risiko |
| `test_console_ui.py` | Tampilan Console lewat Streamlit AppTest |

```bash
python test_hybrid.py
python test_component.py
python test_sync.py
python test_sanitization.py
python test_eval_v3.py
python test_console.py          # butuh requirements_console.txt
python test_console_ui.py       # butuh requirements_console.txt
```

Hasil terakhir: 308 PASS, 0 FAIL ([dokumentasi teknis, bagian 7](docs/TECHNICAL_DOCUMENTATION.md#7-pengujian)).

## Menyiapkan Langflow dan MCP

1. Impor flow dari `flows/` ke Langflow (dipakai: Langflow Desktop 1.11.6). Isi API key model dan Composio
   langsung di Langflow, jangan di berkas repo.
2. Ekspos kedua flow sebagai tool MCP di tab MCP Langflow, lalu tambahkan servernya di pengaturan MCP IBM Bob.
   Konfigurasi `.bob/mcp.json` berisi kunci dan tidak di-commit.

## Hasil Evaluasi (holdout v3)

Sumber: [eval/results/eval_v3_20261028_045128.md](eval/results/eval_v3_20261028_045128.md).

- **Setup:**
  - 33 kasus (9 malicious, 24 clean), dikunci dengan SHA-256 sebelum evaluasi.
  - 5 run per kasus (165 panggilan) ke flow Langflow sungguhan.
  - Model: `gemini-3.5-flash-lite`.
- **Aturan saja:** 0 dari 9 serangan ditandai. Semua serangan di holdout ini berupa kalimat halus tanpa pola
  yang dicari aturan.
- **Hybrid (aturan + LLM):**
  - Skor ≥ 20 (MEDIUM ke atas): 9 dari 9 serangan ditandai di semua run (recall 100%).
  - Skor ≥ 50 (HIGH): 48,9% run.
- **False positive (skor ≥ 20):** 1 dari 24 tool bersih, yaitu 5 dari 120 run (4,2%). Kasusnya tool resmi
  `fetch` dari repo MCP servers, yang deskripsinya berisi kalimat perintah ke model.
- **Waktu per audit:**
  - Di dalam komponen: median 1,2 detik, p90 2,4 detik.
  - Round-trip: median 1,5 detik.
- **Kegagalan:** 0 permintaan gagal dan 0 kegagalan LLM.

Angka yang dulu ditampilkan di README berasal dari set pengembangan `eval.py`/`eval_v2.py`: 25 tool bersih
tanpa false positive, dan 11 serangan baru yang semuanya ditandai. Set itu sudah dipakai untuk menyetel aturan
(sudah "terbakar"), jadi angkanya optimistis dan bukan angka utama.

## Keterbatasan

- Holdout kecil (33 kasus, 9 serangan). Selisih satu kasus menggeser recall lebih dari 10 poin persen.
- Belum ada kasus dari penguji independen atau dataset serangan publik berlisensi. Kasus serangan ditulis tim
  atau dibuat dengan bantuan Gemini, sedangkan lapisan LLM juga memakai Gemini, sehingga hasilnya bisa
  optimistis.
- Lebih dari separuh serangan halus hanya mencapai MEDIUM, belum HIGH.
- Yang diaudit hanya nama dan deskripsi tool. `inputSchema`, nilai default, dan output tool belum diperiksa.
- Deteksi tidak menjamin semua serangan tertangkap. Hasil MEDIUM dan flag `needs_human_review` memerlukan
  tinjauan manusia.
- Auto-remediation (memblokir tool otomatis) sengaja tidak diimplementasikan.

Batasan lengkap dan roadmap: [dokumentasi teknis, bagian 8.5 dan 10](docs/TECHNICAL_DOCUMENTATION.md).

## Lisensi

Dirilis di bawah [Apache License 2.0](LICENSE).
Copyright 2026 Mukhammad Nuruddin Alhaffaf dan Salsabilla Fadillah Safina.
