# WhisperGuard

AI security co-pilot untuk memeriksa **integritas nama dan deskripsi tool MCP** (deteksi *tool poisoning*),
dibangun dengan IBM Bob + Langflow + MCP untuk Hacktiv8 Hackathon National (IBM SkillsBuild).

## Masalah
Agent seperti IBM Bob memilih dan memercayai tool hanya dari **nama dan deskripsinya**. Deskripsi yang disisipi
instruksi tersembunyi dapat membuat agent mengeksekusi aksi yang tidak diminta pengguna (MCP Tool Poisoning).

## Cara kerja
```
Pengguna (chat) -> IBM Bob -> MCP -> Langflow
   tool 1: audit_tool_description_integrity   (lapisan aturan + lapisan LLM -> skor, level, bukti)
   tool 2: record_audit_findings              (Google Sheets + Google Docs + Gmail DRAFT)
```
- **Lapisan 1 (aturan deterministik):** karakter tak terlihat, markup tersembunyi, penyembunyian dari pengguna,
  akses kredensial, eksfiltrasi, override instruksi, blob base64, homoglyph, konvensi penamaan, dan lainnya.
- **Lapisan 2 (LLM terisolasi):** menilai maksud deskripsi. Hanya dapat **menaikkan** skor; bukti dikutip
  harus ada di deskripsi asli; jika LLM gagal sistem tetap memakai lapisan 1 dan meminta tinjauan manusia.
- **Aksi:** hasil dicatat ke risk register; email hanya berupa **draft** (human oversight).
- **Mitigasi injeksi lanjutan:** kutipan bukti di output dinetralkan (karakter tak terlihat dibuang, tanda `< >`
  dinonaktifkan, panjang dibatasi) karena output dibaca agent lain.

## Struktur repo
| Berkas | Fungsi |
|---|---|
| `auditor.py` | Mesin aturan (lapisan 1) dan skor risiko |
| `hybrid.py` | Lapisan LLM dan penggabungan skor (hanya naik) |
| `whisperguard_component_v2.py` | Custom Component Langflow (berkas mandiri; dihasilkan `build_component.py`) |
| `build_component.py` | Membangun komponen dari `auditor.py` + `hybrid.py` |
| `eval.py`, `eval_v2.py`, `test_hybrid.py` | Set uji dan tes properti keamanan |
| `llm_prompt.md` | Prompt lapisan LLM dan catatan desain |
| `kasus_uji_*.md` | Kasus uji untuk Playground Langflow |
| `panduan_aksi_otomatis.md` | Panduan flow aksi (Sheets/Docs/Gmail) |
| `flows/` | Ekspor flow Langflow **tanpa API key** |

## Menjalankan tes lokal
Butuh Python 3.10+. Tidak ada dependensi eksternal untuk inti kode.
```
python eval_v2.py
python test_hybrid.py
```

## Menyiapkan Langflow dan MCP
1. Impor flow dari `flows/`, isi API key sendiri (model bahasa dan Composio) di Langflow, jangan di berkas repo.
2. Aktifkan MCP Server di Langflow, buat `mcp.json` sendiri (tidak disertakan karena berisi kunci), lalu tambahkan
   server di pengaturan MCP IBM Bob.

## Hasil evaluasi (sampel kecil, kasus uji sebagian ditulis sendiri oleh tim)
- Tool bersih: 25 kasus, 0 false positive.
- Serangan baru: 11 kasus, semuanya ditandai (8 HIGH, 3 MEDIUM).
- Lapisan aturan saja pada set holdout awal: 1 dari 8; setelah lapisan LLM, kasus-kasus itu terdeteksi,
  tetapi set tersebut sudah dipakai selama pengembangan sehingga bukan ukuran generalisasi.

## Keterbatasan
- Sampel uji kecil dan belum divalidasi pada dataset serangan skala besar atau registry MCP sungguhan.
- Deteksi belum menjamin menangkap semua serangan; hasil MEDIUM dan flag `needs_human_review` memerlukan tinjauan manusia.
- Auto-remediation (memblokir tool otomatis) sengaja tidak diimplementasikan.
