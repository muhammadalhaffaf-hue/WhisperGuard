# WhisperGuard Console v3 (produk tahap 1, lokal)

Ruang kendali manusia untuk hasil audit. Bob tetap jalur utama untuk developer
(chat -> Bob -> tool Langflow via MCP -> aksi). Console dipakai tim keamanan/TI untuk:

1. **Audit**: tempel nama server (opsional), nama, dan deskripsi tool. Console mengaudit memakai flow
   Langflow yang sama dengan Bob. Jika Langflow tidak bisa dihubungi, Console memakai lapisan aturan
   lokal (`auditor.py`) dan menandai hasilnya "perlu tinjauan manusia".
2. **Jejak eksekusi** (baru): diagram alur yang menyala langkah demi langkah
   (Input -> Karakter tersembunyi -> Aturan -> LLM -> Verifikasi bukti -> Gabung skor -> Cek perubahan
   -> Keputusan manusia) plus tabel rincian dan durasi asli. Jejak diputar ulang dari langkah yang
   benar-benar dijalankan, bukan animasi hiasan.
3. **Deteksi rug pull** (baru): saat manusia menyetujui sebuah tool, deskripsinya menjadi acuan.
   Audit berikutnya untuk tool yang sama (server + nama sama) diberi label BARU / SAMA / BERUBAH.
   BERUBAH = persetujuan lama tidak berlaku, wajib ditinjau ulang, dan perbedaan kata ditampilkan
   (karakter tersembunyi ditampakkan sebagai ⟦U+....⟧). Skor risiko tidak diubah oleh cek ini.
4. **Riwayat**: semua audit dengan kolom server dan status perubahan, filter, unduh CSV.
5. **Keputusan**: Setujui / Karantina / Perlu revisi. Menyetujui tool HIGH, atau versi yang BERUBAH,
   wajib disertai alasan minimal 20 karakter. Keputusan otomatis dicatat atas nama akun yang login.
   Jejak keputusan tidak bisa diubah.
6. **Akun dan organisasi** (baru): wajib login. Setiap audit, keputusan, dan cek rug pull hanya
   berlaku di organisasi akun. Akun organisasi A tidak bisa melihat atau memutuskan data organisasi B.

## Peran

| Peran | Audit + Riwayat | Keputusan | Kelola pengguna |
|---|---|---|---|
| developer | Ya | - | - |
| peninjau | Ya | Ya | - |
| admin | Ya | Ya | Ya |

Hak akses diperiksa di `console_core.py` / `console_auth.py` setiap kali data dibaca atau ditulis,
dan akun dibaca ulang dari database (akun yang dinonaktifkan atau diturunkan perannya langsung
kehilangan akses walaupun sesinya masih terbuka). Admin tidak bisa menonaktifkan dirinya sendiri
atau admin aktif terakhir.

## Keamanan akun
- Password di-hash dengan `hashlib.scrypt` + salt acak per akun, dibandingkan dengan
  `hmac.compare_digest`. Password asli tidak pernah disimpan atau dicatat.
- Password minimal 10 karakter. Password sementara dari admin wajib diganti saat login pertama.
- 5 kali gagal login berturut-turut mengunci akun 5 menit. Pesan gagal selalu sama.
- Logout manual, dan logout otomatis setelah 30 menit tidak aktif (dicek pada interaksi berikutnya).
- Log aktivitas akun (login berhasil/gagal, akun dibuat/dinonaktifkan, reset password) di tab Pengguna.

## Berkas

| Berkas | Fungsi | Push ke GitHub? |
|---|---|---|
| `whisperguard_component_v2_2.py` | Kode komponen Langflow, hasil `python build_component.py` (mode lokal Console memakai `auditor.py` + `hybrid.py` yang sama) | Ya |
| `console_app.py` | Tampilan Streamlit | Ya |
| `console_core.py` | Logika: Langflow, cadangan lokal, jejak, rug pull, database, hak akses | Ya |
| `console_auth.py` | Akun, password, penguncian, sesi, log aktivitas | Ya |
| `manage_users.py` | Kelola akun dari baris perintah (admin pertama) | Ya |
| `test_console.py` | Tes logika Console (Langflow tiruan, isolasi, peran, penguncian, password) | Ya |
| `test_console_ui.py` | Tes tampilan lewat Streamlit AppTest | Ya |
| `test_component.py` | Tes komponen tanpa Langflow | Ya |
| `requirements_console.txt` | Daftar paket | Ya |
| `.env.example` | Contoh konfigurasi tanpa rahasia | Ya |
| `.env` | Alamat dan API key Langflow asli | **TIDAK** |
| `console_data.db` | Riwayat audit, keputusan, akun (hash), log aktivitas | **TIDAK** |

Database lama (`console_data.db`) otomatis ditambah tabel dan kolom baru; data lama tidak hilang.
Audit dan keputusan lama dimasukkan ke organisasi pertama (dibuat otomatis bernama
"Organisasi utama" jika belum ada).

## Menjalankan

```powershell
pip install -r requirements_console.txt
python test_console.py
python test_console_ui.py
python test_component.py
python manage_users.py create-admin     # sekali saja: admin pertama, password lewat getpass
streamlit run console_app.py
```

Perintah lain: `python manage_users.py list`, `create-org "Nama"`,
`create-admin --org "Nama"`, `reset-password <username>` (pemulihan, password sementara).
Tidak ada halaman pendaftaran di web; akun lain dibuat admin di tab **Pengguna**.

## Skenario demo rug pull (sekitar 2 menit)
0. Masuk dengan akun peninjau atau admin.
1. Contoh cepat "Demo rug pull 1", lalu Audit. Label: BARU.
2. Tab Keputusan: setujui audit tersebut.
3. Contoh cepat "Demo rug pull 2", lalu Audit. Banner merah BERUBAH muncul beserta perbedaan katanya.
4. Tab Keputusan: coba setujui tanpa alasan. Console menolak.

## Batasan (nyatakan terus terang)
- Deteksi perubahan hanya membandingkan audit yang lewat Console. Audit lewat Bob tersimpan di
  Google Sheets dan belum ikut dibandingkan.
- Identitas tool = nama server (diisi manual) + nama tool.
- Jejak eksekusi ditampilkan setelah audit selesai (diputar ulang), bukan siaran langsung dari Langflow.
- Sesi disimpan di memori Streamlit per tab browser; memuat ulang halaman berarti login lagi.
- Penguncian login per akun; belum ada pembatasan per alamat IP.
- Masih satu proses lokal dengan SQLite; belum untuk banyak server sekaligus.
