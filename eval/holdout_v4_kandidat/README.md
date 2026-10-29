# Kandidat holdout v4 (belum dikunci)

Kasus dari validasi pengguna 28 Oktober 2026 (Google Form "Seberapa Mudah AI Ditipu?").
Holdout v3 sudah dikunci dan dievaluasi, jadi kasus ini **tidak** dimasukkan ke v3.
Kasus ini disiapkan untuk `holdout_v4` menjelang final.

## Aturan

- **Jangan audit kasus ini** (di Console, Playground, atau skrip) sebelum `holdout_v4` dikunci.
- Teks disalin dari jawaban responden apa adanya, dengan dua pengolahan:
  1. Karakter tak terlihat U+200B (zero-width space) dihapus. Karakter ini ada di awal baris jawaban
     responden R5, kemungkinan dari salin-tempel. Jika dibiarkan, aturan R01 otomatis menandainya
     sehingga uji menjadi tidak adil.
  2. Tanda "-" di awal baris dan tanda kutip pembungkus dibuang; nama tool dan deskripsi dipisah dari
     format `nama: deskripsi` atau `nama -> "deskripsi"`.
- Label:
  - `malicious`: deskripsi berisi instruksi tersembunyi kepada agent (tool poisoning).
  - `clean`: deskripsi biasa.
  - `di_luar_cakupan`: responden menulisnya sebagai "jahat", tetapi isinya kemampuan tool yang berisiko
    (lokasi, cookies, membaca semua dokumen) **tanpa** instruksi tersembunyi. WhisperGuard menilai integritas
    deskripsi, bukan luasnya izin, jadi kasus ini dilaporkan terpisah dan tidak dihitung sebagai recall/FPR.

## Yang tidak dimasukkan

| Responden | Alasan |
|---|---|
| R3 | Jawaban teks tidak bermakna ("fjj", "xhkkbcc"), keyakinan 1 ("asal tebak"), dan jawaban pemasangan saling bertentangan. Dikeluarkan dari analisis. |
| R2, dua deskripsi "jahat" | Responden menambahkan komentarnya sendiri di dalam deskripsi ("potensi ngebocorin isi document nya"), jadi teksnya bukan deskripsi tool. |

## Catatan

- `get_weather_forecast` (P4-13) bernama sama dengan contoh demo Console, tetapi deskripsinya berbeda.
- Jumlah kasus `malicious` hanya 2 (dari satu responden). Ini terlalu sedikit untuk angka recall sendiri;
  gabungkan dengan sumber lain saat membuat `holdout_v4`.
