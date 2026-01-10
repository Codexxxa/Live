# Alat Live Streaming YouTube Otomatis (Looping)

Alat ini dirancang untuk pengguna Windows (RDP/VPS) yang ingin melakukan live streaming 24/7 di YouTube menggunakan video pendek yang diulang-ulang (looping).

## Fitur
- **Ringan:** Berbasis Command Line Interface (CLI), hemat RAM/CPU.
- **Looping Otomatis:** Video pendek akan diputar berulang-ulang tanpa perlu menggabungkan file.
- **Auto-Restart:** Jika streaming putus, alat akan mencoba menyambungkan kembali secara otomatis.
- **Bahasa Indonesia:** Antarmuka menu yang mudah dipahami.

## Persiapan (Wajib Dilakukan)

### 1. Install Python
Pastikan Python sudah terinstall di Windows RDP Anda.
- Download di: https://www.python.org/downloads/windows/
- **PENTING:** Saat instalasi, centang opsi **"Add Python to PATH"**.

### 2. Install FFmpeg
Alat ini membutuhkan FFmpeg untuk memproses video.
1. Download build FFmpeg dari: https://www.gyan.dev/ffmpeg/builds/ (pilih `ffmpeg-git-full.7z` atau `release-essentials.zip`).
2. Ekstrak file zip tersebut.
3. Masuk ke folder `bin` di dalamnya (Anda akan melihat `ffmpeg.exe`).
4. Copy path folder `bin` tersebut (contoh: `C:\ffmpeg\bin`).
5. Tambahkan ke "Environment Variables" Windows:
   - Cari "Edit the system environment variables" di menu Start.
   - Klik tombol "Environment Variables".
   - Di bagian "System variables", cari "Path", lalu klik "Edit".
   - Klik "New", lalu paste path folder bin tadi.
   - Klik OK, OK, OK.
6. Buka CMD baru, ketik `ffmpeg -version` untuk memastikan sudah terinstall.

### 3. Install Dependensi
Buka Command Prompt (CMD) di folder ini, lalu jalankan:
```cmd
pip install -r requirements.txt
```

## Cara Penggunaan
1. Jalankan program dengan mengetik:
   ```cmd
   python main.py
   ```
2. Pilih menu **2. Atur Konfigurasi** untuk memasukkan Stream Key dan lokasi file video Anda.
3. Pilih menu **1. Mulai Live Streaming** untuk memulai.

## Struktur File
- `main.py`: Script utama.
- `.env`: File konfigurasi (dibuat otomatis).
- `requirements.txt`: Daftar library yang dibutuhkan.
