# Panduan Instalasi & Konfigurasi DeepSeek Security Scanner

Panduan ini disusun secara LENGKAP agar Anda bisa menginstal semua alat yang dibutuhkan tanpa terkecuali. Tidak ada "dan lain-lain". Ikuti setiap langkah di bawah ini.

---

## 1. Prasyarat Sistem

Sebelum mulai, pastikan Anda memiliki:
*   **Python 3.10+**: [Download di sini](https://www.python.org/downloads/).
    *   *PENTING:* Centang opsi **"Add Python to PATH"** saat instalasi.
*   **Google Chrome**: Diperlukan untuk simulasi browser.

---

## 2. Instalasi Alat Python (Otomatis)

Alat-alat berikut akan diinstal secara otomatis melalui Python:
*   **Arjun** (Hidden Parameter Discovery)
*   **Wapiti** (Web Vulnerability Scanner)
*   **Pwntools** (Exploit Development Library)
*   **Playwright** (Browser Automation)

**Langkah Instalasi:**
1.  Buka Terminal (CMD / PowerShell).
2.  Masuk ke folder proyek ini.
3.  Jalankan perintah:
    ```bash
    pip install -r requirements.txt
    playwright install chromium
    ```

---

## 3. Instalasi Alat Eksternal (Manual & Wajib)

Alat-alat di bawah ini adalah program independen (binary) yang harus didownload dan didaftarkan ke sistem (PATH) agar bisa dipanggil oleh Agen.

### A. NUCLEI (Vulnerability Scanner)
*Fungsi: Scanner kerentanan modern & cepat.*
1.  Download file **Zip** untuk Windows dari: [Release Nuclei](https://github.com/projectdiscovery/nuclei/releases)
    *   Pilih file bernama: `nuclei_x.x.x_windows_amd64.zip`
2.  Buat folder baru, misal: `C:\Tools\nuclei`
3.  Ekstrak isi zip (file `nuclei.exe`) ke dalam folder tersebut.

### B. FFUF (Fuzz Faster U Fool)
*Fungsi: Fuzzing direktori web super cepat (Pengganti Wfuzz).*
1.  Download file **Zip** dari: [Release FFUF](https://github.com/ffuf/ffuf/releases)
    *   Pilih file bernama: `ffuf_x.x.x_windows_amd64.zip`
2.  Buat folder baru, misal: `C:\Tools\ffuf`
3.  Ekstrak isi zip (file `ffuf.exe`) ke dalam folder tersebut.

### C. TRUFFLEHOG (Secret Scanner)
*Fungsi: Mencari kunci rahasia/password yang bocor.*
1.  Download file **Tar.gz** atau **Zip** dari: [Release TruffleHog](https://github.com/trufflesecurity/trufflehog/releases)
    *   Pilih file bernama: `trufflehog_x.x.x_windows_amd64.tar.gz` (Gunakan 7-Zip atau WinRAR untuk ekstrak).
2.  Buat folder baru, misal: `C:\Tools\trufflehog`
3.  Ekstrak file `trufflehog.exe` ke folder tersebut.

### D. SQLMAP (SQL Injection Tool)
*Fungsi: Eksploitasi database otomatis.*
1.  Download file **Zip** dari: [Website SQLMap](https://sqlmap.org/)
2.  Buat folder baru, misal: `C:\Tools\sqlmap`
3.  Ekstrak seluruh isi zip ke folder tersebut.
4.  Pastikan ada file `sqlmap.py` di dalam `C:\Tools\sqlmap`.

### E. DALFOX (XSS Scanner)
*Fungsi: Scanner khusus celah XSS.*
1.  Download file **Zip/Tar** dari: [Release Dalfox](https://github.com/hahwul/dalfox/releases)
    *   Pilih file bernama: `dalfox_x.x.x_windows_amd64.zip`
2.  Buat folder baru, misal: `C:\Tools\dalfox`
3.  Ekstrak file `dalfox.exe` ke folder tersebut.

### F. NMAP (Port Scanner)
*Fungsi: Melihat port/layanan yang terbuka.*
1.  Download Installer (`.exe`) dari: [Website Nmap](https://nmap.org/download.html)
    *   Pilih "Latest Stable Release Self-Installer".
2.  Jalankan Installer dan ikuti petunjuk (Next > Next > Finish).

---

## 4. Konfigurasi PATH (SANGAT PENTING)

Agar Agen bisa menemukan alat-alat di atas, Anda harus memberi tahu Windows di mana letak folder-foldernya.

1.  Tekan tombol **Windows**, ketik **"env"**, pilih **"Edit the system environment variables"**.
2.  Klik tombol **"Environment Variables"** (kanan bawah).
3.  Di kolom bawah (**System variables**), cari baris bernama **Path**, lalu klik **Edit**.
4.  Klik **New** dan masukkan alamat folder satu per satu:
    *   `C:\Tools\nuclei`
    *   `C:\Tools\ffuf`
    *   `C:\Tools\trufflehog`
    *   `C:\Tools\sqlmap`
    *   `C:\Tools\dalfox`
    *   *(Untuk Nmap biasanya otomatis masuk, tapi jika tidak, tambahkan folder instalasinya)*
5.  Klik **OK** di semua jendela.

---

## 5. Cek Kesuksesan Instalasi

Tutup terminal lama, buka **Terminal Baru**. Ketik perintah ini satu per satu untuk memastikan tidak ada error:

```cmd
nuclei -version
ffuf -version
trufflehog --version
sqlmap --version
dalfox version
nmap --version
arjun --help
wapiti --help
```

Jika semua perintah di atas menampilkan versi/help, maka instalasi **SUKSES 100%**.

---

## 6. Jalankan Agen

```bash
python main.py
```
