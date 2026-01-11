# Panduan Instalasi & Konfigurasi DeepSeek Security Scanner

Panduan ini akan membantu Anda mempersiapkan lingkungan kerja untuk menjalankan agen keamanan AI ini secara maksimal di **Windows (VPS/RDP)**.

Agen ini dirancang untuk bekerja dengan alat-alat keamanan standar industri. Agar fitur "Advance Attack" berfungsi, Anda **WAJIB** menginstal alat-alat eksternal di bawah ini.

---

## 1. Prasyarat Sistem

Pastikan sistem Anda sudah terinstall:
*   **Python 3.10 ke atas**: [Download Python](https://www.python.org/downloads/) (Jangan lupa centang "Add Python to PATH" saat instalasi).
*   **Git**: [Download Git](https://git-scm.com/downloads) (Opsional, tapi disarankan).
*   **Go (Golang)**: [Download Go](https://go.dev/dl/) (Diperlukan untuk install Nuclei, TruffleHog, dll dengan mudah).
*   **Google Chrome**: Diperlukan untuk simulasi browser oleh Playwright.

---

## 2. Instalasi Dasar (Aplikasi)

Buka terminal (Command Prompt / PowerShell) di folder proyek ini, lalu jalankan perintah berikut secara berurutan:

```bash
# 1. Install Library Python yang dibutuhkan (termasuk Wapiti, Arjun, Wfuzz, Pwntools, dll)
pip install -r requirements.txt

# 2. Install Browser untuk Playwright
playwright install chromium
```

---

## 3. Instalasi Alat Eksternal (Wajib untuk Mode Advance)

Agar DeepSeek bisa menggunakan alat-alat canggih seperti **Nuclei**, **SQLMap**, dan **Dalfox**, Anda harus menginstalnya dan mendaftarkannya ke sistem.

### A. Nuclei (Vulnerability Scanner)
*   **Via Go (Recommended):**
    ```cmd
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    ```
*   **Manual (Binary):**
    1. Download Nuclei dari [Github Releases](https://github.com/projectdiscovery/nuclei/releases).
    2. Ekstrak dan masukkan file `nuclei.exe` ke folder tools Anda.

### B. SQLMap (Untuk SQL Injection Tingkat Lanjut)
1.  Download **SQLMap** (Format `.zip`) dari: [sqlmap.org](https://sqlmap.org/)
2.  Ekstrak file zip tersebut ke folder yang mudah diakses, misal: `C:\Tools\sqlmap`
3.  **Penting:** Pastikan di dalam folder tersebut ada file `sqlmap.py`.

### C. Dalfox (Untuk XSS Scanning Cepat)
*   **Via Go:**
    ```cmd
    go install github.com/hahwul/dalfox/v2@latest
    ```
*   **Manual (Binary):**
    1. Download dari [Github Releases](https://github.com/hahwul/dalfox/releases).
    2. Ekstrak dan ambil file `dalfox.exe`.

### D. Nmap (Untuk Port Scanning)
1.  Download Installer **Nmap** (`.exe`) dari: [nmap.org/download.html](https://nmap.org/download.html)
2.  Jalankan installer. Nmap biasanya otomatis menambahkan dirinya ke PATH.

---

## 4. Konfigurasi Environment Variables (PATH)

Agar agen bisa memanggil `nuclei`, `sqlmap`, atau `dalfox` dari mana saja, Anda harus menambahkan folder tempat binary Go atau tools Anda ke **PATH Windows**.

1.  Tekan tombol **Windows**, ketik **"env"**, lalu pilih **"Edit the system environment variables"**.
2.  Klik tombol **"Environment Variables"** di kanan bawah.
3.  Di bagian **"System variables"** (bawah), cari variabel bernama **Path**, lalu klik **Edit**.
4.  Klik **New**, lalu masukkan alamat folder:
    *   Folder Go Bin (biasanya `C:\Users\<User>\go\bin`).
    *   Folder Tools Manual (misal `C:\Tools`).
    *   Folder SQLMap (misal `C:\Tools\sqlmap`).
5.  Klik **OK** di semua jendela untuk menyimpan.

---

## 5. Verifikasi Instalasi

Tutup terminal lama Anda dan buka terminal **baru**. Coba ketik perintah berikut:

```cmd
# Cek Nuclei
nuclei -version

# Cek Arjun (sudah via pip)
arjun --help

# Cek Wapiti (sudah via pip)
wapiti --help

# Cek Wfuzz (sudah via pip)
wfuzz --help

# Cek SQLMap
sqlmap --version

# Cek Dalfox
dalfox version
```

Jika semua perintah di atas tidak error, maka **DeepSeek Security Scanner** siap digunakan dalam mode Full Power!

---

## 6. Menjalankan Aplikasi

```bash
python main.py
```
