# Panduan Instalasi & Konfigurasi DeepSeek Security Scanner

Panduan ini akan membantu Anda mempersiapkan lingkungan kerja untuk menjalankan agen keamanan AI ini secara maksimal di **Windows (VPS/RDP)**.

Agen ini dirancang untuk bekerja dengan alat-alat keamanan standar industri. Agar fitur "Advance Attack" berfungsi, Anda **WAJIB** menginstal alat-alat eksternal di bawah ini.

---

## 1. Prasyarat Sistem

Pastikan sistem Anda sudah terinstall:
*   **Python 3.10 ke atas**: [Download Python](https://www.python.org/downloads/) (Jangan lupa centang "Add Python to PATH" saat instalasi).
*   **Git**: [Download Git](https://git-scm.com/downloads) (Opsional, tapi disarankan).
*   **Google Chrome**: Diperlukan untuk simulasi browser oleh Playwright.

---

## 2. Instalasi Dasar (Aplikasi)

Buka terminal (Command Prompt / PowerShell) di folder proyek ini, lalu jalankan perintah berikut secara berurutan:

```bash
# 1. Install Library Python yang dibutuhkan
pip install -r requirements.txt

# 2. Install Browser untuk Playwright
playwright install chromium
```

---

## 3. Instalasi Alat Eksternal (Wajib untuk Mode Advance)

Agar DeepSeek bisa menggunakan **SQLMap** dan **Dalfox**, Anda harus menginstalnya secara manual dan mendaftarkannya ke sistem.

### A. SQLMap (Untuk SQL Injection Tingkat Lanjut)
1.  Download **SQLMap** (Format `.zip`) dari: [sqlmap.org](https://sqlmap.org/)
2.  Ekstrak file zip tersebut ke folder yang mudah diakses, misal: `C:\Tools\sqlmap`
3.  **Penting:** Pastikan di dalam folder tersebut ada file `sqlmap.py`.

### B. Dalfox (Untuk XSS Scanning Cepat)
1.  Download **Dalfox** (Versi Windows `.exe`) dari: [Github Releases](https://github.com/hahwul/dalfox/releases)
    *   Cari file bernama `dalfox_x.x.x_windows_amd64.tar.gz` atau `.zip`.
2.  Ekstrak dan ambil file `dalfox.exe`.
3.  Pindahkan `dalfox.exe` ke folder tools Anda, misal: `C:\Tools\dalfox.exe`.

### C. Nmap (Untuk Port Scanning)
1.  Download Installer **Nmap** (`.exe`) dari: [nmap.org/download.html](https://nmap.org/download.html)
2.  Jalankan installer dan ikuti petunjuknya. Nmap biasanya otomatis menambahkan dirinya ke PATH.

---

## 4. Konfigurasi Environment Variables (PATH)

Agar agen bisa memanggil `sqlmap` atau `dalfox` dari mana saja, Anda harus menambahkan folder tempat Anda menyimpannya ke **PATH Windows**.

1.  Tekan tombol **Windows**, ketik **"env"**, lalu pilih **"Edit the system environment variables"**.
2.  Klik tombol **"Environment Variables"** di kanan bawah.
3.  Di bagian **"System variables"** (bawah), cari variabel bernama **Path**, lalu klik **Edit**.
4.  Klik **New**, lalu masukkan alamat folder tempat Anda menaruh tool tadi.
    *   Contoh: `C:\Tools\sqlmap`
    *   Contoh: `C:\Tools` (jika dalfox ada di sana)
5.  Klik **OK** di semua jendela untuk menyimpan.

---

## 5. Verifikasi Instalasi

Tutup terminal lama Anda dan buka terminal **baru** (agar setting PATH terbaca). Coba ketik perintah berikut untuk memastikan semua berjalan:

1.  **Cek SQLMap:**
    ```cmd
    python sqlmap.py --version
    # ATAU jika sudah di path bisa langsung:
    sqlmap --version
    ```
    *Jika muncul versi, berarti sukses.*

2.  **Cek Dalfox:**
    ```cmd
    dalfox version
    ```

3.  **Cek Nmap:**
    ```cmd
    nmap --version
    ```

Jika semua perintah di atas tidak error, maka **DeepSeek Security Scanner** siap digunakan dalam mode Full Power!

---

## 6. Menjalankan Aplikasi

```bash
python main.py
```

Pilih menu **[1] Mulai Scan**, masukkan URL target, dan biarkan AI bekerja. Jangan lupa berikan izin (Approval) saat AI meminta untuk menjalankan serangan agresif.
