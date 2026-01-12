# Agen Keamanan AI Otonom (Autonomous AI Security Agent)

Agen keamanan siber berbasis AI yang dirancang untuk melakukan pengujian penetrasi (penetration testing) dan _bug bounty hunting_ secara otomatis. Alat ini menggabungkan kecerdasan buatan **DeepSeek** dengan kerangka kerja **LangGraph** untuk meniru pola pikir seorang _security engineer_, mulai dari rekognisi hingga eksploitasi, dengan mekanisme _Human-in-the-loop_ untuk keamanan dan kontrol.

---

## ⚠️ DISCLAIMER (PENTING)

**HARAP BACA SEBELUM MENGGUNAKAN:**

Alat ini dibuat **HANYA UNTUK TUJUAN EDUKASI DAN PENGUJIAN KEAMANAN YANG SAH**.

1.  **Izin Tertulis:** Jangan pernah menjalankan alat ini pada target (website/server) yang tidak Anda miliki atau tanpa izin tertulis yang eksplisit dari pemiliknya.
2.  **Tanggung Jawab:** Penulis/pembuat kode ini **TIDAK BERTANGGUNG JAWAB** atas kerusakan, kerugian data, atau konsekuensi hukum apa pun yang timbul dari penyalahgunaan alat ini.
3.  **Hukum:** Penggunaan alat ini untuk menyerang target tanpa izin adalah tindakan ilegal dan dapat dikenakan sanksi pidana sesuai hukum yang berlaku di negara Anda (misal: UU ITE di Indonesia).

**Dengan menggunakan alat ini, Anda setuju untuk mematuhi semua hukum yang berlaku dan bertanggung jawab penuh atas tindakan Anda.**

---

## 🔥 Fitur Utama

Script ini mengintegrasikan berbagai alat keamanan terkemuka di bawah kendali AI:

### 🧠 Inti AI (AI Core)
*   **DeepSeek Integration:** Menggunakan model DeepSeek untuk penalaran (_reasoning_) mendalam tentang celah keamanan.
*   **LangGraph Architecture:** Alur kerja otonom yang dapat mengambil keputusan, memperbaiki kesalahan, dan merencanakan serangan bertahap.
*   **Human-in-the-Loop:** Mekanisme persetujuan manual sebelum AI melakukan tindakan berbahaya (ofensif) seperti SQL Injection atau XSS attack.

### 🔍 Rekognisi & Analisis (Reconnaissance)
*   **Subdomain Enumeration:** Pencarian subdomain pasif menggunakan `crt.sh`.
*   **WAF Detection:** Mendeteksi Web Application Firewall menggunakan `wafw00f`.
*   **Port Scanning:** Pemindaian port cepat menggunakan `Nmap`.
*   **Attack Surface Analysis:** Analisis struktur HTML (Form, Input, API Endpoint) secara otomatis.
*   **Browser Stealth:** Menggunakan `Playwright` dengan teknik anti-bot untuk merender halaman JavaScript/SPA.

### ⚔️ Pemindaian & Eksploitasi (Scanning & Exploitation)
*   **Vulnerability Scanner:** Integrasi `Nuclei` dan `Wapiti` untuk pemindaian kerentanan umum.
*   **Fuzzing:** Pencarian direktori dan file tersembunyi menggunakan `FFUF`.
*   **Parameter Discovery:** Menemukan parameter tersembunyi menggunakan `Arjun`.
*   **SQL Injection:** Pengujian otomatis menggunakan `SQLMap`.
*   **XSS (Cross-Site Scripting):** Pemindaian celah XSS menggunakan `Dalfox`.
*   **Secret Scanning:** Pencarian kebocoran kredensial/token menggunakan `TruffleHog`.

---

## 🛠️ Prasyarat (Requirements)

Sebelum menjalankan, pastikan sistem Anda memiliki:

1.  **Python 3.10** atau lebih baru.
2.  **API Keys:**
    *   DeepSeek API Key (untuk otak AI).
    *   Webshare API Key (untuk rotasi proxy agar tidak terblokir).
3.  **External Tools:** Alat-alat berikut harus terinstall dan dapat diakses melalui terminal (PATH):
    *   `nmap`
    *   `nuclei`
    *   `sqlmap`
    *   `ffuf`
    *   `dalfox`
    *   `wapiti` (bisa via pip)
    *   `arjun` (bisa via pip)
    *   `trufflehog`

> 📘 **Panduan Instalasi Lengkap:** Silakan baca file `PANDUAN_INSTALASI.md` untuk instruksi detail cara menginstall semua alat di atas pada Windows/Linux.

---

## 🚀 Cara Instalasi

1.  **Clone Repository**
    ```bash
    git clone https://github.com/username/repo-ini.git
    cd repo-ini
    ```

2.  **Install Python Dependencies**
    Buat virtual environment (disarankan) dan install paket:
    ```bash
    python -m venv venv
    # Windows:
    .\venv\Scripts\activate
    # Linux/Mac:
    source venv/bin/activate

    pip install -r requirements.txt
    ```

3.  **Install Playwright Browser**
    ```bash
    playwright install chromium
    ```

4.  **Konfigurasi Environment (.env)**
    Buat file `.env` di root folder (atau gunakan menu konfigurasi di dalam aplikasi nanti):
    ```env
    DEEPSEEK_API_KEY=sk-xxxx...
    WEBSHARE_API_KEY=xxxx...
    ```

---

## 🎮 Cara Menjalankan

Jalankan script utama menggunakan Python:

```bash
python main.py
```

### Menu Interaktif

Aplikasi berbasis CLI (Command Line Interface) dengan menu interaktif:

1.  **Mulai Scan Website:**
    *   Masukkan URL target (contoh: `https://target-anda.com`).
    *   (Opsional) Masukkan fokus serangan (contoh: `Cari celah SQL Injection di halaman login`).
    *   AI akan mulai menganalisis. Jika AI memutuskan perlu melakukan serangan berat (seperti menjalankan SQLMap), ia akan **MEMINTA IZIN** Anda terlebih dahulu.

2.  **Konfigurasi API Key:**
    *   Menu untuk memasukkan atau mengubah API Key DeepSeek dan Webshare tanpa mengedit file `.env` manual.

3.  **Lihat Log Hasil Analisis:**
    *   Membaca laporan hasil scan yang tersimpan di folder `logs/`. Format laporan adalah Markdown yang rapi.

---

## 📂 Struktur Folder

*   `main.py`: Entry point aplikasi (antarmuka pengguna).
*   `src/`: Kode sumber logika program.
    *   `agent.py`: Logika AI (LangGraph & DeepSeek).
    *   `tools.py`: Alat internal (Playwright, BeautifulSoup, dll).
    *   `external_tools.py`: Wrapper untuk alat eksternal (Nmap, SQLMap, dll).
*   `logs/`: Tempat penyimpanan laporan hasil scan (dibuat otomatis).
*   `PANDUAN_INSTALASI.md`: Panduan setup tools eksternal.

---

## 🐛 Troubleshooting

*   **Error "Tool not found":** Pastikan alat tersebut (misal `nmap`) sudah terinstall dan path-nya sudah ditambahkan ke System Variables (Environment Variables).
*   **Error Browser/Playwright:** Jalankan `playwright install chromium` lagi.
*   **Koneksi Gagal:** Periksa Webshare API Key Anda atau koneksi internet. Script ini sangat bergantung pada proxy untuk menghindari pemblokiran.

---

Selamat menggunakan, dan ingat: **Stay Ethical, Stay Safe.**
