🛡️ DeepSeek Security Scanner
DeepSeek Security Scanner adalah alat penetrasi tes (pentest) berbasis AI tingkat lanjut. Menggunakan otak dari DeepSeek R1, script ini bertindak sebagai Security Researcher otonom yang mampu melakukan pengumpulan informasi (reconnaissance) hingga eksploitasi kerentanan secara cerdas.
✨ Fitur Utama
 * 🧠 AI-Driven Reasoning: Menggunakan model deepseek-reasoner untuk menganalisis target dan menentukan langkah serangan terbaik.
 * 🛠️ Terintegrasi dengan Pro Arsenal: Menggabungkan berbagai alat keamanan industri (Nuclei, SQLMap, Nmap, dll) dalam satu alur kerja.
 * 🕵️ Reconnaissance Canggih: Pencarian subdomain pasif, deteksi WAF, dan pemetaan hidden parameters (Arjun).
 * 💥 Validasi Eksploitasi: Melakukan pengecekan aktif terhadap celah SQL Injection dan XSS secara otomatis.
 * 📑 Laporan Otomatis: Hasil analisis disimpan dalam format Markdown yang rapi di folder logs/.
 * 🔒 Human-in-the-loop: Meminta persetujuan pengguna sebelum melakukan tindakan yang berbahaya atau "offensive".
🚀 Arsenal Alat (Tools)
Script ini membungkus (wraps) berbagai alat hebat berikut:
| Alat | Fungsi Utama |
|---|---|
| Nuclei | Scanning kerentanan berbasis template yang sangat cepat. |
| SQLMap | Deteksi dan eksploitasi SQL Injection otomatis. |
| Dalfox | Analisis dan eksploitasi kerentanan XSS. |
| Nmap | Port scanning dan identifikasi layanan. |
| Arjun | Menemukan parameter HTTP tersembunyi. |
| FFUF | Fuzzing direktori dan parameter web. |
| TruffleHog | Mencari secrets (API Key, password) yang bocor. |
| Wapiti | Web vulnerability scanner menyeluruh. |
📋 Prasyarat
Sebelum menjalankan script, pastikan sistem Anda memiliki:
 * Python 3.10+
 * Google Chrome (untuk simulasi browser)
 * API Keys:
   * DeepSeek API Key
   * Webshare API Key (untuk rotasi proxy agar tidak diblokir target)
🛠️ Instalasi
1. Clone & Install Library Python
# Clone repository ini (atau download zip)
# Masuk ke folder proyek
pip install -r requirements.txt
playwright install chromium

2. Install Alat Eksternal
Pastikan alat seperti nuclei, sqlmap, nmap, dll sudah terinstal di sistem Anda dan terdaftar di Sistem PATH. Panduan lengkap ada di file PANDUAN_INSTALASI.md.
💻 Cara Penggunaan
 * Jalankan script utama:
   python main.py

 * Pilih Menu 2 untuk memasukkan API Key Anda.
 * Pilih Menu 1 untuk mulai melakukan scanning. Masukkan URL target (misal: https://example.com).
 * Pantau proses analisis AI dan berikan persetujuan jika AI ingin melakukan serangan aktif.
📂 Struktur Folder
.
├── main.py              # Entry point aplikasi (CLI)
├── src/
│   ├── agent.py         # Logika AI Agent & LangGraph
│   ├── tools.py         # Koleksi alat internal
│   ├── external_tools.py# Wrapper untuk alat eksternal (Nuclei, dll)
│   └── proxy_manager.py # Pengelola rotasi proxy
├── logs/                # Tempat menyimpan laporan hasil scan (.md)
├── requirements.txt     # Daftar dependency Python
└── PANDUAN_INSTALASI.md # Panduan instalasi alat pendukung

⚠️ Disclaimer
Peringatan Etika: Alat ini dibuat untuk tujuan edukasi dan pengujian keamanan yang sah. JANGAN menggunakan alat ini pada website tanpa izin tertulis dari pemiliknya. Penggunaan ilegal terhadap alat ini sepenuhnya merupakan tanggung jawab pengguna.
