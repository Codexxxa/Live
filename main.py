import os
import sys
import shutil
import time
from colorama import init, Fore, Style
import config_manager
import streamer

# Inisialisasi colorama untuk warna di Windows
init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    clear_screen()
    print(Fore.CYAN + "=============================================")
    print(Fore.CYAN + "   ALAT LIVE STREAMING YOUTUBE AUTO-LOOP")
    print(Fore.CYAN + "=============================================")
    print(Style.RESET_ALL)

def check_ffmpeg():
    """Mengecek apakah FFmpeg terinstall."""
    if shutil.which("ffmpeg"):
        return True, "Terinstall"
    return False, "TIDAK DITEMUKAN (Cek README.md)"

def menu_config():
    while True:
        print_header()
        current_config = config_manager.load_config()
        print(Fore.YELLOW + "--- KONFIGURASI ---")
        print(f"1. Stream Key   : {current_config['stream_key'][:5]}..." if current_config['stream_key'] else "1. Stream Key   : [KOSONG]")
        print(f"2. File Video   : {current_config['video_path']}")
        print(f"3. Kualitas     : {current_config['quality']} (high/medium/low)")
        print("4. Kembali ke Menu Utama")

        choice = input(Fore.GREEN + "\nPilih menu (1-4): " + Style.RESET_ALL)

        if choice == '1':
            new_key = input("Masukkan YouTube Stream Key: ").strip()
            if new_key:
                config_manager.update_config('stream_key', new_key)
        elif choice == '2':
            new_path = input(r"Masukkan Path Lengkap File Video (contoh C:\Videos\live.mp4): ").strip()
            # Hapus tanda kutip jika user melakukan copy path "..."
            new_path = new_path.replace('"', '')
            if os.path.exists(new_path):
                config_manager.update_config('video_path', new_path)
            else:
                input(Fore.RED + f"\nFile tidak ditemukan di: {new_path}\nTekan Enter..." + Style.RESET_ALL)
        elif choice == '3':
            print("\nPilih Kualitas:")
            print("a. High (1080p, Bitrate tinggi)")
            print("b. Medium (720p, Standar)")
            print("c. Low (480p, Hemat Bandwidth RDP)")
            q_choice = input("Pilih (a/b/c): ").lower()
            if q_choice == 'a': config_manager.update_config('quality', 'high')
            elif q_choice == 'b': config_manager.update_config('quality', 'medium')
            elif q_choice == 'c': config_manager.update_config('quality', 'low')
        elif choice == '4':
            break

def show_help():
    print_header()
    print(Fore.YELLOW + "--- PANDUAN SINGKAT ---" + Style.RESET_ALL)
    print("1. Pastikan Anda memiliki 'Stream Key' dari YouTube Studio.")
    print("   (Buat Live Stream -> Copy Stream Key)")
    print("2. Siapkan satu file video pendek yang ingin diputar.")
    print("3. Masuk ke menu Konfigurasi, masukkan Key dan Lokasi Video.")
    print("4. Pilih 'Mulai Live Streaming'. Video akan diputar berulang-ulang.")
    print("5. Jangan tutup jendela CMD ini agar stream tetap jalan.")
    print("\nTips: Gunakan kualitas 'Low' jika RDP terasa lambat.")
    input("\nTekan Enter untuk kembali...")

def main_menu():
    while True:
        print_header()

        # Status Cek
        ffmpeg_ok, ffmpeg_status = check_ffmpeg()
        config = config_manager.load_config()
        config_ready = bool(config['stream_key'] and config['video_path'])

        status_ffmpeg_color = Fore.GREEN if ffmpeg_ok else Fore.RED
        status_config_color = Fore.GREEN if config_ready else Fore.RED

        print(f"Status FFmpeg : {status_ffmpeg_color}{ffmpeg_status}{Style.RESET_ALL}")
        print(f"Konfigurasi   : {status_config_color}{'Siap' if config_ready else 'Belum Lengkap'}{Style.RESET_ALL}")
        print("---------------------------------------------")

        print("1. Mulai Live Streaming")
        print("2. Atur Konfigurasi")
        print("3. Cek / Test Koneksi FFmpeg")
        print("4. Panduan")
        print("5. Keluar")

        choice = input(Fore.GREEN + "\nPilih menu (1-5): " + Style.RESET_ALL)

        if choice == '1':
            if not ffmpeg_ok:
                print(Fore.RED + "\nError: FFmpeg belum terinstall!" + Style.RESET_ALL)
                input("Tekan Enter...")
                continue
            if not config_ready:
                print(Fore.RED + "\nError: Konfigurasi belum lengkap (Key/Video kosong)!" + Style.RESET_ALL)
                input("Tekan Enter...")
                continue

            streamer.start_stream(config)

        elif choice == '2':
            menu_config()

        elif choice == '3':
            print("\nMengecek versi FFmpeg...")
            if ffmpeg_ok:
                os.system("ffmpeg -version")
            else:
                print(Fore.RED + "FFmpeg tidak ditemukan.")
            input("\nTekan Enter...")

        elif choice == '4':
            show_help()

        elif choice == '5':
            print("Sampai jumpa!")
            sys.exit()
        else:
            input("Pilihan tidak valid. Tekan Enter...")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nKeluar program...")
