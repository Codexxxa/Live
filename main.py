import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import the actual agent executor
# We assume the backend exists in src/agent.py or similar in the user's environment
try:
    from src.agent import agent_executor
except ImportError:
    # Fallback/Placeholder if running in an environment without the full backend
    print("Warning: Could not import agent_executor from src.agent.")
    print("Ensure the backend files are present.")
    agent_executor = None

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    print("========================================")
    print("      AI Security Scanner               ")
    print("========================================")

def run_scan_interface():
    """
    Menjalankan antarmuka scanning.
    """
    target_url = input("Masukkan URL Target (contoh: https://example.com): ")
    if not target_url:
        print("URL tidak boleh kosong.")
        return

    focus = input("Fokus Pencarian (Opsional) (misal: SQL Injection, XSS) (): ")

    print("\nMemulai Agen AI...")
    print("Agen sedang berpikir dan menjalankan alat...\n")

    inputs = {"url": target_url, "focus": focus}
    config = {"configurable": {"thread_id": "1"}}

    if agent_executor is None:
        print("Error: Agent backend not loaded. Cannot proceed with scan.")
        input("Tekan Enter untuk kembali...")
        return

    try:
        for value in agent_executor.stream(inputs, config=config):
            # ============================================================
            # FIX: Check if value is None to prevent AttributeError
            # ============================================================
            if value is None:
                continue

            new_msgs = value.get("messages", [])
            for msg in new_msgs:
                print(f"[AI]: {msg}")

    except AttributeError as e:
        print(f"\n[ERROR] Terjadi Kesalahan Atribut: {e}")
        print("Bug: Objek stream mengembalikan None yang tidak tertangani.")
    except Exception as e:
        print(f"\n[ERROR] Terjadi kesalahan: {e}")

    input("\nTekan Enter untuk kembali...:")

def configure_api_key():
    print("\n--- Konfigurasi API Key ---")
    print("Fitur ini akan menyimpan API key ke file .env")
    # Implementation placeholder
    input("Tekan Enter untuk kembali...")

def view_logs():
    print("\n--- Log Hasil Analisis ---")
    log_dir = "logs"
    if not os.path.exists(log_dir):
        print("Folder logs tidak ditemukan.")
    else:
        files = os.listdir(log_dir)
        if not files:
            print("Tidak ada log.")
        else:
            for f in files:
                print(f"- {f}")
    input("Tekan Enter untuk kembali...")

def main_menu():
    while True:
        clear_screen()
        print_banner()
        print("[1] Mulai Scan Website")
        print("[2] Konfigurasi API Key")
        print("[3] Lihat Log Hasil Analisis")
        print("[0] Keluar")

        choice = input("\nPilih Menu [1/2/3/0] (1): ").strip()
        if not choice:
            choice = "1"

        if choice == "1":
            run_scan_interface()
        elif choice == "2":
            configure_api_key()
        elif choice == "3":
            view_logs()
        elif choice == "0":
            print("Keluar...")
            sys.exit()
        else:
            input("Menu belum tersedia. Tekan Enter...")

if __name__ == "__main__":
    # Ensure logs directory exists
    if not os.path.exists("logs"):
        os.makedirs("logs")

    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nProgram dihentikan pengguna.")
        sys.exit()
