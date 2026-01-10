import typer
import time
import os
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.markdown import Markdown
from datetime import datetime

from src.config import get_api_key, set_api_key, get_target_url, set_target_url
from src.agent import run_agent_scan
from src.tools import check_http_headers # Just to have it available if needed, though agent handles it

app = typer.Typer()
console = Console()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    console.print(Panel.fit("[bold cyan]AI Security Scanner Integration (DeepSeek R1)[/bold cyan]", border_style="cyan"))

def view_logs():
    log_dir = "logs"
    if not os.path.exists(log_dir):
        console.print("[yellow]Belum ada log yang tersimpan.[/yellow]")
        return

    files = sorted(os.listdir(log_dir), reverse=True)
    if not files:
        console.print("[yellow]Direktori log kosong.[/yellow]")
        return

    console.print("[bold]Daftar Log Riwayat Scan:[/bold]")
    for idx, f in enumerate(files):
        console.print(f"{idx + 1}. {f}")

    choice = Prompt.ask("Pilih nomor log untuk dilihat (0 untuk kembali)", default="0")
    if choice == "0":
        return

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(files):
            with open(os.path.join(log_dir, files[idx]), "r", encoding="utf-8") as f:
                content = f.read()
            console.print(Markdown(content))
            Prompt.ask("\nTekan Enter untuk kembali...")
        else:
            console.print("[red]Pilihan tidak valid.[/red]")
    except ValueError:
        console.print("[red]Input harus angka.[/red]")

def save_log(target: str, content: str):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    clean_target = target.replace("http://", "").replace("https://", "").replace("/", "_")
    filename = f"scan_{clean_target}_{timestamp}.md"

    os.makedirs("logs", exist_ok=True)
    filepath = os.path.join("logs", filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"# Laporan Scan Keamanan: {target}\n")
        f.write(f"Tanggal: {datetime.now()}\n\n")
        f.write(content)

    console.print(f"[green]Laporan berhasil disimpan di: {filepath}[/green]")

def run_scan():
    target = get_target_url()
    api_key = get_api_key()

    if not target:
        console.print("[red]Target URL belum diatur! Silakan atur di menu 1.[/red]")
        return
    if not api_key:
        console.print("[red]DeepSeek API Key belum diatur! Silakan atur di menu 2.[/red]")
        return

    console.print(f"[bold green]Target:[/bold green] {target}")

    use_focus = Confirm.ask("Apakah Anda ingin menambahkan fokus analisis khusus? (Misal: SQL Injection, XSS)")
    focus_prompt = ""
    if use_focus:
        focus_prompt = Prompt.ask("Masukkan fokus analisis")

    console.print("\n[yellow]Memulai Agen AI... Mohon tunggu...[/yellow]")

    full_response_text = ""
    try:
        # Get the generator
        event_stream = run_agent_scan(target, focus_prompt)

        for event in event_stream:
            # Analyze event to print meaningful status updates
            current_messages = event.get("messages", [])
            if current_messages:
                last_msg = current_messages[-1]

                # Check if it's a tool call (Agent deciding to do something)
                if hasattr(last_msg, 'tool_calls') and last_msg.tool_calls:
                    for tc in last_msg.tool_calls:
                        console.print(f"[cyan]Agent menggunakan alat:[/cyan] {tc['name']}")

                # Check if it's a tool output (Result from a tool)
                if hasattr(last_msg, 'type') and last_msg.type == 'tool':
                     console.print(f"[dim]Output alat diterima...[/dim]")

                # Check if it's the final AI response
                if hasattr(last_msg, 'content') and last_msg.content and not last_msg.tool_calls:
                    # We only want to accumulate the final answer, usually the last message in the conversation
                    # that isn't a tool call/tool message.
                    # In a streaming loop "values", we get the full state.
                    pass

        # After loop finishes, get final message from the state (re-run or just store last known)
        # Actually `event` in the loop holds the final state of that step.
        # The last `event` should contain the conversation.
        final_messages = event['messages']
        final_response = final_messages[-1].content

        console.print("\n[bold]=== HASIL ANALISIS ===[/bold]")
        console.print(Markdown(final_response))

        save = Confirm.ask("\nSimpan laporan ini ke file?", default=True)
        if save:
            save_log(target, final_response)

    except Exception as e:
        console.print(f"[red]Terjadi kesalahan saat scanning: {str(e)}[/red]")
        # Often happens if API key is wrong or model name invalid
        console.print("[yellow]Tips: Pastikan API Key benar dan model 'deepseek-reasoner' tersedia di akun Anda.[/yellow]")

def main_menu():
    while True:
        clear_screen()
        print_banner()

        target = get_target_url() or "[Belum diset]"
        key_status = "[Sudah diset]" if get_api_key() else "[Belum diset]"

        console.print(f"\nTarget Aktif: [bold]{target}[/bold]")
        console.print(f"Status API Key: [bold]{key_status}[/bold]")

        console.print("\n[1] Atur Target URL")
        console.print("[2] Atur DeepSeek API Key")
        console.print("[3] Lihat Log Riwayat")
        console.print("[4] Mulai Scan")
        console.print("[5] Keluar")

        choice = Prompt.ask("\nPilih Menu", choices=["1", "2", "3", "4", "5"])

        if choice == "1":
            new_url = Prompt.ask("Masukkan URL Website Target (contoh: example.com)")
            set_target_url(new_url)
            console.print("[green]Target tersimpan![/green]")
            time.sleep(1)

        elif choice == "2":
            new_key = Prompt.ask("Masukkan DeepSeek API Key", password=True)
            set_api_key(new_key)
            console.print("[green]API Key tersimpan![/green]")
            time.sleep(1)

        elif choice == "3":
            view_logs()

        elif choice == "4":
            run_scan()
            Prompt.ask("\nTekan Enter untuk kembali ke menu utama...")

        elif choice == "5":
            console.print("Terima kasih telah menggunakan alat ini.")
            break

if __name__ == "__main__":
    main_menu()
