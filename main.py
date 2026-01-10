import os
import sys
import asyncio
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.live import Live
from src.config import get_deepseek_key, get_webshare_key, set_deepseek_key, set_webshare_key, load_config
from src.agent import create_agent_graph, get_initial_input

# Initialize Rich Console
console = Console()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    console.print(Panel.fit(
        "[bold cyan]DeepSeek Security Scanner[/bold cyan]\n"
        "[dim]Powered by DeepSeek AI & Webshare Proxy[/dim]",
        border_style="cyan"
    ))

def configure_keys():
    """Menu 2: Configuration"""
    console.print("[bold yellow]Konfigurasi API Key[/bold yellow]")

    current_ds = get_deepseek_key()
    current_ws = get_webshare_key()

    console.print(f"DeepSeek Key saat ini: [green]{'Terisi' if current_ds else 'Kosong'}[/green]")
    console.print(f"Webshare Key saat ini: [green]{'Terisi' if current_ws else 'Kosong'}[/green]")

    if Confirm.ask("Ganti DeepSeek API Key?"):
        new_ds = Prompt.ask("Masukkan DeepSeek API Key baru")
        set_deepseek_key(new_ds)
        console.print("[green]DeepSeek Key disimpan![/green]")

    if Confirm.ask("Ganti Webshare API Key?"):
        new_ws = Prompt.ask("Masukkan Webshare API Key baru")
        set_webshare_key(new_ws)
        console.print("[green]Webshare Key disimpan![/green]")

    Prompt.ask("\nTekan Enter untuk kembali...")

def view_logs():
    """Menu 3: View Logs"""
    log_dir = "logs"
    if not os.path.exists(log_dir):
        console.print("[red]Belum ada log tersedia.[/red]")
        Prompt.ask("\nTekan Enter untuk kembali...")
        return

    files = [f for f in os.listdir(log_dir) if f.endswith(".md")]
    files.sort(reverse=True) # Newest first

    if not files:
        console.print("[yellow]Folder logs kosong.[/yellow]")
        Prompt.ask("\nTekan Enter untuk kembali...")
        return

    table = Table(title="Log Analisis")
    table.add_column("No", style="cyan")
    table.add_column("Filename", style="green")

    for idx, f in enumerate(files, 1):
        table.add_row(str(idx), f)

    console.print(table)

    choice = Prompt.ask("Pilih nomor log untuk dibaca (atau '0' untuk kembali)", default="0")
    if choice == "0":
        return

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(files):
            filename = files[idx]
            with open(os.path.join(log_dir, filename), "r", encoding="utf-8") as f:
                content = f.read()

            clear_screen()
            console.print(Markdown(content))
            Prompt.ask("\n[bold]Akhir dari log. Tekan Enter untuk kembali...[/bold]")
        else:
            console.print("[red]Pilihan tidak valid.[/red]")
            Prompt.ask("...")
    except ValueError:
        console.print("[red]Input bukan angka.[/red]")
        Prompt.ask("...")

async def run_scan_interface():
    """Menu 1: Run Scan"""
    # Check keys first
    if not get_deepseek_key() or not get_webshare_key():
        console.print("[bold red]ERROR: API Key belum lengkap![/bold red]")
        console.print("Silakan ke menu Konfigurasi terlebih dahulu.")
        Prompt.ask("Tekan Enter untuk kembali...")
        return

    url = Prompt.ask("[bold green]Masukkan URL Target[/bold green] (contoh: https://example.com)")
    focus = Prompt.ask("[bold green]Fokus Pencarian (Opsional)[/bold green] (misal: SQL Injection, XSS)", default="")

    console.print("\n[bold cyan]Memulai Agen AI...[/bold cyan]")

    try:
        graph = create_agent_graph()
        initial_input = get_initial_input(url, focus)

        log_content = []
        log_content.append(f"# Laporan Analisis Keamanan: {url}")
        log_content.append(f"**Waktu Scan**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        log_content.append(f"**Fokus**: {focus if focus else 'Umum'}\n")
        log_content.append("---")

        console.print("[dim]Agen sedang berpikir dan menjalankan alat...[/dim]\n")

        async for event in graph.astream(initial_input):
            for key, value in event.items():
                # Handle DeepSeek Reasoner Output
                if key == "reasoner":
                    msg = value["messages"][-1]
                    content = msg.content
                    if content:
                        console.print(Panel(Markdown(content), title="DeepSeek Reasoner", border_style="blue"))
                        log_content.append(f"\n## Analisis AI\n\n{content}")

                # Handle Tool Executor Output
                elif key == "executor":
                    # The executor node returns a HumanMessage with the tool output
                    messages = value["messages"]
                    for m in messages:
                        # Extract tool name from content if possible, or just print content
                        content_str = str(m.content)
                        preview = content_str[:200] + "..." if len(content_str) > 200 else content_str

                        console.print(f"[dim italic]System/Tool Output: {preview}[/dim italic]")
                        log_content.append(f"\n> **System/Tool Output**:\n> {content_str}\n")

        # Save Log
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_url = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "")
        filename = f"report_{timestamp}_{safe_url}.md"
        filepath = os.path.join("logs", filename)

        if not os.path.exists("logs"):
            os.makedirs("logs")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(log_content))

        console.print(f"\n[bold green]Scan Selesai! Laporan disimpan di: {filepath}[/bold green]")
        Prompt.ask("Tekan Enter untuk kembali...")

    except Exception as e:
        console.print(f"[bold red]Terjadi Kesalahan: {e}[/bold red]")
        Prompt.ask("Tekan Enter untuk kembali...")

def main_menu():
    load_config()
    while True:
        clear_screen()
        print_banner()
        console.print("\n[1] [bold green]Mulai Scan Website[/bold green]")
        console.print("[2] [bold yellow]Konfigurasi API Key[/bold yellow]")
        console.print("[3] [bold blue]Lihat Log Hasil Analisis[/bold blue]")
        console.print("[0] Keluar")

        choice = Prompt.ask("\nPilih Menu", choices=["1", "2", "3", "0"], default="1")

        if choice == "1":
            asyncio.run(run_scan_interface())
        elif choice == "2":
            configure_keys()
        elif choice == "3":
            view_logs()
        elif choice == "0":
            console.print("Sampai jumpa!")
            break

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\n[red]Program dihentikan paksa.[/red]")
