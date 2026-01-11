import os
import sys
import asyncio
import re
from datetime import datetime
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.live import Live
from langchain_core.messages import HumanMessage
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

        # --- REFACTORED LOOP FOR HUMAN-IN-THE-LOOP ---

        messages = initial_input["messages"]
        offensive_mode = initial_input["offensive_mode"]

        while True:
            # Create a new graph run with current history and mode
            current_inputs = {
                "messages": messages,
                "offensive_mode": offensive_mode
            }

            # We track if we hit the approval node in this run
            hit_approval = False

            async for event in graph.astream(current_inputs):
                for key, value in event.items():
                    # value is {"messages": [Msg]}
                    new_msgs = value.get("messages", [])

                    # Append to our local history so we can resume later
                    # Note: LangGraph add_messages logic handles IDs, here we just append.
                    messages.extend(new_msgs)

                    # Log/Print logic (same as before)
                    if key == "reasoner":
                        msg = new_msgs[-1]
                        content = msg.content
                        if content:
                            reasoning_match = re.search(r'<reasoning>(.*?)</reasoning>', content, re.DOTALL)
                            reasoning_text = reasoning_match.group(1).strip() if reasoning_match else ""
                            clean_content = re.sub(r'<reasoning>.*?</reasoning>', '', content, flags=re.DOTALL).strip()

                            if reasoning_text:
                                console.print(Panel(Markdown(reasoning_text), title="[bold blue]DeepSeek Reasoner[/bold blue]", border_style="blue", title_align="left"))
                                log_content.append(f"\n### Reasoning\n{reasoning_text}\n")
                            if clean_content:
                                console.print(Panel(Markdown(clean_content), title="[bold green]DeepSeek Action[/bold green]", border_style="green", title_align="left"))
                                log_content.append(f"\n### Action\n{clean_content}\n")

                    elif key == "executor":
                        for m in new_msgs:
                            content_str = str(m.content)
                            display_summary = f"[dim]Tool Output ({len(content_str)} chars)[/dim]"
                            if "**HASIL ALAT" in content_str:
                                 tool_header = content_str.split('\n')[0]
                                 display_summary = f"[bold magenta]{tool_header}[/bold magenta]"
                            console.print(Panel(display_summary, title="System Output", border_style="white"))
                            log_content.append(f"\n> **Tool Output**:\n> {content_str}\n")

                    elif key == "approval_wait":
                        hit_approval = True
                        console.print(Panel("[bold red]PERHATIAN: Persetujuan Diperlukan![/bold red]", border_style="red"))

            # End of stream (Graph hit END or paused)

            if hit_approval:
                # Ask user
                if Confirm.ask("Izinkan DeepSeek mengeksekusi rencana serangan?", default=False):
                    messages.append(HumanMessage(content="User Approved. Lanjutkan."))
                    console.print("[green]Melanjutkan... (Mode Offensive Diaktifkan)[/green]")
                    offensive_mode = True # Enable One-Time Approval for subsequent calls
                else:
                    messages.append(HumanMessage(content="User Denied. JANGAN lakukan. Ganti strategi."))
                    console.print("[red]Ditolak. Melanjutkan...[/red]")
                # Continue the outer 'while True' loop to rerun graph with new history
                continue

            # If we didn't hit approval, and the stream ended, we are done.
            break


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
        import traceback
        traceback.print_exc()
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
