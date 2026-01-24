import os
import subprocess
import sys
from colorama import Fore, Style

def repair_video(input_path):
    """
    Mencoba memperbaiki file video dengan melakukan re-encoding
    menggunakan FFmpeg ke format standar (H.264/AAC MP4).
    """
    if not os.path.exists(input_path):
        print(Fore.RED + f"Error: File tidak ditemukan: {input_path}")
        return None

    # Buat nama file output: filename_fixed.mp4
    directory, filename = os.path.split(input_path)
    name, ext = os.path.splitext(filename)
    output_filename = f"{name}_FIXED.mp4"
    output_path = os.path.join(directory, output_filename)

    print(Fore.CYAN + f"\nSedang memperbaiki video...")
    print(f"Input : {input_path}")
    print(f"Output: {output_path}")
    print(Fore.YELLOW + "Proses ini mungkin memakan waktu tergantung durasi video.")
    print("Mohon tunggu sampai 100%...\n" + Style.RESET_ALL)

    # Command FFmpeg untuk re-encode total
    # -c:v libx264: Re-encode video ke H.264
    # -preset ultrafast: Supaya cepat (kualitas cukup untuk streaming loop)
    # -c:a aac: Re-encode audio ke AAC
    # -movflags +faststart: Optimasi untuk web/streaming
    # -y: Overwrite output jika ada
    command = [
        'ffmpeg',
        '-i', input_path,
        '-c:v', 'libx264',
        '-preset', 'ultrafast',
        '-crf', '23',
        '-c:a', 'aac',
        '-b:a', '128k',
        '-movflags', '+faststart',
        output_path,
        '-y'
    ]

    try:
        # Jalankan FFmpeg
        subprocess.check_call(command)

        print(Fore.GREEN + "\n[BERHASIL] Video telah diperbaiki!" + Style.RESET_ALL)
        print(f"File baru tersimpan di: {output_path}")
        return output_path

    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"\n[GAGAL] Terjadi error saat memperbaiki video." + Style.RESET_ALL)
        print(Fore.RED + "Pastikan file input tidak rusak parah (corrupt header)." + Style.RESET_ALL)
        return None
    except Exception as e:
        print(Fore.RED + f"\n[ERROR] {str(e)}" + Style.RESET_ALL)
        return None
