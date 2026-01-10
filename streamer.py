import subprocess
import time
import sys
import os
from config_manager import get_quality_settings

def build_ffmpeg_command(config):
    """
    Membuat list argumen perintah FFmpeg berdasarkan konfigurasi.
    """
    stream_key = config.get('stream_key')
    video_path = config.get('video_path')
    quality = config.get('quality', 'medium')

    if not stream_key or not video_path:
        raise ValueError("Stream Key atau Path Video belum diatur.")

    if not os.path.exists(video_path):
        raise FileNotFoundError(f"File video tidak ditemukan: {video_path}")

    settings = get_quality_settings(quality)

    # URL Server RTMP YouTube
    rtmp_url = f"rtmp://a.rtmp.youtube.com/live2/{stream_key}"

    command = [
        'ffmpeg',
        '-re',                  # Read input at native frame rate
        '-stream_loop', '-1',   # Loop input infinite times
        '-i', video_path,       # Input file
        '-c:v', 'libx264',      # Video codec
        '-preset', settings['preset'],
        '-b:v', settings['maxrate'],
        '-maxrate', settings['maxrate'],
        '-bufsize', settings['bufsize'],
        '-pix_fmt', 'yuv420p',
        '-g', '50',             # GOP size (keyframe interval), YouTube recommends 2 seconds (approx 60 frames for 30fps)
        '-c:a', 'aac',          # Audio codec
        '-b:a', '128k',
        '-ar', '44100',
        '-f', 'flv',            # Output format
        rtmp_url
    ]

    return command

def start_stream(config):
    """
    Menjalankan proses streaming dengan fitur auto-restart.
    """
    print("\n[INFO] Menyiapkan streaming...")

    try:
        command = build_ffmpeg_command(config)
    except Exception as e:
        print(f"[ERROR] Konfigurasi tidak valid: {e}")
        return

    retry_count = 0
    max_retries = 999999 # Loop hampir tak terbatas untuk "always on"

    while True:
        try:
            print(f"\n[INFO] Memulai Stream ke YouTube... (Tekan Ctrl+C untuk berhenti)")
            print(f"[INFO] File: {config['video_path']}")
            print(f"[INFO] Kualitas: {config['quality']}")

            # Jalankan FFmpeg
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )

            # Baca output stderr FFmpeg (karena FFmpeg menulis status ke stderr)
            # Kita hanya print jika user ingin debug, atau biar kelihatan "hidup"
            # Untuk simplisitas CLI, kita tunggu saja prosesnya.

            try:
                # Loop untuk membaca output agar buffer tidak penuh, tapi tidak membanjiri layar
                while True:
                    output = process.stderr.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        # Tampilkan info bitrate/time sekilas (opsional, bisa bikin spam)
                        # Untuk user biasa, lebih baik tampilkan indikator sederhana
                        if "time=" in output:
                            sys.stdout.write(f"\r[STREAMING] {output.strip().split('bitrate=')[0]}...")
                            sys.stdout.flush()
            except KeyboardInterrupt:
                # User menekan Ctrl+C
                print("\n\n[STOP] Menghentikan streaming...")
                process.kill()
                return # Keluar dari fungsi, kembali ke menu

            # Jika proses mati sendiri (bukan karena Ctrl+C)
            return_code = process.poll()

            if return_code != 0:
                print(f"\n[WARN] FFmpeg berhenti dengan kode: {return_code}")
                print("[INFO] Mencoba menyambungkan kembali dalam 5 detik...")
                time.sleep(5)
                retry_count += 1
            else:
                print("\n[INFO] FFmpeg berhenti normal.")
                break

        except FileNotFoundError:
            print("\n[ERROR] FFmpeg tidak ditemukan. Pastikan FFmpeg sudah terinstall dan masuk ke PATH.")
            return
        except KeyboardInterrupt:
            print("\n[STOP] Berhenti atas permintaan pengguna.")
            return
        except Exception as e:
            print(f"\n[ERROR] Terjadi kesalahan tak terduga: {e}")
            time.sleep(5)
