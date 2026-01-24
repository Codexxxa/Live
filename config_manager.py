import os
from dotenv import load_dotenv, set_key
from pathlib import Path

# Nama file konfigurasi
ENV_FILE = '.env'

def initialize_config():
    """Memastikan file .env ada."""
    if not os.path.exists(ENV_FILE):
        with open(ENV_FILE, 'w') as f:
            f.write("# Konfigurasi Live Streaming\n")
            f.write("YOUTUBE_STREAM_KEY=\n")
            f.write("VIDEO_FILE_PATH=\n")
            f.write("STREAM_QUALITY=high\n") # high, medium, low
            f.write("USE_PROXY=false\n")

def load_config():
    """Membaca konfigurasi dari file .env."""
    initialize_config()
    load_dotenv(ENV_FILE, override=True)

    # Helper untuk convert string "true"/"false" ke boolean
    use_proxy_str = os.getenv('USE_PROXY', 'false').lower()
    use_proxy = use_proxy_str == 'true'

    return {
        'stream_key': os.getenv('YOUTUBE_STREAM_KEY', ''),
        'video_path': os.getenv('VIDEO_FILE_PATH', ''),
        'quality': os.getenv('STREAM_QUALITY', 'high'),
        'use_proxy': use_proxy
    }

def update_config(key, value):
    """Memperbarui nilai konfigurasi."""
    initialize_config()
    # Mapping key internal ke key .env
    env_keys = {
        'stream_key': 'YOUTUBE_STREAM_KEY',
        'video_path': 'VIDEO_FILE_PATH',
        'quality': 'STREAM_QUALITY',
        'use_proxy': 'USE_PROXY'
    }

    if key in env_keys:
        env_key = env_keys[key]

        # Jika boolean, convert ke string lowercase untuk .env
        if isinstance(value, bool):
            value = str(value).lower()

        # set_key akan menulis/mengupdate file .env
        set_key(ENV_FILE, env_key, value)
        return True
    return False

def get_quality_settings(quality_preset):
    """Mengembalikan setting bitrate berdasarkan preset."""
    presets = {
        # Semua diubah ke 'ultrafast' agar ramah untuk semua jenis RDP/VPS murah
        'high': {'maxrate': '4500k', 'bufsize': '9000k', 'preset': 'ultrafast'}, # 1080p ish
        'medium': {'maxrate': '2500k', 'bufsize': '5000k', 'preset': 'ultrafast'}, # 720p
        'low': {'maxrate': '1000k', 'bufsize': '2000k', 'preset': 'ultrafast'}  # 480p / hemat bandwidth
    }
    return presets.get(quality_preset, presets['medium'])
