import os
import random

def generate_playlist(video_dir):
    """
    Scans the directory for video files, shuffles them, and creates a playlist.txt.
    Returns the path to the playlist file.
    """
    valid_extensions = ('.mp4', '.mkv', '.avi', '.mov', '.flv')
    videos = []

    try:
        # Scan directory
        for entry in os.scandir(video_dir):
            if entry.is_file() and entry.name.lower().endswith(valid_extensions):
                videos.append(os.path.abspath(entry.path))
    except Exception as e:
        print(f"[ERROR] Failed to scan directory {video_dir}: {e}")
        return None

    if not videos:
        return None

    random.shuffle(videos)

    playlist_path = os.path.join(video_dir, 'playlist.txt')

    try:
        with open(playlist_path, 'w', encoding='utf-8') as f:
            for video in videos:
                # FFmpeg concat demuxer quirks:
                # 1. Backslashes should be escaped or use forward slashes.
                #    Forward slashes are safer and cross-platform compatible in FFmpeg.
                safe_path = video.replace('\\', '/')

                # 2. Single quotes must be escaped as '\''.
                safe_path = safe_path.replace("'", "'\\''")

                f.write(f"file '{safe_path}'\n")
    except Exception as e:
        print(f"[ERROR] Failed to write playlist file: {e}")
        return None

    return playlist_path
