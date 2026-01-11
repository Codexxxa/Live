import os
from dotenv import load_dotenv, set_key
from pathlib import Path

ENV_PATH = Path(".env")

def load_config():
    load_dotenv(dotenv_path=ENV_PATH, override=True)

def get_deepseek_key():
    return os.getenv("DEEPSEEK_API_KEY")

def get_webshare_key():
    return os.getenv("WEBSHARE_API_KEY")

def set_deepseek_key(key: str):
    if not ENV_PATH.exists():
        ENV_PATH.touch()
    set_key(ENV_PATH, "DEEPSEEK_API_KEY", key)
    os.environ["DEEPSEEK_API_KEY"] = key

def set_webshare_key(key: str):
    if not ENV_PATH.exists():
        ENV_PATH.touch()
    set_key(ENV_PATH, "WEBSHARE_API_KEY", key)
    os.environ["WEBSHARE_API_KEY"] = key
