import os
from dotenv import load_dotenv, set_key
from pathlib import Path

# Load environment variables
env_path = Path('.env')
if not env_path.exists():
    env_path.touch()

load_dotenv(dotenv_path=env_path)

def get_api_key():
    """Returns the DeepSeek API key."""
    return os.getenv("DEEPSEEK_API_KEY")

def set_api_key(key: str):
    """Sets the DeepSeek API key in the .env file."""
    set_key(env_path, "DEEPSEEK_API_KEY", key)
    os.environ["DEEPSEEK_API_KEY"] = key

def get_target_url():
    """Returns the target URL."""
    return os.getenv("TARGET_URL")

def set_target_url(url: str):
    """Sets the target URL in the .env file."""
    set_key(env_path, "TARGET_URL", url)
    os.environ["TARGET_URL"] = url

def get_base_url():
    """Returns the DeepSeek Base URL."""
    return os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
