import os
import requests
import random
from typing import Dict, Optional

class ProxyManager:
    def __init__(self):
        self.api_key = os.getenv("WEBSHARE_API_KEY")
        self.api_url = "https://proxy.webshare.io/api/v2/proxy/list/"
        self.proxies = []

    def fetch_proxies(self) -> None:
        """Fetches the list of proxies from Webshare API."""
        if not self.api_key:
            # If no key, we can't fetch.
            # In a real app we might want to prompt, but here we expect env var.
            return

        headers = {"Authorization": f"Token {self.api_key}"}
        params = {
            "mode": "direct",
            "page": 1,
            "page_size": 50
        }

        try:
            response = requests.get(self.api_url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()
            self.proxies = data.get("results", [])
        except Exception as e:
            print(f"Warning: Failed to fetch proxies: {e}")
            self.proxies = []

    def get_random_proxy(self) -> Optional[Dict[str, str]]:
        """Returns a random proxy in requests format."""
        if not self.proxies:
            self.fetch_proxies()

        if not self.proxies:
            return None

        proxy_data = random.choice(self.proxies)
        proxy_url = f"http://{proxy_data['username']}:{proxy_data['password']}@{proxy_data['proxy_address']}:{proxy_data['port']}"

        return {
            "http": proxy_url,
            "https": proxy_url
        }

    def get_proxy_string(self) -> Optional[str]:
        """Returns a random proxy as a single string."""
        proxy_dict = self.get_random_proxy()
        if proxy_dict:
            return proxy_dict["http"]
        return None

    def get_playwright_proxy(self) -> Optional[Dict[str, str]]:
        """
        Returns a random proxy in Playwright format.
        Format: { "server": "http://ip:port", "username": "user", "password": "pass" }
        """
        if not self.proxies:
            self.fetch_proxies()

        if not self.proxies:
            return None

        proxy_data = random.choice(self.proxies)

        # Webshare proxies are typically HTTP/HTTPS.
        # We construct the server URL without auth, and pass auth separately.
        server_url = f"http://{proxy_data['proxy_address']}:{proxy_data['port']}"

        return {
            "server": server_url,
            "username": proxy_data['username'],
            "password": proxy_data['password']
        }
