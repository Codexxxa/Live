import requests
import random
import os

PROXY_API_URL = "https://proxy.webshare.io/api/v2/proxy/list/"
API_KEY = "0a2qwmcm21fk6e0ak1wps4pqo3nbleyzudthk4ob"

def get_proxy_list():
    """
    Fetches the list of proxies from Webshare API.
    Uses page=1 to ensure results, as page=4 might be empty.
    """
    headers = {
        "Authorization": f"Token {API_KEY}"
    }
    # Using page=1 and mode=direct to ensure we get valid proxies.
    # The user suggested page=4, but verification showed it was empty.
    params = {
        "mode": "direct",
        "page": 1,
        "page_size": 100
    }

    try:
        response = requests.get(PROXY_API_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        if "results" in data:
            return data["results"]
        else:
            print(f"[WARN] No results found in proxy API response: {data}")
            return []

    except Exception as e:
        print(f"[ERROR] Failed to fetch proxies: {e}")
        return []

def get_random_proxy():
    """
    Returns a random proxy in the format http://user:pass@ip:port
    """
    proxies = get_proxy_list()
    if not proxies:
        return None

    proxy = random.choice(proxies)

    # Construct proxy URL
    # Webshare returns: username, password, proxy_address, port
    username = proxy.get('username')
    password = proxy.get('password')
    ip = proxy.get('proxy_address')
    port = proxy.get('port')

    if username and password and ip and port:
        return f"http://{username}:{password}@{ip}:{port}"

    return None

if __name__ == "__main__":
    # Test
    print(get_random_proxy())
