from langchain_core.tools import tool
import requests
import subprocess
import shutil
import json
from typing import Optional, Dict, Any, List
from src.proxy_manager import ProxyManager

proxy_manager = ProxyManager()

@tool
def analyze_headers(url: str) -> Dict[str, Any]:
    """
    Fetches HTTP headers and checks for missing security headers.
    Useful for checking X-Frame-Options, CSP, HSTS, etc.
    """
    proxy = proxy_manager.get_random_proxy()
    try:
        response = requests.head(url, proxies=proxy, timeout=10, allow_redirects=True)
        headers = dict(response.headers)

        security_headers = [
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "Permissions-Policy"
        ]

        missing_headers = [h for h in security_headers if h not in headers]

        return {
            "status_code": response.status_code,
            "headers": headers,
            "missing_security_headers": missing_headers
        }
    except Exception as e:
        return {"error": str(e)}

@tool
def fetch_page_content(url: str) -> str:
    """
    Downloads the HTML source code of the page for analysis.
    Useful for finding hidden comments, version info, or sensitive data in source.
    """
    proxy = proxy_manager.get_random_proxy()
    try:
        response = requests.get(url, proxies=proxy, timeout=15)
        return response.text[:10000] # Return first 10k chars to avoid token limit issues
    except Exception as e:
        return f"Error fetching page: {str(e)}"

@tool
def identify_waf(url: str) -> str:
    """
    Runs `wafw00f` against the URL to detect firewalls.
    Returns the detection output.
    """
    # Since importing WAFW00F class directly is tricky due to package structure,
    # we will run it as a subprocess command which is reliable.

    wafw00f_path = shutil.which("wafw00f")
    if not wafw00f_path:
        return "Error: wafw00f tool not found in path."

    proxy_str = proxy_manager.get_proxy_string()

    cmd = [wafw00f_path, url, "--output", "-"]
    if proxy_str:
        cmd.extend(["--proxy", proxy_str])

    try:
        # Run wafw00f and capture output
        # Using subprocess to run the CLI tool
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            return f"Wafw00f failed: {result.stderr}"

        return result.stdout
    except Exception as e:
        return f"Error running wafw00f: {str(e)}"

@tool
def send_custom_request(url: str, method: str = "GET", data: Optional[Dict] = None, headers: Optional[Dict] = None) -> str:
    """
    Sends a custom HTTP request to the target.
    Useful for testing SQL Injection payloads, XSS, or other specific exploits.

    Args:
        url: Target URL
        method: HTTP method (GET, POST, etc.)
        data: Body data (for POST/PUT)
        headers: Custom headers
    """
    proxy = proxy_manager.get_random_proxy()
    try:
        response = requests.request(
            method=method,
            url=url,
            data=data,
            headers=headers,
            proxies=proxy,
            timeout=10
        )
        return f"Status: {response.status_code}\nBody: {response.text[:2000]}"
    except Exception as e:
        return f"Error sending request: {str(e)}"
