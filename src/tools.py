import asyncio
import requests
import subprocess
import shutil
import json
from bs4 import BeautifulSoup, Comment
from langchain_core.tools import tool
from typing import Optional, Dict, Any, List
from src.proxy_manager import ProxyManager
from src.attack_tools import check_sqli, check_xss
from playwright.async_api import async_playwright

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
    Returns truncated content (max 5000 chars) to save tokens.
    """
    proxy = proxy_manager.get_random_proxy()
    try:
        response = requests.get(url, proxies=proxy, timeout=15)
        text = response.text
        if len(text) > 5000:
            return text[:5000] + "\n...[Content Truncated. Use scan_attack_surface for detailed element analysis]..."
        return text
    except Exception as e:
        return f"Error fetching page: {str(e)}"

@tool
def identify_waf(url: str) -> str:
    """
    Runs `wafw00f` against the URL to detect firewalls.
    Returns the detection output.
    """
    wafw00f_path = shutil.which("wafw00f")
    if not wafw00f_path:
        return "Error: wafw00f tool not found in path."

    proxy_str = proxy_manager.get_proxy_string()

    cmd = [wafw00f_path, url, "--output", "-"]
    if proxy_str:
        cmd.extend(["--proxy", proxy_str])

    try:
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
    Useful for manual verification of exploits if needed.
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

@tool
def scan_attack_surface(url: str) -> str:
    """
    [HIGH PRIORITY] Scans the page for interactive elements that could be attack vectors.
    Returns a structured JSON summary of:
    - Input Forms (action, method, fields)
    - URL Parameters
    - Cookies
    - API Endpoints (guessed from scripts)

    Use this instead of reading full HTML to save context.
    """
    proxy = proxy_manager.get_random_proxy()
    try:
        response = requests.get(url, proxies=proxy, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')

        surface = {
            "url": url,
            "forms": [],
            "links_with_params": [],
            "cookies": list(response.cookies.keys()),
            "potential_api_endpoints": []
        }

        # 1. Forms
        forms = soup.find_all('form')
        for form in forms:
            form_data = {
                "action": form.get('action', ''),
                "method": form.get('method', 'GET').upper(),
                "inputs": []
            }
            for inp in form.find_all(['input', 'textarea', 'select']):
                inp_data = {
                    "name": inp.get('name'),
                    "type": inp.get('type', 'text'),
                    "id": inp.get('id')
                }
                if inp_data["name"]: # Only list inputs with names
                    form_data["inputs"].append(inp_data)
            surface["forms"].append(form_data)

        # 2. Links with Params
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            if '?' in href:
                surface["links_with_params"].append(href)

        # 3. Scripts (Heuristic for APIs)
        scripts = soup.find_all('script', src=True)
        for s in scripts:
            src = s['src']
            if "api" in src or "v1" in src:
                surface["potential_api_endpoints"].append(src)

        return json.dumps(surface, indent=2)

    except Exception as e:
        return f"Error scanning attack surface: {str(e)}"

@tool
async def render_page(url: str) -> str:
    """
    Renders the page using a headless browser (Playwright).
    Use this if the site is a Single Page Application (SPA) or loads content via JS.
    """
    try:
        async with async_playwright() as p:
            # Launch browser (Chromium)
            browser = await p.chromium.launch(headless=True)

            # Context with basic strict settings to avoid detection/blocks if possible
            # Note: We can add proxy here if needed, but keeping it simple for now
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            )

            page = await context.new_page()

            try:
                await page.goto(url, timeout=30000, wait_until="networkidle")
            except Exception:
                # If networkidle fails, try domcontentloaded
                await page.goto(url, timeout=30000, wait_until="domcontentloaded")

            content = await page.content()
            await browser.close()

            # Simple summarization for context saving
            if len(content) > 10000:
                return content[:5000] + "\n...[Truncated]..."
            return content

    except Exception as e:
        return f"Error rendering page with Playwright: {str(e)}"

@tool
def exploit_sqli(url: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    [OFFENSIVE] Tests for SQL Injection vulnerabilities.
    REQUIRES APPROVAL.
    """
    proxy = proxy_manager.get_random_proxy()
    return check_sqli(url, params, proxies=proxy)

@tool
def exploit_xss(url: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    [OFFENSIVE] Tests for Reflected XSS vulnerabilities.
    REQUIRES APPROVAL.
    """
    proxy = proxy_manager.get_random_proxy()
    return check_xss(url, params, proxies=proxy)

# Deprecated/Wrapper for legacy support if needed, but we rely on the above tools now
@tool
def crawl_website(url: str) -> str:
    """Deprecated. Use render_page instead."""
    return "Please use 'render_page' tool."
