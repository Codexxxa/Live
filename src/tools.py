import asyncio
import requests
import subprocess
import shutil
import json
from bs4 import BeautifulSoup, Comment
from langchain_core.tools import tool
from typing import Optional, Dict, Any, List
from src.proxy_manager import ProxyManager
from crawl4ai import AsyncWebCrawler

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
    Useful for testing SQL Injection payloads, XSS, or other specific exploits.
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
def crawl_website(url: str) -> str:
    """
    Crawls the website using a headless browser to get dynamic content.
    Returns Markdown-formatted text of the page content.
    Useful for SPA (Single Page Applications) or sites heavily using JavaScript.
    """
    async def run_crawl():
        # TODO: Integrate proxy usage for crawl4ai if supported/needed
        # For now, we assume crawl4ai uses system environment or direct connection
        # To add proxy: AsyncWebCrawler(proxy=...) if supported

        async with AsyncWebCrawler(verbose=True) as crawler:
            result = await crawler.arun(url=url)
            return result.markdown

    try:
        # Check if we are in an existing loop
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If we are in a running loop (which we are, in main.py),
            # we cannot use run_until_complete directly if this function is called synchronously.
            # However, this tool is wrapped by LangChain.
            # If the executor node is sync, this will fail.
            # We will refactor the executor node to be async.
            # For now, returning a coroutine might be expected if the node is async.
            return run_crawl()
    except RuntimeError:
        # If no loop is running, we can use asyncio.run
        return asyncio.run(run_crawl())

    # Fallback/Safe path for sync execution context if needed
    # But since we will update the executor to be async, we return the coroutine?
    # Actually, the tool_executor_node will await it if it detects a coroutine.
    return run_crawl()

@tool
def analyze_critical_elements(url: str) -> str:
    """
    Analyzes the page to extract ONLY critical elements for security testing:
    - Forms and Inputs
    - Scripts (src or inline)
    - Comments
    - Meta tags

    Reduces noise compared to full HTML fetch.
    """
    proxy = proxy_manager.get_random_proxy()
    try:
        response = requests.get(url, proxies=proxy, timeout=15)
        soup = BeautifulSoup(response.text, 'html.parser')

        report = []

        # 1. Forms
        forms = soup.find_all('form')
        report.append(f"Found {len(forms)} forms:")
        for i, form in enumerate(forms):
            action = form.get('action', 'N/A')
            method = form.get('method', 'GET')
            inputs = form.find_all(['input', 'textarea', 'select'])
            input_names = [inp.get('name', 'unnamed') for inp in inputs]
            report.append(f"  Form #{i+1}: action='{action}' method='{method}' inputs={input_names}")

        # 2. Scripts
        scripts = soup.find_all('script')
        src_scripts = [s.get('src') for s in scripts if s.get('src')]
        report.append(f"\nExternal Scripts ({len(src_scripts)}):")
        for src in src_scripts:
            report.append(f"  - {src}")

        # 3. Comments
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        report.append(f"\nComments ({len(comments)}):")
        for c in comments:
            s = str(c).strip()
            if len(s) > 0:
                report.append(f"  - <!-- {s[:100]}... -->")

        return "\n".join(report)

    except Exception as e:
        return f"Error analyzing elements: {str(e)}"
