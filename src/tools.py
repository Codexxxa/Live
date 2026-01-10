import requests
import subprocess
from langchain_core.tools import tool
import urllib3
from urllib.parse import urlparse

# Disable warnings for self-signed certs (common in testing)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@tool
def check_http_headers(url: str) -> str:
    """
    Fetches the HTTP headers of the target URL to analyze security configurations.
    Returns the headers as a text string.
    """
    try:
        if not url.startswith('http'):
            url = 'http://' + url

        response = requests.head(url, verify=False, timeout=10)
        headers = response.headers

        # Format headers for the AI
        output = "HTTP Headers:\n"
        for key, value in headers.items():
            output += f"{key}: {value}\n"

        return output
    except Exception as e:
        return f"Error fetching headers: {str(e)}"

@tool
def detect_waf(url: str) -> str:
    """
    Detects the presence of a Web Application Firewall (WAF) using wafw00f logic.
    Returns the detection result.
    """
    try:
        # Extract hostname from URL for wafw00f
        parsed = urlparse(url)
        target = parsed.netloc or parsed.path

        # Run wafw00f as a subprocess since it's a CLI tool
        # capturing stdout
        cmd = ["wafw00f", target]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode != 0:
            return f"WAF Detection Failed: {result.stderr}"

        # Parse output for relevant info (simplified)
        output = result.stdout
        if "No WAF detected" in output:
            return "No WAF detected by wafw00f."
        else:
            # Return the full output for the AI to parse, it's usually verbose but contains the specific WAF name
            return f"WAF Detection Output:\n{output}"

    except Exception as e:
        return f"Error running wafw00f: {str(e)}"

@tool
def fetch_html_content(url: str) -> str:
    """
    Fetches the HTML content of the homepage (first 5000 chars) to check for comments,
    version numbers, or other information leakage.
    """
    try:
        if not url.startswith('http'):
            url = 'http://' + url

        response = requests.get(url, verify=False, timeout=10)
        return response.text[:10000] # Return first 10k chars
    except Exception as e:
        return f"Error fetching content: {str(e)}"

@tool
def check_robots_txt(url: str) -> str:
    """
    Fetches the robots.txt file of the target website.
    """
    try:
        if not url.startswith('http'):
            url = 'http://' + url

        # Ensure we look at root
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        robots_url = f"{base}/robots.txt"

        response = requests.get(robots_url, verify=False, timeout=10)
        if response.status_code == 200:
            return f"robots.txt content:\n{response.text}"
        else:
            return f"robots.txt not found (Status: {response.status_code})"
    except Exception as e:
        return f"Error checking robots.txt: {str(e)}"
