import shutil
import subprocess
import os
import sys
from typing import Optional, Dict, Any, List
from langchain_core.tools import tool

def get_executable_path(tool_name: str) -> Optional[str]:
    """Finds the executable path for a given tool."""
    return shutil.which(tool_name)

@tool
def run_nuclei(url: str, tags: Optional[str] = None) -> str:
    """
    [ACTIVE SCANNER] Runs Nuclei vulnerability scanner.
    Args:
        url: Target URL
        tags: Optional comma-separated tags (e.g., "cve,misconfiguration,cms")
    """
    nuclei_path = get_executable_path("nuclei")
    if not nuclei_path:
        return "ERROR: Nuclei not found in PATH. Please install Nuclei."

    # cmd: nuclei -u [url] -json
    cmd = [nuclei_path, "-u", url, "-no-color"]

    if tags:
        cmd.extend(["-tags", tags])
    else:
        # Default mild scan if no tags
        cmd.extend(["-tags", "cve,misconfiguration,technologies"])

    try:
        # Run process
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300 # 5 mins
        )

        output = result.stdout + result.stderr
        if not output.strip():
            return "Nuclei finished with no output (possibly no vulnerabilities found)."

        # Return summary or full output if short
        if len(output) > 2000:
             return f"Nuclei Output (Truncated):\n{output[:1000]}\n...\n{output[-1000:]}"
        return f"Nuclei Output:\n{output}"

    except subprocess.TimeoutExpired:
        return "Nuclei scan timed out."
    except Exception as e:
        return f"Error running Nuclei: {str(e)}"

@tool
def run_arjun(url: str) -> str:
    """
    [ACTIVE SCANNER] Runs Arjun to discover hidden HTTP parameters.
    """
    # Arjun is a python module, usually run as 'arjun' command if installed
    arjun_path = get_executable_path("arjun")
    if not arjun_path:
         # Try running via python -m arjun
         arjun_path = "arjun" # hope it's in path or alias

    cmd = ["arjun", "-u", url, "--stable", "-oT", "/tmp/arjun_out.json"] # stable scan

    try:
        # We try to run it. If 'arjun' command fails, we might try 'python -m arjun' logic, but let's stick to CLI
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        if result.returncode != 0:
             # Try fallback: python -m arjun
             cmd = [sys.executable, "-m", "arjun", "-u", url, "--stable"]
             result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

        output = result.stdout
        # Arjun output can be verbose. Look for "Parameters found"
        if "parameters found" in output.lower():
            return f"Arjun Found Parameters:\n{output}"
        else:
            return f"Arjun finished. Output:\n{output[-1000:]}"

    except Exception as e:
        return f"Error running Arjun: {str(e)}"

@tool
def run_wapiti(url: str) -> str:
    """
    [ACTIVE SCANNER] Runs Wapiti web vulnerability scanner.
    """
    wapiti_path = get_executable_path("wapiti")
    if not wapiti_path:
        wapiti_path = "wapiti"

    # Wapiti is heavy. Quick scan.
    # -u URL --scope folder -m common_modules --flush-session -f txt
    cmd = [wapiti_path, "-u", url, "--scope", "folder", "--flush-session", "-f", "txt", "--color", "--max-scan-time", "300"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=360 # 6 mins
        )
        return f"Wapiti Output:\n{result.stdout[-3000:]}" # Last 3000 chars

    except Exception as e:
        return f"Error running Wapiti: {str(e)}"

@tool
def run_ffuf(url: str, wordlist_path: Optional[str] = None) -> str:
    """
    [ACTIVE SCANNER] Runs FFUF (Fuzz Faster U Fool) for fuzzing directories or parameters.
    Replaces Wfuzz.
    Args:
        url: Target URL. Use 'FUZZ' keyword to mark injection point (e.g., http://target/FUZZ).
             If 'FUZZ' is not present, it will default to directory discovery at the end.
        wordlist_path: Path to the wordlist file.
    """
    ffuf_path = get_executable_path("ffuf")
    if not ffuf_path:
        return "ERROR: FFUF not found in PATH. Please install FFUF."

    # Validate or set default wordlist
    # Note: On a real VPS, user usually has SecLists. We will try common paths or ask user.
    if not wordlist_path:
         # Try heuristics or fail
         # For simplicity, if no wordlist is provided, we can't fuzz effectively.
         return "ERROR: FFUF requires a wordlist. Please provide 'wordlist_path' argument."

    if "FUZZ" not in url:
        if not url.endswith("/"):
            url += "/"
        url += "FUZZ"

    # cmd: ffuf -u [url] -w [wordlist] -mc 200,301,302,403
    cmd = [ffuf_path, "-u", url, "-w", wordlist_path, "-mc", "200,301,302,403", "-s"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )
        if result.stdout:
            return f"FFUF Found:\n{result.stdout}"
        return "FFUF finished. No matches found."

    except Exception as e:
        return f"Error running FFUF: {str(e)}"

@tool
def run_trufflehog(url: str) -> str:
    """
    [ACTIVE SCANNER] Runs TruffleHog to scan for secrets in the page/endpoint.
    """
    th_path = get_executable_path("trufflehog")
    if not th_path:
        # Check pip version (trufflehog3)
        th_path = get_executable_path("trufflehog3")

    if not th_path:
        return "ERROR: TruffleHog not found."

    # Scan url
    cmd = [th_path, "filesystem", url, "--no-update"] # This is for filesystem
    # TruffleHog git/filesystem. For URL, it might be 'git' or we need to download source first.
    # TruffleHog also has 's3', 'gcs', etc.
    # For a generic URL, 'trufflehog3' (python) can scan a URL?
    # Actually trufflehog3 is 'trufflehog3 [URL]'.

    cmd = [th_path, url]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.stdout:
            return f"TruffleHog Found:\n{result.stdout}"
        return "TruffleHog finished. No secrets found."
    except Exception as e:
        return f"Error: {str(e)}"

@tool
def run_sqlmap(url: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Wraps SQLMap execution.
    Assumes 'sqlmap' is in PATH or 'sqlmap.py' is runnable via python.
    """
    # Check if sqlmap is available
    sqlmap_path = get_executable_path("sqlmap")

    # In some Windows envs, it might be 'python sqlmap.py'
    cmd = []
    if sqlmap_path:
        cmd = [sqlmap_path]
    else:
        # Fallback check for sqlmap.py in current or specific folder (optional)
        # For now, return error if not in path
        return "ERROR: SQLMap not found in PATH. Please install SQLMap and add it to your system PATH."

    # Construct arguments
    # --batch: non-interactive
    # --random-agent: avoid blocking
    # --forms: parse forms
    # --level 1 --risk 1: basic scan (safe-ish)
    cmd.extend(["-u", url, "--batch", "--random-agent", "--forms", "--level", "1", "--risk", "1"])

    if params:
        # If specific params needed, complex. Usually SQLMap auto-detects.
        pass

    try:
        # Run process
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300 # 5 minutes max
        )

        output = result.stdout
        if "detected" in output.lower() or "injectable" in output.lower():
             # Extract relevant part
             return f"SQLMap Found Vulnerabilities!\n\n{output[-2000:]}"
        else:
             return f"SQLMap finished. No obvious vulnerabilities found.\nSummary:\n{output[-1000:]}"

    except subprocess.TimeoutExpired:
        return "SQLMap timed out."
    except Exception as e:
        return f"Error running SQLMap: {str(e)}"

@tool
def run_dalfox(url: str) -> str:
    """
    Wraps Dalfox execution for XSS scanning.
    """
    dalfox_path = get_executable_path("dalfox")
    if not dalfox_path:
        return "ERROR: Dalfox not found in PATH. Please install Dalfox."

    # cmd: dalfox url [target]
    cmd = [dalfox_path, "url", url, "--skip-bav", "--silence", "--no-color"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode == 0 and result.stdout.strip():
            return f"Dalfox XSS Found:\n{result.stdout}"
        else:
            return "Dalfox finished. No XSS found."

    except Exception as e:
        return f"Error running Dalfox: {str(e)}"

@tool
def run_nmap(url: str) -> str:
    """
    Wraps Nmap for port scanning.
    """
    nmap_path = get_executable_path("nmap")
    if not nmap_path:
        return "ERROR: Nmap not found in PATH."

    # Clean URL to hostname
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.netloc if parsed.netloc else parsed.path
    if ":" in hostname:
        hostname = hostname.split(":")[0]

    # cmd: nmap -F [host] (Fast scan)
    cmd = [nmap_path, "-F", hostname]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        return f"Nmap Scan Result:\n{result.stdout}"
    except Exception as e:
        return f"Error running Nmap: {str(e)}"
