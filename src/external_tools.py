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

    # Heuristics to find Arjun
    cmd = []
    if arjun_path:
        cmd = [arjun_path, "-u", url, "--stable", "-oT", "/tmp/arjun_out.json"]
    else:
        # Fallback to python -m arjun
        cmd = [sys.executable, "-m", "arjun", "-u", url, "--stable"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        output = result.stdout
        # Arjun output can be verbose. Look for "Parameters found"
        if output and "parameters found" in output.lower():
            return f"Arjun Found Parameters:\n{output}"

        # If arjun command failed (return code non-zero or no output), try alternate method
        if result.returncode != 0 and arjun_path:
             # Try fallback: python -m arjun just in case 'arjun' executable is broken/shimmed
             cmd = [sys.executable, "-m", "arjun", "-u", url, "--stable"]
             result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
             if result.stdout and "parameters found" in result.stdout.lower():
                 return f"Arjun Found Parameters:\n{result.stdout}"

        if result.stderr:
             return f"Arjun Error:\n{result.stderr}"
        return f"Arjun finished. No parameters found or no output.\n{result.stdout[-500:]}"

    except Exception as e:
        return f"Error running Arjun: {str(e)}"

@tool
def run_wapiti(url: str) -> str:
    """
    [ACTIVE SCANNER] Runs Wapiti web vulnerability scanner.
    """
    wapiti_path = get_executable_path("wapiti")

    # If not found, check common python script locations or try python -m wapiti
    cmd = []
    if wapiti_path:
        cmd = [wapiti_path]
    else:
        # Fallback
        cmd = [sys.executable, "-m", "wapiti"]

    # -u URL --scope folder -m common_modules --flush-session -f txt
    cmd.extend(["-u", url, "--scope", "folder", "--flush-session", "-f", "txt", "--color", "--max-scan-time", "300"])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=360 # 6 mins
        )
        if result.returncode != 0 and "No such file" in result.stderr:
             return "ERROR: Wapiti not found. Please install via 'pip install wapiti3'."

        return f"Wapiti Output:\n{result.stdout[-3000:]}" # Last 3000 chars

    except Exception as e:
        return f"Error running Wapiti: {str(e)}"

@tool
def run_ffuf(url: str, wordlist_path: Optional[str] = None) -> str:
    """
    [ACTIVE SCANNER] Runs FFUF (Fuzz Faster U Fool) for fuzzing directories or parameters.
    Args:
        url: Target URL. Use 'FUZZ' keyword to mark injection point.
        wordlist_path: Path to the wordlist file.
    """
    ffuf_path = get_executable_path("ffuf")
    if not ffuf_path:
        return "ERROR: FFUF not found in PATH. Please install FFUF."

    if not wordlist_path:
         return "ERROR: FFUF requires a wordlist. Please provide 'wordlist_path' argument (e.g., C:\\Wordlists\\common.txt)."

    if "FUZZ" not in url:
        if not url.endswith("/"):
            url += "/"
        url += "FUZZ"

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
    [ACTIVE SCANNER] Runs TruffleHog to scan for secrets.
    NOTE: TruffleHog is best for Git Repositories.
    If URL is a website, consider using Nuclei with tags="tokens".
    """
    th_path = get_executable_path("trufflehog")
    if not th_path:
        return "ERROR: TruffleHog not found in PATH. Please install TruffleHog."

    # Check if URL is a git repo
    is_git = ".git" in url or "github.com" in url or "gitlab.com" in url

    if is_git:
        cmd = [th_path, "git", url, "--json"]
    else:
        # Fallback: Warning or try scanning as filesystem?
        # Scanning a website URL as filesystem won't work with TruffleHog CLI directly
        # It expects a local path for 'filesystem'.
        return "TruffleHog is designed for Git Repositories. Please provide a Git URL (e.g. https://github.com/user/repo) or use 'run_nuclei' with tags='tokens' for websites."

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout

        # Parse JSON output if possible, or just return raw
        if output:
            return f"TruffleHog Found Secrets:\n{output[:2000]}"
        return "TruffleHog finished. No secrets found."
    except Exception as e:
        return f"Error running TruffleHog: {str(e)}"

@tool
def run_sqlmap(url: str, params: Optional[Dict[str, Any]] = None) -> str:
    """
    Wraps SQLMap execution.
    """
    sqlmap_path = get_executable_path("sqlmap")

    # Heuristics for Windows 'python sqlmap.py' vs linux 'sqlmap'
    cmd = []
    if sqlmap_path:
        cmd = [sqlmap_path]
    else:
        # Check if sqlmap.py exists in a common location or return error
        return "ERROR: SQLMap not found in PATH. Please install SQLMap and add it to your system PATH."

    cmd.extend(["-u", url, "--batch", "--random-agent", "--forms", "--level", "1", "--risk", "1"])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300
        )

        output = result.stdout
        if "detected" in output.lower() or "injectable" in output.lower():
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

    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.netloc if parsed.netloc else parsed.path
    if ":" in hostname:
        hostname = hostname.split(":")[0]

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
