import shutil
import subprocess
import os
from typing import Optional, Dict, Any
from langchain_core.tools import tool

def get_executable_path(tool_name: str) -> Optional[str]:
    """Finds the executable path for a given tool."""
    return shutil.which(tool_name)

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
