"""SIFT Workstation forensic tool subprocess wrappers."""

import logging
import os
import subprocess
import time

logger = logging.getLogger(__name__)

_MAX_OUTPUT = 5000


def _truncate_output(text: str) -> tuple[str, bool]:
    truncated = len(text) > _MAX_OUTPUT
    if truncated:
        text = text[:_MAX_OUTPUT]
    return text, truncated


def _run_tool(tool: str, cmd: list[str], timeout: int) -> dict:
    command = " ".join(cmd)
    logger.debug(f"Running: {command}")
    start = time.perf_counter()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        duration_sec = time.perf_counter() - start
        output, truncated = _truncate_output(result.stdout or "")
        return {
            "tool": tool,
            "command": command,
            "success": result.returncode == 0,
            "output": output,
            "error": result.stderr or "",
            "duration_sec": duration_sec,
            "truncated": truncated,
        }
    except subprocess.TimeoutExpired:
        duration_sec = time.perf_counter() - start
        return {
            "tool": tool,
            "command": command,
            "success": False,
            "output": "",
            "error": f"TIMEOUT after {timeout}s",
            "duration_sec": duration_sec,
            "truncated": False,
        }
    except Exception as e:
        duration_sec = time.perf_counter() - start
        return {
            "tool": tool,
            "command": command,
            "success": False,
            "output": "",
            "error": str(e),
            "duration_sec": duration_sec,
            "truncated": False,
        }


def run_vol3_pslist(memory_path: str, timeout: int = 120) -> dict:
    """List all running processes from a memory dump."""
    cmd = ["vol3", "-f", memory_path, "windows.pslist.PsList"]
    return _run_tool("vol3_pslist", cmd, timeout)


def run_vol3_netscan(memory_path: str, timeout: int = 120) -> dict:
    """List network connections from a memory dump."""
    cmd = ["vol3", "-f", memory_path, "windows.netscan.NetScan"]
    return _run_tool("vol3_netscan", cmd, timeout)


def run_vol3_cmdline(memory_path: str, timeout: int = 120) -> dict:
    """Get command-line arguments for each process from memory."""
    cmd = ["vol3", "-f", memory_path, "windows.cmdline.CmdLine"]
    return _run_tool("vol3_cmdline", cmd, timeout)


def run_vol3_malfind(memory_path: str, timeout: int = 180) -> dict:
    """Find suspicious memory injections."""
    cmd = ["vol3", "-f", memory_path, "windows.malfind.Malfind"]
    return _run_tool("vol3_malfind", cmd, timeout)


def run_strings_search(
    target_path: str,
    pattern: str = "powershell|cmd|http|base64|encoded",
    timeout: int = 60,
) -> dict:
    """Search for suspicious ASCII strings in a file using strings + grep pipe."""
    tool = "strings_search"
    command = f"strings {target_path} | grep -iE {pattern}"
    logger.debug(f"Running: {command}")
    start = time.perf_counter()
    p1 = None
    p2 = None
    try:
        p1 = subprocess.Popen(["strings", target_path], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(
            ["grep", "-iE", pattern],
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        p1.stdout.close()
        out, err = p2.communicate(timeout=timeout)
        if p1.poll() is None:
            p1.wait(timeout=5)
        duration_sec = time.perf_counter() - start
        output_str = out.decode(errors="replace")
        output_str, truncated = _truncate_output(output_str)
        return {
            "tool": tool,
            "command": command,
            "success": p2.returncode == 0,
            "output": output_str,
            "error": err.decode(errors="replace"),
            "duration_sec": duration_sec,
            "truncated": truncated,
        }
    except subprocess.TimeoutExpired:
        duration_sec = time.perf_counter() - start
        for proc in (p2, p1):
            if proc is not None and proc.poll() is None:
                proc.kill()
        return {
            "tool": tool,
            "command": command,
            "success": False,
            "output": "",
            "error": f"TIMEOUT after {timeout}s",
            "duration_sec": duration_sec,
            "truncated": False,
        }
    except Exception as e:
        duration_sec = time.perf_counter() - start
        for proc in (p2, p1):
            if proc is not None and proc.poll() is None:
                proc.kill()
        return {
            "tool": tool,
            "command": command,
            "success": False,
            "output": "",
            "error": str(e),
            "duration_sec": duration_sec,
            "truncated": False,
        }


def extract_7z(archive_path: str, output_dir: str, timeout: int = 300) -> dict:
    """Extract a .7z archive. Used to unpack compressed memory dumps."""
    cmd = ["7z", "x", archive_path, f"-o{output_dir}", "-y"]
    return _run_tool("extract_7z", cmd, timeout)


def run_sha256(file_path: str, timeout: int = 60) -> dict:
    """Hash a file for evidence integrity. Works on any file."""
    cmd = ["sha256sum", file_path]
    return _run_tool("sha256", cmd, timeout)
