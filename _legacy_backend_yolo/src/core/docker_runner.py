"""
Docker Runner Utilities
=======================
Helper functions for running malware analysis inside Docker containers.
"""

import os
import subprocess
from typing import Dict


def is_docker_available(timeout: int = 5) -> bool:
    """Check whether Docker is available on the host."""
    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.SubprocessError):
        return False


def run_malware_pe(image: str, file_path: str, timeout: int = 300) -> Dict[str, str]:
    """Run PE malware scan inside a Docker container."""
    if not os.path.exists(file_path):
        return {"success": "false", "error": "file_not_found"}

    host_dir = os.path.dirname(os.path.abspath(file_path))
    file_name = os.path.basename(file_path)
    container_path = f"/data/{file_name}"

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{host_dir}:/data",
        image,
        "python3",
        "Extract/PE_main.py",
        container_path,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "success": "true" if result.returncode == 0 else "false",
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"success": "false", "error": "timeout"}
    except subprocess.SubprocessError as exc:
        return {"success": "false", "error": str(exc)}


def run_malware_url(image: str, url: str, timeout: int = 300) -> Dict[str, str]:
    """Run URL malware scan inside a Docker container."""
    cmd = [
        "docker",
        "run",
        "--rm",
        "-i",
        image,
        "python3",
        "Extract/url_main.py",
    ]

    try:
        result = subprocess.run(
            cmd,
            input=f"{url}\n",
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "success": "true" if result.returncode == 0 else "false",
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"success": "false", "error": "timeout"}
    except subprocess.SubprocessError as exc:
        return {"success": "false", "error": str(exc)}
