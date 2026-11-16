"""
common.py — shared utilities for the Forensic Orchestrator.

Provides:
  - load_config(): read config.yaml once
  - get_logger(): consistent logging to file + stdout
  - run_local(): execute a local command safely
  - run_remote(): execute a command on the Agent over SSH
  - fetch_remote(): scp a file from Agent to local case dir
  - sha256_file(): streaming SHA-256 of a local file
  - utc_now(): ISO-8601 UTC timestamp with Z suffix

Wazuh-Based Automated Forensic Framework
Politecnico di Torino — MSc Cybersecurity 2026
"""

import hashlib
import logging
import os
import shlex
import subprocess
import sys
from datetime import datetime, timezone

import yaml

_CONFIG_PATH = os.environ.get(
    "FORENSIC_CONFIG",
    "/opt/forensic-orchestrator/config.yaml",
)
_config_cache = None


def load_config():
    """Load and cache config.yaml."""
    global _config_cache
    if _config_cache is None:
        with open(_CONFIG_PATH, "r") as f:
            _config_cache = yaml.safe_load(f)
    return _config_cache


def utc_now():
    """ISO-8601 UTC timestamp, e.g. 2026-05-28T15:30:00Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_logger(name="orchestrator"):
    cfg = load_config()
    log_file = cfg["orchestrator"]["log_file"]
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    fh = logging.FileHandler(log_file)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    return logger


def run_local(cmd, timeout=300):
    """
    Run a local shell command.
    Returns (returncode, stdout, stderr).
    `cmd` may be a list or a string.
    """
    if isinstance(cmd, str):
        cmd_list = shlex.split(cmd)
    else:
        cmd_list = cmd
    try:
        p = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as e:  # noqa: BLE001
        return 1, "", str(e)


def _ssh_base():
    cfg = load_config()["agent"]
    return (
        f"ssh -i {cfg['ssh_key']} {cfg['ssh_opts']} "
        f"{cfg['user']}@{cfg['host']}"
    )


def run_remote(remote_cmd, timeout=300, use_sudo=False):
    """
    Run a command on the Agent over SSH.
    Returns (returncode, stdout, stderr).
    """
    if use_sudo and load_config()["agent"].get("user") != "root":
        remote_cmd = f"sudo {remote_cmd}"
    full = f"{_ssh_base()} {shlex.quote(remote_cmd)}"
    return run_local(full, timeout=timeout)


def fetch_remote_stream(remote_cmd, local_path, timeout=600, use_sudo=False):
    """
    Run a command on the Agent and stream its STDOUT into a local file.
    Used for memory/disk acquisition (e.g. dd of /proc/kcore).
    Returns (returncode, bytes_written, stderr).
    """
    cfg = load_config()["agent"]
    if use_sudo and cfg.get("user") != "root":
        remote_cmd = f"sudo {remote_cmd}"
    ssh_cmd = (
        f"ssh -i {cfg['ssh_key']} {cfg['ssh_opts']} "
        f"{cfg['user']}@{cfg['host']} {shlex.quote(remote_cmd)}"
    )
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    try:
        with open(local_path, "wb") as out:
            p = subprocess.run(
                shlex.split(ssh_cmd),
                stdout=out,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
        size = os.path.getsize(local_path)
        return p.returncode, size, p.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired:
        size = os.path.getsize(local_path) if os.path.exists(local_path) else 0
        return 124, size, f"timeout after {timeout}s"
    except Exception as e:  # noqa: BLE001
        return 1, 0, str(e)


def fetch_remote_file(remote_path, local_path, timeout=120, use_sudo=False):
    """
    Copy a single file from the Agent to local using cat over SSH
    (works even when the file is root-only, via sudo cat).
    Returns (returncode, bytes_written, stderr).
    """
    cmd = f"cat {shlex.quote(remote_path)}"
    return fetch_remote_stream(cmd, local_path, timeout=timeout, use_sudo=use_sudo)


def sha256_file(path):
    """Streaming SHA-256 of a local file. Returns hex digest or None."""
    if not os.path.exists(path):
        return None
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:  # noqa: BLE001
        return None


def human_size(num):
    """Human-readable byte size."""
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PiB"
