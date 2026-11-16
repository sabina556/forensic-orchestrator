"""
logs.py — collect system logs from the Agent over SSH:
  - journalctl (last 24h, all priorities)
  - /var/log/auth.log (authentication events)
  - /var/log/syslog (general, tail)

Returns a list of artefact descriptors.

Wazuh-Based Automated Forensic Framework
Politecnico di Torino — MSc Cybersecurity 2026
"""

import os

from common import (
    load_config,
    get_logger,
    run_remote,
    fetch_remote_file,
    sha256_file,
    utc_now,
    human_size,
)

log = get_logger("collector.logs")


def _write(case_dir, name, content):
    out_dir = os.path.join(case_dir, "evidence", "logs")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, name)
    with open(path, "w") as f:
        f.write(content or "")
    return path


def collect_logs(case_dir):
    artefacts = []

    # 1. journalctl last 24h
    rc, out, err = run_remote(
        "journalctl --since '24 hours ago' --no-pager",
        timeout=120, use_sudo=True,
    )
    path = _write(case_dir, "journalctl_24h.log", out)
    artefacts.append({
        "type": "log_journal",
        "path": path,
        "sha256": sha256_file(path),
        "size": os.path.getsize(path),
        "source": "agent:journalctl --since 24h",
        "collected_at": utc_now(),
        "notes": "systemd journal, last 24 hours",
    })
    log.info("journalctl: %s", human_size(os.path.getsize(path)))

    # 2. auth.log (copy raw file)
    out_dir = os.path.join(case_dir, "evidence", "logs")
    os.makedirs(out_dir, exist_ok=True)
    auth_local = os.path.join(out_dir, "auth.log")
    rc, size, err = fetch_remote_file(
        "/var/log/auth.log", auth_local, timeout=60, use_sudo=True
    )
    if size > 0:
        artefacts.append({
            "type": "log_auth",
            "path": auth_local,
            "sha256": sha256_file(auth_local),
            "size": size,
            "source": "agent:/var/log/auth.log",
            "collected_at": utc_now(),
            "notes": "authentication log",
        })
        log.info("auth.log: %s", human_size(size))
    else:
        log.warning("auth.log not collected (%s)", err[:80])

    return artefacts
