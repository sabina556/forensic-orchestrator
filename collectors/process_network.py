"""
process_network.py — capture volatile system state from the Agent over SSH:
  - running processes (ps aux + ps -ef)
  - process tree (ps axjf)
  - network connections (ss -tunap)
  - listening sockets (ss -tlnp)
  - open files (lsof, best effort)

Volatile data is collected FIRST in the orchestration order (order of
volatility principle, RFC 3227): the most ephemeral evidence is captured
before slower acquisitions like the memory image.

Returns a list of artefact descriptors.

Wazuh-Based Automated Forensic Framework
Politecnico di Torino — MSc Cybersecurity 2026
"""

import os

from common import (
    load_config,
    get_logger,
    run_remote,
    sha256_file,
    utc_now,
)

log = get_logger("collector.procnet")

_CAPTURES = [
    ("processes_ps_aux.txt", "ps aux", False),
    ("processes_ps_ef.txt", "ps -ef", False),
    ("process_tree.txt", "ps axjf", False),
    ("network_connections.txt", "ss -tunap", True),
    ("network_listening.txt", "ss -tlnp", True),
    ("open_files.txt", "lsof -n -P", True),
]


def _write(case_dir, name, content):
    out_dir = os.path.join(case_dir, "evidence", "volatile")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, name)
    with open(path, "w") as f:
        f.write(content or "")
    return path


def collect_process_network(case_dir):
    artefacts = []
    for fname, cmd, needs_sudo in _CAPTURES:
        rc, out, err = run_remote(cmd, timeout=60, use_sudo=needs_sudo)
        path = _write(case_dir, fname, out)
        artefacts.append({
            "type": "volatile_state",
            "path": path,
            "sha256": sha256_file(path),
            "size": os.path.getsize(path),
            "source": f"agent:{cmd}",
            "collected_at": utc_now(),
            "notes": f"volatile snapshot: {cmd}",
        })
        log.info("Captured %s (%d bytes)", fname, os.path.getsize(path))
    return artefacts
