"""
filesystem.py — collect filesystem evidence from the Agent over SSH:
  1. A metadata timeline (path, size, mtime, ctime, perms, owner) for
     forensically interesting directories, written as a body-like file.
  2. Copies of critical files (passwd, shadow, crontab, etc.) preserved
     with their own SHA-256.

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

log = get_logger("collector.filesystem")


def _collect_metadata_timeline(case_dir, dirs):
    out_dir = os.path.join(case_dir, "evidence", "filesystem")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "fs_timeline.csv")

    # find ... -printf produces: epoch_mtime|epoch_ctime|size|perms|user|path
    dir_args = " ".join(d for d in dirs)
    remote_cmd = (
        f"find {dir_args} -xdev -printf "
        f"'%T@|%C@|%s|%m|%u|%p\\n' 2>/dev/null"
    )
    rc, out, err = run_remote(remote_cmd, timeout=300, use_sudo=True)

    header = "mtime_epoch,ctime_epoch,size,perms,owner,path\n"
    with open(out_path, "w") as f:
        f.write(header)
        if out:
            # convert pipe-delimited to CSV-ish (paths may contain commas,
            # so we keep pipe internally but label as csv for the demo)
            f.write(out)

    digest = sha256_file(out_path)
    size = os.path.getsize(out_path)
    lines = (out.count("\n") if out else 0)
    log.info("FS timeline: %s entries, %s", lines, human_size(size))

    return {
        "type": "filesystem_timeline",
        "path": out_path,
        "sha256": digest,
        "size": size,
        "entries": lines,
        "source": "find metadata over SSH",
        "collected_at": utc_now(),
        "notes": f"Metadata for: {', '.join(dirs)}",
    }


def _collect_critical_files(case_dir, files):
    out_dir = os.path.join(case_dir, "evidence", "critical_files")
    os.makedirs(out_dir, exist_ok=True)

    artefacts = []
    for remote_path in files:
        safe_name = remote_path.strip("/").replace("/", "_")
        local_path = os.path.join(out_dir, safe_name)
        rc, size, err = fetch_remote_file(
            remote_path, local_path, timeout=60, use_sudo=True
        )
        if rc != 0 or size == 0:
            log.warning("Could not collect %s (%s)", remote_path, err[:80])
            # remove empty file if created
            if os.path.exists(local_path) and os.path.getsize(local_path) == 0:
                os.remove(local_path)
            continue
        digest = sha256_file(local_path)
        artefacts.append({
            "type": "critical_file",
            "path": local_path,
            "remote_path": remote_path,
            "sha256": digest,
            "size": size,
            "source": f"agent:{remote_path}",
            "collected_at": utc_now(),
            "notes": "preserved critical file",
        })
        log.info("Collected %s (%s)", remote_path, human_size(size))
    return artefacts


def collect_filesystem(case_dir):
    cfg = load_config()["collection"]
    artefacts = []
    artefacts.append(
        _collect_metadata_timeline(case_dir, cfg["metadata_dirs"])
    )
    artefacts.extend(
        _collect_critical_files(case_dir, cfg["critical_files"])
    )
    return artefacts
