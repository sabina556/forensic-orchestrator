"""
tsk_analyzer.py — run The Sleuth Kit against a disk image to produce a
filesystem timeline. TSK works natively on ARM (no kernel symbols needed),
so this analyzer operates on real images when available.

Workflow:
  1. mmls   — partition layout (if image is a full disk)
  2. fls    — recursively list files -> body file
  3. mactime — convert body file to a human timeline (CSV)

If no disk image artefact is provided, the analyzer instead builds a
timeline from the filesystem metadata CSV already collected by the
filesystem collector (graceful degradation for the demo).

Findings -> <case>/findings/tsk/
Returns a dict: {engine, mode, outputs:{name:{path,sha256}}}

Wazuh-Based Automated Forensic Framework
Politecnico di Torino — MSc Cybersecurity 2026
"""

import os

from common import (
    load_config,
    get_logger,
    run_local,
    sha256_file,
    utc_now,
)

log = get_logger("analyzer.tsk")


def _timeline_from_metadata(case_dir, out_dir):
    """
    Build a mactime-style timeline from the fs_timeline.csv that the
    filesystem collector produced (pipe-delimited:
    mtime_epoch|ctime_epoch|size|perms|owner|path).
    """
    meta = os.path.join(case_dir, "evidence", "filesystem", "fs_timeline.csv")
    out_path = os.path.join(out_dir, "filesystem_timeline.csv")
    if not os.path.exists(meta):
        return None

    rows = []
    with open(meta, "r") as f:
        next(f, None)  # header
        for line in f:
            parts = line.rstrip("\n").split("|")
            if len(parts) < 6:
                continue
            mtime, ctime, size, perms, owner, path = parts[:6]
            try:
                mt = int(float(mtime))
            except ValueError:
                continue
            rows.append((mt, size, perms, owner, path))

    rows.sort(reverse=True)  # most recent first
    with open(out_path, "w") as f:
        f.write("mtime_epoch,size,perms,owner,path\n")
        for mt, size, perms, owner, path in rows:
            f.write(f"{mt},{size},{perms},{owner},{path}\n")

    return out_path


def analyze_disk(case_dir, disk_artifact=None):
    cfg = load_config()["analyzers"]["tsk"]
    if not cfg.get("enabled", False):
        return {"engine": "tsk", "mode": "disabled", "outputs": {}}

    out_dir = os.path.join(case_dir, "findings", "tsk")
    os.makedirs(out_dir, exist_ok=True)

    results = {
        "engine": "the_sleuth_kit",
        "analyzed_at": utc_now(),
        "outputs": {},
    }

    image_path = disk_artifact.get("path") if disk_artifact else None

    if image_path and os.path.exists(image_path):
        results["mode"] = "disk_image"
        fls_bin = cfg["fls_bin"]
        mactime_bin = cfg["mactime_bin"]

        body_path = os.path.join(out_dir, "filesystem.body")
        rc, out, err = run_local(
            f"{fls_bin} -r -m / {image_path}", timeout=600
        )
        with open(body_path, "w") as f:
            f.write(out or "")
        results["outputs"]["body"] = {
            "path": body_path, "sha256": sha256_file(body_path)
        }

        tl_path = os.path.join(out_dir, "filesystem_timeline.csv")
        rc, out, err = run_local(
            f"{mactime_bin} -d -b {body_path}", timeout=300
        )
        with open(tl_path, "w") as f:
            f.write(out or "")
        results["outputs"]["timeline"] = {
            "path": tl_path, "sha256": sha256_file(tl_path)
        }
        log.info("TSK disk image timeline produced")
    else:
        # Graceful degradation: build timeline from collected metadata
        results["mode"] = "metadata_timeline"
        tl_path = _timeline_from_metadata(case_dir, out_dir)
        if tl_path:
            results["outputs"]["timeline"] = {
                "path": tl_path, "sha256": sha256_file(tl_path)
            }
            log.info("TSK metadata-based timeline produced: %s", tl_path)
        else:
            log.warning("No disk image and no metadata; TSK produced nothing")

    return results
