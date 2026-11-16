"""
memory.py — acquire physical memory from the Agent over SSH.

The method is selected by collection.memory_method in config.yaml:

  kcore           Legacy collector used for the v2 evaluation set (stratum A).
                  Sequential read of the first memory_max_bytes of /proc/kcore.
                  On the ARM64 testbed this returns the ELF header and zero-filled
                  gaps only, because the first RAM segment lies ~27 TiB into the
                  virtual core file (thesis, Section 6.5). The code path is kept
                  byte-for-byte unchanged so that stratum-A cases stay reproducible.

  kcore_segments  Segment-aware acquisition (stratum B). Reads the kcore program
                  headers, streams only the PT_LOAD segments that map physical RAM
                  (byte-exact dd offsets, nothing installed on the Agent), writes a
                  LiME image compressed on the fly, hashes the UNCOMPRESSED image
                  (canonical SHA-256) and each segment, and applies a content-
                  validity gate (non-zero page ratio, short reads).

  none            Memory acquisition disabled.

Storage convention for kcore_segments: the manifest records the logical image
evidence/memory/memory.lime with the SHA-256 of the uncompressed LiME stream;
the bytes are stored as memory.lime.gz. This is exactly the convention the
lifecycle manager already uses for warm-tier artefacts, so `lifecycle_manager.py
verify` checks the image without modification (gunzip -> SHA-256 -> compare).

Pre-campaign smoke test (reads 16 MiB of RAM, writes nothing):
    cd /opt/forensic-orchestrator && python3 -m collectors.memory --probe

Returns an artefact descriptor dict:
  {type, path, sha256, size, method, source, collected_at, notes, ...}

Wazuh-Based Automated Forensic Framework
Politecnico di Torino — MSc Cybersecurity 2026
"""

import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time

from common import (
    load_config,
    get_logger,
    fetch_remote_stream,
    sha256_file,
    utc_now,
    human_size,
    _ssh_base,
)
from collectors import kcore_lime

log = get_logger("collector.memory")

GiB = 1 << 30


def collect_memory(case_dir):
    cfg = load_config()
    coll = cfg["collection"]
    agent = cfg["agent"]
    method = coll.get("memory_method", "kcore")

    if method == "kcore":
        return _collect_kcore_legacy(case_dir, cfg)
    if method == "kcore_segments":
        return _collect_kcore_segments(case_dir, cfg)

    log.info("memory_method=%s -> skipping memory acquisition", method)
    return {
        "type": "memory",
        "path": None,
        "sha256": None,
        "size": 0,
        "method": method,
        "source": f"{agent['user']}@{agent['host']}",
        "collected_at": utc_now(),
        "notes": "memory acquisition disabled by config",
    }


# ---------------------------------------------------------------------------
# Stratum A: legacy collector (unchanged behaviour)
# ---------------------------------------------------------------------------
def _collect_kcore_legacy(case_dir, cfg):
    coll = cfg["collection"]
    agent = cfg["agent"]

    out_dir = os.path.join(case_dir, "evidence", "memory")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "memory.kcore.raw")

    max_bytes = int(coll.get("memory_max_bytes", 0))
    # dd of /proc/kcore; cap with count if max_bytes > 0 (1 MiB blocks)
    if max_bytes > 0:
        blocks = max(1, max_bytes // (1024 * 1024))
        remote_cmd = f"dd if=/proc/kcore bs=1M count={blocks} 2>/dev/null"
        note = (
            f"Partial acquisition via /proc/kcore "
            f"(first {human_size(max_bytes)}); full acquisition configurable."
        )
    else:
        remote_cmd = "dd if=/proc/kcore bs=1M 2>/dev/null"
        note = "Full acquisition via /proc/kcore."

    log.info("Acquiring memory from %s@%s via /proc/kcore",
             agent["user"], agent["host"])
    rc, size, err = fetch_remote_stream(
        remote_cmd, out_path, timeout=600, use_sudo=True
    )

    if rc != 0 or size == 0:
        log.error("Memory acquisition failed rc=%s err=%s", rc, err[:200])
        return {
            "type": "memory",
            "path": out_path if size else None,
            "sha256": sha256_file(out_path) if size else None,
            "size": size,
            "method": "kcore",
            "source": f"{agent['user']}@{agent['host']}",
            "collected_at": utc_now(),
            "notes": f"acquisition error: {err[:200]}",
        }

    digest = sha256_file(out_path)
    log.info("Memory acquired: %s (%s) sha256=%s",
             out_path, human_size(size), digest[:16] if digest else "n/a")

    return {
        "type": "memory",
        "path": out_path,
        "sha256": digest,
        "size": size,
        "method": "kcore",
        "source": f"{agent['user']}@{agent['host']}:/proc/kcore",
        "collected_at": utc_now(),
        "notes": note,
    }


# ---------------------------------------------------------------------------
# Stratum B: segment-aware acquisition
# ---------------------------------------------------------------------------
class _SSHRunner:
    """runner(cmd) -> Popen for kcore_lime, built from the same SSH settings as
    run_remote(). Keeps track of the processes so a watchdog can kill them, and
    sends ssh's own stderr to a scratch file outside the evidence tree."""

    def __init__(self, cfg):
        self.base = shlex.split(_ssh_base())
        self.use_sudo = cfg["agent"].get("user") != "root"
        self.procs = []
        self.lock = threading.Lock()
        self.err = tempfile.TemporaryFile()

    def __call__(self, remote_cmd):
        if self.use_sudo:
            remote_cmd = f"sudo {remote_cmd}"
        p = subprocess.Popen(self.base + [remote_cmd], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=self.err,
                             start_new_session=True)  # own process group for the watchdog
        with self.lock:
            self.procs.append(p)
        return p

    def kill_all(self):
        with self.lock:
            for p in self.procs:
                if p.poll() is None:
                    try:
                        os.killpg(p.pid, signal.SIGKILL)
                    except OSError:
                        p.kill()

    def stderr_tail(self, n=300):
        try:
            self.err.seek(0)
            return self.err.read().decode("utf-8", "replace").strip()[-n:]
        except Exception:  # noqa: BLE001
            return ""


def _free_bytes(path):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def _collect_kcore_segments(case_dir, cfg):
    coll = cfg["collection"]
    agent = cfg["agent"]
    source = f"{agent['user']}@{agent['host']}:/proc/kcore"

    out_dir = os.path.join(case_dir, "evidence", "memory")
    os.makedirs(out_dir, exist_ok=True)
    logical = os.path.join(out_dir, "memory.lime")
    stored = logical + ".gz"

    max_bytes = int(coll.get("memory_segments_max_bytes", 0))
    reserve = int(coll.get("memory_reserve_bytes", 2 * GiB))
    timeout = int(coll.get("memory_timeout_seconds", 900))

    def plan_check(planned):
        # Worst case: incompressible RAM. Refuse to start rather than fill the
        # partition that also hosts the evidence store and the Wazuh indexer.
        free = _free_bytes(out_dir)
        need = planned + reserve
        log.info("Pre-flight: %s of RAM to acquire, %s free, %s required "
                 "(worst case + reserve)", human_size(planned), human_size(free),
                 human_size(need))
        if free < need:
            raise kcore_lime.KcoreError(
                f"insufficient free space: {human_size(free)} free, "
                f"{human_size(need)} required (RAM {human_size(planned)} + "
                f"reserve {human_size(reserve)})")

    runner = _SSHRunner(cfg)
    deadline = time.monotonic() + timeout
    watchdog = threading.Timer(timeout, runner.kill_all)
    watchdog.daemon = True
    started = utc_now()
    log.info("Acquiring physical memory from %s (segment-aware, LiME)", source)
    watchdog.start()
    try:
        meta = kcore_lime.acquire(runner, stored, max_bytes=max_bytes,
                                  log=log.info, plan_check=plan_check,
                                  deadline=deadline)
    except Exception as e:  # noqa: BLE001
        log.error("Memory acquisition failed: %s %s", e, runner.stderr_tail())
        partial = os.path.exists(stored)
        return {
            "type": "memory",
            "path": None,
            "sha256": None,
            "size": 0,
            "method": "kcore_segments",
            "format": "lime",
            "source": source,
            "acquisition_started_at": started,
            "collected_at": utc_now(),
            "failed_output": stored if partial else None,
            "failed_output_sha256": sha256_file(stored) if partial else None,
            "content_check": {"status": "fail", "reasons": [str(e)]},
            "notes": f"acquisition error: {e}"[:300],
        }
    finally:
        watchdog.cancel()
        runner.kill_all()

    try:
        os.chmod(stored, 0o444)  # evidence is write-once
    except OSError:
        pass

    gate = meta["content_check"]
    log.info("Memory acquired: %s RAM in %.1fs (%.0f MiB/s), stored %s, "
             "sha256(LiME)=%s, content gate %s %s",
             human_size(meta["ram_bytes"]), meta["acquisition_seconds"],
             meta["throughput_mib_s"] or 0, human_size(meta["stored_size"]),
             meta["sha256"][:16], gate["status"].upper(),
             "; ".join(gate["reasons"]))

    note = (f"Segment-aware acquisition of {len(meta['segments'])} physical-RAM "
            f"segment(s) from /proc/kcore into LiME; sha256 is over the "
            f"uncompressed image, stored as {os.path.basename(stored)}.")
    if meta["partial"]:
        note += f" PARTIAL: capped at {human_size(max_bytes)}."

    acquisition = {k: v for k, v in meta.items()
                   if k not in ("type", "format", "method", "sha256", "size",
                                "stored_path", "stored_sha256", "stored_size",
                                "compression", "content_check")}
    return {
        "type": "memory",
        "path": logical,                     # logical image (manifest hash refers to it)
        "sha256": meta["sha256"],            # SHA-256 of the uncompressed LiME image
        "size": meta["size"],
        "method": "kcore_segments",
        "format": "lime",
        "source": source,
        "acquisition_started_at": started,
        "collected_at": utc_now(),
        "stored_path": stored,
        "stored_sha256": meta["stored_sha256"],
        "stored_size": meta["stored_size"],
        "compression": meta["compression"],
        "compressed_at": "acquisition",
        "content_check": gate,
        "acquisition": acquisition,
        "notes": note,
    }


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------
def _main(argv):
    if "--probe" not in argv:
        print("usage: python3 -m collectors.memory --probe [--mib N]")
        return 2
    mib = 16
    if "--mib" in argv:
        mib = int(argv[argv.index("--mib") + 1])
    cfg = load_config()
    runner = _SSHRunner(cfg)
    try:
        res = kcore_lime.probe(runner, sample_bytes=mib << 20)
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"verdict": "error", "error": str(e),
                          "ssh_stderr": runner.stderr_tail()}, indent=1))
        return 1
    finally:
        runner.kill_all()
    root = cfg["orchestrator"]["cases_root"]
    reserve = int(cfg["collection"].get("memory_reserve_bytes", 2 * GiB))
    free = _free_bytes(root)
    res["preflight"] = {"cases_root_free_bytes": free,
                        "required_per_case_worst_case": res["ram_bytes"] + reserve,
                        "ok": free >= res["ram_bytes"] + reserve}
    print(json.dumps(res, indent=1))
    return 0 if res["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
