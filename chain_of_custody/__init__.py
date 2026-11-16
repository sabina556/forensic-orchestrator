"""
chain_of_custody/__init__.py — append-only, hash-chained custody ledger.

This preserves and strengthens the original design: each record stores a
prev_hash and current_hash, forming a tamper-evident chain (a broken or
edited record invalidates every subsequent hash). The first record uses
"Genesis" as prev_hash.

Improvements over the prototype:
  - per-case custody records (case_id field)
  - records the analyst and organization
  - stores full evidence + findings manifest with individual SHA-256
  - atomic append with fsync
  - helper to write a standalone chain_of_custody.json inside each case

Wazuh-Based Automated Forensic Framework
Politecnico di Torino — MSc Cybersecurity 2026
"""

import hashlib
import json
import os
from typing import Optional

from common import load_config, utc_now, get_logger

log = get_logger("custody")


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _custody_log_path() -> str:
    return load_config()["chain_of_custody"]["custody_log"]


def _get_last_hash() -> Optional[str]:
    path = _custody_log_path()
    try:
        with open(path, "r") as f:
            lines = [ln for ln in f.readlines() if ln.strip()]
        if not lines:
            return None
        last = json.loads(lines[-1])
        return last.get("chain", {}).get("current_hash")
    except FileNotFoundError:
        return None
    except Exception as e:  # noqa: BLE001
        log.warning("Could not read last custody hash: %s", e)
        return None


def record_event(*, case_id, alert, evidence, findings=None, source="wazuh"):
    """
    Append a custody record for a completed collection.

    case_id   : unique case identifier
    alert     : normalized alert dict (from wazuh_trigger.parse_alert)
    evidence  : list of artefact descriptors (each has type/path/sha256/size)
    findings  : optional dict of analyzer results
    Returns the chained record dict.
    """
    cfg = load_config()["chain_of_custody"]
    prev_hash = _get_last_hash()

    manifest = []
    for item in evidence:
        manifest.append({
            "type": item.get("type"),
            "path": item.get("path"),
            "sha256": item.get("sha256"),
            "size": item.get("size"),
            "source": item.get("source"),
            "collected_at": item.get("collected_at"),
        })

    record = {
        "case_id": case_id,
        "source": source,
        "analyst": cfg.get("analyst"),
        "organization": cfg.get("organization"),
        "incident": {
            "rule_id": alert.get("rule_id"),
            "level": alert.get("level"),
            "description": alert.get("description"),
            "mitre_ids": alert.get("mitre_ids"),
            "mitre_techniques": alert.get("mitre_techniques"),
            "mitre_tactics": alert.get("mitre_tactics"),
            "agent_name": alert.get("agent_name"),
            "agent_id": alert.get("agent_id"),
            "agent_ip": alert.get("agent_ip"),
        },
        "timeline": {
            "alert_time": alert.get("timestamp"),
            "collection_time": utc_now(),
        },
        "evidence": manifest,
        "findings_summary": _summarize_findings(findings) if findings else {},
    }

    record_bytes = json.dumps(record, sort_keys=True).encode()

    if prev_hash is None:
        previous_hash = "Genesis"
        current_hash = _sha256_bytes(record_bytes)
    else:
        previous_hash = prev_hash
        current_hash = _sha256_bytes(prev_hash.encode() + record_bytes)

    chained = {
        **record,
        "chain": {
            "prev_hash": previous_hash,
            "current_hash": current_hash,
            "hash_algorithm": "SHA-256",
        },
    }

    # atomic append to global ledger
    path = _custody_log_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(chained) + "\n")
        f.flush()
        os.fsync(f.fileno())

    log.info("Custody record appended for %s (hash=%s)",
             case_id, current_hash[:16])
    return chained


def write_case_custody(case_dir, chained_record):
    """Write a standalone chain_of_custody.json inside the case folder."""
    path = os.path.join(case_dir, "chain_of_custody.json")
    with open(path, "w") as f:
        json.dump(chained_record, f, indent=2)
    return path


def _summarize_findings(findings):
    summary = {}
    vol = findings.get("volatility") if findings else None
    if vol:
        summary["volatility"] = {
            "mode": vol.get("mode"),
            "image": vol.get("image"),
            "plugins": list(vol.get("plugins", {}).keys()),
        }
    tsk = findings.get("tsk") if findings else None
    if tsk:
        summary["tsk"] = {
            "mode": tsk.get("mode"),
            "outputs": list(tsk.get("outputs", {}).keys()),
        }
    return summary
