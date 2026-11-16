#!/usr/bin/env python3
"""
incident_dedup.py — incident-level alert correlation / debouncing.

Problem: a single real attack (e.g. one `cat /etc/shadow`) produces multiple
Wazuh alerts in quick succession, and each would otherwise trigger a separate,
expensive forensic acquisition — flooding storage with near-identical cases.

Solution (DFIR-correct): separate *alert* from *incident*. Alerts sharing the
same (rule_id, agent) tuple within a configurable correlation window are
AGGREGATED into a single forensic case. No alert is discarded — duplicates are
appended to the incident's related-alerts log — but the costly acquisition runs
once per incident. This mirrors NIST SP 800-61 incident handling and standard
SOC alert-aggregation practice, and is preferable to suppressing detection at
the rule level (which would create blind spots for repeated/ongoing attacks).

State is persisted in a small JSON index so it survives orchestrator restarts.
Access is guarded by a lock + atomic write to handle concurrent ingests.
"""

import os
import json
import time
import threading
import tempfile

_LOCK = threading.Lock()

DEFAULT_WINDOW_SECONDS = 300
INDEX_FILENAME = "incident_index.json"


def _index_path(cfg):
    storage_root = os.path.dirname(cfg["orchestrator"]["cases_root"].rstrip("/"))
    return os.path.join(storage_root, INDEX_FILENAME)


def _window(cfg):
    return int(
        cfg.get("orchestrator", {}).get("debounce_window_seconds",
                                        DEFAULT_WINDOW_SECONDS)
    )


def _load_index(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_index(path, index):
    """Atomic write so a concurrent reader never sees a half-written file."""
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".idx_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(index, f, indent=2)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _key(alert):
    rule = str(alert.get("rule_id") or "NA")
    agent = str(alert.get("agent") or alert.get("agent_name") or "unknown")
    return f"{rule}:{agent}"


def check_and_register(alert, case_id, cfg, log=None):
    """
    Decide whether this alert should start a NEW forensic acquisition.

    Returns:
      (True,  case_id)            -> new incident; caller proceeds with collection
      (False, existing_case_id)   -> duplicate within window; collection skipped,
                                     alert appended to the existing incident.
    """
    window = _window(cfg)
    path = _index_path(cfg)
    now = time.time()
    k = _key(alert)

    with _LOCK:
        index = _load_index(path)
        entry = index.get(k)

        if entry and (now - entry.get("ts", 0)) < window:
            # Active incident exists — aggregate this alert into it.
            existing = entry["case_id"]
            entry["count"] = entry.get("count", 1) + 1
            entry["last_seen"] = now
            index[k] = entry
            _save_index(path, index)
            _append_related_alert(cfg, existing, alert, now)
            if log:
                log.info(
                    "Debounce: alert %s aggregated into active incident %s "
                    "(count=%d, window=%ds) — acquisition skipped",
                    k, existing, entry["count"], window)
            return (False, existing)

        # New incident — register and allow collection.
        index[k] = {
            "case_id": case_id,
            "ts": now,
            "last_seen": now,
            "count": 1,
        }
        _save_index(path, index)
        if log:
            log.info("Debounce: new incident %s for %s (window=%ds)",
                     case_id, k, window)
        return (True, case_id)


def _append_related_alert(cfg, case_id, alert, ts):
    """Record an aggregated (duplicate) alert in the incident's case folder,
    so nothing is lost and the report can show 'N related detections'."""
    case_dir = os.path.join(cfg["orchestrator"]["cases_root"], case_id)
    try:
        os.makedirs(case_dir, exist_ok=True)
        rec = {
            "aggregated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
            "rule_id": alert.get("rule_id"),
            "level": alert.get("level"),
            "description": alert.get("description"),
            "agent": alert.get("agent") or alert.get("agent_name"),
            "mitre_ids": alert.get("mitre_ids"),
        }
        with open(os.path.join(case_dir, "related_alerts.jsonl"), "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        # Best-effort; never break ingest because of bookkeeping.
        pass
