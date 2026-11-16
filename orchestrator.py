
"""
orchestrator.py — central Forensic Orchestrator.

Runs an HTTP service that receives Wazuh alerts (forwarded by the Wazuh
integration subsystem via custom-forensic) and executes the full forensic pipeline:

  1. Parse alert + extract MITRE ATT&CK techniques
  2. Create a case folder (case_id = CASE-<UTC>-<rule>)
  3. Collect evidence; the order is set by collection.order:
       legacy   process/network -> logs -> filesystem -> memory
                (v2 evaluation set, stratum A: memory last as the costliest step)
       rfc3227  process/network -> memory -> logs -> filesystem
                (stratum B: decreasing order of volatility, RFC 3227 §2.1)
  4. Analyze: TSK filesystem timeline (Volatility disabled on ARM64)
  5. Append tamper-evident chain-of-custody record
  6. Write case manifest (used later by the PDF report generator)

Endpoints:
  POST /api/v1/ingest   - receive an alert, run pipeline (async)
  GET  /api/v1/health   - liveness probe
  GET  /api/v1/cases    - list cases

Run:
  python3 orchestrator.py            # serve
  python3 orchestrator.py --once     # process last alert from alerts.json

Wazuh-Based Automated Forensic Framework
Politecnico di Torino — MSc Cybersecurity 2026

"""

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone

from flask import Flask, request, jsonify

from common import load_config, get_logger, utc_now
from integrations.wazuh_trigger import parse_alert
from incident_dedup import check_and_register
from collectors.process_network import collect_process_network
from collectors.logs import collect_logs
from collectors.filesystem import collect_filesystem
from collectors.memory import collect_memory
from analyzers.volatility_analyzer import analyze_memory
from analyzers.tsk_analyzer import analyze_disk
from chain_of_custody import record_event, write_case_custody

log = get_logger("orchestrator")
app = Flask(__name__)


# ----------------------------------------------------------------
# Pipeline
# ----------------------------------------------------------------
def _make_case_id(alert):
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rule = alert.get("rule_id") or "NA"
    return f"CASE-{ts}-rule{rule}"


COLLECTION_ORDERS = {
    "legacy":  ("process_network", "logs", "filesystem", "memory"),
    "rfc3227": ("process_network", "memory", "logs", "filesystem"),
}


def _ts_ms():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def collection_profile(cfg):
    """Experimental conditions recorded in every manifest (stratification key)."""
    coll = cfg["collection"]
    method = coll.get("memory_method", "kcore")
    order = coll.get("order", "legacy")
    stratum = coll.get("stratum") or ("B" if method == "kcore_segments" else "A")
    return {"stratum": str(stratum), "memory_method": method, "order": order}


def run_pipeline(alert_json):
    """Execute the full forensic pipeline for one alert. Returns manifest."""
    cfg = load_config()
    alert = parse_alert(alert_json)
    case_id = _make_case_id(alert)
    proceed, existing_case = check_and_register(alert, case_id, cfg, log)
    if not proceed:
        log.info("Acquisition skipped — alert aggregated into incident %s", existing_case)
        return {"case_id": existing_case, "aggregated": True, "evidence": [], "custody_hash": None}
    case_dir = os.path.join(cfg["orchestrator"]["cases_root"], case_id)
    os.makedirs(case_dir, exist_ok=True)

    log.info("=== Pipeline start: %s ===", case_id)
    log.info("Rule %s level %s | MITRE %s | agent %s",
             alert.get("rule_id"), alert.get("level"),
             alert.get("mitre_ids"), alert.get("agent_name"))

    evidence = []
    profile = collection_profile(cfg)
    order = COLLECTION_ORDERS.get(profile["order"])
    if order is None:
        log.error("unknown collection.order=%r, falling back to legacy", profile["order"])
        profile["order"] = "legacy"
        order = COLLECTION_ORDERS["legacy"]
    log.info("Collection profile: stratum %s, memory=%s, order=%s",
             profile["stratum"], profile["memory_method"], " -> ".join(order))

    mem_artifact = None
    phase_timing = []

    def _phase_memory():
        nonlocal mem_artifact
        mem_artifact = collect_memory(case_dir)
        return [mem_artifact]

    phases = {
        "process_network": lambda: collect_process_network(case_dir),  # volatile state
        "logs": lambda: collect_logs(case_dir),
        "filesystem": lambda: collect_filesystem(case_dir),  # metadata + critical files
        "memory": _phase_memory,
    }
    for name in order:
        start, t0 = _ts_ms(), time.monotonic()
        try:
            evidence.extend(phases[name]())
        except Exception as e:  # noqa: BLE001
            log.error("%s collection failed: %s", name, e)
        phase_timing.append({"phase": name, "start": start, "end": _ts_ms(),
                             "seconds": round(time.monotonic() - t0, 3)})

    # 5. Analysis
    findings = {}
    a_start, a_t0 = _ts_ms(), time.monotonic()
    try:
        findings["volatility"] = analyze_memory(case_dir, mem_artifact)
    except Exception as e:  # noqa: BLE001
        log.error("volatility analysis failed: %s", e)
        findings["volatility"] = {"engine": "volatility3", "error": str(e)}

    try:
        findings["tsk"] = analyze_disk(case_dir, disk_artifact=None)
    except Exception as e:  # noqa: BLE001
        log.error("tsk analysis failed: %s", e)
        findings["tsk"] = {"engine": "tsk", "error": str(e)}
    phase_timing.append({"phase": "analysis", "start": a_start, "end": _ts_ms(),
                         "seconds": round(time.monotonic() - a_t0, 3)})

    # 6. Chain of custody
    # timeline.collection_time is written by record_event() via utc_now(), i.e.
    # truncated to whole seconds (unchanged, so that MTTE stays comparable with
    # stratum A). The millisecond timestamp taken immediately before sealing
    # allows the exact MTTE and the truncation offset to be measured.
    seal_requested_at = _ts_ms()
    chained = record_event(
        case_id=case_id,
        alert=alert,
        evidence=evidence,
        findings=findings,
        source="wazuh",
    )
    write_case_custody(case_dir, chained)

    # 7. Case manifest (consumed by report generator on Day 3)
    manifest = {
        "case_id": case_id,
        "created_at": utc_now(),
        "alert": alert,
        "evidence": evidence,
        "findings": findings,
        "custody_hash": chained["chain"]["current_hash"],
        "case_dir": case_dir,
        "collection_profile": profile,
        "phase_timing": phase_timing,
        "seal_requested_at": seal_requested_at,
    }
    manifest_path = os.path.join(case_dir, "case_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2, default=str)

    log.info("=== Pipeline complete: %s (%d artefacts) ===",
             case_id, len(evidence))
    return manifest


# ----------------------------------------------------------------
# HTTP endpoints
# ----------------------------------------------------------------
@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": utc_now()})


@app.route("/api/v1/ingest", methods=["POST"])
def ingest():
    try:
        payload = request.get_json(force=True, silent=True)
        if not payload:
            return jsonify({"error": "invalid or empty JSON"}), 400

        # forensic_dispatch.sh may wrap as {"alert": {...}} or send raw alert
        alert_json = payload.get("alert", payload)

        # Run pipeline in a background thread so HTTP returns immediately
        case_id_holder = {}

        def _worker():
            m = run_pipeline(alert_json)
            case_id_holder["case_id"] = m["case_id"]

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

        return jsonify({
            "status": "accepted",
            "message": "forensic pipeline started",
            "time": utc_now(),
        }), 202
    except Exception as e:  # noqa: BLE001
        log.error("ingest error: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/cases", methods=["GET"])
def list_cases():
    cfg = load_config()
    root = cfg["orchestrator"]["cases_root"]
    cases = []
    if os.path.isdir(root):
        for name in sorted(os.listdir(root), reverse=True):
            mpath = os.path.join(root, name, "case_manifest.json")
            if os.path.exists(mpath):
                try:
                    with open(mpath) as f:
                        m = json.load(f)
                    cases.append({
                        "case_id": m.get("case_id"),
                        "created_at": m.get("created_at"),
                        "rule_id": m.get("alert", {}).get("rule_id"),
                        "mitre_ids": m.get("alert", {}).get("mitre_ids"),
                        "artefacts": len(m.get("evidence", [])),
                    })
                except Exception:  # noqa: BLE001
                    pass
    return jsonify({"count": len(cases), "cases": cases})


# ----------------------------------------------------------------
# Entrypoint
# ----------------------------------------------------------------
def _run_once():
    """Process the last alert from alerts.json (manual test mode)."""
    alerts_path = "/var/ossec/logs/alerts/alerts.json"
    with open(alerts_path, "r") as f:
        lines = [ln for ln in f.readlines() if ln.strip()]
    if not lines:
        print("No alerts found.")
        return
    alert_json = json.loads(lines[-1])
    manifest = run_pipeline(alert_json)
    print(json.dumps({
        "case_id": manifest["case_id"],
        "artefacts": len(manifest["evidence"]),
        "custody_hash": manifest["custody_hash"],
    }, indent=2))


if __name__ == "__main__":
    if "--once" in sys.argv:
        _run_once()
    else:
        cfg = load_config()["orchestrator"]
        log.info("Forensic Orchestrator listening on %s:%s%s",
                 cfg["listen_host"], cfg["listen_port"], cfg["ingest_path"])
        app.run(
            host=cfg["listen_host"],
            port=cfg["listen_port"],
            threaded=True,
        )
