#!/usr/bin/env python3
"""
post_seal_hook.py - post-seal service of the forensic orchestrator.

Watches the append-only custody ledger. Every new record is a newly sealed case;
for each one the service, in order:
  1. writes a JSON event to a log file that the Wazuh manager monitors, so that
     the sealing (or an incomplete collection) becomes a Wazuh alert itself
     (rules 100300 / 100301) and reaches every Wazuh integration;
  2. re-indexes the dashboard (dashboard_exporter.py --apply);
  3. generates the evidentiary (forensic) PDF report of the case;
  4. sends an external notification (Telegram and/or generic JSON webhook),
     if configured in /etc/forensic-notify.env.

Design constraints (forensic soundness):
  * Read-only with respect to evidence: it reads the ledger and the case
    manifest, never writes under storage/cases/<case>/evidence/ and never
    touches the ledger. The report is written next to the manifest, as the
    report portal does.
  * The acquisition code path is unchanged: the service runs as a separate
    process after sealing, so the cases of the evaluation sets remain produced
    by the evaluated orchestrator.
  * Starts at the current end of the ledger: existing cases are never
    re-notified (state in storage/analysis/post_seal_state.json).
  * Notifications carry metadata only (case id, rule, technique, times,
    digests), never artefact content.
"""
import json, os, subprocess, sys, time, logging, datetime, urllib.request, urllib.parse

BASE = "/opt/forensic-orchestrator"
LEDGER = os.path.join(BASE, "chain_of_custody", "custody_log.json")
CASES = os.path.join(BASE, "storage", "cases")
STATE = os.path.join(BASE, "storage", "analysis", "post_seal_state.json")
EVENT_LOG = "/var/log/forensic-orchestrator/events.json"   # monitored by the Wazuh manager
PORTAL = os.environ.get("FORENSIC_PORTAL_URL", "http://192.168.64.8:8088")
POLL_S = 2.0

logging.basicConfig(level=logging.INFO, format="%(asctime)s post-seal %(levelname)s %(message)s")
log = logging.getLogger("post-seal")


def _count_lines(path):
    with open(path, encoding="utf-8") as f:
        return sum(1 for ln in f if ln.strip())


def _read_from(path, start):
    """Return the non-empty ledger records after the first `start` ones."""
    out, n = [], 0
    with open(path, encoding="utf-8") as f:
        for ln in f:
            if not ln.strip():
                continue
            n += 1
            if n > start:
                try:
                    out.append(json.loads(ln))
                except Exception:
                    out.append({})
    return out, n


def _load_state():
    try:
        return json.load(open(STATE))
    except Exception:
        return None


def _save_state(n):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"ledger_records_seen": n,
                   "updated": datetime.datetime.now(datetime.timezone.utc).isoformat()}, f)
    os.replace(tmp, STATE)


def _iso(s):
    if not s:
        return None
    s = str(s).replace("Z", "+00:00")
    if len(s) > 5 and s[-5] in "+-" and s[-3] != ":":
        s = s[:-2] + ":" + s[-2:]
    try:
        return datetime.datetime.fromisoformat(s)
    except Exception:
        return None


def summarise(case_id):
    """Metadata of a sealed case, from its manifest (waits briefly for the file)."""
    path = os.path.join(CASES, case_id, "case_manifest.json")
    for _ in range(30):
        if os.path.exists(path):
            break
        time.sleep(1)
    m = json.load(open(path))
    a = m.get("alert") or {}
    ev = m.get("evidence") or []
    mem = next((e for e in ev if e.get("type") == "memory"), {}) or {}
    cc = (mem.get("content_check") or {})
    t_alert = _iso(a.get("timestamp"))
    t_seal = _iso(m.get("seal_requested_at")) or _iso(m.get("created_at"))
    tte = round((t_seal - t_alert).total_seconds(), 3) if (t_alert and t_seal) else None
    problems = []
    if mem.get("method") == "kcore_segments" and cc.get("status") != "pass":
        problems.append("memory: " + ("; ".join(cc.get("reasons") or []) or "content check failed"))
    if len(ev) < 16:
        problems.append("only %d of 16 artefacts recorded" % len(ev))
    empty = [os.path.basename(e.get("path", "")) for e in ev
             if e.get("type") != "memory" and int(e.get("size") or 0) == 0]
    if empty:
        problems.append("empty artefacts: " + ", ".join(empty))
    return {
        "case_id": case_id,
        "rule_id": str(a.get("rule_id")),
        "technique": ",".join(a.get("mitre_ids") or []),
        "tactic": ",".join(a.get("mitre_tactics") or []),
        "agent": a.get("agent_name") or a.get("agent"),
        "agent_ip": a.get("agent_ip"),
        "alert_time": a.get("timestamp"),
        "sealed_at": m.get("seal_requested_at") or m.get("created_at"),
        "tte_s": tte,
        "artefacts": len(ev),
        "memory_method": mem.get("method"),
        "memory_gate": cc.get("status"),
        "custody_hash": m.get("custody_hash"),
        "stratum": (m.get("collection_profile") or {}).get("stratum", "A"),
        "problems": problems,
    }


def wazuh_event(s):
    """Append one JSON line for the Wazuh manager (localfile, log_format json)."""
    ev = {"forensic": {
        "event": "collection_incomplete" if s["problems"] else "case_sealed",
        "case_id": s["case_id"], "rule_id": s["rule_id"], "technique": s["technique"],
        "agent": s["agent"], "tte_s": s["tte_s"], "artefacts": s["artefacts"],
        "memory_gate": s["memory_gate"], "custody_hash": s["custody_hash"],
        "reason": "; ".join(s["problems"]) or None,
        "report": "%s/pdf/%s?which=forensic" % (PORTAL, s["case_id"]),
    }}
    os.makedirs(os.path.dirname(EVENT_LOG), exist_ok=True)
    with open(EVENT_LOG, "a") as f:
        f.write(json.dumps(ev, sort_keys=True) + "\n")


def run(cmd, cwd, timeout):
    r = subprocess.run(["nice", "-n", "10"] + cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        log.warning("%s failed: %s", cmd[1:3], (r.stderr or r.stdout)[-300:])
    return r.returncode == 0


def notify(s):
    ok = "✅" if not s["problems"] else "⚠️"
    lines = [
        "%s Forensic case %s" % (ok, "sealed" if not s["problems"] else "sealed with problems"),
        "Case: %s" % s["case_id"],
        "Rule %s · %s (%s)" % (s["rule_id"], s["technique"], s["tactic"]),
        "Host: %s (%s)" % (s["agent"], s["agent_ip"]),
        "Alert: %s" % s["alert_time"],
        "Evidence sealed after %s s · %d artefacts · memory gate: %s" % (s["tte_s"], s["artefacts"], s["memory_gate"] or "n/a"),
        "Custody: %s…" % (s["custody_hash"] or "")[:16],
    ]
    if s["problems"]:
        lines.append("Problems: " + "; ".join(s["problems"]))
    lines.append("Report (analyst network / VPN only): %s/pdf/%s?which=forensic" % (PORTAL, s["case_id"]))
    text = "\n".join(lines)

    tok, chat = os.environ.get("NOTIFY_TELEGRAM_TOKEN"), os.environ.get("NOTIFY_TELEGRAM_CHAT")
    if tok and chat:
        try:
            data = urllib.parse.urlencode({"chat_id": chat, "text": text, "disable_web_page_preview": "true"}).encode()
            urllib.request.urlopen("https://api.telegram.org/bot%s/sendMessage" % tok, data=data, timeout=10).read()
        except Exception as e:
            log.warning("telegram failed: %s", e)
    hook = os.environ.get("NOTIFY_WEBHOOK_URL")
    if hook:
        try:
            body = json.dumps({"text": text, "case": s}).encode()
            req = urllib.request.Request(hook, data=body, headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as e:
            log.warning("webhook failed: %s", e)


def handle(record):
    cid = record.get("case_id") or (record.get("incident") or {}).get("case_id")
    if not cid or not os.path.isdir(os.path.join(CASES, cid)):
        log.info("ledger record without a case directory (%s); skipped", cid)
        return
    s = summarise(cid)
    wazuh_event(s)
    log.info("sealed %s rule=%s tte=%s problems=%s", cid, s["rule_id"], s["tte_s"], s["problems"])
    run(["python3", "dashboard_exporter.py", "--apply"], BASE, 120)
    run(["python3", "report_generator.py", os.path.join(CASES, cid), "--forensic-clean"],
        os.path.join(BASE, "reporting"), 240)
    notify(s)


def main():
    st = _load_state()
    seen = st["ledger_records_seen"] if st else _count_lines(LEDGER)
    if not st:
        _save_state(seen)
    log.info("watching %s from record %d", LEDGER, seen)
    while True:
        try:
            new, total = _read_from(LEDGER, seen)
            for rec in new:
                try:
                    handle(rec)
                except Exception as e:
                    log.exception("post-seal failed: %s", e)
            if total != seen:
                seen = total
                _save_state(seen)
        except FileNotFoundError:
            pass
        time.sleep(POLL_S)


if __name__ == "__main__":
    sys.exit(main())
