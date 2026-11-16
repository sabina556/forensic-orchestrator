#!/usr/bin/env python3
"""
threat_analysis.py — post-collection threat-analysis layer for sealed cases.

Read-only analysis over evidence that the pipeline has already acquired and sealed.
Three components:

  T1  Indicator rules        technique indicators in the acquired authentication log and
                             system journal of each case (the five detection techniques plus
                             report-only hunting rules), with attribution (user, tty, cwd)
  T2  State difference       difference of each case's host state against the previous
                             in-scope case of the same host: local accounts, security-relevant
                             files, listening sockets, log continuity, files changed between
                             the two acquisitions
  T3  Attack chains          cases grouped into sessions; ordered ATT&CK tactic sequence per
                             session, built from T1 findings and T2 indicators

Forensic properties (same as supertimeline.py)
  * Integrity gate: every input artefact is re-hashed and compared with the digest in the
    case manifest BEFORE it is read; a mismatch excludes the case and is reported.
  * Evidence is never modified: outputs go to storage/analysis/threat/, outside the cases.
    The custody ledger is not touched.
  * Deterministic: no wall-clock data in the outputs; a re-run yields identical files
    (check with --verify).
  * The journal time zone is derived from records present in both the journal and the
    RFC 3339 authentication log, not assumed.

Usage (on the manager, from the orchestrator root):
    sudo python3 analyzers/threat_analysis.py                       # all in-scope cases
    sudo python3 analyzers/threat_analysis.py --alerts alerts.json  # + agreement with Wazuh alerts
    sudo python3 analyzers/threat_analysis.py --verify              # determinism check

Wazuh-Based Automated Forensic Framework — Politecnico di Torino, MSc Cybersecurity 2026
"""

import argparse
import collections
import csv
import gzip
import hashlib
import io
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

TOOL, VERSION = "threat_analysis", "1.0.0"
ORCH = os.environ.get("FORENSIC_ORCH", "/opt/forensic-orchestrator")
CASES = os.path.join(ORCH, "storage", "cases")
OUT = os.path.join(ORCH, "storage", "analysis", "threat")

MANAGER_IP = "192.168.64.8"          # collector source address (SSH logins from it = collector)
SESSION_GAP = timedelta(hours=6)     # cases further apart start a new session (T3)
TRIGGER_WINDOW = (-15.0, 2.0)        # C1: trigger indicator within [alert-15 s, alert+2 s]
ALERT_MATCH = (0.0, 15.0)            # C2: Wazuh alert within [finding, finding+15 s]
DEDUP_S = 2.0                        # same command within 2 s in two sources = one finding

# In-scope cases: main evaluation set (stratum A, n=34) and stratum B (n=5).
# The failed stratum-B attempt CASE-20261026T201102Z-rule100210 is excluded by design.
STRATUM_A = """
CASE-20260602T220125Z-rule100210 CASE-20260609T055405Z-rule100210 CASE-20260609T182652Z-rule100210
CASE-20260611T001424Z-rule100210 CASE-20260611T002235Z-rule100210 CASE-20260611T003747Z-rule100210
CASE-20260613T055942Z-rule100210 CASE-20260614T091238Z-rule100210 CASE-20260614T092509Z-rule100210
CASE-20260620T002912Z-rule100240 CASE-20260620T015617Z-rule100240 CASE-20260623T143436Z-rule100240
CASE-20260623T144638Z-rule100240 CASE-20260815T121110Z-rule100240 CASE-20260816T142305Z-rule100240
CASE-20260825T092035Z-rule100220 CASE-20260825T094656Z-rule100220 CASE-20260825T100650Z-rule100220
CASE-20261011T071338Z-rule100220 CASE-20261011T071408Z-rule100250 CASE-20261011T071438Z-rule100260
CASE-20261011T072138Z-rule100220 CASE-20261011T072208Z-rule100250 CASE-20261011T072238Z-rule100260
CASE-20261011T074519Z-rule100220 CASE-20261011T074759Z-rule100250 CASE-20261011T074829Z-rule100260
CASE-20261011T075943Z-rule100250 CASE-20261011T080013Z-rule100260 CASE-20261011T081556Z-rule100250
CASE-20261011T102548Z-rule100250 CASE-20261011T103208Z-rule100260 CASE-20261011T103216Z-rule100250
CASE-20261011T184302Z-rule100260
""".split()
STRATUM_B = """
CASE-20261025T191709Z-rule100210 CASE-20261026T184313Z-rule100220 CASE-20261026T190602Z-rule100240
CASE-20261027T184825Z-rule100250 CASE-20261027T185428Z-rule100260
""".split()

RULE_TECH = {"100210": "T1003.008", "100220": "T1136.001", "100240": "T1070.002",
             "100250": "T1087.001", "100260": "T1059.004"}
TACTIC = {"T1003.008": "credential-access", "T1136.001": "persistence",
          "T1070.002": "defense-evasion", "T1087.001": "discovery",
          "T1059.004": "execution", "T1098": "persistence", "T1021.004": "lateral-movement",
          "T1110": "credential-access", "T1078": "initial-access",
          "T1548.003": "privilege-escalation", "T1053.003": "persistence",
          "T1098.004": "persistence"}

# ----------------------------------------------------------------- T1 rule set
# Detection-technique indicators: applied to privileged commands recorded by sudo.
SUDO_RULES = [
    ("T1003.008", "credential file read",  re.compile(r"/etc/shadow")),
    ("T1070.002", "log clearing",          re.compile(r"(truncate|shred|tee|/rm|/dd).*/var/log|journalctl.*vacuum")),
    ("T1087.001", "account enumeration",   re.compile(r"(cat|getent|less|more|head|tail).*(/etc/passwd|/etc/group)")),
    ("T1059.004", "shell with payload",    re.compile(r"(bash|sh|/bin/bash|/bin/sh)\s+-c.*(curl|wget|/dev/tcp|nc |ncat|base64)")),
    ("T1136.001", "account creation cmd",  re.compile(r"\b(useradd|adduser)\b")),
]
DETECTION_TECHS = set(RULE_TECH.values())

RE_AUTH = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z|[+-]\d{2}:\d{2}) "
                     r"(\S+) ([^:\[\s]+)(?:\[(\d+)\])?: (.*)$")
RE_JOURNAL = re.compile(r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) "
                        r"(\S+) ([^:\[\s]+)(?:\[(\d+)\])?: (.*)$")
RE_SUDO = re.compile(r"^(\S+) : (?:TTY=(\S+) ; )?(?:PWD=(\S+) ; )?USER=(\S+) ; COMMAND=(.*)$")
RE_NEWUSER = re.compile(r"new user: name=([^,\s]+)")
RE_ACCEPT = re.compile(r"Accepted (\S+) for (\S+) from (\S+)")
RE_FAIL = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
ACCOUNT_PROCS = {"usermod", "userdel", "groupadd", "groupdel", "gpasswd", "passwd", "chpasswd"}
MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}

INPUTS = {
    "auth": "evidence/logs/auth.log",
    "auth_copy": "evidence/critical_files/var_log_auth.log",
    "journal": "evidence/logs/journalctl_24h.log",
    "passwd": "evidence/critical_files/etc_passwd",
    "shadow": "evidence/critical_files/etc_shadow",
    "sudoers": "evidence/critical_files/etc_sudoers",
    "crontab": "evidence/critical_files/etc_crontab",
    "sshd": "evidence/critical_files/etc_ssh_sshd_config",
    "listening": "evidence/volatile/network_listening.txt",
    "fs": "evidence/filesystem/fs_timeline.csv",
}
WATCHED_FILES = ["passwd", "shadow", "sudoers", "crontab", "sshd"]
FILE_TECH = {"sudoers": "T1548.003", "crontab": "T1053.003", "sshd": "T1098.004"}


class IntegrityError(Exception):
    pass


# --------------------------------------------------------------------- helpers
def parse_iso(s):
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    m = re.match(r"^(.*[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)([+-]\d{2}):?(\d{2})$", s)
    if m:
        s = f"{m.group(1)}{m.group(2)}:{m.group(3)}"
    return datetime.fromisoformat(s).astimezone(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt else None


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def read_evidence(path):
    """Bytes of an artefact; warm-tier artefacts are stored as <path>.gz."""
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    if os.path.exists(path + ".gz"):
        with gzip.open(path + ".gz", "rb") as f:
            return f.read()
    return None


def gated_inputs(case_dir, manifest):
    """Integrity gate: {key: text} for inputs whose SHA-256 matches the manifest."""
    recorded = {}
    for e in manifest.get("evidence") or []:
        p = e.get("path") or ""
        rel = os.path.relpath(p, case_dir) if p.startswith(case_dir) else p
        recorded[rel] = (p, e.get("sha256"))
    out, digests, missing = {}, {}, []
    for key, rel in INPUTS.items():
        if rel not in recorded:
            missing.append(key)
            continue
        path, expected = recorded[rel]
        data = read_evidence(path)
        if data is None:
            raise IntegrityError(f"{rel}: recorded in manifest but missing on disk")
        actual = sha256_bytes(data)
        if expected and actual != expected:
            raise IntegrityError(f"{rel}: SHA-256 mismatch")
        out[key] = data.decode("utf-8", "replace")
        digests[key] = actual
    return out, digests, missing


# ---------------------------------------------------------------- log parsing
def parse_auth(text, src):
    recs = []
    for line in text.splitlines():
        m = RE_AUTH.match(line)
        if m:
            recs.append({"ts": parse_iso(m.group(1) + m.group(2)), "prec": "us", "src": src,
                         "host": m.group(3), "proc": m.group(4), "msg": m.group(6)})
    return recs


def parse_journal_naive(text, ref):
    recs = []
    for line in text.splitlines():
        m = RE_JOURNAL.match(line)
        if not m or m.group(1) not in MONTHS:
            continue
        mon = MONTHS[m.group(1)]
        year = ref.year - 1 if mon - ref.month > 6 else ref.year
        naive = datetime(year, mon, int(m.group(2)), int(m.group(3)), int(m.group(4)),
                         int(m.group(5)))
        recs.append({"naive": naive, "host": m.group(6), "proc": m.group(7), "msg": m.group(9)})
    return recs


def journal_offset(jrecs, arecs):
    """UTC offset of the zone-less journal, from sudo/sshd records present in both sources."""
    by_msg = collections.defaultdict(list)
    for a in arecs:
        if a["proc"] in ("sudo", "sshd", "useradd"):
            by_msg[(a["proc"], a["msg"].strip())].append(a["ts"].replace(tzinfo=None))
    votes = collections.Counter()
    for j in jrecs:
        cands = by_msg.get((j["proc"], j["msg"].strip()))
        if not cands:
            continue
        nearest = min(cands, key=lambda t: abs((j["naive"] - t).total_seconds()))
        delta = (j["naive"] - nearest).total_seconds()
        q = round(delta / 900.0) * 900
        if abs(q) <= 14 * 3600 and abs(delta - q) < 2:
            votes[q] += 1
    if not votes:
        return 0, "default-utc"
    off, n = votes.most_common(1)[0]
    conf = "high" if n >= 3 and n / sum(votes.values()) >= 0.8 else "low"
    return off, conf


def journal_records(jrecs, offset):
    out = []
    for j in jrecs:
        ts = (j["naive"] - timedelta(seconds=offset)).replace(tzinfo=timezone.utc)
        out.append({"ts": ts, "prec": "s", "src": "journal", "host": j["host"],
                    "proc": j["proc"], "msg": j["msg"]})
    return out


# ------------------------------------------------------------------- T1 rules
def t1_findings(recs):
    """Indicator findings from log records (auth.log, its copy, journal)."""
    found = []
    for r in recs:
        if r["proc"] == "sudo":
            m = RE_SUDO.match(r["msg"])
            if not m:
                continue
            user, tty, cwd, runas, cmd = m.groups()
            for tech, name, rx in SUDO_RULES:
                if rx.search(cmd):
                    found.append({"ts": r["ts"], "prec": r["prec"], "src": r["src"],
                                  "technique": tech, "rule": name, "kind": "detection",
                                  "user": user, "tty": tty, "cwd": cwd, "runas": runas,
                                  "command": cmd.strip()})
        elif r["proc"] == "useradd":
            m = RE_NEWUSER.search(r["msg"])
            if m:
                found.append({"ts": r["ts"], "prec": r["prec"], "src": r["src"],
                              "technique": "T1136.001", "rule": "account created",
                              "kind": "detection", "user": None, "tty": None, "cwd": None,
                              "runas": None, "command": f"useradd name={m.group(1)}",
                              "account": m.group(1)})
        elif r["proc"] in ACCOUNT_PROCS:
            found.append({"ts": r["ts"], "prec": r["prec"], "src": r["src"],
                          "technique": "T1098", "rule": "account manipulation",
                          "kind": "hunting", "user": None, "tty": None, "cwd": None,
                          "runas": None, "command": f"{r['proc']}: {r['msg'].strip()[:160]}"})
        elif r["proc"] == "sshd":
            m = RE_ACCEPT.search(r["msg"])
            if m:
                method, user, ip = m.groups()
                who = "collector" if (user == "root" and ip == MANAGER_IP) else "other"
                found.append({"ts": r["ts"], "prec": r["prec"], "src": r["src"],
                              "technique": "T1021.004" if who == "other" else "COLLECTOR",
                              "rule": f"ssh login ({who})", "kind": "hunting",
                              "user": user, "tty": None, "cwd": None, "runas": None,
                              "command": f"ssh {method} {user}@ from {ip}"})
            m = RE_FAIL.search(r["msg"])
            if m:
                found.append({"ts": r["ts"], "prec": r["prec"], "src": r["src"],
                              "technique": "T1110", "rule": "failed password",
                              "kind": "hunting", "user": m.group(1), "tty": None,
                              "cwd": None, "runas": None,
                              "command": f"failed password {m.group(1)} from {m.group(2)}"})
    return dedup(found)


def dedup(found):
    """One finding per action: same technique and command within DEDUP_S across sources;
    the most precise timestamp is kept and every source is listed."""
    found.sort(key=lambda f: (f["ts"], f["technique"], f["command"], f["src"]))
    out = []
    for f in found:
        twin = None
        for g in reversed(out[-50:]):
            if (g["technique"] == f["technique"] and g["command"] == f["command"]
                    and abs((g["ts"] - f["ts"]).total_seconds()) <= DEDUP_S):
                twin = g
                break
        if twin is None:
            f = dict(f)
            f["sources"] = [f.pop("src")]
            out.append(f)
        else:
            if f["src"] not in twin["sources"]:
                twin["sources"].append(f["src"])
            if twin["prec"] == "s" and f["prec"] == "us":
                twin["ts"], twin["prec"] = f["ts"], "us"
    return out


def merge_findings(pool):
    """Union of already de-duplicated findings from several cases (overlapping logs)."""
    pool = sorted(pool, key=lambda f: (f["ts"], f["technique"], f["command"]))
    out = []
    for f in pool:
        twin = next((g for g in reversed(out[-50:])
                     if g["technique"] == f["technique"] and g["command"] == f["command"]
                     and abs((g["ts"] - f["ts"]).total_seconds()) <= DEDUP_S), None)
        if twin is None:
            g = dict(f)
            g["sources"] = sorted(set(f["sources"]))
            out.append(g)
        else:
            twin["sources"] = sorted(set(twin["sources"]) | set(f["sources"]))
            if twin["prec"] == "s" and f["prec"] == "us":
                twin["ts"], twin["prec"] = f["ts"], "us"
    return out


# ------------------------------------------------------------- T2 state diff
def accounts(passwd_text):
    return sorted({l.split(":", 1)[0] for l in passwd_text.splitlines() if ":" in l})


def listeners(text):
    out = set()
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] != "LISTEN" or len(parts) < 4:
            continue
        proc = re.search(r'users:\(\("([^"]+)"', line)
        out.add(f"{parts[3]}|{proc.group(1) if proc else '?'}")
    return sorted(out)


def fs_rows(text):
    rows = []
    for line in text.splitlines():
        parts = line.split("|", 5)
        if len(parts) < 6:
            continue
        try:
            mt, ct = float(parts[0]), float(parts[1])
        except ValueError:
            continue
        rows.append((max(mt, ct), parts[5]))
    return rows


def state(inp):
    auth_recs = parse_auth(inp.get("auth", ""), "auth.log")
    return {
        "accounts": accounts(inp.get("passwd", "")),
        "file_sha": {k: sha256_bytes(inp[k].encode()) for k in WATCHED_FILES if k in inp},
        "listeners": listeners(inp.get("listening", "")),
        "auth_first": min((r["ts"] for r in auth_recs), default=None),
    }


def t2_diff(cur, prev, alert, prev_alert, fs_text):
    if prev is None:
        return {"reference": None}
    d = {
        "accounts_added": sorted(set(cur["accounts"]) - set(prev["accounts"])),
        "accounts_removed": sorted(set(prev["accounts"]) - set(cur["accounts"])),
        "files_changed": sorted(k for k in WATCHED_FILES
                                if k in cur["file_sha"] and k in prev["file_sha"]
                                and cur["file_sha"][k] != prev["file_sha"][k]),
        "listeners_added": sorted(set(cur["listeners"]) - set(prev["listeners"])),
        "listeners_removed": sorted(set(prev["listeners"]) - set(cur["listeners"])),
    }
    af = cur["auth_first"]
    d["auth_log_first_record"] = iso(af)
    d["auth_log_first_minus_alert_s"] = (round((af - alert).total_seconds(), 3)
                                         if af else None)
    # history present in the previous copy but absent now: the log was truncated or rotated
    d["auth_log_history_lost"] = bool(af and prev["auth_first"] and af > prev["auth_first"]
                                      and af > prev_alert)
    lo, hi = prev_alert.timestamp(), alert.timestamp()
    changed = sorted(p for t, p in fs_rows(fs_text) if lo < t <= hi)
    d["fs_changed_between_cases"] = len(changed)
    d["fs_changed_sample"] = changed[:25]
    return d


def t2_indicators(diff):
    """Map state differences to ATT&CK-relevant indicators."""
    ind = []
    for a in diff.get("accounts_added", []):
        ind.append(("T1136.001", f"local account added: {a}"))
    if diff.get("auth_log_history_lost"):
        ind.append(("T1070.002", "authentication log lost history since previous case"))
    for k in diff.get("files_changed", []):
        if k in FILE_TECH:
            ind.append((FILE_TECH[k], f"{k} changed since previous case"))
    for l in diff.get("listeners_added", []):
        ind.append(("LISTENER", f"new listening socket: {l}"))
    return ind


# ------------------------------------------------------------------- per case
def analyse_case(cid):
    case_dir = os.path.join(CASES, cid)
    mpath = os.path.join(case_dir, "case_manifest.json")
    if not os.path.exists(mpath):
        raise IntegrityError("no case_manifest.json (cold or archived case)")
    manifest = json.load(open(mpath))
    a = manifest.get("alert") or {}
    alert = parse_iso(a.get("timestamp"))
    rule = str(a.get("rule_id") or cid.rsplit("rule", 1)[-1])
    inp, digests, missing = gated_inputs(case_dir, manifest)

    arecs = parse_auth(inp.get("auth", ""), "auth.log") + \
        parse_auth(inp.get("auth_copy", ""), "var_log_auth.log")
    jnaive = parse_journal_naive(inp.get("journal", ""), alert)
    off, conf = journal_offset(jnaive, arecs)
    recs = arecs + journal_records(jnaive, off)
    findings = t1_findings(recs)

    trig_tech = RULE_TECH.get(rule)
    lo, hi = TRIGGER_WINDOW
    trig = [f for f in findings if f["technique"] == trig_tech
            and lo <= (f["ts"] - alert).total_seconds() <= hi]
    trig.sort(key=lambda f: abs((f["ts"] - alert).total_seconds()))
    return {
        "case": cid, "stratum": "B" if cid in STRATUM_B else "A", "rule": rule,
        "technique": trig_tech, "alert_time": iso(alert), "agent": a.get("agent_name"),
        "inputs_sha256": digests, "inputs_missing": missing,
        "journal_utc_offset_s": off, "journal_tz_confidence": conf,
        "trigger_found": bool(trig),
        "trigger": export_finding(trig[0], alert) if trig else None,
        "findings": [export_finding(f, alert) for f in findings],
        "_alert": alert, "_findings": findings, "_state": state(inp), "_fs": inp.get("fs", ""),
    }


def export_finding(f, alert):
    d = {k: v for k, v in f.items() if k not in ("ts",)}
    d["time"] = iso(f["ts"])
    d["minus_alert_s"] = round((f["ts"] - alert).total_seconds(), 3)
    d["tactic"] = TACTIC.get(f["technique"])
    return d


# ------------------------------------------------------------- alerts export
def load_alerts(path):
    if not path:
        return None
    data = json.load(open(path))
    hits = data.get("hits", {}).get("hits", data if isinstance(data, list) else [])
    out = []
    for h in hits:
        s = h.get("_source", h)
        ts = parse_iso(s.get("timestamp") or s.get("@timestamp"))
        rid = str((s.get("rule") or {}).get("id"))
        agent = (s.get("agent") or {}).get("name")
        if ts and rid in RULE_TECH:
            out.append({"ts": ts, "rule": rid, "agent": agent})
    out.sort(key=lambda x: x["ts"])
    return out


def match_alert(f, alerts, agent):
    rule = {v: k for k, v in RULE_TECH.items()}.get(f["technique"])
    lo, hi = ALERT_MATCH
    for al in alerts:
        d = (al["ts"] - f["ts"]).total_seconds()
        if al["rule"] == rule and al["agent"] == agent and lo <= d <= hi:
            return al
    return None


# --------------------------------------------------------------------- driver
def run(alerts_path):
    order = sorted(STRATUM_A + STRATUM_B, key=lambda c: c.split("-")[1])
    cases, skipped = [], []
    for cid in order:
        try:
            cases.append(analyse_case(cid))
        except IntegrityError as e:
            skipped.append({"case": cid, "reason": str(e)})
    cases.sort(key=lambda c: c["_alert"])

    prev = None
    for c in cases:
        diff = t2_diff(c["_state"], prev["_state"] if prev else None, c["_alert"],
                       prev["_alert"] if prev else None, c["_fs"])
        diff["reference_case"] = prev["case"] if prev else None
        c["state_diff"] = diff
        c["state_indicators"] = [{"technique": t, "indicator": s} for t, s in t2_indicators(diff)]
        prev = c

    # T3: sessions
    sessions, cur = [], []
    for c in cases:
        if cur and c["_alert"] - cur[-1]["_alert"] > SESSION_GAP:
            sessions.append(cur)
            cur = []
        cur.append(c)
    if cur:
        sessions.append(cur)
    sess_out, all_findings = [], []
    for i, s in enumerate(sessions, 1):
        start, end = s[0]["_alert"], s[-1]["_alert"]
        pool = []
        for c in s:
            pool += [f for f in c["_findings"]
                     if start - SESSION_GAP <= f["ts"] <= end + timedelta(seconds=60)]
        merged = merge_findings(pool)
        det = [f for f in merged if f["technique"] in DETECTION_TECHS]
        seq = []
        for f in det:
            t = TACTIC[f["technique"]]
            if not seq or seq[-1] != t:
                seq.append(t)
        sess_out.append({
            "session": i, "start": iso(start), "end": iso(end),
            "cases": [c["case"] for c in s],
            "tactic_sequence": seq,
            "detection_findings": [export_finding(f, start) for f in det],
            "hunting_findings": [export_finding(f, start) for f in merged
                                 if f["technique"] not in DETECTION_TECHS],
            "state_indicators": [dict(case=c["case"], **x) for c in s
                                 for x in c["state_indicators"]],
        })
        all_findings += [(f, s[0]["agent"]) for f in det]

    alerts = load_alerts(alerts_path)
    agreement = None
    if alerts is not None:
        rows = []
        for f, agent in all_findings:
            al = match_alert(f, alerts, agent)
            rows.append({"time": iso(f["ts"]), "technique": f["technique"],
                         "command": f["command"], "sources": f["sources"],
                         "wazuh_alert": iso(al["ts"]) if al else None})
        agreement = {"findings": len(rows),
                     "with_alert": sum(1 for r in rows if r["wazuh_alert"]),
                     "without_alert": [r for r in rows if not r["wazuh_alert"]]}

    # criteria
    c1 = [{"case": c["case"], "technique": c["technique"], "found": c["trigger_found"],
           "minus_alert_s": c["trigger"]["minus_alert_s"] if c["trigger"] else None,
           "sources": c["trigger"]["sources"] if c["trigger"] else None} for c in cases]
    c3 = []
    for c in cases:
        if c["rule"] != "100220":
            continue
        names = {f.get("account") for f in c["_findings"] if f.get("account")
                 and TRIGGER_WINDOW[0] <= (f["ts"] - c["_alert"]).total_seconds() <= TRIGGER_WINDOW[1]}
        added = set(c["state_diff"].get("accounts_added") or [])
        c3.append({"case": c["case"], "useradd_names": sorted(names),
                   "accounts_added": sorted(added),
                   "pass": bool(names) and names <= added})
    c4 = []
    for c in cases:
        if c["rule"] != "100240":
            continue
        cmd = c["trigger"]["command"] if c["trigger"] else ""
        truncates_auth = bool(re.search(r"truncate.*/var/log/auth\.log", cmd))
        d = c["state_diff"]
        c4.append({"case": c["case"], "command": cmd, "truncates_auth_log": truncates_auth,
                   "auth_log_first_minus_alert_s": d.get("auth_log_first_minus_alert_s"),
                   "pass": (None if not truncates_auth else
                            d.get("auth_log_first_minus_alert_s") is not None
                            and d["auth_log_first_minus_alert_s"] >= -2.0)})
    c5 = [{"case": c["case"], "rule": c["rule"],
           "accounts_added": c["state_diff"].get("accounts_added"),
           "auth_log_history_lost": c["state_diff"].get("auth_log_history_lost")}
          for c in cases if c["rule"] in ("100210", "100250", "100260")
          and (c["state_diff"].get("accounts_added") or c["state_diff"].get("auth_log_history_lost"))]

    summary = {
        "tool": TOOL, "version": VERSION,
        "cases_in_scope": len(STRATUM_A) + len(STRATUM_B), "cases_processed": len(cases),
        "cases_skipped": skipped,
        "C1_trigger_recall": {"found": sum(r["found"] for r in c1), "of": len(c1),
                              "missed": [r for r in c1 if not r["found"]]},
        "C2_alert_agreement": agreement,
        "C3_persistence_state": {"pass": sum(r["pass"] for r in c3), "of": len(c3), "rows": c3},
        "C4_log_clearing_state": {"pass": sum(1 for r in c4 if r["pass"]),
                                  "of_truncating": sum(1 for r in c4 if r["truncates_auth_log"]),
                                  "rows": c4},
        "C5_other_cases_with_state_indicators": c5,
        "sessions": [{"session": s["session"], "start": s["start"], "end": s["end"],
                      "n_cases": len(s["cases"]), "tactic_sequence": s["tactic_sequence"]}
                     for s in sess_out],
    }
    per_case = []
    for c in cases:
        per_case.append({k: v for k, v in c.items() if not k.startswith("_")})
    return summary, per_case, sess_out


def render(summary, per_case, sessions):
    files = {
        "summary.json": json.dumps(summary, indent=2, sort_keys=True, default=str),
        "cases.json": json.dumps(per_case, indent=2, sort_keys=True, default=str),
        "sessions.json": json.dumps(sessions, indent=2, sort_keys=True, default=str),
    }
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["case", "rule", "technique", "trigger_found", "trigger_minus_alert_s",
                "trigger_sources", "n_detection_findings", "n_hunting_findings",
                "accounts_added", "files_changed", "listeners_added", "auth_history_lost",
                "fs_changed_between_cases", "journal_tz"])
    for c in per_case:
        d = c["state_diff"]
        w.writerow([c["case"], c["rule"], c["technique"], c["trigger_found"],
                    c["trigger"]["minus_alert_s"] if c["trigger"] else "",
                    "+".join(c["trigger"]["sources"]) if c["trigger"] else "",
                    sum(1 for f in c["findings"] if f["kind"] == "detection"),
                    sum(1 for f in c["findings"] if f["kind"] == "hunting"),
                    ";".join(d.get("accounts_added") or []),
                    ";".join(d.get("files_changed") or []),
                    ";".join(d.get("listeners_added") or []),
                    d.get("auth_log_history_lost", ""),
                    d.get("fs_changed_between_cases", ""),
                    f'{c["journal_utc_offset_s"]}/{c["journal_tz_confidence"]}'])
    files["cases.csv"] = buf.getvalue()
    files["MANIFEST.sha256"] = "".join(f"{sha256_bytes(v.encode())}  {k}\n"
                                       for k, v in sorted(files.items()))
    return files


def main():
    ap = argparse.ArgumentParser(description="Post-collection threat analysis of sealed cases")
    ap.add_argument("--alerts", help="JSON export of Wazuh alerts (rules 100210-100260)")
    ap.add_argument("--verify", action="store_true", help="run twice, confirm identical output")
    ap.add_argument("--out", default=OUT)
    args = ap.parse_args()

    files = render(*run(args.alerts))
    if args.verify:
        again = render(*run(args.alerts))
        print("determinism:", "identical" if again == files else "DIFFERS")
    os.makedirs(args.out, exist_ok=True)
    for name, text in files.items():
        with open(os.path.join(args.out, name), "w") as f:
            f.write(text)
    s = json.loads(files["summary.json"])
    print(f"processed {s['cases_processed']} of {s['cases_in_scope']} cases; "
          f"skipped {len(s['cases_skipped'])}")
    for k in ("C1_trigger_recall", "C3_persistence_state", "C4_log_clearing_state"):
        v = s[k]
        print(f"{k}: {v.get('found', v.get('pass'))} / {v.get('of', v.get('of_truncating'))}")
    if s["C2_alert_agreement"]:
        a = s["C2_alert_agreement"]
        print(f"C2_alert_agreement: {a['with_alert']} / {a['findings']} findings have a Wazuh alert")
    print(f"C5 other-technique cases with state indicators: {len(s['C5_other_cases_with_state_indicators'])}")
    for x in s["sessions"]:
        print(f"session {x['session']}: {x['start'][:16]} .. {x['end'][:16]}  "
              f"{x['n_cases']} case(s)  {' -> '.join(x['tactic_sequence'])}")
    print(f"outputs: {args.out}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
