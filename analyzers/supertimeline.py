
"""
supertimeline.py — unified forensic super-timeline for a sealed case.

Merges every time-bearing source already acquired for a case into a single,
normalised UTC chronology:

    evidence/filesystem/fs_timeline.csv     file mtime / ctime events
    evidence/logs/auth.log                  authentication + privileged exec
    evidence/critical_files/var_log_auth.log  (union with auth.log, de-duplicated)
    evidence/logs/journalctl_24h.log        system journal
    case_manifest.json                      Wazuh detection + per-artefact acquisition
    chain_of_custody.json                   custody seal

Forensic properties
  * Integrity gate: every input artefact is re-hashed (SHA-256) and compared with
    the digest recorded in the case manifest BEFORE it is read. Any mismatch aborts.
  * Evidence is never modified: outputs are written OUTSIDE the sealed case, to
    storage/analysis/<case_id>/timeline/, with their own analysis manifest.
    The global custody ledger is not touched.
  * Journal time zone is DERIVED from evidence (records present in both the
    RFC 3339 auth log and the zone-less journal), not assumed and not queried
    from the live host.
  * Deterministic: stable ordering, no wall-clock data in the CSV outputs, so a
    re-run yields byte-identical files (verify with --verify).

Usage (run on the analysis node, from the orchestrator root):
    sudo python3 analyzers/supertimeline.py CASE-20261011T071338Z-rule100220
    sudo python3 analyzers/supertimeline.py --all
    sudo python3 analyzers/supertimeline.py --all --verify

Wazuh-Based Automated Forensic Framework — Politecnico di Torino, MSc Cybersecurity 2026
"""

import argparse
import csv
import glob
import hashlib
import io
import json
import os
import re
import statistics
import sys
from datetime import datetime, timedelta, timezone

TOOL = "supertimeline"
VERSION = "1.1.0"

ORCH = os.environ.get("FORENSIC_ORCH", "/opt/forensic-orchestrator")
CASES = os.path.join(ORCH, "storage", "cases")
ANALYSIS = os.path.join(ORCH, "storage", "analysis")

WINDOW_S = 900           # incident window: +/- 15 min around the detection
FOCUS_BEFORE_S = 120     # focus view: from 2 min before the trigger/alert ...
FOCUS_AFTER_S = 10       # ... to 10 s after the custody seal
TRIGGER_LOOKBACK_S = 10  # trigger command must precede the alert by <= 10 s
CORROB_TOL_S = 1.0       # auth/journal records within 1 s are the same event
MAX_TZ_S = 14 * 3600     # real-world UTC offsets lie within +/- 14 h

MONTHS = {m: i for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}

RE_AUTH = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z|[+-]\d{2}:\d{2}) "
    r"(\S+) ([^:\[\s]+)(?:\[(\d+)\])?: (.*)$")
RE_JOURNAL = re.compile(
    r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) "
    r"(\S+) ([^:\[\s]+)(?:\[(\d+)\])?: (.*)$")
RE_SUDO = re.compile(r"^(\S+) : .*?USER=(\S+) ; COMMAND=(.*)$")


# --------------------------------------------------------------------- helpers
class IntegrityError(Exception):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def parse_iso(s):
    """Parse the ISO-8601 variants used in manifests and alerts into aware UTC."""
    if s is None:
        return None
    s = s.strip().replace("Z", "+00:00")
    m = re.match(r"^(.*[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)([+-]\d{2}):?(\d{2})$", s)
    if m:
        s = f"{m.group(1)}{m.group(2)}:{m.group(3)}"
    return datetime.fromisoformat(s).astimezone(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def norm_msg(proc, msg):
    return f"{proc}|{msg.strip()}"


# ------------------------------------------------------------ integrity gate
def verified_inputs(case_dir, manifest):
    """Return {relative_path: abs_path} for inputs whose SHA-256 matches the manifest."""
    wanted = {
        "evidence/filesystem/fs_timeline.csv",
        "evidence/logs/auth.log",
        "evidence/critical_files/var_log_auth.log",
        "evidence/logs/journalctl_24h.log",
    }
    recorded = {}
    for e in manifest.get("evidence") or []:
        p = e.get("path") or ""
        rel = os.path.relpath(p, case_dir) if p.startswith(case_dir) else p
        if rel in wanted:
            recorded[rel] = (p, e.get("sha256"))
    out, digests = {}, {}
    for rel in sorted(wanted):
        if rel not in recorded:
            continue  # artefact not acquired for this case
        path, expected = recorded[rel]
        if not os.path.exists(path):
            raise IntegrityError(f"{rel}: recorded in manifest but missing on disk")
        actual = sha256_file(path)
        if expected and actual != expected:
            raise IntegrityError(f"{rel}: SHA-256 mismatch (manifest {expected[:12]}..., "
                                 f"on disk {actual[:12]}...)")
        out[rel] = path
        digests[rel] = actual
    return out, digests


# ------------------------------------------------------------------- parsers
def ev(ts, precision, source, etype, subject, detail):
    return {"ts": ts, "precision": precision, "source": source, "event_type": etype,
            "subject": subject, "detail": detail, "corroboration": ""}


def parse_fs(path):
    events, skipped = [], 0
    with open(path, errors="replace") as f:
        next(f, None)  # header (comma-separated; data rows are pipe-separated)
        for line in f:
            parts = line.rstrip("\n").split("|", 5)
            if len(parts) < 6:
                skipped += 1
                continue
            mtime, ctime, size, perms, owner, fpath = parts
            try:
                mt, ct = float(mtime), float(ctime)
            except ValueError:
                skipped += 1
                continue
            md = datetime.fromtimestamp(mt, tz=timezone.utc)
            cd = datetime.fromtimestamp(ct, tz=timezone.utc)
            meta = f"{fpath} (owner={owner}, mode={perms}, size={size})"
            if abs(mt - ct) < 1e-6:
                events.append(ev(md, "us", "fs_timeline", "FILE_MC", owner, meta))
            else:
                events.append(ev(md, "us", "fs_timeline", "FILE_MODIFIED", owner, meta))
                events.append(ev(cd, "us", "fs_timeline", "FILE_META_CHANGED", owner, meta))
    return events, skipped


def classify_auth(proc, msg):
    if proc == "sudo":
        m = RE_SUDO.match(msg)
        if m:
            return "PRIV_EXEC", f"{m.group(1)}->{m.group(2)}", m.group(3)
    if proc in ("useradd", "usermod", "userdel", "groupadd", "passwd", "chpasswd"):
        return "ACCOUNT_CHANGE", proc, msg
    if proc == "sshd":
        return "SSH", proc, msg
    if proc == "CRON":
        return "CRON", proc, msg
    return "AUTH", proc, msg


def parse_auth(paths):
    """Union of auth.log and var_log_auth.log, exact duplicates removed."""
    seen, events, skipped = set(), [], 0
    for path in paths:
        with open(path, errors="replace") as f:
            for line in f:
                m = RE_AUTH.match(line.rstrip("\n"))
                if not m:
                    skipped += 1 if line.strip() else 0
                    continue
                ts = parse_iso(m.group(1) + m.group(2))
                host, proc, msg = m.group(3), m.group(4), m.group(6)
                key = (ts, proc, msg)
                if key in seen:
                    continue
                seen.add(key)
                etype, subject, detail = classify_auth(proc, msg)
                e = ev(ts, "us", "auth.log", etype, subject, f"[{host}] {detail}")
                e["_norm"] = norm_msg(proc, msg)
                events.append(e)
    return events, skipped


def parse_journal_naive(path, ref_year, ref_month):
    """Return journal records with NAIVE timestamps (zone resolved later)."""
    recs, skipped = [], 0
    with open(path, errors="replace") as f:
        for line in f:
            m = RE_JOURNAL.match(line.rstrip("\n"))
            if not m:
                skipped += 1 if line.strip() and not line.startswith("--") else 0
                continue
            mon = MONTHS.get(m.group(1))
            if not mon:
                skipped += 1
                continue
            year = ref_year - 1 if mon - ref_month > 6 else ref_year  # Dec log in a Jan case
            naive = datetime(year, mon, int(m.group(2)), int(m.group(3)),
                             int(m.group(4)), int(m.group(5)))
            recs.append((naive, m.group(6), m.group(7), m.group(9)))
    return recs, skipped


def derive_journal_offset(journal_naive, auth_events):
    """Derive the journal's UTC offset from records present in both sources.

    For each journal record the NEAREST auth-log twin is used (repetitive messages
    such as periodic CRON sessions would otherwise create spurious pairings), the
    delta is rounded to the 15-minute grid on which real time zones lie, and only
    offsets within +/- 14 h are admitted. The modal offset is adopted only if it is
    supported by at least 3 matches and >= 80 % agreement; otherwise UTC is assumed
    and the result is flagged as low-confidence.
    """
    by_norm = {}
    for e in auth_events:
        by_norm.setdefault(e["_norm"], []).append(e["ts"].replace(tzinfo=None))
    offsets = []
    for naive, _host, proc, msg in journal_naive:
        twins = by_norm.get(norm_msg(proc, msg))
        if not twins:
            continue
        delta = min(((naive - t).total_seconds() for t in twins), key=abs)
        off = int(round(delta / 900.0) * 900)
        if abs(off) <= MAX_TZ_S:
            offsets.append(off)
    if not offsets:
        return 0, "assumed UTC (no cross-source match)", "low"
    best = statistics.mode(offsets)
    agree = offsets.count(best)
    basis = f"derived from {agree}/{len(offsets)} nearest-twin auth/journal matches"
    if agree >= 3 and agree / len(offsets) >= 0.8:
        return best, basis, "high"
    return 0, basis + "; insufficient agreement, UTC assumed", "low"


def journal_events(journal_naive, offset_s, auth_events):
    """Convert to UTC; journal duplicates of auth records become corroboration."""
    idx = {}
    for e in auth_events:
        idx.setdefault(e["_norm"], []).append(e)
    out = []
    for naive, host, proc, msg in journal_naive:
        ts = (naive - timedelta(seconds=offset_s)).replace(tzinfo=timezone.utc)
        twin = None
        for a in idx.get(norm_msg(proc, msg), []):
            # journal has 1 s resolution; auth has microseconds
            if 0 <= (a["ts"] - ts).total_seconds() < CORROB_TOL_S + 1e-6:
                twin = a
                break
        if twin is not None:
            twin["corroboration"] = "journal"
            continue
        # Not present in the auth log: classify it on its own. This recovers, for
        # example, a privileged log-clearing command whose auth.log record was
        # destroyed by that very command but survives in the journal.
        etype, subject, detail = classify_auth(proc, msg)
        if etype == "AUTH":
            etype, subject, detail = "SYSLOG", proc, msg
        out.append(ev(ts, "s", "journal", etype, subject, f"[{host}] {detail}"))
    return out


def case_events(manifest, custody):
    out = []
    a = manifest.get("alert") or {}
    t_alert = parse_iso(a.get("timestamp"))
    if t_alert:
        mitre = ",".join(a.get("mitre_ids") or [])
        out.append(ev(t_alert, "ms", "wazuh_alert", "DETECTION", f"rule {a.get('rule_id')}",
                      f"{a.get('description')} [{mitre}] agent={a.get('agent_name')}"))
    for e in manifest.get("evidence") or []:
        t = parse_iso(e.get("collected_at"))
        if t:
            out.append(ev(t, "s", "acquisition", "ACQUIRED", e.get("type") or "",
                          f"{os.path.basename(e.get('path') or '')} via {e.get('source')} "
                          f"sha256={str(e.get('sha256'))[:16]}"))
    tl = (custody or {}).get("timeline") or {}
    t_seal = parse_iso(tl.get("collection_time")) if isinstance(tl, dict) else None
    if t_seal:
        out.append(ev(t_seal, "s", "custody", "SEALED", "chain_of_custody",
                      "evidence sealed into custody record"))
    return out, t_alert, t_seal


# ---------------------------------------------------------------- the analysis
def build(case_id):
    case_dir = os.path.join(CASES, case_id)
    mpath = os.path.join(case_dir, "case_manifest.json")
    if not os.path.exists(mpath):
        raise IntegrityError("no case_manifest.json (cold/archived case: restore first)")
    manifest = json.load(open(mpath))
    cpath = os.path.join(case_dir, "chain_of_custody.json")
    custody = json.load(open(cpath)) if os.path.exists(cpath) else {}

    inputs, digests = verified_inputs(case_dir, manifest)       # integrity gate
    unparsed = {}

    events = []
    if "evidence/filesystem/fs_timeline.csv" in inputs:
        e, unparsed["fs_timeline.csv"] = parse_fs(inputs["evidence/filesystem/fs_timeline.csv"])
        events += e

    auth_paths = [inputs[k] for k in ("evidence/logs/auth.log",
                                      "evidence/critical_files/var_log_auth.log") if k in inputs]
    auth, unparsed["auth"] = parse_auth(auth_paths)

    c_events, t_alert, t_seal = case_events(manifest, custody)
    ref = t_alert or datetime.now(timezone.utc)

    tz_basis, offset, tz_conf = "no journal", 0, "n/a"
    jev = []
    if "evidence/logs/journalctl_24h.log" in inputs:
        jn, unparsed["journal"] = parse_journal_naive(
            inputs["evidence/logs/journalctl_24h.log"], ref.year, ref.month)
        offset, tz_basis, tz_conf = derive_journal_offset(jn, auth)
        jev = journal_events(jn, offset, auth)

    events += auth + jev + c_events
    for e in events:
        e.pop("_norm", None)

    # trigger = last privileged command shortly before the detection
    trigger = None
    if t_alert:
        cands = [e for e in events if e["event_type"] == "PRIV_EXEC"
                 and 0 <= (t_alert - e["ts"]).total_seconds() <= TRIGGER_LOOKBACK_S]
        if cands:
            trigger = max(cands, key=lambda e: e["ts"])
            trigger["event_type"] = "PRIV_EXEC_TRIGGER"

    events.sort(key=lambda e: (e["ts"], e["source"], e["event_type"], e["detail"]))

    acq = [e["ts"] for e in events if e["event_type"] == "ACQUIRED"]
    summary = {
        "case_id": case_id,
        "rule_id": (manifest.get("alert") or {}).get("rule_id"),
        "t_trigger_command": iso(trigger["ts"]) if trigger else None,
        "trigger_command": trigger["detail"] if trigger else None,
        "trigger_source": trigger["source"] if trigger else None,
        # journal timestamps are truncated to the second: the latency derived from
        # them is an upper bound, the true value lying within the preceding second
        "detection_latency_resolution": ({"us": "microsecond", "s": "upper bound, 1 s"}
                                         [trigger["precision"]] if trigger else None),
        "t_detection": iso(t_alert) if t_alert else None,
        "t_first_acquisition": iso(min(acq)) if acq else None,
        "t_last_acquisition": iso(max(acq)) if acq else None,
        "t_sealed": iso(t_seal) if t_seal else None,
        "detection_latency_s": round((t_alert - trigger["ts"]).total_seconds(), 3)
        if (trigger and t_alert) else None,
        "time_to_evidence_s": round((t_seal - t_alert).total_seconds(), 3)
        if (t_alert and t_seal) else None,
        "journal_utc_offset_s": offset,
        "journal_tz_basis": tz_basis,
        "journal_tz_confidence": tz_conf,
        "events_total": len(events),
        "note": "detection_latency spans two hosts (agent clock vs manager clock) "
                "and is subject to their clock offset",
    }
    return events, summary, digests, unparsed, t_alert


def to_csv(events):
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["timestamp_utc", "precision", "source", "event_type",
                "subject", "detail", "corroborated_by"])
    for e in events:
        w.writerow([iso(e["ts"]), e["precision"], e["source"], e["event_type"],
                    e["subject"], e["detail"], e["corroboration"]])
    return buf.getvalue().encode()


def run_case(case_id, write=True):
    events, summary, digests, unparsed, t_alert = build(case_id)
    window = [e for e in events if t_alert and
              abs((e["ts"] - t_alert).total_seconds()) <= WINDOW_S]
    summary["events_in_window"] = len(window)
    summary["fs_changes_in_window"] = sum(1 for e in window if e["source"] == "fs_timeline")

    # compact focus view: the incident itself, from shortly before the trigger to the seal
    focus = []
    if t_alert:
        start_ref = parse_iso(summary["t_trigger_command"]) or t_alert
        end_ref = parse_iso(summary["t_sealed"]) or t_alert
        lo = start_ref - timedelta(seconds=FOCUS_BEFORE_S)
        hi = end_ref + timedelta(seconds=FOCUS_AFTER_S)
        focus = [e for e in events if lo <= e["ts"] <= hi]
    summary["events_in_focus"] = len(focus)

    full_b, win_b, foc_b = to_csv(events), to_csv(window), to_csv(focus)
    sum_b = (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode()
    outputs = {"supertimeline.csv": full_b, "incident_window.csv": win_b,
               "incident_focus.csv": foc_b, "incident_summary.json": sum_b}

    if write:
        out_dir = os.path.join(ANALYSIS, case_id, "timeline")
        os.makedirs(out_dir, exist_ok=True)
        for name, data in outputs.items():
            with open(os.path.join(out_dir, name), "wb") as f:
                f.write(data)
        amanifest = {
            "tool": TOOL, "version": VERSION, "case_id": case_id,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "inputs_sha256_verified_against_manifest": digests,
            "outputs_sha256": {n: sha256_bytes(d) for n, d in outputs.items()},
            "unparsed_lines": unparsed,
            "window_seconds": WINDOW_S,
        }
        with open(os.path.join(out_dir, "analysis_manifest.json"), "w") as f:
            json.dump(amanifest, f, indent=2, sort_keys=True)
    return summary, {n: sha256_bytes(d) for n, d in outputs.items()}


# ------------------------------------------------------------------ case set
def in_scope_cases():
    """Same frozen set as the dashboard: FORENSIC_RULES minus DEDUP_TEST_CASES."""
    src = open(os.path.join(ORCH, "dashboard_exporter.py")).read()

    def grab(name):
        m = re.search(name + r"\s*=\s*\{(.*?)\}", src, re.S)
        return set(re.findall(r"[\"']([^\"']+)[\"']", m.group(1))) if m else set()
    rules, excluded = grab("FORENSIC_RULES"), grab("DEDUP_TEST_CASES")
    out = []
    for d in sorted(glob.glob(os.path.join(CASES, "CASE-*"))):
        cid = os.path.basename(d)
        if cid.split("rule")[-1] in rules and cid not in excluded:
            out.append(cid)
    return out


def main():
    ap = argparse.ArgumentParser(description="Forensic super-timeline for sealed cases")
    ap.add_argument("case", nargs="?", help="case id, e.g. CASE-20261011T071338Z-rule100220")
    ap.add_argument("--all", action="store_true", help="process the frozen in-scope case set")
    ap.add_argument("--verify", action="store_true",
                    help="re-run in memory and confirm outputs are byte-identical")
    args = ap.parse_args()

    cases = in_scope_cases() if args.all else ([args.case] if args.case else [])
    if not cases:
        ap.error("give a case id or --all")

    rows, lat, lat_us, skipped = [], [], [], []
    for cid in cases:
        try:
            s, h1 = run_case(cid, write=True)
            det = "n/a"
            if args.verify:
                _, h2 = run_case(cid, write=False)
                det = "identical" if h1 == h2 else "DIFFERS"
            rows.append((cid, s, det))
            if s["detection_latency_s"] is not None:
                lat.append(s["detection_latency_s"])
                if s["trigger_source"] == "auth.log":
                    lat_us.append(s["detection_latency_s"])
        except IntegrityError as e:
            skipped.append((cid, str(e)))

    if len(cases) == 1 and rows:
        cid, s, det = rows[0]
        print(json.dumps(s, indent=2, sort_keys=True))
        print(f"\noutputs: {os.path.join(ANALYSIS, cid, 'timeline')}/  determinism: {det}")
    else:
        print(f"{'case':38} {'rule':7} {'cmd->alert':>10} {'src':>8} {'alert->seal':>11} "
              f"{'events':>7} {'focus':>6}  tz offset / conf / determinism")
        for cid, s, det in rows:
            dl = s["detection_latency_s"]
            src = {"auth.log": "auth", "journal": "journal"}.get(s["trigger_source"], "-")
            print(f"{cid:38} {str(s['rule_id']):7} "
                  f"{(f'{dl:.3f}' if dl is not None else '-'):>10} {src:>8} "
                  f"{str(s['time_to_evidence_s']):>11} {s['events_total']:>7} "
                  f"{s['events_in_focus']:>6}  {s['journal_utc_offset_s']}s / "
                  f"{s['journal_tz_confidence']} / {det}")
        print(f"\nprocessed {len(rows)} case(s), skipped {len(skipped)}")
        for cid, why in skipped:
            print(f"   SKIPPED {cid}: {why}")

        def stats(xs):
            return (f"mean {statistics.mean(xs):.3f} s, median {statistics.median(xs):.3f} s, "
                    f"min {min(xs):.3f} s, max {max(xs):.3f} s")
        if lat:
            print(f"detection latency, all {len(lat)} cases with a recovered trigger: {stats(lat)}")
        if lat_us:
            print(f"detection latency, {len(lat_us)} cases with microsecond (auth.log) "
                  f"trigger: {stats(lat_us)}")
        n_journal = sum(1 for _, s, _ in rows if s["trigger_source"] == "journal")
        if n_journal:
            print(f"{n_journal} trigger(s) recovered from the journal only "
                  f"(auth.log record absent), latency is a 1 s upper bound")
    return 1 if any(d == "DIFFERS" for _, _, d in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
