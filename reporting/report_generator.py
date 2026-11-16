#!/usr/bin/env python3
"""
report_generator.py — Automated forensic PDF report generator.

Reads a completed case folder produced by the Forensic Orchestrator and renders
a corporate-style DFIR PDF report (via wkhtmltopdf + Jinja2).

Usage:
    python3 report_generator.py /opt/forensic-orchestrator/storage/cases/CASE-...
    python3 report_generator.py            # auto-selects the most recent case

Design notes:
  * Reads the REAL fields written by the orchestrator (case_manifest.json,
    chain_of_custody.json). MITRE fields are often null (e.g. rootcheck rules) —
    the report degrades gracefully and never fabricates data.
  * MTTE (automated) is computed from the case's own timestamps: alert time ->
    seal_requested_at (millisecond resolution, corrected configuration) or, for
    cases that predate that field, collection_time (one-second resolution).
  * The comparison uses the manual baseline of the case's own stratum
    (A: 433 s, B: 458 s; Keystroke-Level Model, thesis Section 6.1.3).
  * The memory section is derived from the memory method and content check
    recorded in the manifest (segment-aware LiME image vs legacy read).
  * Context charts are computed from the sealed cases on this deployment
    (same stratum, validation cases excluded); no synthetic data is shown.
  * If the read-only threat analysis has been run (storage/analysis/threat),
    its attribution of the triggering command is included for the case.

v2.0 (2026-10-30): stratum-aware baselines and memory section, ms-resolution
MTTE, real context charts, threat-analysis section.
"""

import os, sys, json, html, subprocess, datetime, re, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = "report_template.html"


def _ledger_position(case_current_hash):
    """Return (position, total) of this case in the append-only ledger, or (None, None).
    Read-only, best-effort; never raises."""
    if not case_current_hash:
        return None, None
    ledger = os.path.join(os.path.dirname(HERE), "chain_of_custody", "custody_log.json")
    if not os.path.exists(ledger):
        return None, None
    try:
        total = 0
        position = None
        with open(ledger, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if (rec.get("chain") or {}).get("current_hash") == case_current_hash:
                    position = total
        return position, total
    except Exception:
        return None, None


def _verify_custody_ledger():
    """Run verify_chain.py and return (verified: bool|None, ledger_count: int|None).
    Recomputes the whole hash-chained ledger; None if the verifier could not run."""
    root = os.path.dirname(HERE)
    script = os.path.join(root, "chain_of_custody", "verify_chain.py")
    if not os.path.exists(script):
        return None, None
    try:
        env = dict(os.environ)
        env["PYTHONPATH"] = root + os.pathsep + env.get("PYTHONPATH", "")
        r = subprocess.run([sys.executable, script], cwd=root, env=env,
                           capture_output=True, text=True, timeout=120)
        count = None
        for tok in (r.stdout or "").replace(":", " ").split():
            if tok.isdigit():
                count = int(tok)
                break
        return (r.returncode == 0), count
    except Exception:
        return None, None

# ---- manual baselines per stratum (Keystroke-Level Model, thesis Section 6.1.3) ----
# T = 16 M + 1016 K + T_sys, M = 1.35 s, K in [0.28, 0.50] s (central 0.40 s).
# A: T_sys = 5.0 s (same artefact set, legacy memory step).
# B: T_sys replaced by the measured complete-RAM acquisition, 30.1 s.
BASELINES = {
    "A": {"low": 311, "point": 433, "high": 535,
          "system": "measured system time of the same commands (5.0 s), legacy memory step"},
    "B": {"low": 336, "point": 458, "high": 560,
          "system": "measured complete-RAM acquisition (30.1 s) in place of the legacy memory step"},
}
STRATUM_B_CASES = {   # the closed, reported stratum B; later cases of the same profile are "live"
    "CASE-20261025T191709Z-rule100210", "CASE-20261026T184313Z-rule100220",
    "CASE-20261026T190602Z-rule100240", "CASE-20261027T184825Z-rule100250",
    "CASE-20261027T185428Z-rule100260",
}
BASELINES["live"] = BASELINES["B"]


def case_stratum(case_id, manifest):
    st = str((manifest.get("collection_profile") or {}).get("stratum") or "A")
    return st if (st == "A" or case_id in STRATUM_B_CASES) else "live"


COLLECTOR_ROOT_SINCE = datetime.datetime(2026, 6, 20, 1, 56, 0)   # collector logs in as root from here on
EXCLUDED_CASES = {   # validation, stray and failed cases: never used as context (same list as dashboard_exporter)
    "CASE-20261011T072106Z-rule100220", "CASE-20261011T072130Z-rule100250",
    "CASE-20261011T072132Z-rule100260", "CASE-20260830T131959Z-rule100240",
    "CASE-20260602T220336Z-rule100220", "CASE-20260816T203733Z-rule100240",
    "CASE-20260816T205030Z-rule100240", "CASE-20260816T205049Z-rule100210",
    "CASE-20261026T201102Z-rule100210",
}
FORENSIC_RULES = {"100210", "100220", "100240", "100250", "100260"}
TACTIC_ORDER = ["Credential Access", "Persistence", "Defense Evasion", "Discovery", "Execution"]

FRAMEWORK = {
    "name": "WAZUH-FORENSIC ORCHESTRATOR",
    "long": "Automated Forensic Evidence Collection Triggered by Intrusion Detection",
    "org": "Politecnico di Torino — MSc Cybersecurity",
    "version": "2.0",
}

TYPE_LABEL = {
    "volatile_state": "Volatile", "logs": "Logs", "critical_file": "Sensitive",
    "filesystem_timeline": "Timeline", "memory_image": "Memory",
    "memory_dump": "Memory", "memory": "Memory", "tsk_timeline": "Timeline",
}


# ----------------------------- helpers --------------------------------------
def die(msg):
    print(f"[report] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def find_latest_case():
    base = "/opt/forensic-orchestrator/storage/cases"
    if not os.path.isdir(base):
        return None
    cases = [os.path.join(base, d) for d in os.listdir(base) if d.startswith("CASE-")]
    cases = [c for c in cases if os.path.isdir(c)]
    return max(cases, key=os.path.getmtime) if cases else None


def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        die(f"cannot read {path}: {e}")


def human_size(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def parse_ts(ts):
    """Parse the orchestrator's timestamp formats into a datetime (UTC)."""
    if not ts:
        return None
    ts = ts.strip()
    fmts = ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S")
    for fmt in fmts:
        try:
            dt = datetime.datetime.strptime(ts, fmt)
            if dt.tzinfo:
                dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
            return dt
        except ValueError:
            continue
    # last resort: strip fractional/zone manually
    m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", ts)
    if m:
        return datetime.datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S")
    return None


def fmt_duration(seconds):
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds:.1f} s"
    m, s = divmod(int(round(seconds)), 60)
    return f"{m} min {s:02d} s"


def log_width(seconds, max_seconds):
    """Log-scaled bar width (%) for the MTTE comparison chart."""
    import math
    if seconds <= 0:
        return 2
    return max(3, int(round(math.log10(seconds + 1) / math.log10(max_seconds + 1) * 100)))


def memory_section(manifest):
    """Describe the memory artefact from what the manifest records. Returns
    (type_label, summary_phrase, findings, note, recommendation)."""
    mem = next((e for e in manifest.get("evidence", []) if e.get("type") == "memory"), None)
    if not mem:
        return ("Memory", "no memory artefact", ["No memory artefact is recorded for this case."], None,
                None)
    method = mem.get("method") or "kcore"
    cc = mem.get("content_check") or {}
    acq = mem.get("acquisition") or {}
    if method == "kcore_segments" and cc.get("status") == "pass":
        segs = acq.get("segments") or []
        ram = acq.get("ram_bytes")
        f = [
            "Complete physical-memory image in LiME format: %d RAM segments of /proc/kcore, %s bytes "
            "of System RAM, each read at its exact file offset." % (len(segs), f"{ram:,}" if ram else "?"),
            "Content gate: PASS. %.1f %% of the sampled 4 KiB pages are non-zero (threshold %.0f %%, "
            "every %s page sampled); no segment was read short."
            % (100 * float(cc.get("nonzero_ratio") or 0), 100 * float(cc.get("threshold") or 0.01),
               {8: "eighth"}.get(cc.get("sample_stride"), str(cc.get("sample_stride")))),
            "Canonical SHA-256 (uncompressed LiME image): %s." % mem.get("sha256", "-"),
            "Stored compressed (%s), %s; SHA-256 of the stored file: %s."
            % (mem.get("compression", "gzip"), human_size(mem.get("stored_size")), mem.get("stored_sha256", "-")),
        ]
        if acq.get("acquisition_seconds"):
            f.append("Acquisition time: %.1f s." % float(acq["acquisition_seconds"]))
        note = ("Structural memory analysis (Volatility 3) is not performed on this ARM64 platform: the kernel "
                "is identified from the image, but the kernel virtual-address layer required by structured "
                "plugins could not be constructed. The image is preserved with verified digests for analysis "
                "on a supported platform.")
        return ("Memory (LiME, complete)", "a complete, content-validated physical-memory image (LiME)", f, note,
                "Analyse the LiME image on a platform with an AArch64 address layer; verify it first against "
                "the canonical digest recorded in the manifest.")
    if method == "kcore_segments":
        reasons = "; ".join(cc.get("reasons") or []) or "content check did not pass"
        return ("Memory (failed)", "a memory acquisition that failed its content check",
                ["Memory acquisition did not complete: %s." % reasons,
                 "The partial output is preserved as a failed output (SHA-256 %s) and is not memory evidence."
                 % mem.get("failed_output_sha256", "-")], None,
                "Re-acquire memory if the host is still available; the failed output must not be used as evidence.")
    return ("Memory (legacy read)", "the legacy memory artefact (header of /proc/kcore only, see Memory section)",
            ["Legacy sequential read of the first 256 MiB of /proc/kcore. A content audit established that on "
             "this platform the range holds the ELF header, the program headers and the VMCOREINFO note of the "
             "virtual core file, and no physical memory.",
             "The artefact is retained and integrity-verified; it identifies the running kernel but is not "
             "memory evidence. Cases of the corrected configuration carry a complete LiME image."],
            None,
            "Do not treat the legacy memory artefact as memory evidence; it records the kernel release only.")


def context_charts(case_dir, rule_id, tactic, stratum, case_time):
    """Charts computed from the sealed cases of this deployment (same stratum)."""
    root = os.path.dirname(case_dir.rstrip("/"))
    rows = []
    for d in sorted(os.listdir(root)):
        if not d.startswith("CASE-") or d in EXCLUDED_CASES:
            continue
        try:
            m = json.load(open(os.path.join(root, d, "case_manifest.json")))
        except Exception:
            continue
        a = m.get("alert") or {}
        if str(a.get("rule_id")) not in FORENSIC_RULES:
            continue
        if case_stratum(d, m) != stratum:
            continue
        t = parse_ts(a.get("timestamp"))
        rows.append((t, str(a.get("rule_id")), (a.get("mitre_tactics") or ["-"])[0]))
    # tactic distribution
    counts = {}
    for _, _, tac in rows:
        counts[tac] = counts.get(tac, 0) + 1
    order = [t for t in TACTIC_ORDER if t in counts] + sorted(t for t in counts if t not in TACTIC_ORDER)
    mx = max(counts.values()) if counts else 1
    tactics = [{"name": t, "count": counts[t], "pct": int(round(100 * counts[t] / mx)),
                "current": t == tactic} for t in order]
    # weekly frequency of this rule, 10 weeks ending with the case's week
    freq = []
    if case_time:
        week = datetime.timedelta(days=7)
        start = case_time - 10 * week
        n = [0] * 10
        for t, r, _ in rows:
            if t and r == str(rule_id) and start < t <= case_time:
                n[min(9, int((t - start) / week))] += 1
        mxn = max(n) or 1
        for k, c in enumerate(n):
            freq.append({"label": "This" if k == 9 else "W-%d" % (9 - k), "count": c,
                         "h": max(2, int(round(110 * c / mxn))), "current": k == 9})
    return tactics, freq, len(rows)


def threat_section(case_dir, case_id):
    """Findings of the read-only threat analysis for this case, if it has been run."""
    root = os.path.dirname(os.path.dirname(case_dir.rstrip("/")))
    path = os.path.join(root, "analysis", "threat", "cases.json")
    try:
        recs = json.load(open(path))
    except Exception:
        return None
    rec = next((r for r in recs if r.get("case") == case_id), None)
    if not rec:
        return None
    out = []
    trg = rec.get("trigger") or {}
    if rec.get("trigger_found") and trg:
        out.append("Triggering command recovered from the acquired logs (%s): %s, issued by %s as %s on %s at %s, "
                   "%.2f s before the alert." % (", ".join(trg.get("sources") or []),
                   html.escape(trg.get("command", "")[:120]), trg.get("user"), trg.get("runas"),
                   trg.get("tty") or "no terminal", trg.get("time"), -float(trg.get("minus_alert_s") or 0)))
    sd = rec.get("state_diff") or {}
    if sd.get("reference_case"):
        bits = []
        if sd.get("accounts_added"):
            bits.append("accounts added: " + ", ".join(sd["accounts_added"]))
        if sd.get("accounts_removed"):
            bits.append("accounts removed: " + ", ".join(sd["accounts_removed"]))
        if sd.get("files_changed"):
            bits.append("security-relevant files changed: " + ", ".join(sd["files_changed"]))
        if sd.get("auth_log_history_lost"):
            bits.append("authentication-log history lost since the previous case")
        out.append("Host state compared with %s: %s." % (sd["reference_case"], "; ".join(bits) or "no change in accounts, security-relevant files or listening sockets"))
    coll = [f for f in rec.get("findings") or [] if f.get("technique") == "COLLECTOR"
            and -15 <= float(f.get("minus_alert_s") or 0) <= 120]
    if coll:
        out.append("%d SSH log-in(s) of the collector from the manager node after the alert, attributed and "
                   "separated from the attacker's activity." % len(coll))
    return out or None


def standards_alignment(ctx):
    """Technical alignment of this case with the standards and regulations cited in the thesis
    (Section 2.3). Every statement is derived from the case's own records. This is an
    engineering self-assessment, not a legal opinion."""
    rows = []
    v = ctx["verified"]
    rows.append({"ref": "ISO/IEC 27037:2012 — auditability",
                 "req": "Every action on the evidence is documented and can be reviewed by an independent party.",
                 "how": "Manifest with per-artefact SHA-256, per-phase timestamps and collection profile; custody record "
                        + (("link %d of %d of the hash-chained ledger, verified by recomputation" % (ctx["pos"], ctx["total"]))
                           if v and ctx["pos"] else "in the hash-chained ledger"),
                 "status": "Supported" if v else "Recorded"})
    rows.append({"ref": "ISO/IEC 27037:2012 — repeatability, reproducibility",
                 "req": "The same procedure yields the same results; the procedure can be reproduced.",
                 "how": "Fixed 16-artefact procedure for every alert; collection profile (order: %s, memory method: %s) "
                        "recorded in the case" % (ctx["order"], ctx["mem_method"]),
                 "status": "Supported"})
    rows.append({"ref": "ISO/IEC 27037:2012 — justifiability; RFC 3227",
                 "req": "Acquisition choices can be justified; most volatile evidence first.",
                 "how": ("Order of volatility applied: live state, memory, logs, files" if ctx["order"] == "rfc3227"
                         else "Legacy order (memory last) recorded in the case; deviation from RFC 3227 documented"),
                 "status": "Supported" if ctx["order"] == "rfc3227" else "Deviation recorded"})
    if ctx["mem_method"] == "kcore_segments" and ctx["mem_ok"]:
        rows.append({"ref": "ISO/IEC 27041:2015 — validated method",
                     "req": "Methods and tools are shown to be fit for purpose before their results are relied upon.",
                     "how": "Segment-aware memory method validated under pre-specified criteria (thesis Section 6.9); "
                            "content gate passed for this image",
                     "status": "Supported"})
    else:
        rows.append({"ref": "ISO/IEC 27041:2015 — validated method",
                     "req": "Methods and tools are shown to be fit for purpose before their results are relied upon.",
                     "how": "Memory artefact of this case was not acquired with the validated method and is not relied "
                            "upon as memory evidence; the other fifteen artefacts use the validated procedure",
                     "status": "Limitation recorded"})
    rows.append({"ref": "c.p.p. art. 247 c. 1-bis, 354 c. 2 (L. 48/2008)",
                 "req": "Technical measures preserve the original data and prevent alteration; copies conform to the "
                        "original and are immutable.",
                 "how": "Acquisition by remote read without installing tools on the host; SHA-256 recorded at acquisition "
                        "for every artefact and bound into the ledger" + ("; collector's own sudo reads present in the "
                        "authentication log (pre-20 June configuration)" if ctx["via_sudo"] else ""),
                 "status": "Technical measures supported"})
    rows.append({"ref": "NIS2 art. 23 (Dir. (EU) 2022/2555; D.Lgs. 138/2024)",
                 "req": "Early warning within 24 h and incident notification within 72 h of awareness of a significant incident.",
                 "how": "Alert %s; evidence sealed %s after the alert. If the incident is classified as significant, the "
                        "24 h early warning falls due at %s UTC and the 72 h notification at %s UTC"
                        % (ctx["alert_s"], ctx["tte"], ctx["d24"], ctx["d72"]),
                 "status": "Timeline supported"})
    rows.append({"ref": "GDPR art. 5(1)(c), 5(1)(e), 32",
                 "req": "Data minimisation, storage limitation and security of processing of personal data.",
                 "how": "Case contains authentication logs, credential hashes (/etc/shadow)%s; legal hold: %s; automatic "
                        "deletion disabled in this deployment. Access control and a retention period must be set by the "
                        "data controller before production use" % (", and a memory image" if ctx["has_mem"] else "",
                                                                     "yes" if ctx["legal_hold"] else "no"),
                 "status": "Action required"})
    rows.append({"ref": "eIDAS art. 41 (Reg. (EU) 910/2014, as amended by 2024/1183)",
                 "req": "A qualified electronic time stamp gives a legal presumption of date, time and integrity.",
                 "how": "The ledger is tamper-evident but its head is not anchored to a qualified time stamp",
                 "status": "Not implemented"})
    return rows


def summarise_text_file(path, max_lines=6):
    try:
        with open(path, errors="replace") as f:
            return [l.rstrip() for l in f.readlines()[:max_lines] if l.strip()]
    except Exception:
        return []


# ----------------------------- build context --------------------------------
def build_context(case_dir):
    manifest = load_json(os.path.join(case_dir, "case_manifest.json"))
    coc_path = os.path.join(case_dir, "chain_of_custody.json")
    custody = load_json(coc_path) if os.path.exists(coc_path) else {}

    case_id = manifest.get("case_id", os.path.basename(case_dir))
    alert = manifest.get("alert", {})
    incident_meta = custody.get("incident", {})
    timeline = custody.get("timeline", {})

    analyst = custody.get("analyst") or "Forensic Analyst"
    org = custody.get("organization") or FRAMEWORK["org"]

    # ---- MTTE (automated), measured FROM this case's own timestamps ----
    # Detection (alert_time) -> last artefact sealed (collection_time).
    # Nothing is hardcoded: the printed figure is the one measured for this case.
    t_alert = parse_ts(alert.get("timestamp") or timeline.get("alert_time"))
    t_seal_ms = parse_ts(manifest.get("seal_requested_at"))
    t_done  = t_seal_ms or parse_ts(timeline.get("collection_time") or manifest.get("created_at"))
    mtte_resolution = "millisecond seal record" if t_seal_ms else "one-second collection record"
    mtte_auto_s = None
    if t_alert and t_done and t_done >= t_alert:
        mtte_auto_s = (t_done - t_alert).total_seconds()
    if mtte_auto_s is None:
        die("cannot compute MTTE: missing/invalid alert_time or collection_time")
    pipeline_runtime_s = mtte_auto_s

    # ---- MITRE (null-safe) ----
    def first(v):
        if isinstance(v, list):
            return v[0] if v else None
        return v
    mitre_id = first(incident_meta.get("mitre_ids"))
    mitre_tech = first(incident_meta.get("mitre_techniques"))
    mitre_tactic = first(incident_meta.get("mitre_tactics"))
    has_mitre = bool(mitre_id)

    severity_label = "Critical" if alert.get("level", 0) >= 12 else \
                     "High" if alert.get("level", 0) >= 7 else "Medium"

    # ---- collection profile, memory, collector mode ----
    prof = manifest.get("collection_profile") or {}
    stratum = case_stratum(case_id, manifest)
    base = BASELINES.get(stratum, BASELINES["A"])
    order = prof.get("order") or "legacy"
    mem_label, mem_phrase, memory_findings, memory_note, mem_reco = memory_section(manifest)
    t_case = parse_ts(manifest.get("created_at")) or t_alert
    via_sudo = bool(t_case and t_case < COLLECTOR_ROOT_SINCE)
    acq_method = ("Remote pull over SSH from the manager node, "
                  + ("as an unprivileged account with sudo elevation (collector configuration before 20 June 2026)"
                     if via_sudo else "authenticated directly as root, no host-side elevation")
                  + "; collection order "
                  + ("RFC 3227: live state, memory, logs, files" if order == "rfc3227"
                     else "of the legacy profile: live state, logs, files, memory"))

    # ---- evidence inventory ----
    evidence = []
    for e in manifest.get("evidence", []):
        evidence.append({
            "name": os.path.basename(e.get("path", "")) + (" (stored .gz)" if e.get("stored_path") else ""),
            "type": mem_label if e.get("type") == "memory" else TYPE_LABEL.get(e.get("type", ""), e.get("type", "Artefact")),
            "size": human_size(e.get("size")),
            "sha256": e.get("sha256", "—"),
        })

    # ---- verify the recorded ledger (honest status: recompute, do not assume) ----
    integrity_verified, ledger_count = _verify_custody_ledger()
    _ledger_pos, _ledger_total = _ledger_position((custody.get("chain") or {}).get("current_hash"))

    # ---- chain of custody ----
    # Orchestrator records a case-level seal under custody["chain"] (prev_hash -> current_hash);
    # each artefact is individually hashed in custody["evidence"]. Extended cases may carry a
    # per-record list under custody["custody_chain"] -- support both.
    coc_steps = []
    chain_obj = custody.get("chain") or {}
    if custody.get("custody_chain"):
        for s in custody["custody_chain"]:
            coc_steps.append({
                "action": s.get("action", "record"),
                "ts": s.get("ts", ""),
                "prev": s.get("prev_hash", "—"),
                "cur": s.get("current_hash", "—"),
            })
    elif chain_obj.get("current_hash"):
        n_art = len(custody.get("evidence", []))
        coc_steps.append({
            "action": "Case sealed — %d artefacts bound under %s" % (
                n_art, chain_obj.get("hash_algorithm", "SHA-256")),
            "ts": (custody.get("timeline", {}) or {}).get("collection_time", ""),
            "prev": chain_obj.get("prev_hash", "—"),
            "cur": chain_obj.get("current_hash", "—"),
        })
    if not coc_steps:
        coc_status = "No chain recorded"
    elif integrity_verified is True:
        _base = ("VERIFIED — ledger intact (%d records)" % ledger_count) if ledger_count else "VERIFIED — ledger intact"
        if _ledger_pos and _ledger_total:
            _base += " · this case = link %d of %d" % (_ledger_pos, _ledger_total)
        coc_status = _base
    elif integrity_verified is False:
        coc_status = "VERIFICATION FAILED"
    else:
        coc_status = "RECORDED — %d record(s)" % len(coc_steps)

    # ---- findings ----
    def ev_path(substr):
        for e in manifest.get("evidence", []):
            if substr in e.get("path", ""):
                return e["path"]
        return None

    volatile_findings = []
    ps = ev_path("processes_ps_aux")
    if ps:
        for ln in summarise_text_file(ps, 4):
            volatile_findings.append(html.escape(ln[:110]))
    if not volatile_findings:
        volatile_findings = ["Volatile process/network snapshots captured (see evidence inventory)."]

    log_findings = []
    auth = ev_path("auth.log")
    if auth:
        for ln in summarise_text_file(auth, 4):
            if any(k in ln.lower() for k in ("sudo", "accepted", "failed", "session")):
                log_findings.append(html.escape(ln[:110]))
    if not log_findings:
        log_findings = ["System and authentication logs acquired for the 24 h window."]

    timeline_findings = []
    tsk = os.path.join(case_dir, "findings", "tsk", "filesystem_timeline.csv")
    if os.path.exists(tsk):
        rows = summarise_text_file(tsk, 4)
        timeline_findings = [html.escape(r[:110]) for r in rows[1:]] or \
                             ["Filesystem metadata timeline generated (TSK)."]
    else:
        timeline_findings = ["Filesystem metadata timeline generated."]

    threat_findings = threat_section(case_dir, case_id)

    # ---- analytics block (baseline of this case's stratum; context from sealed cases) ----
    max_s = max(base["high"], pipeline_runtime_s)
    ratio = base["point"] / pipeline_runtime_s
    tactics, frequency, n_ctx = context_charts(case_dir, alert.get("rule_id"), mitre_tactic, stratum, t_alert)
    analytics = {
        "mtte_auto": fmt_duration(pipeline_runtime_s),
        "mtte_manual": fmt_duration(base["point"]),
        "mtte_reduction": (f"{ratio:.1f}×" if ratio < 20 else f"{ratio:.0f}×"),
        "ratio_range": "%.1f×–%.1f×" % (base["low"] / pipeline_runtime_s, base["high"] / pipeline_runtime_s)
                       if base["high"] / pipeline_runtime_s < 20 else
                       "%.0f×–%.0f×" % (base["low"] / pipeline_runtime_s, base["high"] / pipeline_runtime_s),
        "baseline_point": base["point"], "baseline_system": base["system"],
        "stratum": stratum, "mtte_resolution": mtte_resolution, "n_context": n_ctx,
        "current_tactic": mitre_tactic or "-",
        "kpi_detect_response": fmt_duration(pipeline_runtime_s),
        "kpi_integrity": ("100%" if integrity_verified else ("FAILED" if integrity_verified is False else "Sealed")) if coc_steps else "—",
        "kpi_automation": "Full",
        "cmp_auto": fmt_duration(pipeline_runtime_s), "cmp_auto_w": log_width(pipeline_runtime_s, max_s),
        "cmp_run": f"{base['low']} s",            "cmp_run_w": log_width(base["low"], max_s),
        "cmp_real": f"{base['high']} s",           "cmp_real_w": log_width(base["high"], max_s),
        "frequency": frequency,
        "tactics": tactics,
        "freq_title": (f"Sealed cases of rule {alert.get('rule_id')} ({mitre_id}) on this deployment — 10 weeks to this case"
                       if has_mitre else
                       "Sealed cases of this rule on this deployment — 10 weeks to this case"),
    }

    total_bytes = sum((e.get("size") or 0) for e in manifest.get("evidence", []))
    stored_bytes = sum((e.get("stored_size") or e.get("size") or 0) for e in manifest.get("evidence", []))

    # ---- standards & regulatory alignment (from this case's records) ----
    life_path = os.path.join(case_dir, "lifecycle.json")
    try:
        legal_hold = bool(json.load(open(life_path)).get("legal_hold", False))
    except Exception:
        legal_hold = False
    mem_e = next((e for e in manifest.get("evidence", []) if e.get("type") == "memory"), {}) or {}
    _d24 = (t_alert + datetime.timedelta(hours=24)).strftime("%Y-%m-%d %H:%M") if t_alert else "—"
    _d72 = (t_alert + datetime.timedelta(hours=72)).strftime("%Y-%m-%d %H:%M") if t_alert else "—"
    standards = standards_alignment({
        "verified": integrity_verified is True, "pos": _ledger_pos, "total": _ledger_total,
        "order": order, "mem_method": mem_e.get("method") or "kcore",
        "mem_ok": (mem_e.get("content_check") or {}).get("status") == "pass",
        "via_sudo": via_sudo, "alert_s": alert.get("timestamp", "—"),
        "tte": fmt_duration(pipeline_runtime_s), "d24": _d24, "d72": _d72,
        "has_mem": bool(mem_e), "legal_hold": legal_hold,
    })

    summary_text = (
        f"At {alert.get('timestamp','(detection time)')} the IDS raised "
        f"\"{alert.get('description','an alert')}\" (rule {alert.get('rule_id','?')}, "
        f"level {alert.get('level','?')}) on {alert.get('agent','the monitored asset')}. "
        f"The framework automatically collected {len(evidence)} forensic artefacts — volatile "
        f"process/network state, system and authentication logs, a filesystem metadata timeline, "
        f"sensitive configuration files and {mem_phrase} — each SHA-256 hashed and sealed in a "
        f"tamper-evident chain of custody {fmt_duration(pipeline_runtime_s)} after the alert."
    )

    return {
        "framework": FRAMEWORK,
        "case": {
            "id": case_id,
            "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "classification": "Confidential",
            "analyst": analyst,
        },
        "incident": {
            "rule_id": alert.get("rule_id", "—"),
            "level": alert.get("level", "—"),
            "severity_label": severity_label,
            "rule_desc": alert.get("description", "—"),
            "detect_time": alert.get("timestamp", "—"),
            "response_time": manifest.get("seal_requested_at") or (custody.get("timeline", {}) or {}).get("collection_time", manifest.get("created_at", "—")),
            "acq_method": acq_method,
            "via_sudo": via_sudo,
            "agent_name": incident_meta.get("agent_name") or alert.get("agent", "—"),
            "agent_ip": incident_meta.get("agent_ip") or "—",
            "agent_os": "—",
            "has_mitre": has_mitre,
            "mitre_id": mitre_id or "N/A",
            "mitre_short": (mitre_tech or "")[:24] if mitre_tech else "n/a",
            "mitre_technique": mitre_tech or "Not mapped (non-MITRE rule)",
            "mitre_tactic": mitre_tactic or "—",
            "mitre_behaviour": "This detection rule is not mapped to a MITRE ATT&CK technique."
                               if not has_mitre else
                               ("Triggered by Wazuh rule %s: %s. Corroborate with the authentication and journal logs (findings section)." % (alert.get("rule_id", "?"), alert.get("description", ""))),
        },
        "summary": {
            "text": summary_text,
            "ttE": fmt_duration(pipeline_runtime_s),
            "total_size": human_size(total_bytes),
            "stored_size": human_size(stored_bytes) if stored_bytes != total_bytes else None,
            "coc_status": ("VERIFIED" if integrity_verified else ("FAILED" if integrity_verified is False else "SEALED")) if coc_steps else "—",
        },
        "analytics": analytics,
        "evidence": evidence,
        "coc": {"status": coc_status, "steps": coc_steps},
        "standards": standards,
        "findings": {
            "volatile": volatile_findings,
            "logs": log_findings,
            "timeline": timeline_findings,
            "memory": memory_findings,
            "memory_note": memory_note,
            "threat": threat_findings,
            "timeline_label": ("Filesystem Timeline (Sleuth Kit: fls + mactime)" if ((manifest.get("findings", {}).get("tsk", {}) or {}).get("mode") == "disk_image") else "Filesystem Metadata Timeline (file metadata via SSH)"),
        },
        "recommendations": [
            "Review the collected volatile state and authentication logs for the session implicated by the alert.",
            mem_reco or "Preserve the acquired evidence unchanged; verify digests before any analysis.",
            "Confirm chain-of-custody integrity via the verification command in the appendix before any escalation.",
            "Correlate this case with adjacent detections in the SIEM to rule out a broader campaign.",
        ],
    }


def render(case_dir, out_pdf=None, show_telemetry=True):
    from jinja2 import Environment, FileSystemLoader
    ctx = build_context(case_dir)
    ctx["show_telemetry"] = show_telemetry
    env = Environment(loader=FileSystemLoader(HERE))
    htmlout = env.get_template(TEMPLATE).render(**ctx)

    html_path = os.path.join(case_dir, "report.html")
    with open(html_path, "w") as f:
        f.write(htmlout)

    out_pdf = out_pdf or os.path.join(case_dir, "report.pdf")
    cmd = ["wkhtmltopdf", "--enable-local-file-access",
           "--page-size", "A4", "-T", "0", "-B", "12mm", "-L", "0", "-R", "0",
           "--quiet", html_path, out_pdf]
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        die("wkhtmltopdf not found. Install with: sudo apt-get install -y wkhtmltopdf")
    except subprocess.CalledProcessError as e:
        die(f"wkhtmltopdf failed: {e}")
    print(f"[report] PDF written: {out_pdf}")
    print(f"[report] Size: {os.path.getsize(out_pdf)} bytes")
    return out_pdf


if __name__ == "__main__":
    _args = [a for a in sys.argv[1:] if not a.startswith("--")]
    forensic_clean = "--forensic-clean" in sys.argv[1:]
    case = _args[0] if _args else find_latest_case()
    if not case:
        die("no case folder given and none found under storage/cases")
    if not os.path.isdir(case):
        die(f"not a directory: {case}")
    out_pdf = os.path.join(case, "report_forensic.pdf") if forensic_clean else None
    print(f"[report] Generating report for: {case} (forensic_clean={forensic_clean})")
    render(case, out_pdf=out_pdf, show_telemetry=not forensic_clean)
