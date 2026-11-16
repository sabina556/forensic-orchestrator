#!/usr/bin/env python3
"""Forensic Reports portal - browse cases and download/regenerate PDF reports.
Lab PoC; binds to the testbed LAN (read-only browse + regenerate on demand)."""
import os, re, json, subprocess
from flask import Flask, abort, redirect, request, Response

BASE = "/opt/forensic-orchestrator"
CASES = os.path.join(BASE, "storage", "cases")
REP = os.path.join(BASE, "reporting")
PORT = 8088
app = Flask(__name__)

def _tier(d):
    lf = os.path.join(d, "lifecycle.json")
    if os.path.exists(lf):
        try: return json.load(open(lf)).get("tier", "hot")
        except Exception: return "hot"
    return "hot"

EXCLUDED_CASES = {
    "CASE-20260830T131959Z-rule100240",  # rule-validation artefact
    "CASE-20260816T203733Z-rule100240",   # dedup validation Test A
    "CASE-20260816T205030Z-rule100240",   # dedup validation Test B (defense evasion)
    "CASE-20260816T205049Z-rule100210",   # dedup validation Test B (credential access)
    "CASE-20260602T220336Z-rule100220",   # legacy manager-local persistence, superseded by agent-based
    "CASE-20260530T075357Z-rule510",       # non-detection fixture
    "CASE-20261011T072106Z-rule100220",   # dataset-extension stray (manager-local)
    "CASE-20261011T072130Z-rule100250",   # dataset-extension stray (manager-local)
    "CASE-20261011T072132Z-rule100260",   # dataset-extension stray (manager-local)
    "CASE-20261026T201102Z-rule100210",   # stratum B: interrupted acquisition, excluded from metrics
}  # same exclusions as dashboard_exporter.DEDUP_TEST_CASES

def list_cases():
    rows = []
    if not os.path.isdir(CASES):
        return rows
    for cid in sorted(os.listdir(CASES), reverse=True):
        d = os.path.join(CASES, cid)
        if not (cid.startswith("CASE-") and os.path.isdir(d)):
            continue
        if cid in EXCLUDED_CASES:
            continue
        mr = re.search(r"-rule(\w+)$", cid)
        rows.append({"cid": cid, "rule": mr.group(1) if mr else "", "tier": _tier(d),
                     "full": os.path.exists(os.path.join(d, "report.pdf")),
                     "fore": os.path.exists(os.path.join(d, "report_forensic.pdf"))})
    return rows

def safe_case(cid):
    d = os.path.join(CASES, cid)
    if not (cid.startswith("CASE-") and os.path.isdir(d)
            and os.path.realpath(d).startswith(os.path.realpath(CASES))):
        abort(404)
    return d

HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Forensic Reports</title>
<style>
:root{--navy:#1D3557;--teal:#2A9D8F;--amber:#E76F51;--ink:#22303f;--line:#e3e8ee;}
*{box-sizing:border-box} body{margin:0;font:15px/1.5 -apple-system,Segoe UI,Roboto,Arial,sans-serif;color:var(--ink);background:#f6f8fa}
header{background:var(--navy);color:#fff;padding:22px 32px} header h1{margin:0;font-size:20px;letter-spacing:.3px}
header p{margin:4px 0 0;opacity:.85;font-size:13px}
.wrap{max-width:1100px;margin:24px auto;padding:0 24px}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{padding:12px 16px;text-align:left;border-bottom:1px solid var(--line);font-size:14px}
th{background:#f0f3f7;font-weight:600;color:#55657a;text-transform:uppercase;letter-spacing:.4px;font-size:11px}
tr:last-child td{border-bottom:none}
.cid{font-family:ui-monospace,Menlo,monospace;font-size:13px}
.tier{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;color:#fff}
.tier-hot{background:var(--amber)} .tier-warm{background:var(--teal)} .tier-cold{background:var(--navy)}
.btn{display:inline-block;padding:6px 12px;border-radius:7px;background:var(--teal);color:#fff;text-decoration:none;font-size:13px;border:none;cursor:pointer}
.btn.ghost{background:#fff;color:var(--navy);border:1px solid var(--line)}
.muted{color:#9aa7b5;font-size:13px} form{display:inline;margin:0}
footer{max-width:1100px;margin:8px auto 40px;padding:0 24px;color:#9aa7b5;font-size:12px}
</style></head><body>
<header><h1>Forensic Reports Portal</h1>
<p>Per-case DFIR reports - automated forensic evidence collection framework</p></header>
<div class="wrap"><table>
<tr><th>Case</th><th>Rule</th><th>Tier</th><th>Reports</th></tr>
"""
FOOT = """</table></div>
<footer>"Forensic" = evidentiary-clean report; "Full" includes non-evidentiary telemetry. Cold-archived cases must be restored before regeneration.</footer>
</body></html>"""

@app.route("/")
def index():
    parts = [HEAD]
    for r in list_cases():
        cid = r["cid"]
        fore = ('<a class="btn" href="/pdf/%s?which=forensic">Forensic PDF</a>' % cid) if r["fore"] else '<span class="muted">forensic n/a</span>'
        full = ('<a class="btn ghost" href="/pdf/%s?which=full">Full PDF</a>' % cid) if r["full"] else ''
        regen = '<span class="muted">archived</span>' if r["tier"] == "cold" else (
            '<form method="post" action="/regenerate/%s"><button class="btn ghost" type="submit">Regenerate</button></form>' % cid)
        parts.append('<tr><td class="cid">%s</td><td>%s</td><td><span class="tier tier-%s">%s</span></td><td>%s &nbsp; %s &nbsp; %s</td></tr>'
                     % (cid, r["rule"], r["tier"], r["tier"], fore, full, regen))
    parts.append(FOOT)
    return Response("".join(parts), mimetype="text/html")

@app.route("/pdf/<cid>")
def pdf(cid):
    d = safe_case(cid)
    fn = "report_forensic.pdf" if request.args.get("which", "forensic") == "forensic" else "report.pdf"
    p = os.path.join(d, fn)
    if not os.path.exists(p):
        abort(404)
    return Response(open(p, "rb").read(), mimetype="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="%s-%s"' % (cid, fn)})

@app.route("/regenerate/<cid>", methods=["POST"])
def regenerate(cid):
    d = safe_case(cid)
    for extra in ([], ["--forensic-clean"]):
        try:
            subprocess.run(["python3", "report_generator.py", d] + extra, cwd=REP, timeout=180, check=False)
        except Exception:
            pass
    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
