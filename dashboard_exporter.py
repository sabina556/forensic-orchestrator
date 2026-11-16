
"""
dashboard_exporter.py - export sealed forensic case metadata into the Wazuh
indexer (OpenSearch) index 'forensic-cases' for dashboard visualisation.

Provenance: every field is read from the case's own sealed records
(case_manifest.json, chain_of_custody.json, lifecycle.json). No value is
fabricated. MTTE is the real per-case wall-clock from detection (alert_time)
to evidence collection (collection_time) as recorded in the chain of custody.

Stratification: cases are grouped by the collection conditions recorded in
their manifest (collection_profile.stratum; cases without it are stratum A, the
frozen v2 evaluation set). Each stratum goes to its own index and its own
statistics, so stratum-B cases can never shift the v2 figures on the dashboard:
    stratum A -> forensic-cases        (v2, frozen; drives the existing dashboard)
    stratum B -> forensic-cases-b      (corrected memory acquisition)

Safety: default run is DRY (prints, indexes nothing). Use --apply to write to
the indexer; --recreate to drop and rebuild the index mapping(s) first.
"""
import os, sys, json, ssl, base64, datetime, re
import urllib.request, urllib.error

CASES_ROOT = "/opt/forensic-orchestrator/storage/cases"
INDEX = "forensic-cases"                       # stratum A (v2, frozen)
STRATUM_INDEX = {"A": INDEX, "B": "forensic-cases-b", "live": "forensic-cases-live"}
# Stratum B is a closed, reported dataset: only these five cases belong to it. Any later case
# collected with the same profile (e.g. a live demonstration) goes to the "live" index, so that
# the reported statistics of A and B can never change.
STRATUM_B_CASES = {
    "CASE-20261025T191709Z-rule100210", "CASE-20261026T184313Z-rule100220",
    "CASE-20261026T190602Z-rule100240", "CASE-20261027T184825Z-rule100250",
    "CASE-20261027T185428Z-rule100260",
}
OS_URL = "https://localhost:9200"
OS_USER = "admin"
OS_PASS = os.environ.get("OS_PASS", "CHANGE_ME")
MANUAL_BASELINE_S = 433  # KLM-modeled manual MTTE (point estimate) for speedup, stratum A
# Stratum B has its own manual baseline (manual full-RAM acquisition added to the
# KLM operator model). Leave None until it is computed: no speed-up is reported.
MANUAL_BASELINE_BY_STRATUM = {"A": MANUAL_BASELINE_S, "B": 458, "live": 458}  # B: KLM lower bound, K=0.40 (433 s - 5.0 s partial + 30.1 s full RAM)
FORENSIC_RULES = {"100210", "100220", "100240", "100250", "100260"}  # rules that drive the automated forensic pipeline
DEDUP_TEST_CASES = {
    "CASE-20261011T072106Z-rule100220",  # manager-local (dataset-extension stray), excluded
    "CASE-20261011T072130Z-rule100250",  # manager-local (dataset-extension stray), excluded
    "CASE-20261011T072132Z-rule100260",  # manager-local (dataset-extension stray), excluded
    "CASE-20260830T131959Z-rule100240",  # rule-validation artefact (logtest vacuum check), not part of the evaluation set
    "CASE-20260602T220336Z-rule100220",  # legacy manager-local persistence case, superseded by agent-based CASE-20260825T092035Z
    "CASE-20260816T203733Z-rule100240",
    "CASE-20260816T205030Z-rule100240",
    "CASE-20260816T205049Z-rule100210",
    "CASE-20261026T201102Z-rule100210",  # stratum B: memory acquisition timed out (watchdog), failed attempt, excluded from metrics
}  # controlled dedup-validation cases, excluded from metrics

INDEX_BODY = {
    "settings": {"number_of_replicas": 0},
    "mappings": {"properties": {
        "case_id": {"type": "keyword"},
        "case_kind": {"type": "keyword"},
        "stratum": {"type": "keyword"},
        "memory_method": {"type": "keyword"},
        "collection_order": {"type": "keyword"},
        "memory_content_status": {"type": "keyword"},
        "memory_ram_bytes": {"type": "long"},
        "memory_acquisition_seconds": {"type": "float"},
        "@timestamp": {"type": "date"},
        "detected_at": {"type": "date"},
        "collected_at": {"type": "date"},
        "created_at": {"type": "date"},
        "mtte_seconds": {"type": "float"},
        "mtte_resolution": {"type": "keyword"},
        "manual_baseline_seconds": {"type": "float"},
        "speedup_x": {"type": "float"},
        "speedup_mean_based": {"type": "float"},
        "rule_id": {"type": "keyword"},
        "rule_level": {"type": "integer"},
        "rule_description": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
        "mitre_ids": {"type": "keyword"},
        "mitre_techniques": {"type": "keyword"},
        "mitre_tactics": {"type": "keyword"},
        "agent_name": {"type": "keyword"},
        "agent_id": {"type": "keyword"},
        "agent_ip": {"type": "keyword"},
        "artifact_count": {"type": "integer"},
        "total_bytes": {"type": "long"},
        "custody_sealed": {"type": "boolean"},
        "custody_hash": {"type": "keyword"},
        "tier": {"type": "keyword"},
        "legal_hold": {"type": "boolean"},
        "analyst": {"type": "keyword"},
        "organization": {"type": "keyword"},
    }},
}


def _iso(s):
    if not s:
        return None
    t = str(s).strip()
    t = re.sub(r"[zZ]$", "+00:00", t)
    t = re.sub(r"^(\d{4}-\d{2}-\d{2}) ", r"\1T", t)
    t = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", t)
    try:
        return datetime.datetime.fromisoformat(t)
    except Exception:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.datetime.strptime(t, fmt)
        except Exception:
            continue
    return None


def _load(path):
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:
        return None


def build_doc(case_dir):
    cid = os.path.basename(case_dir)
    m = re.search(r"CASE-(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z", cid)
    cid_ts = _iso("%s-%s-%sT%s:%s:%sZ" % m.groups()) if m else None
    mr = re.search(r"-rule(\w+)$", cid)
    cid_rule = mr.group(1) if mr else None
    man = _load(os.path.join(case_dir, "case_manifest.json")) or {}
    coc = _load(os.path.join(case_dir, "chain_of_custody.json")) or {}
    life = _load(os.path.join(case_dir, "lifecycle.json")) or {}

    alert = man.get("alert") or coc.get("incident") or {}
    tl = coc.get("timeline") or {}
    evidence = man.get("evidence") or coc.get("evidence") or []

    alert_t = _iso(tl.get("alert_time") or alert.get("timestamp")) or cid_ts
    # Sealing instant: millisecond record where the case carries it (corrected configuration),
    # otherwise the one-second collection_time of the chain of custody (frozen stratum A, unchanged).
    seal_ms = _iso(man.get("seal_requested_at"))
    coll_t = seal_ms or _iso(tl.get("collection_time"))
    created = _iso(man.get("created_at")) or cid_ts

    mtte = None
    if alert_t and coll_t:
        d = (coll_t - alert_t).total_seconds()
        mtte = d if d >= 0 else None

    total_bytes = 0
    for e in evidence:
        try:
            total_bytes += int(e.get("size") or 0)
        except Exception:
            pass

    chain = coc.get("chain") or {}
    ts = alert_t or created
    prof = man.get("collection_profile") or {}
    stratum = str(prof.get("stratum") or "A")
    if stratum != "A" and cid not in STRATUM_B_CASES:
        stratum = "live"
    baseline = MANUAL_BASELINE_BY_STRATUM.get(stratum)
    mem = next((e for e in evidence if isinstance(e, dict) and e.get("type") == "memory"), {})
    mem_acq = mem.get("acquisition") or {}
    doc_mem = {}
    if stratum != "A":  # stratum-A documents keep their v2 fields (plus "stratum")
        doc_mem = {
            "memory_method": mem.get("method"),
            "collection_order": prof.get("order"),
            "memory_content_status": (mem.get("content_check") or {}).get("status"),
            "memory_ram_bytes": mem_acq.get("ram_bytes"),
            "memory_acquisition_seconds": mem_acq.get("acquisition_seconds"),
        }
    return {
        "case_id": cid,
        "stratum": stratum,
        **doc_mem,
        "case_kind": ("detection" if str(alert.get("rule_id") or cid_rule) in FORENSIC_RULES else "other"),
        "@timestamp": (ts.isoformat() if ts else None),
        "detected_at": (alert_t.isoformat() if alert_t else None),
        "collected_at": (coll_t.isoformat() if coll_t else None),
        "created_at": (created.isoformat() if created else None),
        "mtte_seconds": mtte,
        "mtte_resolution": "ms" if seal_ms else "1s",
        "manual_baseline_seconds": baseline,
        "speedup_x": (round(baseline / mtte, 1) if baseline and mtte and mtte > 0 else None),
        "rule_id": alert.get("rule_id") or cid_rule,
        "rule_level": alert.get("level"),
        "rule_description": alert.get("description"),
        "mitre_ids": alert.get("mitre_ids") or [],
        "mitre_techniques": alert.get("mitre_techniques") or [],
        "mitre_tactics": alert.get("mitre_tactics") or [],
        "agent_name": alert.get("agent_name"),
        "agent_id": alert.get("agent_id"),
        "agent_ip": alert.get("agent_ip"),
        "artifact_count": len(evidence),
        "total_bytes": total_bytes,
        "custody_sealed": bool(chain.get("current_hash")) or life.get("tier") == "cold",
        "custody_hash": chain.get("current_hash"),
        "tier": life.get("tier", "hot"),
        "legal_hold": bool(life.get("legal_hold", False)),
        "analyst": coc.get("analyst"),
        "organization": coc.get("organization"),
    }


def _http(method, path, body=None):
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(OS_URL + path, data=data, method=method)
    tok = base64.b64encode(("%s:%s" % (OS_USER, OS_PASS)).encode()).decode()
    req.add_header("Authorization", "Basic " + tok)
    req.add_header("Content-Type", "application/x-ndjson" if path.endswith("_bulk") else "application/json")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, context=ctx) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {"raw": e.read().decode("utf-8", "replace")}


def ensure_index(recreate=False, index=INDEX):
    if recreate:
        _http("DELETE", "/" + index)
    st, _ = _http("GET", "/" + index)
    if st == 200 and not recreate:
        return "exists"
    st, resp = _http("PUT", "/" + index, INDEX_BODY)
    return "created" if st in (200, 201) else ("ERROR %s: %s" % (st, resp))


def bulk_index(docs, index=INDEX):
    lines = []
    for d in docs:
        lines.append(json.dumps({"index": {"_index": index, "_id": d["case_id"]}}))
        lines.append(json.dumps(d))
    body = ("\n".join(lines) + "\n").encode("utf-8")
    return _http("POST", "/_bulk", body)


def main():
    apply = "--apply" in sys.argv or "--recreate" in sys.argv
    recreate = "--recreate" in sys.argv
    dirs = sorted(os.path.join(CASES_ROOT, d) for d in os.listdir(CASES_ROOT)
                  if d.startswith("CASE-") and os.path.isdir(os.path.join(CASES_ROOT, d)))
    docs = [build_doc(d) for d in dirs]
    docs = [d for d in docs if d.get("case_id") not in DEDUP_TEST_CASES]  # exclude dedup-validation cases

    print("%-44s %8s %6s %-9s %-14s %4s %-5s %s" %
          ("CASE", "MTTE_s", "x", "rule", "technique", "art", "tier", "sealed"))
    print("-" * 110)
    for d in docs:
        tech = ",".join(d["mitre_techniques"]) or "-"
        print("%-44s %8s %6s %-9s %-14s %4d %-5s %s" % (
            d["case_id"],
            ("%.1f" % d["mtte_seconds"]) if d["mtte_seconds"] is not None else "n/a",
            ("%.0f" % d["speedup_x"]) if d["speedup_x"] is not None else "-",
            str(d["rule_id"]), tech[:14], d["artifact_count"], d["tier"],
            "Y" if d["custody_sealed"] else "N"))
    print("-" * 110)
    strata = sorted({d["stratum"] for d in docs})
    for st_ in strata:
        sd = [d for d in docs if d["stratum"] == st_]
        mttes = [d["mtte_seconds"] for d in sd
                 if d["mtte_seconds"] is not None and d.get("case_kind") == "detection"]
        if not mttes:
            print("stratum %s: cases=%d  (no MTTE timestamps parsed)" % (st_, len(sd)))
            continue
        mean = sum(mttes) / len(mttes)
        sdv = (sum((x - mean) ** 2 for x in mttes) / (len(mttes) - 1)) ** 0.5 if len(mttes) > 1 else 0.0
        base = MANUAL_BASELINE_BY_STRATUM.get(st_)
        spd = ("mean speedup=%.0fx (vs %ds manual)" % (base / mean, base)) if base else "speedup: baseline not set"
        print("stratum %s -> %s: detection cases=%d (of %d)  MTTE mean=%.2fs sd=%.2fs min=%.1fs max=%.1fs  %s"
              % (st_, STRATUM_INDEX.get(st_, "?"), len(mttes), len(sd), mean, sdv, min(mttes), max(mttes), spd))

    if not apply:
        print("\nDRY RUN. Re-run with --apply to write to index '%s' (--recreate to rebuild mapping)." % INDEX)
        return 0
    # --- honest mean-based speedup: baseline / mean(mtte), computed PER STRATUM ---
    for st_ in sorted({d["stratum"] for d in docs}):
        index = STRATUM_INDEX.get(st_)
        if index is None:
            print("\nstratum %s has no index configured; skipped" % st_)
            continue
        sd = [d for d in docs if d["stratum"] == st_]
        base = MANUAL_BASELINE_BY_STRATUM.get(st_)
        _det = [d for d in sd if d.get("case_kind") == "detection"]
        _mttes = [d["mtte_seconds"] for d in _det if d.get("mtte_seconds")]
        _mean_mtte = (sum(_mttes) / len(_mttes)) if _mttes else None
        _speedup_mean = round(base / _mean_mtte, 1) if (base and _mean_mtte) else None
        for d in _det:
            d["speedup_mean_based"] = _speedup_mean
        print("\nstratum %s index %s: %s" % (st_, index, ensure_index(recreate=recreate, index=index)))
        st, resp = bulk_index(_det, index=index)
        errors = resp.get("errors") if isinstance(resp, dict) else None
        print("bulk status=%s errors=%s indexed=%d" % (st, errors, len(_det)))
        if errors:
            for it in resp.get("items", [])[:3]:
                print("  sample item:", json.dumps(it)[:300])
    return 0


if __name__ == "__main__":
    sys.exit(main())
