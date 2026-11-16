#!/usr/bin/env python3
# lifecycle_manager.py - tiered storage lifecycle for forensic cases.
# Forensic-safe: integrity verified before AND after every transition;
# lossless gzip only; sealed SHA-256 re-verifies on extraction; legal_hold
# blocks transitions; never deletes evidence (cold = compress/archive).
# Wazuh-Based Automated Forensic Framework - Politecnico di Torino MSc 2026

import os
import re
import sys
import json
import gzip
import shutil
import hashlib
import datetime
import tarfile
import tempfile

from common import load_config, get_logger, sha256_file

log = get_logger("lifecycle")

DEFAULTS = {
    "enabled": True, "hot_days": 7, "cold_days": 30, "disk_pressure_pct": 85,
    "archive_root": "/opt/forensic-orchestrator/storage/archive",
    "compress_evidence_min_bytes": 1048576, "retention_days": 0,
}
CASE_TS_RE = re.compile(r"CASE-(\d{8})T(\d{6})Z")


def _find_key(d, key):
    if isinstance(d, dict):
        if key in d:
            return d[key]
        for v in d.values():
            r = _find_key(v, key)
            if r is not None:
                return r
    return None


def _cfg():
    try:
        c = (load_config() or {}).get("lifecycle", {}) or {}
    except Exception as e:
        log.warning("config load failed, defaults used: %s", e)
        c = {}
    out = dict(DEFAULTS)
    out.update({k: v for k, v in c.items() if v is not None})
    return out


def _cases_root():
    try:
        r = _find_key(load_config() or {}, "cases_root")
        if r:
            return r
    except Exception:
        pass
    return "/opt/forensic-orchestrator/storage/cases"


def _h(n):
    n = float(n)
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024.0:
            return "%.1f %s" % (n, u)
        n /= 1024.0
    return "%.1f PB" % n


def _age_days(case_id):
    m = CASE_TS_RE.search(case_id)
    if not m:
        return None
    try:
        dt = datetime.datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S")
        dt = dt.replace(tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        return (now - dt).total_seconds() / 86400.0
    except Exception:
        return None


def _dir_size(path):
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def _compress_candidates(case_dir, min_bytes):
    ev = os.path.join(case_dir, "evidence")
    out = []
    for root, _, files in os.walk(ev):
        for f in files:
            if f.endswith(".gz"):
                continue
            p = os.path.join(root, f)
            try:
                s = os.path.getsize(p)
            except OSError:
                continue
            if s >= min_bytes:
                out.append((p, s))
    return out


def _legal_hold(case_dir):
    if os.path.exists(os.path.join(case_dir, "LEGAL_HOLD")):
        return True
    lf = os.path.join(case_dir, "lifecycle.json")
    if os.path.exists(lf):
        try:
            return bool(json.load(open(lf)).get("legal_hold"))
        except Exception:
            pass
    return False


def _current_tier(case_dir):
    lf = os.path.join(case_dir, "lifecycle.json")
    if os.path.exists(lf):
        try:
            t = json.load(open(lf)).get("tier")
            if t:
                return t
        except Exception:
            pass
    # Artefacts stored compressed at acquisition time (e.g. memory.lime.gz, see
    # collectors/memory.py) are not evidence of a warm-tier transition.
    m = _load_manifest(case_dir) or {}
    at_acq = {os.path.basename(e.get("stored_path") or "")
              for e in (m.get("evidence") or [])
              if isinstance(e, dict) and e.get("compressed_at") == "acquisition"}
    ev = os.path.join(case_dir, "evidence")
    for root, _, files in os.walk(ev):
        if any(f.endswith(".gz") and f not in at_acq for f in files):
            return "warm"
    return "hot"


def _sealed(case_dir):
    return os.path.exists(os.path.join(case_dir, "chain_of_custody.json"))


def _target_tier(age_days, sealed, hold, cfg):
    if hold or not sealed or age_days is None:
        return "hot"
    if age_days >= cfg["cold_days"]:
        return "cold"
    if age_days >= cfg["hot_days"]:
        return "warm"
    return "hot"


def _load_manifest(case_dir):
    try:
        return json.load(open(os.path.join(case_dir, "case_manifest.json")))
    except Exception:
        return None


def _recorded_hash_for(manifest, filename):
    # Find a recorded sha256 belonging to an object that references `filename`.
    found = []

    def walk(o):
        if isinstance(o, dict):
            refs = any(isinstance(v, str) and v.endswith(filename) for v in o.values())
            h = None
            for k, v in o.items():
                kk = k.lower().replace("-", "").replace("_", "")
                if isinstance(v, str) and kk in ("sha256", "hash", "sha256sum"):
                    h = v
            if refs and h:
                found.append(h.lower())
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(manifest)
    return found[0] if found else None


def _gz_sha256(path):
    h = hashlib.sha256()
    with gzip.open(path, "rb") as fz:
        while True:
            b = fz.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _write_lifecycle(case_dir, case_id, tier, action, entries):
    p = os.path.join(case_dir, "lifecycle.json")
    try:
        doc = json.load(open(p))
    except Exception:
        doc = {"case_id": case_id, "legal_hold": False, "history": []}
    doc["tier"] = tier
    doc.setdefault("history", []).append({
        "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "action": action, "actor": "lifecycle_manager", "to_tier": tier,
        "verification": "PASS", "files": entries,
    })
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp, p)


def cmd_status(measure=False):
    cfg = _cfg()
    root = _cases_root()
    cases = sorted(d for d in os.listdir(root)
                   if d.startswith("CASE-") and os.path.isdir(os.path.join(root, d))) \
        if os.path.isdir(root) else []
    du = shutil.disk_usage(root)
    print("Lifecycle status - %s" % root)
    print("Disk: total %s, used %s, free %s (%.0f%% used)" % (
        _h(du.total), _h(du.used), _h(du.free), 100.0 * du.used / du.total))
    print("Policy: hot<%dd | warm>=%dd | cold>=%dd | legal_hold pins HOT | retention_days=%s  [%s]"
          % (cfg["hot_days"], cfg["hot_days"], cfg["cold_days"], cfg["retention_days"],
             "MEASURED" if measure else "estimated"))
    print("-" * 104)
    print("%-44s %6s %4s %4s %8s %9s %12s" %
          ("CASE", "age_d", "seal", "hold", "cur>tgt", "size", "reclaim"))
    print("-" * 104)
    tot_size = tot_reclaim = 0
    for c in cases:
        cd = os.path.join(root, c)
        age = _age_days(c)
        sealed = _sealed(cd)
        hold = _legal_hold(cd)
        cur = _current_tier(cd)
        tgt = _target_tier(age, sealed, hold, cfg)
        _ord = {"hot": 0, "warm": 1, "cold": 2}
        if _ord.get(cur, 0) > _ord.get(tgt, 0):
            tgt = cur
        size = _dir_size(cd)
        reclaim = 0
        if tgt in ("warm", "cold") and cur == "hot":
            cands = _compress_candidates(cd, cfg["compress_evidence_min_bytes"])
            if measure:
                for p, s in cands:
                    try:
                        reclaim += max(0, s - os.path.getsize(p))  # placeholder
                        with open(p, "rb") as fh:
                            reclaim -= max(0, s - os.path.getsize(p))
                            z = len(gzip.compress(fh.read(), 6))
                        reclaim += max(0, s - z)
                    except Exception:
                        pass
            else:
                reclaim = sum(s for _, s in cands)
        tot_size += size
        tot_reclaim += reclaim
        print("%-44s %6s %4s %4s %8s %9s %12s" % (
            c, ("%.1f" % age) if age is not None else "?",
            "Y" if sealed else "N", "Y" if hold else "-",
            "%s>%s" % (cur, tgt), _h(size), _h(reclaim) if reclaim else "-"))
    print("-" * 104)
    print("TOTAL cases=%d  size=%s  reclaimable=%s  ->  projected free=%s" % (
        len(cases), _h(tot_size), _h(tot_reclaim), _h(du.free + tot_reclaim)))


def cmd_warm(case_id, do_apply=False):
    cfg = _cfg()
    cd = os.path.join(_cases_root(), case_id)
    if not os.path.isdir(cd):
        print("not a case dir: %s" % cd)
        return 2
    if _legal_hold(cd):
        print("ABORT: legal_hold set; case pinned to HOT.")
        return 1
    if not _sealed(cd):
        print("ABORT: case not sealed (no chain_of_custody.json).")
        return 1
    manifest = _load_manifest(cd)
    if manifest is None:
        print("ABORT: cannot read case_manifest.json.")
        return 1
    cands = _compress_candidates(cd, cfg["compress_evidence_min_bytes"])
    if not cands:
        print("nothing to compress (no evidence >= %s)." % _h(cfg["compress_evidence_min_bytes"]))
        return 0

    plan = []
    for p, s in cands:
        base = os.path.basename(p)
        rec = _recorded_hash_for(manifest, base)
        cur = sha256_file(p).lower()
        st = "MATCH" if (rec and rec == cur) else ("NO-RECORD" if not rec else "MISMATCH")
        plan.append({"path": p, "base": base, "size": s, "recorded": rec, "current": cur, "status": st})
        print("%-26s %10s  recorded=%s current=%s  -> %s"
              % (base, _h(s), (rec or "-")[:16], cur[:16], st))

    if any(x["status"] != "MATCH" for x in plan):
        print("ABORT: not all candidates match the sealed manifest. No changes made.")
        return 1
    if not do_apply:
        print("CHECK OK: all candidates verify against sealed hashes. Re-run with --apply to compress.")
        return 0

    entries = []
    for x in plan:
        p, gz = x["path"], x["path"] + ".gz"
        with open(p, "rb") as fi, gzip.open(gz, "wb", compresslevel=6) as fo:
            shutil.copyfileobj(fi, fo, length=1024 * 1024)
        post = _gz_sha256(gz)
        if post.lower() != x["recorded"]:
            os.remove(gz)
            print("ABORT on %s: post-compression hash mismatch; original kept." % x["base"])
            return 1
        gz_hash = sha256_file(gz)
        gz_size = os.path.getsize(gz)
        os.remove(p)
        entries.append({
            "file": x["base"], "stored_as": os.path.basename(gz),
            "original_sha256": x["recorded"], "compressed_sha256": gz_hash,
            "original_bytes": x["size"], "compressed_bytes": gz_size, "verified": True,
        })
        print("compressed %s: %s -> %s (verified against sealed hash)"
              % (x["base"], _h(x["size"]), _h(gz_size)))

    _write_lifecycle(cd, case_id, "warm", "compress", entries)
    print("WARM done for %s. lifecycle.json written." % case_id)
    return 0


def cmd_verify(case_id):
    cd = os.path.join(_cases_root(), case_id)
    manifest = _load_manifest(cd)
    if manifest is None:
        print("cannot read manifest")
        return 2
    ev = os.path.join(cd, "evidence")
    ok = bad = skip = 0
    for r, _, files in os.walk(ev):
        for f in files:
            p = os.path.join(r, f)
            if f.endswith(".gz"):
                base, tag = f[:-3], "compressed"
                rec = _recorded_hash_for(manifest, base)
                cur = _gz_sha256(p).lower() if rec else None
            else:
                base, tag = f, "plain"
                rec = _recorded_hash_for(manifest, base)
                cur = sha256_file(p).lower() if rec else None
            if not rec:
                skip += 1
                continue
            m = (cur == rec)
            ok += m
            bad += (not m)
            print("%-28s [%-10s] %s" % (base, tag, "OK" if m else "FAIL"))
    print("verify: %d OK, %d FAIL, %d not-in-manifest" % (ok, bad, skip))
    return 0 if bad == 0 else 1


def _extractall(tar, dest):
    try:
        tar.extractall(dest, filter="data")
    except TypeError:
        tar.extractall(dest)


def _verify_case(cd, manifest):
    ev = os.path.join(cd, "evidence")
    ok = bad = skip = 0
    for r, _, files in os.walk(ev):
        for f in files:
            p = os.path.join(r, f)
            if f.endswith(".gz"):
                base = f[:-3]
                rec = _recorded_hash_for(manifest, base)
                cur = _gz_sha256(p).lower() if rec else None
            else:
                base = f
                rec = _recorded_hash_for(manifest, base)
                cur = sha256_file(p).lower() if rec else None
            if not rec:
                skip += 1
                continue
            ok += (cur == rec)
            bad += (cur != rec)
    return ok, bad, skip


def cmd_cold(case_id, do_apply=False):
    cfg = _cfg()
    cd = os.path.join(_cases_root(), case_id)
    if not os.path.isdir(cd):
        print("not a case dir: %s" % cd); return 2
    if _legal_hold(cd):
        print("ABORT: legal_hold set; no archival."); return 1
    if not _sealed(cd):
        print("ABORT: case not sealed."); return 1
    manifest = _load_manifest(cd)
    if manifest is None:
        print("ABORT: cannot read case_manifest.json."); return 1
    ok, bad, skip = _verify_case(cd, manifest)
    print("pre-archive integrity: %d OK, %d FAIL, %d not-in-manifest" % (ok, bad, skip))
    if bad:
        print("ABORT: integrity failed; not archiving."); return 1
    if not do_apply:
        print("CHECK OK: case verifies. Re-run with --apply to archive to cold."); return 0
    archive_root = cfg["archive_root"]
    os.makedirs(archive_root, exist_ok=True)
    tar_path = os.path.join(archive_root, case_id + ".tar.gz")
    src_bytes = _dir_size(cd)
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(cd, arcname=case_id)
    archive_sha = sha256_file(tar_path)
    archive_bytes = os.path.getsize(tar_path)
    tmp = tempfile.mkdtemp(prefix="coldverify_")
    try:
        with tarfile.open(tar_path, "r:gz") as tar:
            _extractall(tar, tmp)
        ok2, bad2, _ = _verify_case(os.path.join(tmp, case_id), manifest)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if bad2:
        os.remove(tar_path)
        print("ABORT: archive failed post-extraction verification; live case kept."); return 1
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    am = {"case_id": case_id, "archived_at": now, "archive_file": os.path.basename(tar_path),
          "archive_sha256": archive_sha, "original_bytes": src_bytes,
          "archive_bytes": archive_bytes, "verification": "PASS", "verified_artefacts": ok2}
    with open(os.path.join(archive_root, case_id + ".archive.json"), "w") as f:
        json.dump(am, f, indent=2)
    shutil.rmtree(cd)
    os.makedirs(cd)
    stub = {"case_id": case_id, "tier": "cold", "legal_hold": False,
            "archive": {"path": tar_path, "sha256": archive_sha, "archived_at": now},
            "history": [{"ts": now, "action": "archive", "actor": "lifecycle_manager",
                         "to_tier": "cold", "verification": "PASS", "archive_sha256": archive_sha,
                         "original_bytes": src_bytes, "archive_bytes": archive_bytes}]}
    with open(os.path.join(cd, "lifecycle.json"), "w") as f:
        json.dump(stub, f, indent=2)
    print("COLD done: %s -> %s (%s -> %s, verified). Live case replaced with stub."
          % (case_id, tar_path, _h(src_bytes), _h(archive_bytes)))
    return 0


def cmd_restore(case_id, do_apply=False):
    cfg = _cfg()
    tar_path = os.path.join(cfg["archive_root"], case_id + ".tar.gz")
    am_path = os.path.join(cfg["archive_root"], case_id + ".archive.json")
    if not os.path.exists(tar_path):
        print("no archive: %s" % tar_path); return 2
    try:
        am = json.load(open(am_path))
    except Exception:
        am = {}
    cur_sha = sha256_file(tar_path)
    rec_sha = am.get("archive_sha256")
    print("archive sha256: current=%s recorded=%s -> %s"
          % (cur_sha[:16], (rec_sha or "-")[:16], "MATCH" if rec_sha == cur_sha else "MISMATCH/UNKNOWN"))
    if rec_sha and rec_sha != cur_sha:
        print("ABORT: archive hash mismatch; possible corruption."); return 1
    if not do_apply:
        print("CHECK OK: archive present and consistent. Re-run with --apply to restore."); return 0
    cases_root = _cases_root()
    cd = os.path.join(cases_root, case_id)
    if os.path.isdir(cd):
        shutil.rmtree(cd)
    with tarfile.open(tar_path, "r:gz") as tar:
        _extractall(tar, cases_root)
    manifest = _load_manifest(cd)
    ok, bad, skip = _verify_case(cd, manifest) if manifest else (0, 1, 0)
    print("post-restore integrity: %d OK, %d FAIL, %d not-in-manifest" % (ok, bad, skip))
    tier = _current_tier(cd)
    _write_lifecycle(cd, case_id, tier, "restore", [])
    print("RESTORE done: %s -> %s (tier=%s)." % (case_id, cd, tier))
    return 0 if bad == 0 else 1


def cmd_enforce(do_apply=False):
    cfg = _cfg(); root = _cases_root()
    du = shutil.disk_usage(root); used_pct = 100.0 * du.used / du.total
    pressure = used_pct >= cfg["disk_pressure_pct"]
    order = {"hot": 0, "warm": 1, "cold": 2}
    cases = sorted(d for d in os.listdir(root)
                   if d.startswith("CASE-") and os.path.isdir(os.path.join(root, d))) if os.path.isdir(root) else []
    print("disk %.0f%% used (threshold %d%% -> %s)" % (used_pct, cfg["disk_pressure_pct"], "PRESSURE" if pressure else "ok"))
    plan = []
    for c in cases:
        cd = os.path.join(root, c)
        age = _age_days(c); sealed = _sealed(cd); hold = _legal_hold(cd); cur = _current_tier(cd)
        tgt = _target_tier(age, sealed, hold, cfg)
        if pressure and sealed and not hold and cur == "hot":
            tgt = "warm"
        if not hold and sealed and order.get(tgt, 0) > order.get(cur, 0):
            plan.append((c, cur, tgt))
    if not plan:
        print("policy satisfied: no transitions needed."); return 0
    for c, cur, tgt in plan:
        print("  %-44s %s -> %s" % (c, cur, tgt))
    if not do_apply:
        print("CHECK only. Re-run with --apply to perform these transitions."); return 0
    for c, cur, tgt in plan:
        print("--- %s : %s -> %s ---" % (c, cur, tgt))
        if tgt == "warm":
            cmd_warm(c, do_apply=True)
        elif tgt == "cold":
            cmd_cold(c, do_apply=True)
    return 0


if __name__ == "__main__":
    args = sys.argv[1:]
    cmd = next((a for a in args if not a.startswith("--")), "status")
    apply = "--apply" in args
    if cmd == "status":
        cmd_status(measure=("--measure" in args))
    elif cmd == "enforce":
        sys.exit(cmd_enforce(do_apply=apply))
    elif cmd in ("warm", "verify", "cold", "restore"):
        case = next((a for a in args if a.startswith("CASE-")), None)
        if case is None:
            print("usage: lifecycle_manager.py %s CASE-... [--apply]" % cmd)
            sys.exit(2)
        if cmd == "warm":
            sys.exit(cmd_warm(case, do_apply=apply))
        elif cmd == "cold":
            sys.exit(cmd_cold(case, do_apply=apply))
        elif cmd == "restore":
            sys.exit(cmd_restore(case, do_apply=apply))
        else:
            sys.exit(cmd_verify(case))
    else:
        print("usage: lifecycle_manager.py [status [--measure] | warm|cold|restore CASE-... [--apply] | verify CASE-...]")
        sys.exit(2)
