#!/usr/bin/env python3
"""Stratum B content validation: stream a memory image (raw/LiME, optionally gzip)
through a YARA marker rule. Read-only on evidence; writes JSON report only."""
import sys, os, gzip, json, hashlib, datetime, yara

CHUNK, OVERLAP = 64 * 1024 * 1024, 4096

def opener(p):
    with open(p, 'rb') as f:
        magic = f.read(2)
    return gzip.open(p, 'rb') if magic == b'\x1f\x8b' else open(p, 'rb')

def offsets(s):
    if isinstance(s, tuple):                     # yara-python < 4.3
        return [s[0]]
    return [i.offset for i in s.instances]       # yara-python >= 4.3

def main(case, img, marker, outdir):
    rule = yara.compile(source='rule stratb_marker { strings: $m = "%s" ascii wide nocase '
                               'condition: $m }' % marker.replace('"', '\\"'))
    h = hashlib.sha256()
    with open(img, 'rb') as f:
        for b in iter(lambda: f.read(CHUNK), b''):
            h.update(b)
    hits, total, nonzero, pos, tail, head = set(), 0, 0, 0, b'', None
    with opener(img) as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            if head is None:
                head = b[:4]
            buf, base = tail + b, pos - len(tail)
            for m in rule.match(data=buf):
                for s in m.strings:
                    hits.update(base + o for o in offsets(s))
            total += len(b); nonzero += len(b) - b.count(0)
            pos += len(b); tail = buf[-OVERLAP:]
    rep = {
        "case": case, "image": img, "image_sha256": h.hexdigest(),
        "decompressed_bytes": total, "nonzero_bytes": nonzero,
        "lime_magic": head == b'EMiL', "marker": marker,
        "hits": len(hits), "first_offsets": sorted(hits)[:10],
        "yara_version": yara.__version__,
        "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    os.makedirs(outdir, exist_ok=True)
    out = os.path.join(outdir, f"yara_{marker}.json")
    with open(out, 'w') as f:
        json.dump(rep, f, indent=2)
    print(json.dumps(rep))

if __name__ == '__main__':
    main(*sys.argv[1:5])
