"""
verify_chain.py — verify the integrity of the hash-chained custody ledger.

Recomputes each record's hash from its content and the previous hash, and
confirms the stored chain matches. Detects any edited, inserted, or removed
record. Run manually:  python3 chain_of_custody/verify_chain.py

Wazuh-Based Automated Forensic Framework
Politecnico di Torino — MSc Cybersecurity 2026
"""

import hashlib
import json
import sys

from common import load_config


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_chain():
    path = load_config()["chain_of_custody"]["custody_log"]
    try:
        with open(path, "r") as f:
            lines = [ln for ln in f.readlines() if ln.strip()]
    except FileNotFoundError:
        print(f"[!] Custody log not found: {path}")
        return False

    if not lines:
        print("[!] No records to verify")
        return False

    previous_hash = None
    for index, line in enumerate(lines):
        record = json.loads(line)
        chain = record.get("chain")
        if not chain:
            print(f"[X] Missing chain at record {index}")
            return False

        expected_prev = chain.get("prev_hash")
        current_hash = chain.get("current_hash")

        record_copy = dict(record)
        record_copy.pop("chain")
        record_bytes = json.dumps(record_copy, sort_keys=True).encode()

        if expected_prev == "Genesis":
            recalculated = _sha256(record_bytes)
        else:
            recalculated = _sha256(expected_prev.encode() + record_bytes)

        if current_hash != recalculated:
            print(f"[X] Chain broken at record {index}")
            print(f"    Expected: {recalculated}")
            print(f"    Found:    {current_hash}")
            return False

        if previous_hash is not None and expected_prev != previous_hash:
            print(f"[X] prev_hash mismatch at record {index}")
            return False

        previous_hash = current_hash

    print(f"[Success] Chain integrity verified: {len(lines)} record(s) intact")
    return True


if __name__ == "__main__":
    ok = verify_chain()
    sys.exit(0 if ok else 1)
