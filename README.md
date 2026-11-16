# Automated Forensic Evidence Collection Triggered by Intrusion Detection

A proof-of-concept framework that couples a Wazuh-based intrusion-detection layer to an
automated digital-forensic collection pipeline. When a monitored host exhibits adversarial
activity, a detection alert triggers the acquisition of sixteen forensic artefacts from that host
(live process and network state, physical memory, logs, security-relevant files and a filesystem
timeline), without human action and without installing an acquisition tool on the host. Every
artefact is hashed at acquisition and sealed into a hash-chained, independently verifiable custody
ledger.

This repository accompanies the MSc thesis *"Automated Forensic Evidence Collection Triggered by
Intrusion Detection: Design and Evaluation of a Wazuh-Based Pipeline with a Verifiable Chain of
Custody"* (Sabina Tursunova, Politecnico di Torino, MSc in Cybersecurity). It is a research proof
of concept, not production software.

---

## Research questions

> To what extent can digital-forensic evidence collection be automated in direct response to an
> intrusion-detection alert, and what does such automation yield in terms of speed and evidential
> quality relative to a manual approach?

- **RQ1 (Feasibility).** Can an alert trigger a complete, unattended collection across distinct
  classes of adversarial activity?
- **RQ2 (Efficiency).** What is the time-to-evidence, and how does it compare with manual
  collection?
- **RQ3 (Forensic soundness).** Is the collected evidence complete, unaltered, uncontaminated by
  the collector and verifiable by a third party?

## Key results

The evaluation uses two datasets that are never pooled (thesis, Chapter 6).

**Main evaluation set (stratum A), n = 34 cases, five ATT&CK techniques.**

- Every case was opened by a detection alert and collected without human action; 103 raw
  detections were consolidated into incident-level cases.
- All 578 hashed artefacts matched their recorded digests; the custody ledger verified intact;
  a deliberate alteration of one artefact was detected and localised.
- Every case was reconstructed into a super-timeline; median detection latency (command to alert)
  1.23 s over 28 cases.
- **Memory defect.** The memory step of this set (`dd if=/proc/kcore bs=1M count=256`) captured
  only the ELF header of the sparse `/proc/kcore` file and no physical memory. The claim that
  memory was acquired in this set is withdrawn. Its time-to-evidence of 5.02 ± 1.18 s (about 86×
  faster than a modelled manual procedure with the same memory step) is reported only as a
  like-for-like comparison.

**Corrected configuration (stratum B), n = 5 cases, one per technique.**

- Segment-aware acquisition of `/proc/kcore` into LiME: every image covered all System RAM of the
  host (2,142,371,840 bytes), verified against its canonical SHA-256, with 94.6–94.8 % non-zero
  pages.
- The ground-truth marker of each incident was found in its image (5/5); no marker appeared in any
  image acquired before it existed (16 pairs); a canary test was passed and replicated under a
  pre-registered protocol.
- Time-to-evidence with complete memory: **37.9 ± 7.3 s**, at least about **12×** faster than a
  conservative Keystroke-Level Model of the manual procedure (≥ 458 s). The ratio is bounded by the
  memory transfer (~30 s), which costs the same for an analyst and for the pipeline.

---

## Architecture

```
 Monitored host (Wazuh agent)
        | auth.log, journal
        v
 Wazuh manager  -- rule match (5 custom rules, ATT&CK-annotated) -->  alert (JSON)
        |  integration subsystem: custom-forensic -> HTTP POST, loopback only
        v
 Forensic orchestrator (systemd service)
   1. incident consolidation      key (rule, agent), 300 s window (NIST SP 800-61)
   2. collectors, order recorded  live state -> memory -> logs -> files   (order: rfc3227)
      over SSH, standard tools    memory: RAM segments of /proc/kcore -> LiME, content gate
   3. SHA-256 per artefact        canonical digest of memory = uncompressed LiME image
   4. hash-chained custody ledger append-only, verified by an independent tool
        v
 Evidence store (tiered: hot / warm / cold, nothing deleted)
        v
 Read-only layer: PDF reports on demand (report portal), super-timeline, dashboard
```

Evidence is acquired **from** the monitored host and preserved **on** the manager node, so that
the act of collection remains distinguishable from the activity under investigation.

---

## Detection coverage

| Rule   | Technique | Tactic            | Triggering action                                   |
|--------|-----------|-------------------|-----------------------------------------------------|
| 100210 | T1003.008 | Credential Access | Privileged read of `/etc/shadow`                    |
| 100220 | T1136.001 | Persistence       | Creation of a local user account                    |
| 100240 | T1070.002 | Defense Evasion   | Clearing of the authentication log                  |
| 100250 | T1087.001 | Discovery         | Privileged read of `/etc/passwd` or `/etc/group`    |
| 100260 | T1059.004 | Execution         | Shell `-c` with a download / reverse-shell / encoding primitive |

Rules 100210, 100240, 100250 and 100260 are children of the `sudo` command rules (5402/5403) and
fire only on commands that `sudo` records; rule 100220 is a child of the account-creation rule
(5902). Detection and collection are decoupled: a technique is added by defining a rule and adding
its identifier to the integration filter, without changing the pipeline.

---

## Repository structure

```
forensic-orchestrator/
├── orchestrator.py              # HTTP ingest service; pipeline, collection profile, sealing
├── incident_dedup.py            # incident-level alert consolidation (NIST SP 800-61)
├── common.py                    # configuration, SSH runner, hashing, logging
├── config.yaml                  # orchestrator / agent / collection / lifecycle configuration
│
├── collectors/
│   ├── process_network.py       # ps, ss, lsof
│   ├── memory.py                # method selection: kcore (legacy) | kcore_segments | none
│   ├── kcore_lime.py            # segment-aware /proc/kcore -> LiME, content gate, probe
│   ├── logs.py                  # journal (24 h), auth.log
│   └── filesystem.py            # critical files, filesystem metadata timeline
│
├── analyzers/
│   ├── supertimeline.py         # read-only super-timeline and detection latency
│   ├── tsk_analyzer.py          # Sleuth Kit timeline
│   └── volatility_analyzer.py   # disabled on the ARM64 testbed
│
├── chain_of_custody/
│   ├── __init__.py              # ledger writer: SHA-256(prev_hash || record)
│   └── verify_chain.py          # independent verifier
│
├── lifecycle_manager.py         # tiered retention, archive/restore, verify (incl. LiME gunzip)
├── reporting/report_generator.py  # forensic and full PDF reports from the case manifest
├── report_portal.py             # per-case report browsing and download (on demand)
├── dashboard_exporter.py        # per-dataset indices: forensic-cases (A), forensic-cases-b (B)
└── storage/
    ├── cases/                   # per-case evidence, manifest, custody record
    ├── analysis/                # super-timeline outputs (outside the sealed cases)
    └── archive/                 # cold-tier archives
```

---

## Requirements

- **Manager node:** Ubuntu 22.04 (tested on ARM64), Wazuh manager / indexer / dashboard 4.14,
  Python 3.10+, The Sleuth Kit, `pigz` (recommended for on-the-fly compression of memory images).
- **Monitored host:** Linux with the Wazuh agent; `/proc/kcore` readable by root (not available
  under kernel lockdown in confidentiality mode). Tested on Ubuntu 24.04, ARM64, kernels 6.8.0.
- **Connectivity:** key-based SSH from the manager to the monitored host.
- **Storage:** the evidence store must hold a worst-case uncompressed memory image plus a
  configurable reserve (default 2 GiB); the collector refuses to acquire otherwise.

---

## Configuration

Core settings live in `config.yaml` (excerpt in Appendix B of the thesis):

- `orchestrator` — loopback ingest endpoint, `debounce_window_seconds` (300).
- `agent` — host, SSH user and key, SSH options (cipher).
- `collection` — `memory_method` (`kcore` legacy | `kcore_segments`), `order`
  (`legacy` | `rfc3227`), memory reserve and watchdog timeout, critical files, metadata
  directories.
- `lifecycle` — hot / cold age windows, disk-pressure threshold, `retention_days: 0` (never
  delete).

The collection profile (memory method and order) is recorded in every case manifest.

---

## Running

1. Deploy the Wazuh manager and agent; register the agent.
2. Install `local_rules.xml` and the `custom-forensic` integration on the manager (Appendix B).
3. Configure `config.yaml` and the SSH key; check memory access with
   `python3 -m collectors.memory --probe` (reads a sample, writes no evidence).
4. Start the orchestrator and the report portal (`systemd` services).
5. On a detection, the pipeline runs automatically; sealed cases appear under `storage/cases/`.

Verification:

```bash
PYTHONPATH=. python3 chain_of_custody/verify_chain.py      # custody ledger
python3 lifecycle_manager.py verify <CASE_ID>              # per-artefact digests (incl. memory)
```

---

## Status and scope

Research proof of concept, evaluated on a single monitored host with emulated adversarial
triggers. Not production software: it acquires as `root` over SSH with host-key verification
disabled in the testbed configuration, uses a minimal rule set, collects host-based evidence only,
and does not analyse memory on ARM64. The memory image is a live, non-atomic acquisition (page
smearing). These limits and the work needed for production are discussed in Chapters 7 and 8 of
the thesis.

---

## Author

**Sabina Tursunova** — MSc in Cybersecurity, Politecnico di Torino.
Supervisor: Prof. Andrea Atzeni.
