"""
kcore_lime.py — segment-aware acquisition of physical memory from /proc/kcore.

Why this exists
    /proc/kcore is a *virtual ELF core file*. It starts with an ELF header, a
    program-header table and a note segment; each memory segment is placed at a
    file offset derived from its kernel virtual address. On the ARM64 testbed the
    first RAM segment lies ~27 TiB into the file, so reading the first N MiB
    sequentially (the original collector) captures only the header and zeros.

What this module does
    1. reads only the first 64 KiB of /proc/kcore from the monitored host;
    2. parses the program headers on the analysis node and keeps the PT_LOAD
       segments that map physical RAM (valid p_paddr), dropping aliases fully
       contained in a larger RAM segment (e.g. the kernel-text mapping) and every
       range without a physical address (vmalloc, modules, vmemmap);
    3. streams each RAM segment from the host with byte-exact offsets
       (dd iflag=skip_bytes,count_bytes) — no tool is installed on the host;
    4. writes the result in LiME format (Volatility 3 compatible), compressing
       on the fly because of the analysis node's storage budget, while computing
       SHA-256 over the uncompressed LiME stream (the canonical image) and per
       segment;
    5. runs a content-validity check (non-zero page ratio, short reads), because
       integrity hashing proves that bytes were not altered, not that they are
       meaningful.

The module is transport-agnostic: the caller supplies `runner(cmd) -> Popen`
whose stdout yields the remote command's output (SSH in production).

Wazuh-Based Automated Forensic Framework — Politecnico di Torino, MSc Cybersecurity 2026
"""

import hashlib
import os
import shutil
import struct
import subprocess
import time

PT_LOAD, PT_NOTE = 1, 4
NO_PADDR = 0xFFFFFFFFFFFFFFFF
LIME_MAGIC = 0x4C694D45      # "EMiL" little-endian
LIME_VERSION = 1
PAGE = 4096
ZERO_PAGE = bytes(PAGE)
HEADER_BYTES = 65536
CHUNK = 4 << 20
MIN_NONZERO_RATIO = 0.01     # content gate: at least 1 % of pages must be non-zero

KCORE = "/proc/kcore"


class KcoreError(Exception):
    pass


# --------------------------------------------------------------- ELF parsing
def parse_notes(buf, segs):
    """Extract VMCOREINFO key/values (kernel release, build id, KASLR offset)."""
    info = {}
    for s in segs:
        if s["type"] != PT_NOTE:
            continue
        pos, end = s["offset"], min(s["offset"] + s["filesz"], len(buf))
        while pos + 12 <= end:
            namesz, descsz, _ = struct.unpack_from("<III", buf, pos)
            pos += 12
            name = buf[pos:pos + namesz].rstrip(b"\0")
            pos += (namesz + 3) & ~3
            desc = buf[pos:pos + descsz]
            pos += (descsz + 3) & ~3
            if name == b"VMCOREINFO":
                for line in desc.decode("ascii", "replace").splitlines():
                    k, _, v = line.partition("=")
                    if k in ("OSRELEASE", "BUILD-ID", "KERNELOFFSET", "PAGESIZE"):
                        info[k] = v.strip("\0 ")
    return info


def parse_kcore_header(buf):
    if buf[:4] != b"\x7fELF":
        raise KcoreError("header is not an ELF file")
    if buf[4] != 2 or buf[5] != 1:
        raise KcoreError("only little-endian ELF64 kcore is supported")
    machine = struct.unpack_from("<H", buf, 18)[0]
    phoff = struct.unpack_from("<Q", buf, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", buf, 54)
    if phoff + phentsize * phnum > len(buf):
        raise KcoreError("program-header table extends beyond the fetched header")
    segs = []
    for i in range(phnum):
        t, _fl, off, va, pa, fsz, msz, _al = struct.unpack_from(
            "<IIQQQQQQ", buf, phoff + i * phentsize)
        segs.append({"index": i, "type": t, "offset": off, "vaddr": va,
                     "paddr": pa, "filesz": fsz, "memsz": msz})
    return machine, segs, parse_notes(buf, segs)


def select_ram_segments(segs):
    """PT_LOAD segments with a physical address; drop contained aliases."""
    cands = [s for s in segs if s["type"] == PT_LOAD and s["paddr"] != NO_PADDR
             and s["filesz"] > 0]
    cands.sort(key=lambda s: (-s["filesz"], s["index"]))
    chosen, skipped = [], []
    for s in cands:
        lo, hi = s["paddr"], s["paddr"] + s["filesz"]
        container = next((c for c in chosen
                          if c["paddr"] <= lo and hi <= c["paddr"] + c["filesz"]), None)
        if container is not None:
            skipped.append({**s, "reason": f"alias contained in segment {container['index']}"})
            continue
        if any(lo < c["paddr"] + c["filesz"] and c["paddr"] < hi for c in chosen):
            raise KcoreError(f"segment {s['index']} partially overlaps a RAM segment")
        chosen.append(s)
    chosen.sort(key=lambda s: s["paddr"])
    other = [s for s in segs if s["type"] == PT_LOAD and s["paddr"] == NO_PADDR]
    return chosen, skipped, other


# ------------------------------------------------------------- content gate
class PageStats:
    """Non-zero page ratio over a byte stream, by systematic sampling.

    Every `stride`-th 4 KiB page (by global page index) is inspected, which keeps
    the check off the critical path of acquisition; the decision threshold (1 %)
    is far from the values observed for real RAM, so sampling does not affect it.
    """

    def __init__(self, stride=8):
        self.stride = max(1, stride)
        self.total_pages = 0      # all pages seen
        self.pages = 0            # pages sampled
        self.nonzero = 0          # sampled pages that are not all-zero
        self._carry = b""

    def feed(self, data):
        buf = self._carry + data if self._carry else data
        n = len(buf) - len(buf) % PAGE
        mv = memoryview(buf)
        first = (-self.total_pages) % self.stride
        for i in range(first * PAGE, n, self.stride * PAGE):
            self.pages += 1
            if mv[i:i + PAGE] != ZERO_PAGE:
                self.nonzero += 1
        self.total_pages += n // PAGE
        self._carry = bytes(buf[n:])

    def finish(self):
        if self._carry:
            if self.total_pages % self.stride == 0:
                self.pages += 1
                if self._carry.strip(b"\0"):
                    self.nonzero += 1
            self.total_pages += 1
            self._carry = b""

    @property
    def ratio(self):
        return self.nonzero / self.pages if self.pages else 0.0


def content_verdict(stats, short_bytes):
    reasons = []
    if stats.pages == 0:
        reasons.append("no pages acquired")
    elif stats.ratio < MIN_NONZERO_RATIO:
        reasons.append(f"non-zero page ratio {stats.ratio:.4%} < {MIN_NONZERO_RATIO:.0%}")
    if short_bytes:
        reasons.append(f"{short_bytes} bytes missing from short reads (zero-padded)")
    return {"status": "pass" if not reasons else "fail",
            "total_pages": stats.total_pages, "sampled_pages": stats.pages,
            "sample_stride": stats.stride, "nonzero_sampled_pages": stats.nonzero,
            "nonzero_ratio": round(stats.ratio, 6),
            "threshold": MIN_NONZERO_RATIO, "reasons": reasons}


def check_image_bytes(stream_iter, stride=1):
    """Content gate for an existing image given as an iterable of byte chunks
    (exhaustive by default: used offline, not on the acquisition path)."""
    st = PageStats(stride)
    for chunk in stream_iter:
        st.feed(chunk)
    st.finish()
    return content_verdict(st, 0)


# -------------------------------------------------------------- acquisition
def _compressor_cmd():
    if shutil.which("pigz"):
        return ["pigz", "-1", "-c"]
    return ["gzip", "-1", "-c"]


def _run_capture(runner, cmd):
    p = runner(cmd)
    out = p.stdout.read()
    p.wait()
    return p.returncode, out


def read_plan(runner, kcore=KCORE):
    """Fetch and parse the kcore header; return (head, machine, segs, vmcoreinfo,
    ram, aliases, nonram). Only HEADER_BYTES are read from the monitored host."""
    rc, head = _run_capture(runner, f"dd if={kcore} bs={HEADER_BYTES} count=1 2>/dev/null")
    if len(head) < 64:
        raise KcoreError(f"could not read kcore header (rc={rc}, {len(head)} bytes)")
    machine, segs, vmcoreinfo = parse_kcore_header(head)
    ram, aliases, nonram = select_ram_segments(segs)
    if not ram:
        raise KcoreError("no physical-RAM segment found in kcore program headers")
    return head, machine, segs, vmcoreinfo, ram, aliases, nonram


def acquire(runner, out_path_gz, kcore=KCORE, max_bytes=0, log=print,
            plan_check=None, deadline=None):
    """
    Acquire physical memory as a gzip-compressed LiME image.

    runner(cmd)      -> subprocess.Popen with stdout=PIPE (the remote command).
    plan_check(n)    optional; called with the number of RAM bytes about to be
                     read, before the output file is created (pre-flight checks;
                     raise to abort without touching the evidence store).
    deadline         optional time.monotonic() value; past it the acquisition is
                     aborted instead of being zero-padded (the caller is expected
                     to kill hung transport processes, which unblocks reads).
    Returns the evidence-metadata dict (sha256 is over the UNCOMPRESSED image).
    """
    t0 = time.monotonic()
    head, machine, segs, vmcoreinfo, ram, aliases, nonram = read_plan(runner, kcore)
    log(f"kcore: {len(segs)} program headers, {len(ram)} RAM segment(s) "
        f"{sum(s['filesz'] for s in ram) / 2**20:.1f} MiB, "
        f"{len(aliases)} alias(es) and {len(nonram)} non-RAM range(s) skipped")
    planned = sum(s["filesz"] for s in ram)
    if max_bytes > 0:
        planned = min(planned, max_bytes)
    if plan_check is not None:
        plan_check(planned)

    def _expired():
        return deadline is not None and time.monotonic() > deadline

    whole = hashlib.sha256()
    stats = PageStats()
    budget = max_bytes if max_bytes > 0 else None
    seg_meta, short_total, total = [], 0, 0

    with open(out_path_gz, "wb") as fout:
        comp = subprocess.Popen(_compressor_cmd(), stdin=subprocess.PIPE, stdout=fout)

        def emit(b):
            whole.update(b)
            comp.stdin.write(b)

        for s in ram:
            size = s["filesz"] if budget is None else min(s["filesz"], budget)
            if size <= 0:
                break
            emit(struct.pack("<IIQQQ", LIME_MAGIC, LIME_VERSION,
                             s["paddr"], s["paddr"] + size - 1, 0))
            seg_hash = hashlib.sha256()
            got = 0
            p = runner(f"dd if={kcore} iflag=skip_bytes,count_bytes "
                       f"skip={s['offset']} count={size} bs={CHUNK} 2>/dev/null")
            while got < size:
                chunk = p.stdout.read(min(CHUNK, size - got))
                if not chunk:
                    break
                got += len(chunk)
                seg_hash.update(chunk)
                stats.feed(chunk)
                emit(chunk)
            p.stdout.close()
            p.wait()
            short = size - got
            if short and _expired():
                comp.stdin.close()
                comp.wait()
                raise KcoreError(f"acquisition timed out in segment paddr={s['paddr']:#x} "
                                 f"after {got} of {size} bytes")
            if short:
                pad = bytes(min(short, CHUNK))
                left = short
                while left:
                    piece = pad[:min(left, len(pad))]
                    seg_hash.update(piece)
                    stats.feed(piece)
                    emit(piece)
                    left -= len(piece)
            short_total += short
            total += size
            if budget is not None:
                budget -= size
            seg_meta.append({"paddr": hex(s["paddr"]), "size": size,
                             "kcore_offset": hex(s["offset"]), "vaddr": hex(s["vaddr"]),
                             "sha256": seg_hash.hexdigest(), "short_bytes": short})
        comp.stdin.close()
        comp.wait()
        if comp.returncode != 0:
            raise KcoreError(f"compressor exited with status {comp.returncode}")
        fout.flush()
        os.fsync(fout.fileno())
    stats.finish()
    elapsed = time.monotonic() - t0

    h = hashlib.sha256()
    with open(out_path_gz, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)

    verdict = content_verdict(stats, short_total)
    return {
        "type": "memory",
        "format": "lime",
        "method": "kcore_segments",
        "sha256": whole.hexdigest(),               # uncompressed LiME image
        "size": total + 32 * len(seg_meta),       # uncompressed LiME bytes
        "stored_path": out_path_gz,
        "stored_sha256": h.hexdigest(),
        "stored_size": os.path.getsize(out_path_gz),
        "compression": " ".join(_compressor_cmd()[:2]),
        "ram_bytes": total,
        "partial": max_bytes > 0 and total < sum(s["filesz"] for s in ram),
        "segments": seg_meta,
        "skipped_aliases": [{"paddr": hex(a["paddr"]), "size": a["filesz"],
                             "reason": a["reason"]} for a in aliases],
        "kcore_header_sha256": hashlib.sha256(head).hexdigest(),
        "elf_machine": machine,
        "vmcoreinfo": vmcoreinfo,
        "acquisition_seconds": round(elapsed, 3),
        "throughput_mib_s": round(total / 2**20 / elapsed, 1) if elapsed else None,
        "content_check": verdict,
    }


def probe(runner, kcore=KCORE, sample_bytes=16 << 20):
    """Pre-campaign smoke test: parse the header, then read `sample_bytes` from
    the middle of the largest RAM segment and report whether real content comes
    back (non-zero ratio) and at what transport throughput. Writes nothing."""
    head, machine, segs, vmcoreinfo, ram, aliases, nonram = read_plan(runner, kcore)
    main = max(ram, key=lambda s: s["filesz"])
    n = min(sample_bytes, main["filesz"])
    off = main["offset"] + ((main["filesz"] - n) // 2) // PAGE * PAGE
    st = PageStats(stride=1)
    t0 = time.monotonic()
    p = runner(f"dd if={kcore} iflag=skip_bytes,count_bytes skip={off} count={n} "
               f"bs={CHUNK} 2>/dev/null")
    got = 0
    while got < n:
        b = p.stdout.read(min(CHUNK, n - got))
        if not b:
            break
        got += len(b)
        st.feed(b)
    p.stdout.close()
    p.wait()
    st.finish()
    dt = time.monotonic() - t0
    return {"elf_machine": machine, "program_headers": len(segs),
            "vmcoreinfo": vmcoreinfo,
            "ram_segments": [{"paddr": hex(s["paddr"]), "size": s["filesz"],
                              "kcore_offset": hex(s["offset"])} for s in ram],
            "ram_bytes": sum(s["filesz"] for s in ram),
            "aliases_skipped": len(aliases), "nonram_ranges_skipped": len(nonram),
            "sample_offset": hex(off), "sample_requested": n, "sample_read": got,
            "sample_nonzero_ratio": round(st.ratio, 4),
            "sample_seconds": round(dt, 3),
            "sample_mib_s": round(got / 2**20 / dt, 1) if dt else None,
            "verdict": ("pass" if got == n and st.ratio >= MIN_NONZERO_RATIO else "fail")}


def iter_lime(fileobj):
    """Yield (s_addr, e_addr, data_reader_length) records from an uncompressed LiME stream."""
    while True:
        hdr = fileobj.read(32)
        if not hdr:
            return
        magic, ver, s, e, _ = struct.unpack("<IIQQQ", hdr)
        if magic != LIME_MAGIC or ver != LIME_VERSION:
            raise KcoreError("invalid LiME record header")
        yield s, e, e - s + 1
