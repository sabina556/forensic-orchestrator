"""
volatility_analyzer.py — run Volatility 3 plugins against a memory image.

For demonstration, analysis targets a REFERENCE Linux memory image
(config: analyzers.volatility.reference_image) because pre-built kernel
symbols (ISF) for the Agent's ARM kernel (6.8.0-110-generic aarch64) are
not available. This is documented in the thesis as a deployment
prerequisite (§9.2 Future Work). The framework's analyzer-integration
capability is fully demonstrated; only ARM-native symbol generation is
deferred.

Findings are written to: <case>/findings/volatility/<plugin>.txt
Returns a dict: {engine, mode, image, plugins:{name:{path,sha256,lines}}}

Wazuh-Based Automated Forensic Framework
Politecnico di Torino — MSc Cybersecurity 2026
"""

import os

from common import (
    load_config,
    get_logger,
    run_local,
    sha256_file,
    utc_now,
)

log = get_logger("analyzer.volatility")


def analyze_memory(case_dir, memory_artifact=None):
    cfg = load_config()["analyzers"]["volatility"]
    if not cfg.get("enabled", False):
        return {"engine": "volatility3", "mode": "disabled", "plugins": {}}

    vol_bin = cfg["vol_bin"]
    ref_image = cfg["reference_image"]
    demo_mode = cfg.get("demonstration_mode", True)

    out_dir = os.path.join(case_dir, "findings", "volatility")
    os.makedirs(out_dir, exist_ok=True)

    # Decide which image to analyze.
    # In demonstration_mode we always use the reference image (symbols exist).
    image = ref_image
    if not os.path.exists(image):
        log.error("Reference image not found: %s", image)
        return {
            "engine": "volatility3",
            "mode": "error",
            "image": image,
            "error": "reference image missing",
            "plugins": {},
        }

    results = {
        "engine": "volatility3",
        "mode": "demonstration" if demo_mode else "endpoint",
        "image": image,
        "analyzed_at": utc_now(),
        "plugins": {},
    }

    for plugin in cfg.get("plugins", []):
        safe = plugin.replace(".", "_")
        out_path = os.path.join(out_dir, f"{safe}.txt")
        cmd = f"{vol_bin} -q -f {image} {plugin}"
        log.info("Running Volatility plugin: %s", plugin)
        rc, out, err = run_local(cmd, timeout=600)

        # Volatility prints progress to stderr; capture stdout as findings
        content = out if out else ""
        if rc != 0 and not content:
            content = f"[plugin error rc={rc}]\n{err[:500]}"

        with open(out_path, "w") as f:
            f.write(content)

        results["plugins"][plugin] = {
            "path": out_path,
            "sha256": sha256_file(out_path),
            "lines": content.count("\n"),
            "ok": rc == 0,
        }
        log.info("Plugin %s -> %d lines (rc=%s)",
                 plugin, content.count("\n"), rc)

    return results
