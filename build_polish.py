
import os
import json, ssl, base64, urllib.request, urllib.error
OSD = "https://localhost"; USER, PASS = "admin", os.environ.get("OS_PASS", "CHANGE_ME")
TEAL, BLUE, AMBER = "#54B399", "#6092C0", "#E7664C"

def _http(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(OSD + path, data=data, method=method)
    r.add_header("Authorization", "Basic " + base64.b64encode(("%s:%s" % (USER, PASS)).encode()).decode())
    r.add_header("osd-xsrf", "true"); r.add_header("Content-Type", "application/json")
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(r, context=ctx) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        try: return e.code, json.load(e)
        except Exception: return e.code, {"raw": e.read().decode("utf-8", "replace")}

def markdown(vid, obj_title, md):
    vs = {"title": "", "type": "markdown", "aggs": [],
          "params": {"fontSize": 12, "openLinksInNewTab": True, "markdown": md}}
    body = {"attributes": {"title": obj_title, "visState": json.dumps(vs), "uiStateJSON": "{}",
            "description": "", "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})}},
            "references": []}
    st, _ = _http("POST", "/api/saved_objects/visualization/%s?overwrite=true" % vid, body)
    print("md  %-12s -> %s" % (vid, st))

def dashboard(panels):
    refs, pjson = [], []
    for i, (t, oid, w, h, x, y, emb) in enumerate(panels):
        name = "panel_%d" % i; refs.append({"name": name, "type": t, "id": oid})
        pjson.append({"version": "2.19.4", "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
                      "panelIndex": str(i), "embeddableConfig": emb, "panelRefName": name})
    body = {"attributes": {"title": "Forensic Automation",
            "description": "Harmonizing IDS detection with automated digital forensics - live metrics from sealed case records and Wazuh alerts",
            "panelsJSON": json.dumps(pjson), "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "version": 1, "timeRestore": True, "timeTo": "now", "timeFrom": "now-90d",
            "refreshInterval": {"pause": True, "value": 0},
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})}},
            "references": refs}
    st, _ = _http("POST", "/api/saved_objects/dashboard/fa-dashboard?overwrite=true", body)
    print("dashboard -> %s" % st)

markdown("fa-md-a", "Layer A",
         "**AUTOMATED FORENSIC RESPONSE**  \u00b7  [Open Forensic Reports \u2192](http://192.168.64.8:8088)\n\nLive metrics computed directly from sealed case records: detection \u2192 evidence collection \u2192 sealed chain of custody. Counts reflect controlled PoC validation runs, not real-world attack frequencies.")
markdown("fa-md-b", "Layer B",
         "**DETECTION LAYER \u2014 WAZUH IDS**\n\n73 raw IDS detections consolidate into 18 incident-level forensic cases through deduplication (NIST SP 800-61).")

HIDE = {"title": ""}
C_TIER = {"vis": {"colors": {"hot": AMBER, "warm": TEAL, "cold": BLUE}}}
C_TECH = {"vis": {"colors": {"T1003.008": TEAL, "T1136.001": BLUE, "T1070.002": AMBER}}}
dashboard([
    ("visualization", "fa-md-a",          48, 6,  0,  0,  HIDE),
    ("visualization", "fa-mtte-mean",     12, 10, 0,  4,  {}),
    ("visualization", "fa-speedup-mean",  12, 10, 12, 4,  {}),
    ("visualization", "fa-cases-total",   12, 10, 24, 4,  {}),
    ("visualization", "fa-custody-sealed",12, 10, 36, 4,  {}),
    ("visualization", "fa-tiers",         24, 15, 0,  14, C_TIER),
    ("visualization", "fa-mitre",         24, 15, 24, 14, C_TECH),
    ("visualization", "fa-mtte-bar",      48, 15, 0,  29, {}),
    ("search",        "fa-table",         48, 20, 0,  44, {}),
    ("visualization", "fa-md-b",          48, 6,  0,  64, HIDE),
    ("visualization", "fa-ids-count",     12, 15, 0,  68, {}),
    ("visualization", "fa-ids-timeline",  36, 15, 12, 68, {}),
    ("visualization", "fa-ids-mitre",     48, 15, 0,  83, C_TECH),
])
print("done.")
