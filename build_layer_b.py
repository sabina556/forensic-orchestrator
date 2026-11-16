#!/usr/bin/env python3
import os
"""Layer B (IDS detections on wazuh-alerts-*) + reassemble the unified
'Forensic Automation' dashboard with two sections (IDS layer / forensic layer),
markdown headers and a consistent palette. Idempotent (overwrite=true)."""
import json, ssl, base64, urllib.request, urllib.error

OSD = "https://localhost"; USER, PASS = "admin", os.environ.get("OS_PASS", "CHANGE_ME")
ALERTS_REF = {"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
              "type": "index-pattern", "id": "wazuh-alerts-*"}
CASES_REF = {"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
             "type": "index-pattern", "id": "forensic-cases"}
TEAL, BLUE, AMBER = "#54B399", "#6092C0", "#E7664C"
PURPLE, GOLD = "#8E6FB3", "#C9A227"          # same hues as the per-case MTTE figure

# v2 evaluation window (frozen). The upper bound keeps the IDS-layer count at the
# v2 value (103) when stratum-B experiments add new trigger alerts later, and the
# dashboard opens on this absolute range so Figure 6.2 is reproducible.
V2_FROM = "2026-06-01T00:00:00.000Z"
V2_TO = "2026-10-16T00:00:00.000Z"


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


def _ss(query, with_index=True):
    d = {"query": {"language": "kuery", "query": query or ""}, "filter": []}
    if with_index:
        d["indexRefName"] = "kibanaSavedObjectMeta.searchSourceJSON.index"
    return json.dumps(d)


def viz_alerts(vid, title, vis_state, query=""):
    body = {"attributes": {"title": title, "visState": json.dumps(vis_state),
            "uiStateJSON": "{}", "description": "", "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": _ss(query)}},
            "references": [ALERTS_REF]}
    st, resp = _http("POST", "/api/saved_objects/visualization/%s?overwrite=true" % vid, body)
    print("viz  %-18s -> %s %s" % (vid, st, resp.get("id", resp)))


def markdown(vid, title, md):
    vs = {"title": "", "type": "markdown", "aggs": [],
          "params": {"fontSize": 13, "openLinksInNewTab": True, "markdown": md}}
    body = {"attributes": {"title": title, "visState": json.dumps(vs), "uiStateJSON": "{}",
            "description": "", "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": _ss("", with_index=False)}},
            "references": []}
    st, resp = _http("POST", "/api/saved_objects/visualization/%s?overwrite=true" % vid, body)
    print("md   %-18s -> %s %s" % (vid, st, resp.get("id", resp)))


def metric_count(label):
    return {"title": "", "type": "metric",
            "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric",
                      "params": {"customLabel": label}}],
            "params": {"addTooltip": True, "addLegend": False, "type": "metric",
                       "metric": {"percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                                  "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 1000000}],
                                  "labels": {"show": True}, "invertColors": False,
                                  "style": {"bgColor": False, "labelColor": False, "subText": "", "fontSize": 56}}}}


def bar_base(ytitle, rotate):
    return {"type": "histogram", "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True,
                              "scale": {"type": "linear"},
                              "labels": {"show": True, "rotate": rotate, "filter": True, "truncate": 100}, "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True,
                           "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                           "title": {"text": ytitle}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                              "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
                              "drawLinesBetweenPoints": True, "showCircles": True}],
            "addTooltip": True, "addLegend": True, "legendPosition": "right", "times": [], "addTimeMarker": False}


def timeline_vis():
    return {"title": "", "type": "histogram", "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "timestamp", "useNormalizedOpenSearchInterval": True, "interval": "auto",
                    "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {"field": "rule.id", "size": 5, "order": "desc", "orderBy": "1"}}],
        "params": bar_base("detections", 0)}


def viz_cases(vid, title, vis_state, query=""):
    body = {"attributes": {"title": title, "visState": json.dumps(vis_state),
            "uiStateJSON": "{}", "description": "", "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": _ss(query)}},
            "references": [CASES_REF]}
    st, resp = _http("POST", "/api/saved_objects/visualization/%s?overwrite=true" % vid, body)
    print("viz  %-18s -> %s %s (forensic-cases)" % (vid, st, resp.get("id", resp)))


def timeline_cases_vis():
    return {"title": "", "type": "histogram", "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
         "params": {"field": "detected_at", "useNormalizedOpenSearchInterval": True, "interval": "auto",
                    "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}},
        {"id": "3", "enabled": True, "type": "terms", "schema": "group",
         "params": {"field": "rule_id", "size": 5, "order": "desc", "orderBy": "1"}}],
        "params": bar_base("detections", 0)}


def terms_bar_vis(field, ytitle, size=10):
    return {"title": "", "type": "histogram", "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {"field": field, "size": size, "order": "desc", "orderBy": "1"}}],
        "params": bar_base(ytitle, 0)}


def dashboard(did, title, panels):
    refs, pjson = [], []
    for i, (otype, oid, w, h, x, y, emb) in enumerate(panels):
        name = "panel_%d" % i
        refs.append({"name": name, "type": otype, "id": oid})
        pjson.append({"version": "2.19.4", "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
                      "panelIndex": str(i), "embeddableConfig": emb, "panelRefName": name})
    body = {"attributes": {"title": title,
            "description": "Harmonizing IDS detection with automated digital forensics - live metrics from sealed case records and Wazuh alerts",
            "panelsJSON": json.dumps(pjson),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "version": 1, "timeRestore": True, "timeFrom": V2_FROM, "timeTo": V2_TO,
            "refreshInterval": {"pause": True, "value": 0},
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})}},
            "references": refs}
    st, resp = _http("POST", "/api/saved_objects/dashboard/%s?overwrite=true" % did, body)
    print("dashboard %-13s -> %s %s" % (did, st, resp.get("id", resp)))


TRIG = "rule.id:(100210 or 100220 or 100240 or 100250 or 100260) and timestamp < \"" + V2_TO + "\" and not (timestamp >= \"2026-08-16T20:00:00.000Z\" and timestamp <= \"2026-08-16T21:30:00.000Z\") and not (timestamp >= \"2026-08-30T00:00:00.000Z\" and timestamp <= \"2026-08-30T23:59:59.000Z\")"

# --- markdown section headers ---
markdown("fa-md-a", "Section A header",
         "## Automated Forensic Response  \u00b7  [Open Forensic Reports \u2192](http://192.168.64.8:8088)\nLive metrics from **sealed case records**: detection \u2192 evidence collection \u2192 sealed chain of custody. Mean time-to-evidence ~5 s.")
markdown("fa-md-b", "Section B header",
         "## Detection Layer \u2014 Wazuh IDS\nThe detection layer that triggers the pipeline. Many alerts collapse into far fewer **incident-level forensic cases** via deduplication (NIST SP 800-61).")

# --- Layer B visualizations (wazuh-alerts) ---
viz_alerts("fa-ids-count", "Forensic-Trigger Detections (IDS)", metric_count("IDS detections"), TRIG)
viz_cases("fa-ids-timeline", "Trigger Detections over Time", timeline_cases_vis(), "case_kind:detection")
viz_alerts("fa-ids-mitre", "Detected Techniques (IDS layer)", terms_bar_vis("rule.mitre.id", "detections", 10), TRIG)

# --- unified dashboard: Layer A (existing ids) + Layer B ---
C_TIER = {"vis": {"colors": {"hot": AMBER, "warm": TEAL, "cold": BLUE}}}
C_TECH = {"vis": {"colors": {"T1003.008": TEAL, "T1136.001": BLUE, "T1070.002": AMBER,
                             "T1087.001": PURPLE, "T1059.004": GOLD}}}
dashboard("fa-dashboard", "Forensic Automation", [
    ("visualization", "fa-md-a",         48, 4,  0,  0,  {}),
    ("visualization", "fa-mtte-mean",    12, 10, 0,  4,  {}),
    ("visualization", "fa-speedup-mean", 12, 10, 12, 4,  {}),
    ("visualization", "fa-cases-total",  12, 10, 24, 4,  {}),
    ("visualization", "fa-custody-sealed",12,10, 36, 4,  {}),
    ("visualization", "fa-tiers",        24, 15, 0,  14, C_TIER),
    ("visualization", "fa-mitre",        24, 15, 24, 14, C_TECH),
    ("visualization", "fa-mtte-bar",     48, 15, 0,  29, {}),
    ("search",        "fa-table",        48, 20, 0,  44, {}),
    ("visualization", "fa-md-b",         48, 4,  0,  64, {}),
    ("visualization", "fa-ids-count",    12, 15, 0,  68, {}),
    ("visualization", "fa-ids-timeline", 36, 15, 12, 68, {}),
    ("visualization", "fa-ids-mitre",    48, 15, 0,  83, C_TECH),
])
print("done.")
