
import os
"""Build the 'Forensic Automation' dashboard in OpenSearch Dashboards
(Wazuh, OSD 2.19.4) via the Saved Objects API. Idempotent (overwrite=true).
All panels read the 'forensic-cases' index populated from sealed case records."""
import json, ssl, base64, urllib.request, urllib.error

OSD = "https://localhost"
USER, PASS = "admin", os.environ.get("OS_PASS", "CHANGE_ME")
IDX = "forensic-cases"
IDX_REF = {"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
           "type": "index-pattern", "id": IDX}


def _http(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(OSD + path, data=data, method=method)
    req.add_header("Authorization", "Basic " +
                   base64.b64encode(("%s:%s" % (USER, PASS)).encode()).decode())
    req.add_header("osd-xsrf", "true")
    req.add_header("Content-Type", "application/json")
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


def _search_source(query):
    return json.dumps({"query": {"language": "kuery", "query": query or ""},
                       "filter": [],
                       "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})


def viz(vid, title, vis_state, query=""):
    body = {"attributes": {
        "title": title,
        "visState": json.dumps(vis_state),
        "uiStateJSON": "{}",
        "description": "",
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source(query)},
    }, "references": [IDX_REF]}
    st, resp = _http("POST", "/api/saved_objects/visualization/%s?overwrite=true" % vid, body)
    print("viz    %-20s -> %s %s" % (vid, st, resp.get("id", resp)))


def metric_vis(agg, field, label, subtext=""):
    a = {"id": "1", "enabled": True, "type": agg, "schema": "metric", "params": {}}
    if field:
        a["params"]["field"] = field
    a["params"]["customLabel"] = label
    return {"title": "", "type": "metric", "aggs": [a],
            "params": {"addTooltip": True, "addLegend": False, "type": "metric",
                       "metric": {"percentageMode": False, "useRanges": False,
                                  "colorSchema": "Green to Red", "metricColorMode": "None",
                                  "colorsRange": [{"from": 0, "to": 1000000}],
                                  "labels": {"show": True}, "invertColors": False,
                                  "style": {"bgFill": "#000", "bgColor": False,
                                            "labelColor": False, "subText": subtext, "fontSize": 56}}}}


def pie_vis(field, size=10):
    return {"title": "", "type": "pie", "aggs": [
        {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {"field": field, "size": size, "order": "desc", "orderBy": "1",
                    "otherBucket": False, "missingBucket": False}}],
        "params": {"type": "pie", "addTooltip": True, "addLegend": True,
                   "legendPosition": "right", "isDonut": True,
                   "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}}}


def bar_vis(metric_agg, metric_field, bucket_field, ytitle):
    return {"title": "", "type": "histogram", "aggs": [
        {"id": "1", "enabled": True, "type": metric_agg, "schema": "metric",
         "params": {"field": metric_field, "customLabel": ytitle}},
        {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
         "params": {"field": bucket_field, "size": 30, "order": "asc", "orderBy": "_key"}}],
        "params": {"type": "histogram", "grid": {"categoryLines": False},
                   "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                                     "show": True, "scale": {"type": "linear"},
                                     "labels": {"show": True, "rotate": 75, "truncate": 100}, "title": {}}],
                   "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                                  "position": "left", "show": True,
                                  "scale": {"type": "linear", "mode": "normal"},
                                  "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                                  "title": {"text": ytitle}}],
                   "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                                     "data": {"label": ytitle, "id": "1"}, "valueAxis": "ValueAxis-1",
                                     "drawLinesBetweenPoints": True, "showCircles": True}],
                   "addTooltip": True, "addLegend": False, "times": [], "addTimeMarker": False}}


def search_obj(sid, title, columns, sort, query):
    body = {"attributes": {
        "title": title, "description": "", "hits": 0, "columns": columns, "sort": sort,
        "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source(query)},
    }, "references": [IDX_REF]}
    st, resp = _http("POST", "/api/saved_objects/search/%s?overwrite=true" % sid, body)
    print("search %-20s -> %s %s" % (sid, st, resp.get("id", resp)))


def dashboard(did, title, panels):
    refs, pjson = [], []
    for i, (otype, oid, w, h, x, y) in enumerate(panels):
        name = "panel_%d" % i
        refs.append({"name": name, "type": otype, "id": oid})
        pjson.append({"version": "2.19.4",
                      "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
                      "panelIndex": str(i), "embeddableConfig": {}, "panelRefName": name})
    body = {"attributes": {
        "title": title,
        "description": "Automated forensic evidence collection - live metrics from sealed case records",
        "panelsJSON": json.dumps(pjson),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "version": 1, "timeRestore": True, "timeTo": "now", "timeFrom": "now-90d",
        "refreshInterval": {"pause": True, "value": 0},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
            {"query": {"language": "kuery", "query": ""}, "filter": []})},
    }, "references": refs}
    st, resp = _http("POST", "/api/saved_objects/dashboard/%s?overwrite=true" % did, body)
    print("dashboard %-17s -> %s %s" % (did, st, resp.get("id", resp)))


# --- build visualizations ---
viz("fa-mtte-mean", "Mean Time-to-Evidence (s)",
    metric_vis("avg", "mtte_seconds", "mean MTTE (s)", "\u00b1 1.44 s  (n = 18 timed; 2 archived excluded)"), "case_kind:detection")
viz("fa-speedup-mean", "Mean Speedup vs Manual (x)",
    metric_vis("max", "speedup_mean_based", "\u00d7 faster than manual", "ratio of means: 433 s / 5.47 s"), "case_kind:detection")
viz("fa-cases-total", "Forensic Cases (total)",
    metric_vis("count", None, "cases under management", "18 timed + 2 archived (cold)"))
viz("fa-custody-sealed", "Sealed Chain of Custody",
    metric_vis("count", None, "cases sealed"), "custody_sealed:true")
viz("fa-tiers", "Storage Tier Distribution", pie_vis("tier", 5))
viz("fa-mitre", "MITRE ATT&CK Techniques", pie_vis("mitre_ids", 10))
viz("fa-mtte-bar", "Time-to-Evidence per Case (s)",
    bar_vis("max", "mtte_seconds", "case_id", "seconds"), "case_kind:detection")

# --- detection->collection table (saved search) ---
search_obj("fa-table", "Detection -> Collection",
           ["case_id", "detected_at", "rule_id", "mitre_ids", "mtte_seconds", "tier", "custody_sealed"],
           [["detected_at", "desc"]], "case_kind:detection")

# --- assemble dashboard (48-col grid) ---
dashboard("fa-dashboard", "Forensic Automation", [
    ("visualization", "fa-mtte-mean",    12, 8,  0,  0),
    ("visualization", "fa-speedup-mean", 12, 8,  12, 0),
    ("visualization", "fa-cases-total",  12, 8,  24, 0),
    ("visualization", "fa-custody-sealed",12, 8, 36, 0),
    ("visualization", "fa-tiers",        24, 15, 0,  8),
    ("visualization", "fa-mitre",        24, 15, 24, 8),
    ("visualization", "fa-mtte-bar",     48, 15, 0,  23),
    ("search",        "fa-table",        48, 20, 0,  38),
])
print("done.")
