"""
wazuh_trigger.py — parse a Wazuh alert into the orchestrator's internal format,
extracting MITRE ATT&CK enrichment (techniques / tactics) that Wazuh adds from
its built-in mitre.db.

Wazuh (this version) exposes MITRE as flat list fields on the rule object:
    rule.mitre_techniques = ["T1003.008"]
    rule.mitre_tactics    = ["TA0006"]
Older/other versions nest them under rule.mitre = {id, technique, tactic}.
This parser handles BOTH shapes.
"""


def _as_list(v):
	if v is None:
		return None
	return v if isinstance(v, list) else [v]


def parse_alert(alert_json):
	rule = alert_json.get("rule", {}) or {}
	agent = alert_json.get("agent", {}) or {}
	nested = rule.get("mitre", {}) if isinstance(rule.get("mitre"), dict) else {}

	mitre_ids = _as_list(rule.get("mitre_techniques") or nested.get("id"))
	mitre_techniques = _as_list(rule.get("mitre_techniques") or nested.get("technique"))
	mitre_tactics = _as_list(rule.get("mitre_tactics") or nested.get("tactic"))

	return {
		"rule_id": rule.get("id"),
		"level": rule.get("level"),
		"description": rule.get("description"),
		"agent": agent.get("name"),
		"agent_name": agent.get("name"),
		"agent_id": agent.get("id"),
		"agent_ip": agent.get("ip"),
		"timestamp": alert_json.get("timestamp"),
		"mitre_ids": mitre_ids,
		"mitre_techniques": mitre_techniques,
		"mitre_tactics": mitre_tactics,
	}
