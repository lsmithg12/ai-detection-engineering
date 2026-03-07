"""
SIEM Deployment Module — Shared interface for deploying detections
to Elastic Security and Splunk.

Reads credentials from orchestration/config.yml (single source of truth).
Used by blue_team_agent.py for automated deployment.
"""

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from uuid import uuid4

import yaml

CONFIG_PATH = Path(__file__).resolve().parent / "config.yml"

# MITRE tactic mapping (shared with blue_team_agent)
TACTIC_MAP = {
    "execution": ("Execution", "TA0002"),
    "persistence": ("Persistence", "TA0003"),
    "privilege_escalation": ("Privilege Escalation", "TA0004"),
    "defense_evasion": ("Defense Evasion", "TA0005"),
    "credential_access": ("Credential Access", "TA0006"),
    "discovery": ("Discovery", "TA0007"),
    "lateral_movement": ("Lateral Movement", "TA0008"),
    "collection": ("Collection", "TA0009"),
    "command_and_control": ("Command and Control", "TA0011"),
    "initial_access": ("Initial Access", "TA0001"),
}

SEVERITY_MAP = {
    "informational": (21, "low"),
    "low": (47, "medium"),
    "medium": (73, "high"),
    "high": (73, "high"),
    "critical": (99, "critical"),
}


def _load_infra_config() -> dict:
    """Load infrastructure config from config.yml."""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            cfg = yaml.safe_load(f) or {}
        return cfg.get("infrastructure", {})
    return {}


def _basic_auth(user: str, password: str) -> str:
    """Create a Basic auth header value."""
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def _splunk_ssl_context() -> ssl.SSLContext:
    """Create an SSL context for Splunk (self-signed cert in lab)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ─── Health Checks ────────────────────────────────────────────────

def check_elastic() -> bool:
    """Check if Elasticsearch is reachable."""
    infra = _load_infra_config()
    es = infra.get("elasticsearch", {})
    url = es.get("url", "http://localhost:9200")
    user = es.get("user", "elastic")
    password = es.get("pass", "changeme")

    try:
        req = urllib.request.Request(f"{url}/_cluster/health")
        req.add_header("Authorization", _basic_auth(user, password))
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def check_splunk() -> bool:
    """Check if Splunk is reachable."""
    infra = _load_infra_config()
    sp = infra.get("splunk", {})
    url = sp.get("url", "https://localhost:8089")
    user = sp.get("user", "admin")
    password = sp.get("pass", "BlueTeamLab1!")

    try:
        req = urllib.request.Request(f"{url}/services/server/health")
        req.add_header("Authorization", _basic_auth(user, password))
        with urllib.request.urlopen(req, context=_splunk_ssl_context(), timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


# ─── Elastic Deployment ──────────────────────────────────────────

def deploy_to_elastic(request: dict, lucene_query: str, sigma_rule: dict) -> dict | None:
    """Deploy a detection rule to Elastic Security Detection Engine."""
    if not check_elastic():
        print("    [siem] Elastic not available — skipping")
        return None

    infra = _load_infra_config()
    es = infra.get("elasticsearch", {})
    kibana_url = infra.get("kibana", {}).get("url", "http://localhost:5601")
    user = es.get("user", "elastic")
    password = es.get("pass", "changeme")

    tid = request["technique_id"]
    tactic_key = request.get("mitre_tactic", "execution")
    tactic_name, tactic_id = TACTIC_MAP.get(tactic_key, ("Execution", "TA0002"))
    title = sigma_rule.get("title", f"Detection for {tid}")
    severity = sigma_rule.get("level", "high")
    risk_score, _ = SEVERITY_MAP.get(severity, (73, "high"))

    rule_id = str(uuid4())
    rule_payload = {
        "rule_id": rule_id,
        "name": title,
        "description": sigma_rule.get("description", f"Detects {tid}"),
        "type": "query",
        "query": lucene_query,
        "index": ["sim-*"],
        "language": "lucene",
        "severity": severity,
        "risk_score": risk_score,
        "interval": "5m",
        "from": "now-6m",
        "enabled": True,
        "tags": [tid, tactic_name],
        "threat": [{
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": tactic_id, "name": tactic_name,
                "reference": f"https://attack.mitre.org/tactics/{tactic_id}/",
            },
            "technique": [{
                "id": tid.split(".")[0], "name": request.get("title", tid),
                "reference": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            }],
        }],
    }

    data = json.dumps(rule_payload).encode()
    req = urllib.request.Request(
        f"{kibana_url}/api/detection_engine/rules",
        data=data, method="POST",
        headers={
            "kbn-xsrf": "true",
            "Content-Type": "application/json",
            "Authorization": _basic_auth(user, password),
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read())
            print(f"    [siem] Elastic rule created: {result.get('id', rule_id)}")
            return {"rule_id": rule_id, "elastic_id": result.get("id", "")}
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:300]
        print(f"    [siem] Elastic deploy failed ({e.code}): {body}")
        return None
    except Exception as e:
        print(f"    [siem] Elastic deploy error: {e}")
        return None


# ─── Splunk Deployment ───────────────────────────────────────────

def deploy_to_splunk(request: dict, spl_query: str, sigma_rule: dict) -> dict | None:
    """Deploy a detection as a Splunk saved search with alerting."""
    if not check_splunk():
        print("    [siem] Splunk not available — skipping")
        return None

    infra = _load_infra_config()
    sp = infra.get("splunk", {})
    url = sp.get("url", "https://localhost:8089")
    user = sp.get("user", "admin")
    password = sp.get("pass", "BlueTeamLab1!")

    tid = request["technique_id"]
    search_name = f"{request.get('title', tid)} {tid}"
    severity = sigma_rule.get("level", "high")
    sev_map = {"informational": "1", "low": "2", "medium": "3", "high": "4", "critical": "5"}
    alert_severity = sev_map.get(severity, "4")

    full_spl = (
        f"index=sysmon {spl_query} "
        f"| table _time host user process.name process.command_line process.executable"
    )

    params = urllib.parse.urlencode({
        "name": search_name,
        "search": full_spl,
        "is_scheduled": "1",
        "cron_schedule": "*/5 * * * *",
        "alert_type": "number of events",
        "alert_comparator": "greater than",
        "alert_threshold": "0",
        "alert.severity": alert_severity,
        "output_mode": "json",
    }).encode()

    req = urllib.request.Request(
        f"{url}/servicesNS/admin/search/saved/searches",
        data=params, method="POST",
        headers={"Authorization": _basic_auth(user, password)},
    )

    try:
        with urllib.request.urlopen(req, context=_splunk_ssl_context(), timeout=15) as resp:
            result = json.loads(resp.read())
            name = result.get("entry", [{}])[0].get("name", search_name)
            print(f"    [siem] Splunk saved search created: {name}")
            return {"search_name": name}
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:300]
        if "already exists" in body.lower():
            print(f"    [siem] Splunk saved search already exists: {search_name}")
            return {"search_name": search_name}
        print(f"    [siem] Splunk deploy failed ({e.code}): {body}")
        return None
    except Exception as e:
        print(f"    [siem] Splunk deploy error: {e}")
        return None


# ─── Orchestration ───────────────────────────────────────────────

def deploy_to_siems(request: dict, lucene: str, spl: str, sigma_rule: dict) -> dict:
    """Deploy to all available SIEMs. Returns deployment results."""
    results = {}

    elastic_result = deploy_to_elastic(request, lucene, sigma_rule)
    if elastic_result:
        results["elastic"] = elastic_result

    splunk_result = deploy_to_splunk(request, spl, sigma_rule)
    if splunk_result:
        results["splunk"] = splunk_result

    return results
