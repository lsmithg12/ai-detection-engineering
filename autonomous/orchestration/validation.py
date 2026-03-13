"""
SIEM-Based Validation Module — Validates detections by running compiled queries
against real Elasticsearch indices instead of local Python matching.

This catches issues that local validation misses:
- Lucene query syntax errors (backslash escaping, wildcard on keyword fields)
- Field mapping mismatches (ECS vs Sysmon naming after transpilation)
- Index template issues (fields not mapped as expected type)

Design:
- Ingests scenario events into ephemeral ES index (sim-validation-{uuid})
- Runs compiled Lucene query against the index
- Calculates TP/FP/FN/TN from _simulation.type tags
- Deletes the index after testing (ILM is safety net for orphans)
- Returns None when ES unreachable (caller falls back to local validation)

Phase 3 extensibility: ingestion_method parameter supports future Cribl routing.
"""

import datetime
import json
import time
import urllib.error
import urllib.request
from uuid import uuid4

from orchestration.siem import _load_infra_config, _basic_auth


def _es_request(url: str, method: str = "GET", data: dict | str | None = None,
                auth: tuple | None = None, content_type: str = "application/json",
                timeout: int = 10) -> tuple[int, dict | str]:
    """
    Make an HTTP request to Elasticsearch.

    Returns (status_code, response_body).
    Raises urllib.error.URLError if connection fails.
    """
    if auth is None:
        infra = _load_infra_config()
        es = infra.get("elasticsearch", {})
        auth = (es.get("user", "elastic"), es.get("pass", "changeme"))

    if isinstance(data, dict):
        body = json.dumps(data).encode("utf-8")
    elif isinstance(data, str):
        body = data.encode("utf-8")
    elif isinstance(data, bytes):
        body = data
    else:
        body = None

    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", _basic_auth(auth[0], auth[1]))
    if body is not None:
        req.add_header("Content-Type", content_type)

    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp_body = resp.read().decode("utf-8")
        try:
            return resp.status, json.loads(resp_body)
        except json.JSONDecodeError:
            return resp.status, resp_body


def _check_es_reachable(es_url: str, auth: tuple) -> bool:
    """Quick health check — is ES responding?"""
    try:
        status, _ = _es_request(f"{es_url}/_cluster/health", auth=auth, timeout=5)
        return status == 200
    except Exception:
        return False


def _flatten_event(event: dict, parent_key: str = "", sep: str = ".") -> dict:
    """
    Flatten a nested dict into dotted-key format for ES ingest.

    Example: {"process": {"name": "cmd.exe"}} -> {"process.name": "cmd.exe"}

    ES handles nested JSON natively for object types, but flattening ensures
    consistent behavior with keyword/text field mappings in the sim-* template.
    """
    items = {}
    for k, v in event.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.update(_flatten_event(v, new_key, sep))
        else:
            items[new_key] = v
    return items


def _build_bulk_body(index_name: str, attack_events: list[dict],
                     benign_events: list[dict], technique_id: str) -> str:
    """
    Build Elasticsearch Bulk API NDJSON body.

    Tags each event with _simulation.type (attack/baseline) for scoring.
    Flattens nested events to dotted-key format.
    """
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    lines = []
    event_id = 0

    for event in attack_events:
        flat = _flatten_event(event)
        flat["_simulation.type"] = "attack"
        flat["_simulation.technique"] = technique_id
        flat.setdefault("@timestamp", now)
        action = json.dumps({"index": {"_index": index_name, "_id": f"atk-{event_id}"}})
        doc = json.dumps(flat)
        lines.append(action)
        lines.append(doc)
        event_id += 1

    for event in benign_events:
        flat = _flatten_event(event)
        flat["_simulation.type"] = "baseline"
        flat["_simulation.technique"] = technique_id
        flat.setdefault("@timestamp", now)
        action = json.dumps({"index": {"_index": index_name, "_id": f"ben-{event_id}"}})
        doc = json.dumps(flat)
        lines.append(action)
        lines.append(doc)
        event_id += 1

    # Bulk API requires trailing newline
    return "\n".join(lines) + "\n"


def validate_against_elasticsearch(
    compiled_lucene: str,
    attack_events: list[dict],
    benign_events: list[dict],
    technique_id: str = "",
    es_url: str | None = None,
    es_auth: tuple | None = None,
    index_prefix: str = "sim-validation",
    ingestion_method: str = "direct",
) -> dict | None:
    """
    Validate a detection by ingesting events into Elasticsearch and running
    the compiled Lucene query against them.

    Args:
        compiled_lucene: The Lucene query string (from sigma-cli transpilation)
        attack_events: Events that SHOULD trigger the detection (expected: TP)
        benign_events: Events that should NOT trigger (expected: TN)
        technique_id: MITRE technique ID for tagging
        es_url: Elasticsearch URL (reads from config.yml if None)
        es_auth: (user, password) tuple (reads from config.yml if None)
        index_prefix: Index name prefix for ephemeral validation indices
        ingestion_method: "direct" (Phase 2) or "cribl" (Phase 3+)

    Returns:
        dict with metrics on success, None if ES unreachable.
        Metrics dict includes 'errors' list for query syntax issues.
    """
    # Resolve config
    if es_url is None or es_auth is None:
        infra = _load_infra_config()
        es = infra.get("elasticsearch", {})
        if es_url is None:
            es_url = es.get("url", "http://localhost:9200")
        if es_auth is None:
            es_auth = (es.get("user", "elastic"), es.get("pass", "changeme"))

    # Pre-flight: is ES reachable?
    if not _check_es_reachable(es_url, es_auth):
        return None

    if not compiled_lucene or not compiled_lucene.strip():
        return {
            "method": "elasticsearch",
            "f1_score": 0.0,
            "tp": 0, "fp": 0, "fn": len(attack_events), "tn": len(benign_events),
            "precision": 0.0, "recall": 0.0,
            "tp_rate": 0.0, "fp_rate": 0.0,
            "total_attack": len(attack_events), "total_benign": len(benign_events),
            "query_used": "",
            "index_used": "",
            "events_ingested": 0,
            "query_hits": 0,
            "query_time_ms": 0,
            "errors": ["Empty Lucene query — transpilation may have failed"],
        }

    index_name = f"{index_prefix}-{uuid4().hex[:8]}"
    total_events = len(attack_events) + len(benign_events)
    errors = []

    try:
        # ─── 1. Bulk ingest events ──────────────────────────────────
        bulk_body = _build_bulk_body(index_name, attack_events, benign_events, technique_id)

        try:
            status, resp = _es_request(
                f"{es_url}/{index_name}/_bulk",
                method="POST",
                data=bulk_body,
                auth=es_auth,
                content_type="application/x-ndjson",
                timeout=15,
            )
        except urllib.error.HTTPError as e:
            # Retry once on bulk failure
            time.sleep(1)
            try:
                status, resp = _es_request(
                    f"{es_url}/{index_name}/_bulk",
                    method="POST",
                    data=bulk_body,
                    auth=es_auth,
                    content_type="application/x-ndjson",
                    timeout=15,
                )
            except Exception:
                _cleanup_index(es_url, index_name, es_auth)
                return None

        # Check for bulk ingest errors
        if isinstance(resp, dict) and resp.get("errors"):
            error_items = [
                item for item in resp.get("items", [])
                if "error" in item.get("index", {})
            ]
            if error_items:
                errors.append(f"Bulk ingest had {len(error_items)} errors: "
                              f"{error_items[0]['index']['error'].get('reason', '?')}")

        # ─── 2. Refresh index for immediate querying ────────────────
        try:
            _es_request(f"{es_url}/{index_name}/_refresh", method="POST", auth=es_auth)
        except Exception:
            time.sleep(1)  # Brief fallback wait if explicit refresh fails

        # ─── 3. Run compiled Lucene query ───────────────────────────
        query_body = {
            "query": {
                "query_string": {
                    "query": compiled_lucene,
                    "default_operator": "AND",
                    "analyze_wildcard": True,
                }
            },
            "size": total_events + 10,  # Get all docs (small validation sets)
            "_source": ["_simulation.type", "_simulation.technique"],
        }

        query_start = time.time()
        try:
            status, search_resp = _es_request(
                f"{es_url}/{index_name}/_search",
                method="POST",
                data=query_body,
                auth=es_auth,
                timeout=10,
            )
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")[:500]
            try:
                error_detail = json.loads(error_body)
                reason = error_detail.get("error", {}).get("root_cause", [{}])[0].get("reason", error_body[:200])
            except (json.JSONDecodeError, IndexError, KeyError):
                reason = error_body[:200]

            errors.append(f"Query syntax error: {reason}")

            _cleanup_index(es_url, index_name, es_auth)
            return {
                "method": "elasticsearch",
                "f1_score": 0.0,
                "tp": 0, "fp": 0, "fn": len(attack_events), "tn": len(benign_events),
                "precision": 0.0, "recall": 0.0,
                "tp_rate": 0.0, "fp_rate": 0.0,
                "total_attack": len(attack_events), "total_benign": len(benign_events),
                "query_used": compiled_lucene,
                "index_used": index_name,
                "events_ingested": total_events,
                "query_hits": 0,
                "query_time_ms": 0,
                "errors": errors,
            }

        query_time_ms = int((time.time() - query_start) * 1000)

        # ─── 4. Score results ───────────────────────────────────────
        hits = search_resp.get("hits", {}).get("hits", [])
        hit_ids = {h["_id"] for h in hits}

        # Classify each hit
        tp = 0
        fp = 0
        for hit in hits:
            sim_type = hit.get("_source", {}).get("_simulation.type", "")
            if sim_type == "attack":
                tp += 1
            elif sim_type == "baseline":
                fp += 1

        fn = len(attack_events) - tp
        tn = len(benign_events) - fp

        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        tp_rate = recall

        result = {
            "method": "elasticsearch",
            "f1_score": round(f1, 3),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "tp_rate": round(tp_rate, 3),
            "fp_rate": round(fp_rate, 3),
            "total_attack": len(attack_events),
            "total_benign": len(benign_events),
            "query_used": compiled_lucene,
            "index_used": index_name,
            "events_ingested": total_events,
            "query_hits": len(hits),
            "query_time_ms": query_time_ms,
            "errors": errors,
        }

        return result

    except Exception as e:
        # Unexpected error — return None to trigger fallback
        print(f"    [validation] Unexpected error during ES validation: {e}")
        return None

    finally:
        # ─── 5. Cleanup — always delete the validation index ────────
        _cleanup_index(es_url, index_name, es_auth)


def _cleanup_index(es_url: str, index_name: str, auth: tuple):
    """Delete the ephemeral validation index. Best-effort — don't raise."""
    try:
        _es_request(f"{es_url}/{index_name}", method="DELETE", auth=auth, timeout=5)
    except Exception:
        pass  # ILM safety net will clean up orphans


def create_validation_infrastructure(es_url: str | None = None,
                                     es_auth: tuple | None = None) -> bool:
    """
    Create the ILM policy and override template for validation indices.

    Called by setup.sh or can be called programmatically.
    Returns True if successful, False if ES unreachable.
    """
    if es_url is None or es_auth is None:
        infra = _load_infra_config()
        es = infra.get("elasticsearch", {})
        if es_url is None:
            es_url = es.get("url", "http://localhost:9200")
        if es_auth is None:
            es_auth = (es.get("user", "elastic"), es.get("pass", "changeme"))

    if not _check_es_reachable(es_url, es_auth):
        return False

    # Create ILM policy
    ilm_policy = {
        "policy": {
            "phases": {
                "hot": {"min_age": "0ms", "actions": {}},
                "delete": {"min_age": "1h", "actions": {"delete": {}}},
            }
        }
    }

    try:
        _es_request(
            f"{es_url}/_ilm/policy/validation-cleanup",
            method="PUT", data=ilm_policy, auth=es_auth,
        )
    except Exception as e:
        print(f"    [validation] ILM policy creation failed: {e}")
        # Non-fatal — validation works without ILM

    # Create override template (higher priority than sim-*)
    # Inherits all mappings from sim-* template, just adds ILM policy reference
    override_template = {
        "index_patterns": ["sim-validation-*"],
        "priority": 600,  # Higher than sim-* (500)
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "index.lifecycle.name": "validation-cleanup",
            }
        }
    }

    try:
        _es_request(
            f"{es_url}/_index_template/sim-validation",
            method="PUT", data=override_template, auth=es_auth,
        )
        print("    [validation] Validation index template and ILM policy created")
        return True
    except Exception as e:
        print(f"    [validation] Override template creation failed: {e}")
        return False
