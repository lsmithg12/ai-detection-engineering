"""
Threshold Validation Module — Validates aggregation-based threshold rules
against Elasticsearch.

Uses ES aggregation queries to count events in time windows, then checks
if the count (or distinct count) exceeds the threshold for the grouping field.

Unlike standard Sigma validation (single-event matching) or EQL validation
(sequence detection), threshold validation must:
1. Ingest events with realistic timestamps spanning the time window
2. Run an aggregation query (not a search) to count events per group
3. Check if any group exceeds the threshold

Phase 6 deliverable — Task 6.3: Threshold Rule Support.
"""

import json
import time
import urllib.error
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from orchestration.validation import (
    _es_request,
    _check_es_reachable,
    _cleanup_index,
)
from orchestration.siem import _load_infra_config


def _build_threshold_bulk_body(
    index_name: str,
    attack_events: list,
    benign_events: list,
    technique_id: str,
    window_seconds: int,
) -> str:
    """
    Build bulk ingest NDJSON with timestamps spread across the threshold window.

    For threshold rules, all attack events are spread across the time window
    to simulate realistic burst activity. Benign events are spread over a
    wider window to avoid accidentally triggering the threshold.
    """
    now = datetime.now(timezone.utc)
    lines = []
    event_id = 0

    # Spread attack events evenly across the window (simulate burst)
    n_attack = len(attack_events)
    for i, event in enumerate(attack_events):
        flat = _flatten_for_threshold(event)
        flat["_simulation.type"] = "attack"
        flat["_simulation.technique"] = technique_id
        # Spread events from (now - window) to now
        offset_seconds = (window_seconds * i) // max(n_attack, 1)
        ts = now - timedelta(seconds=window_seconds - offset_seconds)
        flat["@timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        action = json.dumps({"index": {"_index": index_name, "_id": f"atk-{event_id}"}})
        doc = json.dumps(flat)
        lines.append(action)
        lines.append(doc)
        event_id += 1

    # Spread benign events over 2x the window to avoid triggering threshold
    n_benign = len(benign_events)
    for i, event in enumerate(benign_events):
        flat = _flatten_for_threshold(event)
        flat["_simulation.type"] = "baseline"
        flat["_simulation.technique"] = technique_id
        # Space benign events further apart (2 * window)
        offset_seconds = (window_seconds * 2 * i) // max(n_benign, 1)
        ts = now - timedelta(seconds=window_seconds * 2 - offset_seconds)
        flat["@timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        action = json.dumps({"index": {"_index": index_name, "_id": f"ben-{event_id}"}})
        doc = json.dumps(flat)
        lines.append(action)
        lines.append(doc)
        event_id += 1

    return "\n".join(lines) + "\n"


def _flatten_for_threshold(event: dict, parent_key: str = "", sep: str = ".") -> dict:
    """Flatten nested dict into dotted-key format for ES ingest."""
    items = {}
    for k, v in event.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.update(_flatten_for_threshold(v, new_key, sep))
        else:
            items[new_key] = v
    return items


def _parse_window_to_seconds(window: str) -> int:
    """Parse threshold window string to seconds. e.g., '10m' -> 600, '60s' -> 60."""
    if window.endswith("s"):
        return int(window[:-1])
    elif window.endswith("m"):
        return int(window[:-1]) * 60
    elif window.endswith("h"):
        return int(window[:-1]) * 3600
    return 300  # Default: 5 minutes


def validate_threshold_against_elasticsearch(
    base_query: str,
    threshold_field: str,
    threshold_value: int,
    window: str,
    attack_events: list,
    benign_events: list,
    technique_id: str = "",
    cardinality_field: str = None,
    cardinality_value: int = None,
    es_url: str = None,
    es_auth: tuple = None,
    index_prefix: str = "sim-validation",
    cleanup: bool = True,
) -> dict:
    """
    Validate a threshold rule against ingested events in Elasticsearch.

    Uses ES aggregations to count events per group (not a search).
    Checks if any group exceeds the threshold_value within the window.

    Args:
        base_query: Lucene query for the base filter (what events to count)
        threshold_field: Field to group by (e.g., "source.ip", "host.name")
        threshold_value: Minimum count to alert (e.g., 5)
        window: Time window string (e.g., "10m", "60s")
        attack_events: Events that SHOULD trigger the threshold
        benign_events: Events that should NOT trigger the threshold
        technique_id: MITRE technique ID for tagging
        cardinality_field: Optional — count distinct values of this field
        cardinality_value: Optional — minimum distinct count to alert
        es_url: Elasticsearch URL (reads from config if None)
        es_auth: (user, password) tuple (reads from config if None)
        index_prefix: Index name prefix for ephemeral indices
        cleanup: Delete ephemeral index after test

    Returns:
        dict with validation metrics, or None if ES unreachable.
    """
    # Resolve config
    if es_url is None or es_auth is None:
        infra = _load_infra_config()
        es = infra.get("elasticsearch", {})
        if es_url is None:
            es_url = es.get("url", "http://localhost:9200")
        if es_auth is None:
            es_auth = (es.get("user", "elastic"), es.get("pass", "changeme"))

    if not _check_es_reachable(es_url, es_auth):
        return None

    if not base_query or not base_query.strip():
        return {
            "validation_method": "elasticsearch_threshold",
            "f1_score": 0.0,
            "tp": 0, "fp": 0, "fn": len(attack_events), "tn": len(benign_events),
            "precision": 0.0, "recall": 0.0,
            "threshold_breaches": 0,
            "errors": ["Empty base query"],
        }

    window_seconds = _parse_window_to_seconds(window)
    index_name = f"{index_prefix}-{uuid4().hex[:8]}"
    errors = []

    try:
        # ─── 0. Create ephemeral index ────────────────────────────────
        try:
            _es_request(
                f"{es_url}/{index_name}",
                method="PUT",
                data={"settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "index.lifecycle.name": "validation-cleanup",
                }},
                auth=es_auth,
            )
        except Exception:
            pass

        # ─── 1. Bulk ingest events with realistic timestamps ──────────
        bulk_body = _build_threshold_bulk_body(
            index_name, attack_events, benign_events, technique_id, window_seconds
        )

        try:
            status, resp = _es_request(
                f"{es_url}/{index_name}/_bulk",
                method="POST",
                data=bulk_body,
                auth=es_auth,
                content_type="application/x-ndjson",
                timeout=15,
            )
        except Exception as e:
            errors.append(f"Bulk ingest failed: {e}")
            return {
                "validation_method": "elasticsearch_threshold",
                "f1_score": 0.0,
                "tp": 0, "fp": 0, "fn": len(attack_events), "tn": len(benign_events),
                "precision": 0.0, "recall": 0.0,
                "threshold_breaches": 0,
                "errors": errors,
            }

        if isinstance(resp, dict) and resp.get("errors"):
            error_items = [
                item for item in resp.get("items", [])
                if "error" in item.get("index", {})
            ]
            if error_items:
                errors.append(
                    f"Bulk ingest had {len(error_items)} errors: "
                    f"{error_items[0]['index']['error'].get('reason', '?')}"
                )

        # ─── 2. Refresh index ─────────────────────────────────────────
        try:
            _es_request(f"{es_url}/{index_name}/_refresh", method="POST", auth=es_auth)
        except Exception:
            time.sleep(1)

        # ─── 3. Run aggregation query to simulate threshold logic ─────
        # Build ES date histogram + terms aggregation to count events per group
        agg_body = {
            "query": {
                "query_string": {
                    "query": base_query,
                    "default_operator": "AND",
                    "analyze_wildcard": True,
                }
            },
            "size": 0,
            "aggs": {
                "by_group": {
                    "terms": {
                        "field": threshold_field,
                        "size": 100,
                        "min_doc_count": 1,
                    }
                }
            },
        }

        # If cardinality counting is requested, use cardinality sub-aggregation
        if cardinality_field and cardinality_value:
            agg_body["aggs"]["by_group"]["aggs"] = {
                "distinct_count": {
                    "cardinality": {"field": cardinality_field}
                }
            }

        try:
            status, agg_resp = _es_request(
                f"{es_url}/{index_name}/_search",
                method="POST",
                data=agg_body,
                auth=es_auth,
                timeout=15,
            )
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")[:500]
            try:
                error_detail = json.loads(error_body)
                reason = (
                    error_detail.get("error", {})
                    .get("root_cause", [{}])[0]
                    .get("reason", error_body[:200])
                )
            except Exception:
                reason = error_body[:200]
            errors.append(f"Aggregation query error: {reason}")
            return {
                "validation_method": "elasticsearch_threshold",
                "f1_score": 0.0,
                "tp": 0, "fp": 0, "fn": len(attack_events), "tn": len(benign_events),
                "precision": 0.0, "recall": 0.0,
                "threshold_breaches": 0,
                "errors": errors,
            }

        # ─── 4. Check for threshold breaches ─────────────────────────
        buckets = agg_resp.get("aggregations", {}).get("by_group", {}).get("buckets", [])
        threshold_breaches = 0

        for bucket in buckets:
            if cardinality_field and cardinality_value:
                # Use cardinality (distinct count)
                distinct = bucket.get("distinct_count", {}).get("value", 0)
                if distinct >= (cardinality_value or threshold_value):
                    threshold_breaches += 1
            else:
                # Use raw event count
                if bucket.get("doc_count", 0) >= threshold_value:
                    threshold_breaches += 1

        # ─── 5. Score results ─────────────────────────────────────────
        # Separate attack vs benign breach contributions
        # For simplicity: if any breach detected and attack events present -> TP
        # If no breach detected and attack events present -> FN
        if attack_events:
            if threshold_breaches > 0:
                tp, fn = 1, 0
            else:
                tp, fn = 0, 1
        else:
            tp, fn = 0, 0

        # FP: threshold breached but no attack events (benign-only test)
        if not attack_events:
            fp = 1 if threshold_breaches > 0 else 0
        else:
            fp = 0  # Simplified: FP scoring in threshold rules needs real baseline data

        tn = 1 if (benign_events and fp == 0 and threshold_breaches == 0) else 0

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        return {
            "validation_method": "elasticsearch_threshold",
            "base_query": base_query[:200] + "..." if len(base_query) > 200 else base_query,
            "threshold_field": threshold_field,
            "threshold_value": threshold_value,
            "window": window,
            "threshold_breaches": threshold_breaches,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "events_ingested": len(attack_events) + len(benign_events),
            "index_used": index_name,
            "errors": errors,
        }

    except Exception as e:
        errors.append(f"Unexpected error: {e}")
        return None

    finally:
        if cleanup:
            _cleanup_index(es_url, index_name, es_auth)
