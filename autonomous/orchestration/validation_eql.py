"""
EQL Validation Module — Validates EQL sequence rules against Elasticsearch.

Uses the ES EQL search API (POST /{index}/_eql/search) instead of the
standard _search API used by validation.py. Reuses the ephemeral index
pattern and helper functions from validation.py.

Phase 6 deliverable — Task 6.2: EQL Rule Support.
"""

import json
import time
import urllib.error
from pathlib import Path
from uuid import uuid4

from orchestration.validation import (
    _es_request,
    _check_es_reachable,
    _build_bulk_body,
    _cleanup_index,
)
from orchestration.siem import _load_infra_config


def validate_eql_against_elasticsearch(
    eql_query: str,
    attack_events: list,
    benign_events: list,
    technique_id: str = "",
    es_url: str = None,
    es_auth: tuple = None,
    index_prefix: str = "sim-validation",
    expected_sequences: int = 1,
    cleanup: bool = True,
) -> dict:
    """
    Validate an EQL sequence query against ingested events in Elasticsearch.

    Flow:
    1. Create ephemeral index (sim-validation-{uuid})
    2. Bulk ingest all scenario events (attack + benign)
    3. Run EQL query via POST /{index}/_eql/search
    4. Count matched sequences / events
    5. Score TP/FP/FN/TN
    6. Cleanup index

    Args:
        eql_query: EQL sequence string (e.g., "sequence by host.name with maxspan=60s ...")
        attack_events: Events that SHOULD trigger the detection
        benign_events: Events that should NOT trigger
        technique_id: MITRE technique ID for tagging
        es_url: Elasticsearch URL (reads from config.yml if None)
        es_auth: (user, password) tuple (reads from config.yml if None)
        index_prefix: Index name prefix for ephemeral validation indices
        expected_sequences: Minimum sequences to count as TP (default 1)
        cleanup: Delete ephemeral index after test (default True)

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

    # Pre-flight: is ES reachable?
    if not _check_es_reachable(es_url, es_auth):
        return None

    if not eql_query or not eql_query.strip():
        return {
            "validation_method": "elasticsearch_eql",
            "f1_score": 0.0,
            "tp": 0, "fp": 0, "fn": len(attack_events), "tn": len(benign_events),
            "precision": 0.0, "recall": 0.0,
            "sequences_found": 0,
            "expected_sequences": expected_sequences,
            "errors": ["Empty EQL query"],
        }

    index_name = f"{index_prefix}-{uuid4().hex[:8]}"
    errors = []

    try:
        # ─── 0. Create ephemeral index with ILM settings ─────────────
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
            pass  # Non-fatal — ILM policy may not exist

        # ─── 1. Bulk ingest events ────────────────────────────────────
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
        except Exception as e:
            errors.append(f"Bulk ingest failed: {e}")
            return {
                "validation_method": "elasticsearch_eql",
                "f1_score": 0.0,
                "tp": 0, "fp": 0, "fn": len(attack_events), "tn": len(benign_events),
                "precision": 0.0, "recall": 0.0,
                "sequences_found": 0,
                "expected_sequences": expected_sequences,
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

        # ─── 2. Refresh index ──────────────────────────────────────────
        try:
            _es_request(f"{es_url}/{index_name}/_refresh", method="POST", auth=es_auth)
        except Exception:
            time.sleep(1)

        # ─── 3. Run EQL sequence query ─────────────────────────────────
        eql_body = {
            "query": eql_query,
            "tiebreaker_field": "@timestamp",
            "size": 100,
        }

        try:
            status, response = _es_request(
                f"{es_url}/{index_name}/_eql/search",
                method="POST",
                data=eql_body,
                auth=es_auth,
                timeout=30,
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
            errors.append(f"EQL query error: {reason}")
            return {
                "validation_method": "elasticsearch_eql",
                "f1_score": 0.0,
                "tp": 0, "fp": 0, "fn": len(attack_events), "tn": len(benign_events),
                "precision": 0.0, "recall": 0.0,
                "sequences_found": 0,
                "expected_sequences": expected_sequences,
                "errors": errors,
            }

        # ─── 4. Parse EQL results ─────────────────────────────────────
        hits = response.get("hits", {})
        sequences = hits.get("sequences", [])
        events_matched = hits.get("events", [])

        # Count sequences found. For non-sequence EQL (just event matching),
        # fall back to counting matched events.
        sequences_found = len(sequences) if sequences else (1 if events_matched else 0)

        # ─── 5. Score results ─────────────────────────────────────────
        # For EQL, we score at the sequence level:
        # - If attack events present and sequences found >= expected: TP=1
        # - If attack events present but no sequences: FN=1
        # - If sequences found on benign-only data: FP=1
        if attack_events:
            if sequences_found >= expected_sequences:
                tp, fn = 1, 0
            else:
                tp, fn = 0, 1
        else:
            tp, fn = 0, 0

        # FP: sequences found when there should be none, or excess sequences
        if attack_events:
            fp = max(0, sequences_found - expected_sequences)
        else:
            fp = 1 if sequences_found > 0 else 0

        tn = 1 if (benign_events and fp == 0) else 0

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        return {
            "validation_method": "elasticsearch_eql",
            "eql_query": eql_query[:300] + "..." if len(eql_query) > 300 else eql_query,
            "sequences_found": sequences_found,
            "expected_sequences": expected_sequences,
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


def validate_eql_rule_file(
    rule_path: str,
    attack_scenario_path: str,
    benign_scenario_path: str = None,
) -> dict:
    """
    Convenience wrapper to validate an EQL rule YAML file against scenario JSON files.

    Args:
        rule_path: Path to EQL rule YAML (with detection_type: eql and eql_query)
        attack_scenario_path: Path to attack scenario JSON
        benign_scenario_path: Path to benign scenario JSON (optional)

    Returns:
        Validation result dict with f1, tp, fp, fn, tn metrics.
    """
    import yaml

    with open(rule_path, encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    eql_query = rule.get("eql_query", "")
    if not eql_query:
        return {"error": "No eql_query found in rule", "f1_score": 0.0}

    with open(attack_scenario_path, encoding="utf-8") as f:
        scenario = json.load(f)

    attack_events = scenario.get("attack_events", scenario.get("events", []))
    benign_events = []

    if benign_scenario_path:
        with open(benign_scenario_path, encoding="utf-8") as f:
            benign_scenario = json.load(f)
        benign_events = benign_scenario.get("events", [])

    return validate_eql_against_elasticsearch(
        eql_query=eql_query,
        attack_events=attack_events,
        benign_events=benign_events,
        technique_id=rule.get("tags", [""])[0].replace("attack.", ""),
        expected_sequences=rule.get("eql_min_sequences", 1),
    )
