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
from pathlib import Path
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


def _check_cribl_reachable(cribl_url: str) -> bool:
    """Quick health check — is Cribl Stream responding?"""
    try:
        req = urllib.request.Request(f"{cribl_url}/api/v1/health")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def _send_to_cribl_hec(hec_url: str, hec_token: str,
                       events: list[dict]) -> int:
    """
    Send events to Cribl's HEC input for full streaming pipeline processing.

    Events flow: HEC input -> cim_normalize pipeline -> ES/Splunk outputs.
    Each event should have _validation_index set for routing to the correct index.

    Returns the number of events sent on success, -1 on failure.
    """
    # HEC accepts newline-delimited JSON (one event per line)
    body_lines = []
    for evt in events:
        body_lines.append(json.dumps(evt))
    body = "\n".join(body_lines)

    try:
        req = urllib.request.Request(
            f"{hec_url}/services/collector",
            data=body.encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Splunk {hec_token}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            if resp.status == 200:
                return len(events)
            return -1
    except Exception as e:
        print(f"    [validation] Cribl HEC send failed: {e}")
        return -1


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

    # ─── Cribl full-path streaming validation (Phase 3) ────────────
    # When ingestion_method="cribl", events flow through the full streaming path:
    #   raw events -> Cribl HEC (port 8088) -> cim_normalize pipeline -> ES output
    # This tests the real-world data path, not just query correctness.
    cribl_routed = False
    if ingestion_method == "cribl":
        infra_full = _load_infra_config()
        cribl_cfg = infra_full.get("cribl", {})

        cribl_hec_url = cribl_cfg.get("hec_url", "http://localhost:8088")
        cribl_hec_token = cribl_cfg.get("hec_token", "blue-team-lab-hec-token")

        if not _check_cribl_reachable(cribl_cfg.get("url", "http://localhost:9000")):
            errors.append("Cribl unreachable — falling back to direct ES ingest")
            # Fall through to direct ingest below
        else:
            try:
                # Import raw event converter
                import sys as _sys
                repo_root = Path(__file__).resolve().parent.parent.parent
                if str(repo_root) not in _sys.path:
                    _sys.path.insert(0, str(repo_root))
                from simulator.raw_events import ecs_to_raw

                # Convert ECS events to raw HEC format and tag with validation index.
                # Use the HEC "index" field — Cribl's HEC input recognizes this as
                # a standard HEC property and makes it available as __e.index.
                # Also set _validation_index in fields{} for route filter matching.
                raw_events_hec = []
                for evt in attack_events:
                    raw = ecs_to_raw(evt)
                    raw["index"] = index_name
                    raw["_validation_index"] = index_name
                    raw.setdefault("fields", {})["_validation_index"] = index_name
                    raw_events_hec.append(raw)
                for evt in benign_events:
                    raw = ecs_to_raw(evt)
                    raw["index"] = index_name
                    raw["_validation_index"] = index_name
                    raw.setdefault("fields", {})["_validation_index"] = index_name
                    raw_events_hec.append(raw)

                # Create the ephemeral ES index FIRST (so it exists when Cribl writes)
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
                    pass  # Index may already exist or ILM policy missing — non-fatal

                # Send raw events to Cribl HEC (full streaming path)
                expected_count = len(raw_events_hec)
                sent_count = _send_to_cribl_hec(
                    cribl_hec_url, cribl_hec_token, raw_events_hec
                )

                if sent_count > 0:
                    # Wait for events to flow through Cribl -> ES
                    # Cribl processes near-real-time but buffering + ES refresh adds latency.
                    # Wait up to 12s, break early when all expected events arrive.
                    arrived_count = 0
                    for _wait in range(12):
                        time.sleep(1)
                        try:
                            _es_request(
                                f"{es_url}/{index_name}/_refresh",
                                method="POST", auth=es_auth,
                            )
                            status_code, count_resp = _es_request(
                                f"{es_url}/{index_name}/_count",
                                auth=es_auth,
                            )
                            if isinstance(count_resp, dict):
                                arrived_count = count_resp.get("count", 0)
                                if arrived_count >= expected_count:
                                    break
                                # Partial delivery — keep waiting
                        except Exception:
                            continue

                    if arrived_count > 0:
                        # Verify _simulation.type survived the Cribl pipeline
                        sim_check_ok = False
                        try:
                            _, sample_resp = _es_request(
                                f"{es_url}/{index_name}/_search",
                                method="POST",
                                data={"query": {"match_all": {}}, "size": 1,
                                      "_source": ["_simulation.type", "_simulation"]},
                                auth=es_auth,
                            )
                            sample_hits = sample_resp.get("hits", {}).get("hits", [])
                            if sample_hits:
                                src = sample_hits[0].get("_source", {})
                                sim_type = src.get("_simulation.type", "")
                                # Also check nested form (Cribl may promote fields{} differently)
                                if not sim_type:
                                    sim_type = (src.get("_simulation", {}) or {}).get("type", "")
                                sim_check_ok = sim_type in ("attack", "baseline")
                        except Exception:
                            pass

                        if not sim_check_ok:
                            errors.append(
                                "WARNING: _simulation.type not found in Cribl-routed events — "
                                "scoring will use document ID convention (atk-*/ben-*) as fallback"
                            )

                        if arrived_count < expected_count:
                            errors.append(
                                f"Partial delivery: {arrived_count}/{expected_count} events "
                                f"arrived in ES after 12s"
                            )

                        cribl_routed = True
                        errors.append(
                            f"Cribl streaming: {sent_count} events sent via HEC -> "
                            f"cim_normalize -> {index_name} ({arrived_count} arrived)"
                        )
                    else:
                        errors.append(
                            "Cribl HEC accepted events but none arrived in ES after 12s "
                            "-- falling back to direct ES ingest"
                        )
                else:
                    errors.append("Cribl HEC send failed -- falling back to direct ES ingest")

            except ImportError:
                errors.append("simulator.raw_events not available — falling back to direct ingest")
            except Exception as e:
                errors.append(f"Cribl streaming failed: {e} — falling back to direct ingest")

    try:
        # ─── 0. Create index explicitly with ILM settings ──────────
        # Do NOT use a separate sim-validation-* index template — it would
        # shadow the sim-* template (priority 500) and lose all ECS field
        # mappings. Instead, create the index with ILM settings inline and
        # let the sim-* template provide keyword/text/ip field mappings.
        if not cribl_routed:
            # Only create index for direct ingest — Cribl path already created it
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
                pass  # Index may already exist or ILM policy may not exist — non-fatal

        # ─── 1. Bulk ingest events (skip if Cribl already routed) ──
        if not cribl_routed:
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

        # Classify each hit — prefer _simulation.type field, fall back to doc ID convention
        tp = 0
        fp = 0
        for hit in hits:
            src = hit.get("_source", {})
            sim_type = src.get("_simulation.type", "")
            # Cribl may nest _simulation as an object instead of dotted key
            if not sim_type:
                sim_type = (src.get("_simulation", {}) or {}).get("type", "")
            # Final fallback: infer from document ID (atk-* = attack, ben-* = baseline)
            if not sim_type:
                doc_id = hit.get("_id", "")
                if doc_id.startswith("atk-"):
                    sim_type = "attack"
                elif doc_id.startswith("ben-"):
                    sim_type = "baseline"
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

        result["ingestion_method"] = ingestion_method

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


def validate_against_live_siem(
    compiled_lucene: str,
    technique_id: str = "",
    es_url: str | None = None,
    es_auth: tuple | None = None,
) -> dict | None:
    """
    Run compiled query against persistent sim-attack and sim-baseline indices.

    Unlike validate_against_elasticsearch() which uses ephemeral indices,
    this queries the standing simulation data to cross-check detection quality
    against a larger, more realistic dataset.

    Returns dict with live TP/FP counts, or None if ES unreachable.
    """
    if es_url is None or es_auth is None:
        infra = _load_infra_config()
        es = infra.get("elasticsearch", {})
        if es_url is None:
            es_url = es.get("url", "http://localhost:9200")
        if es_auth is None:
            es_auth = (es.get("user", "elastic"), es.get("pass", "changeme"))

    if not _check_es_reachable(es_url, es_auth):
        return None

    if not compiled_lucene or not compiled_lucene.strip():
        return {"siem_tp_count": 0, "siem_fp_count": 0, "siem_precision": 0.0}

    query_body = {
        "query": {
            "query_string": {
                "query": compiled_lucene,
                "default_operator": "AND",
                "analyze_wildcard": True,
            }
        },
        "size": 0,  # Count only
    }

    def _run_count(index: str) -> int:
        try:
            status, resp = _es_request(
                f"{es_url}/{index}/_count",
                method="POST",
                data={"query": query_body["query"]},
                auth=es_auth,
                timeout=10,
            )
            if isinstance(resp, dict):
                return resp.get("count", 0)
        except Exception:
            pass
        return 0

    attack_hits = _run_count("sim-attack")
    baseline_hits = _run_count("sim-baseline")

    total = attack_hits + baseline_hits
    precision = attack_hits / total if total > 0 else 0.0

    return {
        "siem_tp_count": attack_hits,
        "siem_fp_count": baseline_hits,
        "siem_precision": round(precision, 3),
        "technique_id": technique_id,
    }


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

    # Create ILM policy (safety net for orphaned validation indices)
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
        print("    [validation] ILM policy 'validation-cleanup' created")
    except Exception as e:
        print(f"    [validation] ILM policy creation failed: {e}")
        # Non-fatal — validation works without ILM

    # NOTE: We do NOT create a separate sim-validation-* index template.
    # A higher-priority template would shadow the sim-* template's ECS field
    # mappings (keyword/text/ip types), causing Lucene wildcard queries to fail
    # against dynamic text mappings. Instead, ILM is applied per-index at
    # creation time in validate_against_elasticsearch().

    # Clean up any previously-created override template that would shadow sim-*
    try:
        _es_request(
            f"{es_url}/_index_template/sim-validation",
            method="DELETE", auth=es_auth,
        )
    except Exception:
        pass  # Template may not exist — that's fine

    return True
