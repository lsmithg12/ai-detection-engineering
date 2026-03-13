# Phase 2: SIEM-Based Validation

**Priority**: HIGH
**Estimated effort**: 4-6 hours
**Dependencies**: Docker services running (Elasticsearch + optionally Splunk)
**Branch**: `infra/phase2-siem-validation`

---

## Context

The blue-team agent currently validates detections by matching Sigma selection blocks
against local JSON events in Python. This misses:
- Lucene query syntax errors (backslash escaping, wildcard on keyword fields)
- Field mapping mismatches (ECS vs Sysmon naming after transpilation)
- Index template issues (fields not mapped as expected type)
- Cribl normalization failures (fields dropped or malformed)

Real-world detection failures almost always occur at the query/SIEM layer, not the logic layer.

## Architecture

```
Current:  Scenario JSON → Python matcher → F1 score
Proposed: Scenario JSON → Elasticsearch ingest → Lucene query → F1 score
                        → Splunk ingest → SPL query → F1 score (Phase 3+)
Fallback: When SIEMs offline → current Python matcher (for CI)
```

### Key Design Decisions

1. **Separate module**: Validation lives in `autonomous/orchestration/validation.py`
   (NOT in blue_team_agent.py — it's already 853 lines)
2. **Reuse sim-* template**: `sim-validation-*` indices inherit `sim-*` template mappings
   automatically (same wildcard pattern), so no duplicate template needed
3. **ILM is a safety net**: The function deletes indices after each test (primary cleanup).
   ILM catches orphans from crashes (1-hour auto-delete).
4. **Phase 3 extensibility**: Accept `ingestion_method` parameter from the start
   (direct ingest vs Cribl routing) to avoid refactoring later
5. **Splunk validation deferred**: Splunk doesn't support easy event deletion. Defer to
   Phase 3+ when Cribl routing is available. Elastic-only for now.
6. **SIEM errors fed to retry loop**: When ES returns query syntax errors, include the
   error message in the feedback to Claude for the retry-with-feedback loop.

## Tasks

### Task 2.1: Create Validation ILM Policy (Safety Net)

Create an ILM policy to auto-delete orphaned validation indices.

**Note**: We do NOT need a separate index template — the existing `sim-*` template
(priority 500, created in setup.sh) already matches `sim-validation-*` indices.
The ILM policy is purely a safety net for indices left behind by crashes.

**ILM policy** (`pipeline/validation-ilm-policy.json`):
```json
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {}
      },
      "delete": {
        "min_age": "1h",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

**Steps**:
1. Create `pipeline/validation-ilm-policy.json`
2. Add ILM policy creation to `setup.sh` (after ES health check, before simulator start)
3. Create a thin override template for `sim-validation-*` that only adds the ILM policy
   reference (inherits all mappings from the parent `sim-*` template)

### Task 2.2: Build Elasticsearch Validation Module

Create `autonomous/orchestration/validation.py` with SIEM validation functions.

**Module responsibilities**:
1. Ingest scenario events into ephemeral ES index (Bulk API, NDJSON format)
2. Run compiled Lucene query against the index
3. Calculate TP/FP/FN/TN metrics based on `_simulation.type` tags
4. Delete the ephemeral index after testing
5. Fall back to `None` when ES is unreachable (caller uses local validation)

**Function signature**:
```python
def validate_against_elasticsearch(
    compiled_lucene: str,
    attack_events: list[dict],
    benign_events: list[dict],
    technique_id: str = "",
    es_url: str = "http://localhost:9200",
    es_auth: tuple = ("elastic", "changeme"),
    index_prefix: str = "sim-validation"
) -> dict | None:
    """
    Ingest events into Elasticsearch, run Lucene query, measure TP/FP/FN/TN.

    Returns dict with metrics on success, None if ES unreachable.
    Caller should fall back to local validation when None is returned.

    Returns:
        {
            "method": "elasticsearch",
            "f1_score": float,
            "tp": int, "fp": int, "fn": int, "tn": int,
            "tp_rate": float, "fp_rate": float,
            "query_used": str,
            "index_used": str,
            "events_ingested": int,
            "query_hits": int,
            "query_time_ms": int,
            "errors": []  # Query syntax errors, ingest failures, etc.
        }
    """
```

**Implementation details**:

1. **Index naming**: `sim-validation-{uuid4()[:8]}` (ephemeral, unique per test run)

2. **Event tagging during ingest**: Each event gets metadata added:
   ```python
   event["_simulation"] = {
       "type": "attack",  # or "baseline"
       "technique": technique_id
   }
   event["@timestamp"] = datetime.utcnow().isoformat() + "Z"
   ```

3. **Bulk API format** (NDJSON):
   ```
   {"index": {"_index": "sim-validation-a1b2c3d4"}}
   {"process.name": "cmd.exe", ..., "_simulation": {"type": "attack"}}
   {"index": {"_index": "sim-validation-a1b2c3d4"}}
   {"process.name": "svchost.exe", ..., "_simulation": {"type": "baseline"}}
   ```

4. **Flatten nested events**: ES handles nested dicts natively (dotted field paths
   from nested JSON), but we need to ensure the event structure matches what sigma-cli
   outputs. Since our scenarios already use ECS-nested format AND the sim-* template
   maps fields as dotted paths, no flattening is needed.

5. **Query execution**: Use `query_string` query:
   ```json
   {
     "query": {
       "query_string": {
         "query": "<compiled_lucene>",
         "default_operator": "AND",
         "analyze_wildcard": true
       }
     },
     "size": 1000,
     "_source": ["_simulation.type"]
   }
   ```

6. **Scoring**:
   - Assign each event a unique `_id` during ingest (or use ES auto-IDs)
   - Tag attack events with `_simulation.type: attack`, benign with `baseline`
   - After query: hits on `attack` → TP, hits on `baseline` → FP
   - Non-hits: attack → FN, baseline → TN

7. **Cleanup**: `DELETE /{index}` after scoring (primary cleanup)

8. **Error handling**:
   - ES unreachable → return `None` (caller falls back to local)
   - Query syntax error → return result with `errors` list populated,
     `f1_score: 0.0`, and the error message (for retry loop feedback)
   - Bulk ingest error → retry once, then return `None`

### Task 2.3: Splunk Validation (DEFERRED to Phase 3+)

**Rationale**: Splunk doesn't support deleting individual events from an index.
Workarounds (temporary index, event deletion via searches) are fragile and complex.
Defer until Phase 3 when Cribl can route events to a dedicated Splunk index with
automated cleanup.

**When to revisit**: After Phase 3 Cribl integration provides controlled event routing.

### Task 2.4: Integrate into Blue-Team Agent

Modify `blue_team_agent.py` to use SIEM validation when available, with graceful
fallback to local Python matching.

**Integration point**: After transpilation, before quality assessment.

**Steps**:
1. Import `validation.validate_against_elasticsearch` and `siem.check_elastic`
2. At start of `author_and_validate()`, check ES availability once:
   ```python
   from orchestration.validation import validate_against_elasticsearch
   from orchestration.siem import check_elastic
   use_siem_validation = check_elastic()
   ```
3. After transpiling to Lucene, if `use_siem_validation` AND lucene is non-empty:
   ```python
   siem_metrics = validate_against_elasticsearch(
       compiled_lucene=lucene,
       attack_events=scenario["events"]["attack_sequence"],
       benign_events=scenario["events"]["benign_similar"],
       technique_id=tid,
   )
   if siem_metrics is not None:
       metrics = siem_metrics  # Use SIEM results
       validation_method = "elasticsearch"
   else:
       metrics = validate_detection(...)  # Fallback
       validation_method = "local_json"
   ```
4. If `siem_metrics` has `errors` (query syntax issues), include those errors in the
   retry-with-feedback prompt so Claude can fix Lucene-incompatible patterns
5. Result files record `validation_method` and `validation_details`

**Retry loop enhancement**: When SIEM validation returns errors, append to the refine prompt:
```
Elasticsearch query error: {error_message}
The compiled Lucene query was: {lucene_query}
Fix the Sigma rule to avoid generating Lucene syntax that Elasticsearch rejects.
```

### Task 2.5: Update Result File Schema

Extend result files to track validation method and SIEM details.

**New schema** (backwards-compatible — adds fields, doesn't change existing):
```json
{
  "technique_id": "T1059.001",
  "date": "2026-03-13T10:00:00Z",
  "sigma_rule": "detections/execution/t1059_001.yml",
  "metrics": {
    "tp": 3, "fp": 0, "fn": 0, "tn": 5,
    "precision": 1.0, "recall": 1.0, "f1_score": 1.0,
    "fp_rate": 0.0, "tp_rate": 1.0,
    "total_attack": 3, "total_benign": 5
  },
  "quality_tier": "auto_deploy",
  "validation_method": "elasticsearch",
  "validation_details": {
    "index": "sim-validation-a1b2c3d4",
    "query": "process.name:powershell.exe AND ...",
    "events_ingested": 8,
    "query_hits": 3,
    "query_time_ms": 45,
    "errors": []
  },
  "validated_by": "blue-team-agent",
  "siem_targets": ["elasticsearch", "splunk"],
  "sigma_rule_path": "detections/execution/t1059_001.yml",
  "scenario_path": "simulator/scenarios/t1059_001.json",
  "attack_event_count": 3,
  "benign_event_count": 5,
  "quality_tier_criteria": {
    "auto_deploy": "F1 >= 0.90 AND FP_rate <= 0.05",
    "validated": "F1 >= 0.75",
    "needs_rework": "F1 < 0.75"
  }
}
```

### Task 2.6: CI Fallback Behavior

In GitHub Actions (no SIEM running), validation must still work.

**Behavior**:
1. `validate_against_elasticsearch()` returns `None` if ES unreachable
2. Agent falls back to `validate_detection()` (current local Python matching)
3. Result file notes `validation_method: "local_json"`
4. Quality agent flags local-only validated detections for re-validation when SIEMs available:
   - During quality run, check result files for `validation_method: "local_json"`
   - If SIEM is now available, recommend re-validation (state: `TUNE` recommendation)

### Task 2.7: setup.sh Integration

Add validation infrastructure to `setup.sh`.

**Steps**:
1. After the existing `sim-*` template creation block, add:
   - ILM policy creation: `PUT _ilm/policy/validation-cleanup`
   - Override template: `PUT _index_template/sim-validation` (higher priority, adds ILM)
2. Conditional on ES being available (same guard as existing template block)
3. Non-blocking: `|| log_warn` on failure (validation still works without ILM)

---

## Verification Checklist

- [ ] `validation.py` module exists with `validate_against_elasticsearch()` function
- [ ] Events can be bulk ingested and queried within 2 seconds
- [ ] Validation index auto-deletes after function completes (primary cleanup)
- [ ] ILM policy exists as safety net for orphaned indices
- [ ] `validate_against_elasticsearch()` returns correct TP/FP/FN/TN for known-good rule
- [ ] `validate_against_elasticsearch()` returns `None` when ES offline (fallback triggers)
- [ ] Query syntax errors are captured in `errors` list (not swallowed)
- [ ] Blue-team agent uses SIEM validation when available, local when not
- [ ] Result files record `validation_method` and `validation_details`
- [ ] Retry loop includes SIEM error feedback when available
- [ ] setup.sh creates ILM policy and override template
- [ ] No orphan validation indices left after test run

---

## Commit Strategy

1. `feat(validation): add Elasticsearch-based validation module and ILM policy`
2. `feat(agent): integrate SIEM validation into blue-team agent with fallback`
3. `docs(plans): update Phase 2 plan with architectural fixes`
