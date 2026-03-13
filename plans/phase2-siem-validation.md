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
                        → Splunk ingest → SPL query → F1 score (parallel)
Fallback: When SIEMs offline → current Python matcher (for CI)
```

## Tasks

### Task 2.1: Create Validation Index Template

Create a dedicated `sim-validation` index in Elasticsearch for ephemeral test data.

**Steps**:
1. Create index template `sim-validation` with all ECS fields used in detections
2. Set short retention (auto-delete after 1 hour) via ILM policy
3. Add to `setup.sh` index template creation block

**Index template** (`pipeline/validation-index-template.json`):
```json
{
  "index_patterns": ["sim-validation-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.lifecycle.name": "validation-cleanup",
      "index.lifecycle.rollover_alias": "sim-validation"
    },
    "mappings": {
      "properties": {
        "process.name": { "type": "keyword" },
        "process.executable": { "type": "text", "fields": { "keyword": { "type": "keyword" }}},
        "process.command_line": { "type": "text", "fields": { "keyword": { "type": "keyword" }}},
        "process.pid": { "type": "long" },
        "process.parent.name": { "type": "keyword" },
        "process.parent.executable": { "type": "text", "fields": { "keyword": { "type": "keyword" }}},
        "event.code": { "type": "keyword" },
        "event.category": { "type": "keyword" },
        "event.type": { "type": "keyword" },
        "event.action": { "type": "keyword" },
        "user.name": { "type": "keyword" },
        "user.domain": { "type": "keyword" },
        "host.name": { "type": "keyword" },
        "file.name": { "type": "keyword" },
        "file.path": { "type": "text", "fields": { "keyword": { "type": "keyword" }}},
        "destination.ip": { "type": "ip" },
        "destination.port": { "type": "long" },
        "source.ip": { "type": "ip" },
        "source.port": { "type": "long" },
        "registry.path": { "type": "text", "fields": { "keyword": { "type": "keyword" }}},
        "registry.value": { "type": "keyword" },
        "_simulation.type": { "type": "keyword" },
        "_simulation.technique": { "type": "keyword" },
        "_simulation.expected_result": { "type": "keyword" }
      }
    }
  }
}
```

**ILM policy** (auto-cleanup):
```json
{
  "policy": {
    "phases": {
      "hot": { "actions": {} },
      "delete": { "min_age": "1h", "actions": { "delete": {} } }
    }
  }
}
```

### Task 2.2: Build Elasticsearch Validation Function

Add `validate_against_elasticsearch()` to `blue_team_agent.py` (or a new `validator.py` module).

**Function signature**:
```python
def validate_against_elasticsearch(
    compiled_lucene: str,
    attack_events: list[dict],
    benign_events: list[dict],
    es_url: str = "http://localhost:9200",
    es_auth: tuple = ("elastic", "changeme"),
    index_prefix: str = "sim-validation"
) -> dict:
    """
    Ingest events into Elasticsearch, run Lucene query, measure TP/FP/FN/TN.

    Returns:
        {
            "method": "elasticsearch",
            "f1_score": float,
            "tp": int, "fp": int, "fn": int, "tn": int,
            "tp_rate": float, "fp_rate": float,
            "query_used": str,
            "index_used": str,
            "events_ingested": int,
            "query_hits": int
        }
    """
```

**Implementation steps**:
1. Generate unique index name: `sim-validation-{uuid4()[:8]}`
2. Bulk ingest all events (attack tagged `_simulation.type: attack`, benign tagged `baseline`)
3. Wait for refresh: `POST /{index}/_refresh`
4. Run the compiled Lucene query: `POST /{index}/_search` with `query_string`
5. For each hit, check `_simulation.type`:
   - Hit on `attack` event → TP
   - Hit on `baseline` event → FP
6. For each attack event NOT hit → FN
7. For each baseline event NOT hit → TN
8. Calculate F1, TP rate, FP rate
9. Delete the validation index: `DELETE /{index}`
10. Return metrics

**Error handling**:
- If Elasticsearch is unreachable → fall back to local validation, log warning
- If query syntax error → return error with Lucene query for debugging
- If bulk ingest fails → retry once, then fall back

### Task 2.3: Build Splunk Validation Function (Optional)

Add `validate_against_splunk()` — same concept but using Splunk REST API.

**Steps**:
1. Ingest events via HEC: `POST http://localhost:8288/services/collector/event`
2. Run SPL query as oneshot search
3. Parse results, calculate metrics
4. Clean up: delete events from index

**Note**: Splunk validation is lower priority than Elasticsearch. Implement if time permits.

### Task 2.4: Integrate into Blue-Team Agent

Modify `blue_team_agent.py` to use SIEM validation when available.

**Steps**:
1. At start of `author_and_validate()`, check if Elasticsearch is reachable:
   ```python
   from orchestration.siem import check_elastic
   use_siem_validation = check_elastic()
   ```
2. After transpiling to Lucene, if `use_siem_validation`:
   ```python
   metrics = validate_against_elasticsearch(
       compiled_lucene=lucene_query,
       attack_events=scenario["events"]["attack_sequence"],
       benign_events=scenario["events"]["benign_similar"]
   )
   ```
3. If not available, fall back to current `event_matches_block()` local validation
4. Log which validation method was used in the result file
5. The retry-with-feedback loop works the same — just uses better metrics

### Task 2.5: Add Validation Method to Result Files

Update result file schema to track which validation method was used:

```json
{
  "validation_method": "elasticsearch",  // or "local_json" or "splunk"
  "validation_details": {
    "index": "sim-validation-a1b2c3d4",
    "query": "process.name:powershell.exe AND ...",
    "events_ingested": 8,
    "query_hits": 3,
    "query_time_ms": 45
  }
}
```

### Task 2.6: CI Fallback Behavior

In GitHub Actions (no SIEM running), validation must still work.

**Steps**:
1. `validate_against_elasticsearch()` returns `None` if ES unreachable
2. Agent falls back to `event_matches_block()` (current local validation)
3. Result file notes `validation_method: "local_json"` with warning
4. Quality agent flags local-only validated detections for re-validation when SIEMs available

---

## Verification Checklist

- [ ] `sim-validation` index template created and working
- [ ] Events can be bulk ingested and queried within 2 seconds
- [ ] Validation index auto-deletes after 1 hour (ILM policy)
- [ ] `validate_against_elasticsearch()` returns correct TP/FP/FN/TN for known-good rule
- [ ] `validate_against_elasticsearch()` returns correct metrics for known-bad rule
- [ ] Fallback to local validation works when ES offline
- [ ] Result files record validation method
- [ ] At least 5 detections re-validated using SIEM method and metrics match expectations
- [ ] No orphan validation indices left after test run

---

## Commit Strategy

1. `feat(validation): add sim-validation index template and ILM policy`
2. `feat(validation): add Elasticsearch-based validation function`
3. `feat(agent): integrate SIEM validation into blue-team agent with fallback`
4. `test: re-validate 5 detections using SIEM validation method`
