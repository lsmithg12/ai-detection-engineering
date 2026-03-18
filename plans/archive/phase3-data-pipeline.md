# Phase 3: Data Pipeline — Raw Logs through Cribl

**Status**: COMPLETED — Branch `infra/phase3-data-pipeline` (2026-03-14)
**Priority**: HIGH
**Actual effort**: ~4 hours (single session)
**Dependencies**: Phase 2 (SIEM validation) — DONE (PR #54). Docker + Cribl running.
**Branch**: `infra/phase3-data-pipeline`

---

## Context

Current flow skips the normalization layer where most real-world detection failures occur:

```
Before (Phase 2):  Red-team → pre-normalized ECS JSON → direct to ES → Lucene query → F1
Problem:           Fields are always correct because they're hand-crafted
After (Phase 3):   Red-team → raw Sysmon text → Cribl HEC → normalize → ES → Lucene → F1
```

In production, events arrive as raw vendor text (Sysmon key=value, Windows Event XML).
Cribl Stream sits in the data path as a streaming pipeline — events flow through it to the
SIEM, not through it as a standalone normalizer. Phase 3 implements this full path.

### What Phase 2 Already Built (Leverage Points)

Phase 2 delivered `validation.py` with an `ingestion_method` parameter:
```python
validate_against_elasticsearch(
    ...,
    ingestion_method="direct",  # Phase 2 — bulk ingest to ES
    ingestion_method="cribl",   # Phase 3 — route through Cribl HEC → pipeline → ES
)
```

The ephemeral index pattern (`sim-validation-*`), ILM cleanup, and scoring logic carry over.

## Architecture

```
Red-Team Agent
  ↓ generates ECS events (unchanged)
simulator/raw_events.py (NEW)
  ↓ converts ECS → raw Sysmon text / Windows XML
  ↓ wraps in HEC envelope {event: "<raw text>", sourcetype: ..., _validation_index: ...}
  ↓
Cribl Stream (HEC input, port 8088)
  ↓ route: _validation_index exists → elastic_validation output
  ↓ pipeline: cim_normalize
  ↓   1. serde (JSON parse — fails silently on raw text)
  ↓   2. regex_extract (fires when serde didn't parse — extracts fields from raw text)
  ↓   3. eval (maps extracted fields to ECS dotted notation)
  ↓   4. eval (CIM aliases + cleanup)
  ↓
Elasticsearch (sim-validation-{uuid} index — inherits sim-* template)
  ↓
validation.py (Phase 2 scoring logic, unchanged)
  ↓ runs Lucene query → measures TP/FP
  ↓ cleanup: delete ephemeral index
  ↓
Detection validated end-to-end through full streaming pipeline
```

### Key Design Decisions

1. **Full streaming path, not preview-only**: Events flow through Cribl HEC → pipeline → ES
   output, matching the real-world data path. Cribl is a streaming pipeline, not a normalizer
   you call on demand.

2. **Dedicated validation route**: A Cribl route (`validation_to_elastic`) catches events with
   `_validation_index` set and routes them to a dedicated `elastic_validation` output that uses
   a dynamic index name. This keeps validation events isolated from sim-attack/sim-baseline.

3. **Conditional regex parsing**: Pipeline functions use filter `!__e.event || !__e.event.code`
   so raw text parsers only fire when the JSON serde didn't produce ECS fields. Existing ECS
   JSON flow is completely unaffected.

4. **Graceful fallback**: When Cribl is offline, `ingestion_method="cribl"` falls back to
   direct ES ingest with an error note. CI environments work without Cribl.

5. **_simulation tag preservation**: The `_simulation.type` tag is included in the HEC
   envelope and survives Cribl normalization, enabling TP/FP scoring.

## What Was Built

### simulator/raw_events.py (~300 lines)
- `ecs_to_raw_sysmon()` — ECS → raw Sysmon text for EIDs 1, 3, 7, 8, 10, 11, 13, 17, 18, 22
- `ecs_to_raw_windows_security()` — ECS → Windows Event XML for EIDs 4624, 4688, 7045
- `ecs_to_raw()` — dispatcher by event.code and agent.type
- `convert_scenario_to_raw()` — converts full scenario (attack + benign arrays)

### validation.py additions
- `_check_cribl_reachable()` — health check
- `_cribl_auth()` — authenticate, get bearer token
- `_send_to_cribl_hec()` — send raw events via HEC to Cribl streaming path
- `ingestion_method="cribl"` path in `validate_against_elasticsearch()`
  - Converts ECS events to raw format
  - Tags with `_validation_index` for Cribl routing
  - Sends to Cribl HEC (full streaming path)
  - Creates ephemeral ES index with ILM
  - Waits for events to appear in ES
  - Runs Lucene query against normalized events
  - Falls back to direct ingest if Cribl is offline

### pipeline/configure-cribl.sh updates
- 8 new `regex_extract` functions for raw Sysmon text parsing (EIDs 1/4688, 3, 7, 8, 10, 13, 22)
- 1 new `eval` function mapping regex-extracted fields to ECS dotted notation
- `elastic_validation` output with dynamic index name
- `validation_to_elastic` route (first in priority, final=true)

### gaps/data-sources/ (9 YAML files)
- Structured gap tracking replacing free-text markdown
- Fields: gap_id, source_type, event_id, status, priority, affected_techniques,
  simulator_support, cribl_pipeline, ecs_fields_expected, resolution_notes
- Updated status based on actual simulator capabilities (EIDs 11, 17/18, 22, 7045
  are `partially_available`, not `gap`)

### intel_agent.py additions
- `TECHNIQUE_DATA_SOURCES` mapping — data source requirements per technique
- `get_data_source_requirements()` — look up requirements by technique ID
- `check_data_source_gaps()` — cross-reference against gaps/data-sources/*.yml
- Tags new detection requests with `data_source_requirements` and `data_source_gaps`

### CLI additions
- `python orchestration/cli.py data-sources` — reports gap status by category

### config.yml additions
- `cribl.user`, `cribl.pass`, `cribl.hec_url`, `cribl.hec_token`, `cribl.pipeline`

### Tuning changelog
- `tuning/changelog/cribl-pipeline-2026-03-14.md` — documents all pipeline changes

## Verification Checklist

- [x] Raw event formats documented for Sysmon EID 1, 3, 7, 8, 10, 13, 22
- [x] `ecs_to_raw()` converter handles all active EIDs
- [x] Cribl `cim_normalize` pipeline parses both ECS JSON and raw Sysmon text
- [x] Validation route sends events through full Cribl streaming path
- [x] `_simulation.type` tag survives Cribl normalization
- [x] Fallback to direct ES ingest when Cribl is offline
- [x] Data source gap files exist in `gaps/data-sources/` for all 9 gaps
- [x] Intel agent tags requests with `data_source_requirements`
- [x] CLI `data-sources` command reports gap status
- [x] Pipeline change log created: `tuning/changelog/cribl-pipeline-2026-03-14.md`
- [x] Config.yml has Cribl HEC configuration

---

## Commit Strategy

1. `feat(simulator): add raw vendor event format converter (ecs_to_raw)`
2. `feat(cribl): add raw Sysmon parsing + validation route to pipeline`
3. `feat(validation): add Cribl streaming path to ES validation`
4. `feat(gaps): structured data source gap tracking (YAML)`
5. `feat(intel): tag detection requests with data source requirements`
6. `docs: update Phase 3 plan, ROADMAP, STATUS, CLAUDE.md`
