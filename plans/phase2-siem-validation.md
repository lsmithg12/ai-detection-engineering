# Phase 2: SIEM-Based Validation

**Status**: COMPLETE — PR #54, all tests passing, ready to merge
**Priority**: HIGH
**Actual effort**: ~6 hours across 2 sessions
**Dependencies**: Docker services running (Elasticsearch)
**Branch**: `infra/phase2-siem-validation`

---

## Context

The blue-team agent previously validated detections by matching Sigma selection blocks
against local JSON events in Python. This missed:
- Lucene query syntax errors (backslash escaping, wildcard on keyword fields)
- Field mapping mismatches (ECS vs Sysmon naming after transpilation)
- Index template issues (fields not mapped as expected type)
- Field type issues (text vs keyword affecting wildcard behavior)

Real-world detection failures almost always occur at the query/SIEM layer, not the logic layer.

## Architecture

```
Before:   Scenario JSON → Python matcher → F1 score
After:    Scenario JSON → Elasticsearch ingest → Lucene query → F1 score
Fallback: When ES offline → Python matcher (for CI)
```

### Key Design Decisions

1. **Separate module**: Validation lives in `autonomous/orchestration/validation.py`
   (NOT in blue_team_agent.py — it's already 850+ lines)
2. **Reuse sim-* template**: `sim-validation-*` indices inherit `sim-*` template mappings
   automatically (same wildcard pattern). NO separate override template — it would
   **shadow** the parent template due to ES composable template priority rules.
3. **ILM is a safety net**: The function deletes indices after each test (primary cleanup).
   ILM catches orphans from crashes (1-hour auto-delete).
4. **Phase 3 extensibility**: Accept `ingestion_method` parameter from the start
   (direct ingest vs Cribl routing) to avoid refactoring later
5. **Splunk validation permanently deferred**: Splunk doesn't support easy event deletion,
   and the user declined the ES app license. Elastic-only.
6. **SIEM errors fed to retry loop**: When ES returns query syntax errors, include the
   error message in the feedback to Claude for the retry-with-feedback loop.

## What Was Built

### validation.py (~280 lines)
- `validate_against_elasticsearch()` — main entry point
- `_es_request()` — shared HTTP helper with auth
- `_check_es_reachable()` — health check
- `_flatten_event()` — nested dict → dotted keys for consistent mapping
- `_build_bulk_body()` — NDJSON bulk ingest format
- `_cleanup_index()` — post-test index deletion
- `create_validation_infrastructure()` — ILM policy creation + stale template cleanup

### Blue-team agent integration
- `check_elastic()` called once at start → stored on function object
- SIEM validation called after transpilation, before quality assessment
- Falls back to `validate_detection()` when ES returns `None`
- SIEM errors included in retry-with-feedback prompt
- Result files record `validation_method` and `validation_details`

### setup.sh changes
- ILM policy `validation-cleanup` created after ES health check
- `process.command_line` field mapping fixed: `text` → `keyword`
- Splunk `curl -k` flags documented with security comments
- Removed stale `sim-validation` override template block

### pipeline/validation-ilm-policy.json
- Hot phase (no actions) → Delete phase (1 hour)
- Applied per-index at creation time (not via template)

## Bugs Found & Fixed During Implementation

### BUG: Template priority shadowing (CRITICAL)
- **Symptom**: SIEM validation always returned F1=0.0 — 0 query hits on correct data
- **Root cause**: A `sim-validation-*` index template at priority 600 completely
  **shadowed** the `sim-*` template at priority 500. In ES 8 composable templates,
  only the highest-priority matching template applies — they do NOT merge.
  The override template had no field mappings → all fields got dynamic `text` mapping
  → Lucene wildcards on `keyword` fields failed silently.
- **Fix**: Removed override template entirely. ILM settings applied per-index at creation
  time via explicit `PUT /{index}` with settings. Template cleanup added to
  `create_validation_infrastructure()`.

### BUG: process.command_line mapped as text (CRITICAL)
- **Symptom**: T1083 validation returned F1=0.0 even after template fix
- **Root cause**: `process.command_line` was mapped as `text` (with `.keyword` multi-field)
  in the `sim-*` template. Sigma-cli outputs queries against `process.command_line`
  (not `.keyword`). Text fields are tokenized — wildcard queries match individual tokens,
  not the full string value. `process.command_line:*dir\ *` failed because `dir` was a
  separate token, not part of the full command string.
- **Fix**: Changed mapping to `keyword` in both `setup.sh` template and live ES template.
  Detection lab data doesn't need full-text search on command lines — only wildcard matching.

## Verification Results (2026-03-14)

All tests passing:

| Test | Description | Result |
|------|-------------|--------|
| 1 | ILM policy created via setup.sh | PASS |
| 2a | T1083 (File Discovery) — known-good rule | F1=1.0 (3 TP, 0 FP, 0 FN, 2 TN) |
| 2b | T1059.003 (Windows Command Shell) | F1=0.8 (2 TP, 0 FP, 1 FN, 2 TN) — expected |
| 3 | Bad query syntax — errors captured | PASS — errors list populated, no crash |
| 4 | No orphaned sim-validation-* indices | PASS — 0 indices after 3 test runs |
| 5 | Fallback to local_json when ES offline | PASS — returns None, agent falls back |
| 6 | Blue-team agent integration path | PASS — verified code flow + ES availability check |

## Lessons Learned

1. **ES composable templates don't merge** — highest priority wins entirely. Never create
   a "thin override" template expecting to inherit mappings from a lower-priority template.
2. **Text vs keyword matters for wildcards** — Lucene wildcards on text fields match
   tokens, not full values. Command lines, file paths, and other long strings that sigma
   queries match with wildcards MUST be `keyword` type.
3. **ILM per-index is cleaner than per-template** — applying ILM settings at index
   creation time avoids template priority conflicts entirely.
4. **Always validate with real ES** — the template shadowing bug was invisible to local
   Python matching and would have silently broken every SIEM-validated detection.

## Verification Checklist

- [x] `validation.py` module exists with `validate_against_elasticsearch()` function
- [x] Events can be bulk ingested and queried within 2 seconds
- [x] Validation index auto-deletes after function completes (primary cleanup)
- [x] ILM policy exists as safety net for orphaned indices
- [x] `validate_against_elasticsearch()` returns correct TP/FP/FN/TN for known-good rule
- [x] `validate_against_elasticsearch()` returns `None` when ES offline (fallback triggers)
- [x] Query syntax errors are captured in `errors` list (not swallowed)
- [x] Blue-team agent uses SIEM validation when available, local when not
- [x] Result files record `validation_method` and `validation_details`
- [x] Retry loop includes SIEM error feedback when available
- [x] setup.sh creates ILM policy (no override template)
- [x] No orphan validation indices left after test run
- [x] `process.command_line` mapped as `keyword` (not text)
- [x] Security review warnings addressed (curl -k documented)

---

## What Feeds Into Phase 3

Phase 2 established the ES validation pipeline. Phase 3 (Data Pipeline) extends it:
- `ingestion_method="cribl"` parameter already accepted by validation.py
- Raw vendor-format events → Cribl normalization → ES ingest → query
- Validates the full parsing/normalization chain, not just query correctness
- Splunk validation becomes feasible via Cribl-controlled routing
