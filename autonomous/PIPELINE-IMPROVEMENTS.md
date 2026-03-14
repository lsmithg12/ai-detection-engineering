# Pipeline Improvement Plan — Patronus v2 (COMPLETED)

> **Status**: ALL ISSUES RESOLVED as of 2026-03-14. Fixes 1-4 implemented in PR #44. Fix 5 (SIEM validation)
> completed in Phase 2 (PR #54). Fix 6 (multi-block validator) done in Phase 1 (PR #52). Data pipeline
> vision (Issue 5 raw logs) deferred to Phase 3. This file is retained as historical reference.

Based on learnings from 3 full pipeline cycles (2026-03-08), 28 detections processed,
17 intel requests, 15 scenarios generated, 10 rules authored, 1 deployed to SIEM.

---

## Issue 1: Red-Team / Blue-Team Schema Mismatch (Critical)

### Problem
Red-team generates events with one field schema, blue-team writes Sigma rules
expecting different field names. The two agents don't share context.

**Evidence:**
- T1003.001 (F1=0.0): Rule checks `TargetImage`, events have `target.process.executable`
- T1021.001 (F1=0.5): Rule checks only EID 1, scenario has EID 1+3+11 kill chain
- T1486 (F1=1.0): Accidental — validator treats empty `selection` as "match all"

### Root Causes
1. Red-team prompt says "ECS-compatible" but Claude mixes ECS and Sysmon field names
2. Blue-team Claude writes Sigma with Sysmon fields (standard for Sigma community rules)
3. Validator doesn't handle multi-block selections (`selection_extension`, `selection_suspicious_path`)
4. No feedback loop — when validation fails, detection is tagged `needs_rework` and abandoned

### Fixes

**Fix 1a: Standardize on ECS field names in red-team prompt**
Add explicit field mapping table to `generate_scenario_with_claude()` prompt:
```
IMPORTANT: Use ONLY these ECS dotted field paths in events:
- process.name, process.executable, process.command_line, process.pid
- process.parent.name, process.parent.executable
- event.code, event.category, event.type, event.action
- user.name, user.domain
- host.name
- file.name, file.path, file.extension
- destination.ip, destination.port
- source.ip, source.port
- registry.path, registry.value
Do NOT use Sysmon field names (TargetImage, SourceImage, etc.)
```

**Fix 1b: Blue-team Sigma rules must use ECS field paths**
Add to the blue-team Claude prompt:
```
IMPORTANT: Use ECS field names in Sigma rules, NOT Sysmon field names.
Use process.executable (not SourceImage), use target.process.executable (not TargetImage).
```

**Fix 1c: Retry-with-feedback loop in blue-team agent**
After first validation, if F1 < 0.90:
1. Pass the rule + validation results + mismatched fields to Claude
2. Prompt: "This rule scored F1={score}. These attack events were missed: {events}.
   The rule checks field X but the events have field Y. Fix the rule."
3. Re-validate. Cap at 2 retries (guardrail).

**Fix 1d: Fix validator multi-block selection handling**
`event_matches_block()` currently only checks `detection.get("selection", {})`.
Should also collect `selection_*` blocks and apply AND/OR based on `condition` string.

**Fix 1e: Score only the "primary" event type**
Multi-event scenarios should mark which event is the "detection target" (e.g., EID 1).
Validator scores only against that event, not the full kill chain.
Red-team metadata already has `log_sources_used` — use it to filter.

---

## Issue 2: Deployment Before Human Review (High)

### Problem
`blue_team_agent.py` auto-deploys to Elastic + Splunk when F1 >= 0.90 and FP <= 5%.
This happens on the agent branch BEFORE the PR is merged. If the human rejects the PR,
the rule is already live in the SIEM.

### Fix: Move deployment to post-merge

**Phase 1 (author phase, pre-merge):**
- Blue-team: author → validate → score → PR
- NO SIEM deployment. State stays at VALIDATED.
- Remove `deploy_to_siem()` call from `author_and_validate()` in blue_team_agent.py
- Remove auto-deploy logic from the deployment loop in `run()`

**Phase 2 (deploy phase, post-merge):**
- New workflow: `.github/workflows/deploy-rules.yml`
- Triggers: `push` to `main` where `detections/**` changed
- Reads VALIDATED detection requests, deploys to Elastic + Splunk
- Transitions to DEPLOYED on success
- This can reuse `autonomous/orchestration/siem.py` directly

```yaml
# .github/workflows/deploy-rules.yml
name: Deploy Detection Rules
on:
  push:
    branches: [main]
    paths: ['detections/**']
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: pip install -r autonomous/orchestration/requirements.txt
      - run: |
          cd autonomous
          python -c "
          from orchestration.state import StateManager
          from orchestration.siem import deploy_all_validated
          sm = StateManager()
          deploy_all_validated(sm)
          "
        env:
          ES_URL: ${{ secrets.ES_URL }}
          KIBANA_URL: ${{ secrets.KIBANA_URL }}
          # ... SIEM credentials as secrets
```

**Note**: For the local lab, keep a manual deploy option:
```bash
python3 orchestration/cli.py deploy --validated
```

---

## Issue 3: Manual Back-and-Forth Between Agents (Medium)

### Problem
Current flow requires 4 separate runs with PR merges between each:
```
intel → [merge] → red-team → [merge] → blue-team → [merge] → quality → [merge]
```

### Fix: Add `--pipeline` mode to agent_runner

```bash
python3 orchestration/agent_runner.py --pipeline red-blue-quality
```

This runs red-team → blue-team → quality sequentially on a SINGLE branch,
creates ONE PR at the end. The state machine already tracks transitions —
no merges needed between agents.

Implementation:
- `agent_runner.py` accepts `--pipeline` with a comma-separated agent list
- Creates one branch: `agent/pipeline/20260308-abc123`
- Runs each agent's `run()` in sequence, committing after each
- Creates a single PR with combined summary
- Human reviews one PR instead of three

---

## Issue 4: No Tuning Loop for Low-F1 Detections (Medium)

### Problem
Detections with F1 < 0.90 are stuck at VALIDATED or AUTHORED with no automated
path to improvement. Currently 6 detections need tuning, 3 need rework.

### Fix: Add retry-with-feedback to blue-team agent

After initial validation:
```python
MAX_RETRIES = 2

for attempt in range(1, MAX_RETRIES + 1):
    metrics = validate(rule, scenario)
    if metrics["f1_score"] >= 0.90:
        break

    # Ask Claude to refine the rule
    result = claude_llm.ask(
        prompt=f"""This Sigma rule scored F1={metrics['f1_score']}.

Attack events that SHOULD have triggered but DIDN'T:
{json.dumps(metrics['false_negatives'], indent=2)}

Benign events that SHOULD NOT have triggered but DID:
{json.dumps(metrics['false_positives'], indent=2)}

Current rule:
{rule_yaml}

Fix the rule. The field names in the events are the source of truth.
Return ONLY the corrected Sigma YAML.""",
        agent_name="blue-team",
        allowed_tools=[],
        max_turns=1,
    )
```

This is cheap (one extra Claude call, ~30s) and directly addresses the schema mismatch.

---

## Issue 5: Data Source Gap — No Raw Log → Normalize → Detect Pipeline (Strategic)

### Current State
Red-team generates pre-normalized ECS events → pushed directly to SIEM.
This skips the entire normalization layer where most real-world detection failures occur:
- Fields missing from raw logs
- Wrong format after parsing
- Events dropped by pipeline filters
- CIM field aliases not mapped

### Vision: Full Data Pipeline

```
Intel Agent: "We need Windows Security EventID 4688 for T1059.003"
    ↓ tags request with data_source_requirements
Red-Team Agent: Generates RAW vendor-format events
    (e.g., Windows Event XML with EventID=4688, not pre-parsed ECS)
    ↓ writes to simulator/raw/<source_type>/
Cribl Stream: Normalizes raw → ECS/CIM
    - Regex extraction for missing fields
    - CIM field aliases (process.command_line → CommandLine)
    - Drops noise events
    - Routes to correct index
    ↓ outputs to Elastic + Splunk
Blue-Team Agent: Writes Sigma rules against NORMALIZED schema
    - Tests against data in the SIEM (not local JSON matching)
    - Validates using actual Elasticsearch/Splunk queries
    ↓
Validator: Runs actual SIEM queries against ingested data
    - "Did this Lucene query return the attack events?"
    - "Did it also return benign events?" (FP check)
```

### Implementation Steps

**Step 1: Intel tags data source requirements**
Add to detection request YAML:
```yaml
data_source_requirements:
  - source: windows_security
    event_ids: [4688, 4689]
    fields_needed: [process.command_line, process.parent.name]
  - source: sysmon
    event_ids: [1]
    fields_needed: [process.executable, process.hash.sha256]
```

**Step 2: Red-team generates raw events**
Instead of ECS JSON, generate closer-to-vendor format:
```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <Computer>WS-FINANCE-01</Computer>
    ...
  </System>
  <EventData>
    <Data Name="NewProcessName">C:\Users\jsmith\AppData\Local\Temp\malware.exe</Data>
    <Data Name="CommandLine">malware.exe --payload</Data>
    ...
  </EventData>
</Event>
```

Or at minimum, raw HEC-format JSON that Cribl/Splunk expects:
```json
{
  "event": "<raw syslog or windows event>",
  "sourcetype": "WinEventLog:Security",
  "host": "WS-FINANCE-01",
  "time": 1709900000
}
```

**Step 3: Cribl pipeline normalizes**
Use existing `cribl/mcp-server/` tools:
- `cribl_preview_pipeline` — test normalization without live impact
- `cribl_add_pipeline_function` — add parsers for new event types
- Validate that all `fields_needed` from step 1 exist after normalization

**Step 4: Track data source onboarding**
New state: `DATA_SOURCE_GAP` → `DATA_SOURCE_ONBOARDED`

File: `gaps/data-source-gaps.md` (already exists) + structured YAML:
```yaml
# gaps/data-sources/windows_security_4688.yml
source_type: windows_security
event_id: 4688
status: onboarded  # gap | onboarding | onboarded
cribl_pipeline: cim_normalize
cribl_function_index: 3  # position in pipeline
ecs_fields_mapped:
  - process.name
  - process.command_line
  - process.parent.name
  - user.name
techniques_requiring:
  - T1059.003
  - T1059.001
onboarded_date: 2026-03-08
```

**Step 5: Blue-team validates against SIEM, not local JSON**
Replace the local `event_matches_block()` validator with actual SIEM queries:
```python
# Instead of local JSON matching:
result = validate_against_scenario(rule, scenario)

# Do this:
# 1. Ingest scenario events into sim-attack index
# 2. Run the compiled Lucene/SPL query
# 3. Check which events matched
es_result = requests.post(f"{ES_URL}/sim-attack/_search", json={
    "query": {"query_string": {"query": compiled_lucene}}
})
```

This catches normalization failures, field mapping issues, and query syntax problems
that local JSON matching cannot detect.

---

## Issue 6: Validator Bug — Multi-Block Selections (Low but Important)

### Problem
`event_matches_block()` in blue_team_agent.py only looks for `detection.selection`.
Rules with `selection_extension` + `selection_suspicious_path` get an empty selection
dict, which matches ALL events. T1486 got F1=1.0 by accident because of this.

### Fix
```python
# Current (broken):
selection = detection.get("selection", {})

# Fixed:
# Collect all selection_* blocks
selections = {}
for key, val in detection.items():
    if key.startswith("selection"):
        selections[key] = val

# Parse condition string to determine AND/OR logic
condition = detection.get("condition", "selection")
# Simple parser: "selection_a and selection_b" → all must match
# "selection_a or selection_b" → any must match
```

---

## Priority Order (ALL COMPLETED)

| # | Fix | Status | Completed In |
|---|-----|--------|-------------|
| 1 | Move deploy to post-merge | DONE | PR #44 (deploy-rules.yml + cli.py deploy) |
| 2 | Retry-with-feedback loop | DONE | PR #44 (max 2 retries, FN/FP feedback to Claude) |
| 3 | Fix validator multi-block | DONE | PR #44 (AND/OR/1-of/all-of parsing) |
| 4 | `--pipeline` mode | DONE | PR #44 (presets: red-blue, red-blue-quality, full) |
| 5 | Standardize field names | DONE | PR #44 (red-team + blue-team prompts) |
| 6 | Raw logs + Cribl normalize | DEFERRED | Phase 3 (plans/phase3-data-pipeline.md) |
| 7 | Data source tracking | DEFERRED | Phase 3 (plans/phase3-data-pipeline.md) |
| 8 | SIEM-based validation | DONE | Phase 2 — PR #54 (validation.py) |
