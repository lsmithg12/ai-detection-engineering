# Phase 1: Detection Quality Remediation

**Priority**: IMMEDIATE
**Estimated effort**: 2-3 hours
**Dependencies**: None (works offline, no SIEM needed)
**Branch**: `infra/phase1-detection-quality`

---

## Context

28 detections exist but many have quality issues:
- 3 stuck at AUTHORED due to bugs now fixed (backslash normalization, non-dict crash)
- 1 has malformed Sigma (T1562.001 — hard-coded process name, broken filter)
- 25/28 lack compiled Elastic JSON outputs
- Multi-event test scenarios inflate FN metrics
- Tuning changelog is empty (no audit trail)
- Result files lack timestamps and SIEM metadata

## Tasks

### Task 1.1: Fix Stuck Detections (T1046, T1562.006, T1569.002)

These three detections are stuck at AUTHORED with F1=0.0 due to bugs fixed in PR #47:
- BUG 7: Backslash normalization (YAML `\\` vs JSON `\`)
- BUG 8: Non-dict Sigma crash (rate-limit error stored as YAML string)

**Steps**:
1. Read each detection request: `autonomous/detection-requests/t1046.yml`, `t1562_006.yml`, `t1569_002.yml`
2. Read the corresponding scenario files in `simulator/scenarios/`
3. Read the current Sigma rules in `detections/`
4. For each, determine if the rule is valid YAML with a `detection` key
5. If T1569.002 has a corrupted rule (rate-limit error text), regenerate the Sigma rule
6. Re-validate each rule against its scenario using the blue-team validator logic
7. If F1 >= 0.75, transition to VALIDATED. If not, manually fix the rule.
8. Update the detection request YAML with new metrics

**Files to modify**:
- `detections/discovery/t1046.yml` (or wherever it lives)
- `detections/defense_evasion/t1562_006.yml`
- `detections/execution/t1569_002.yml`
- `autonomous/detection-requests/t1046.yml`
- `autonomous/detection-requests/t1562_006.yml`
- `autonomous/detection-requests/t1569_002.yml`

### Task 1.2: Fix T1562.001 Malformed Sigma Rule

**Current problems**:
- Hard-coded `process.name: update_helper.exe` — easily evaded by renaming
- Filter block references variables not defined in selection
- Won't transpile to Lucene/SPL

**Steps**:
1. Read `detections/defense_evasion/t1562_001.yml`
2. Read the corresponding scenario: `simulator/scenarios/t1562_001.json`
3. Read `templates/detection-authoring-rules.md` for guidance
4. Rewrite the detection logic:
   - Selection: process loading `amsi.dll` or `clr.dll` from suspicious path
   - Use path-based patterns (`*\\AppData\\Local\\Temp\\*`, `*\\ProgramData\\*`)
   - Filter: exclude known legitimate CLR hosts (dotnet.exe, powershell.exe, msbuild.exe)
   - Condition: `selection and not filter_legitimate`
5. Validate against scenario events
6. Transpile: `sigma convert -t lucene -p ecs_windows detections/defense_evasion/t1562_001.yml`
7. Update detection request with new metrics

### Task 1.3: Compile Missing Elastic/Splunk Outputs

25/28 rules lack compiled outputs. Generate them all.

**Steps**:
1. List all Sigma rules: `find detections/ -name "*.yml" -not -path "*/compiled/*"`
2. For each rule, run:
   ```bash
   sigma convert -t lucene -p ecs_windows <rule>.yml > <tactic>/compiled/<technique_id>.lucene
   sigma convert -t splunk --without-pipeline <rule>.yml > <tactic>/compiled/<technique_id>.spl
   ```
3. If transpilation fails, fix the Sigma rule syntax first (common issues in `templates/detection-authoring-rules.md`)
4. For rules that already have `.json` files in compiled/, verify they match the current Sigma rule
5. Track which rules fail transpilation — these need manual fix

**Note**: Some rules may fail due to:
- Backslash escaping in Lucene (known issue — use simplified patterns)
- Unsupported Sigma modifiers (check sigma-cli version compatibility)
- Missing logsource mapping (ECS pipeline may not cover all sources)

### Task 1.4: Split Multi-Event Test Scenarios

T1046 and T1027 have multi-event scenarios (3+ events) that inflate FN counts because
the rule only checks one event type but gets scored against the full sequence.

**Steps**:
1. Read `tests/true_positives/t1046_tp.json` — identify the "primary" event (EID matching the rule)
2. Create `tests/true_positives/t1046_tp.json` with ONLY the primary event
3. Move the full sequence to `tests/integration/t1046_killchain.json` (new directory)
4. Repeat for T1027 and any other multi-event test files
5. Re-validate F1 scores with single-event TP tests

**New directory**: `tests/integration/` for multi-event kill chain tests (separate from single-rule validation)

### Task 1.5: Enrich Validation Result Files

Current result files (`tests/results/*.json`) are sparse. Add operational metadata.

**Steps**:
1. Read a few result files to understand current schema
2. Add these fields to each result:
   ```json
   {
     "validated_at": "2026-03-13T10:00:00Z",
     "validated_by": "blue-team-agent",
     "validation_method": "local_json",
     "siem_targets": ["elasticsearch", "splunk"],
     "sigma_rule_path": "detections/execution/t1059_001.yml",
     "scenario_path": "simulator/scenarios/t1059_001.json",
     "attack_event_count": 3,
     "benign_event_count": 5,
     "quality_tier_criteria": {
       "auto_deploy": "F1 >= 0.90 AND FP <= 0.05",
       "validated": "F1 >= 0.75",
       "needs_rework": "F1 < 0.75"
     }
   }
   ```
3. Fix `quality_tier` to actually reflect metrics (not hardcoded "auto_deploy")

### Task 1.6: Update Coverage Matrix

`coverage/attack-matrix.md` is dated 2026-03-07. Update with current state.

**Steps**:
1. Read all detection requests: `autonomous/detection-requests/*.yml`
2. Compile actual state per technique (AUTHORED/VALIDATED/DEPLOYED/MONITORING)
3. Update `coverage/attack-matrix.md` with correct statuses
4. Update detection counts and coverage percentages
5. Mark techniques that were re-validated after bug fixes

### Task 1.7: Populate Tuning Changelog

`tuning/changelog/` is empty. Create audit trail entries.

**Steps**:
1. Review git log for tuning-related commits
2. For each detection that had FP adjustments, create `tuning/changelog/<technique_id>.md`:
   ```markdown
   # T1059.001 — PowerShell Bypass Tuning History

   ## 2026-03-05 — Initial deployment
   - FP rate: 12% (SCCM deployment scripts triggering)
   - Added filter: exclude parent process `sccm_agent.exe`
   - FP rate after: 3%

   ## 2026-03-08 — Pipeline v1 re-validation
   - F1 score: 0.95
   - No changes needed
   ```

---

## Verification Checklist

- [ ] All 28 Sigma rules pass `sigma check <rule>.yml`
- [ ] All 28 rules have compiled Lucene output
- [ ] All 28 rules have compiled SPL output
- [ ] No test file has more than 1 event per TP test (multi-event → integration/)
- [ ] All result files have `validated_at` timestamp
- [ ] coverage/attack-matrix.md reflects actual detection states
- [ ] tuning/changelog/ has at least entries for deployed detections
- [ ] T1046, T1562.006, T1569.002 are no longer stuck at AUTHORED
- [ ] T1562.001 uses path-based patterns (no hard-coded process names)

---

## Commit Strategy

Single branch `infra/phase1-detection-quality` with these commits:
1. `fix(detection): regenerate stuck detections (T1046, T1562.006, T1569.002)`
2. `fix(detection): rewrite T1562.001 AMSI bypass rule — use path patterns`
3. `feat(detection): compile Lucene/SPL for all 28 rules`
4. `refactor(tests): split multi-event scenarios into single-event TP tests`
5. `docs(coverage): update attack matrix and tuning changelog`
