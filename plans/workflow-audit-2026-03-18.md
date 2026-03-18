# Workflow Audit — 2026-03-18

Manual walkthrough of the full detection engineering pipeline to identify gaps,
broken steps, and areas for improvement before planning a next improvement phase.

## Scope

Walk through every step of the lab workflow end-to-end:
0. Infrastructure health check
1. Pipeline state (`cli.py status`)
2. Intel agent
3. Red-team agent
4. Author agent
5. Validation agent
6. Deployment agent
7. Tuning agent
8. Coverage agent
9. Security agent (PR gate)
10. Deploy validated detections

---

## Issues Log

Issues are numbered sequentially. Each issue includes:
- **What**: observed behavior
- **Where**: file/command/step
- **Why**: root cause hypothesis
- **Fix plan**: proposed resolution

---

---

## ISSUE-001 — Phase 6 rules not registered in state machine

**Step**: Step 1 (`cli.py status`)
**What**: State machine reports 28 detection requests. `detections/` contains 37 rule files (30 Sigma + 3 EQL + 4 threshold). The 9-rule gap is entirely Phase 6 content — no detection-request YAML was created for any of them.

**Missing detection-requests** (8 new Phase 6 rules have no `autonomous/detection-requests/` file):
| File | Technique ID |
|------|-------------|
| `detections/privilege_escalation/t1055_004_apc_injection.yml` | T1055.004 |
| `detections/privilege_escalation/t1055_sequence_eql.yml` | T1055 (EQL) |
| `detections/discovery/t1087_002_discovery_burst_eql.yml` | T1087.002 (EQL) |
| `detections/discovery/t1087_002_discovery_threshold.yml` | T1087.002 (threshold) |
| `detections/execution/t1059_001_t1547_001_persistence_after_exec_eql.yml` | T1059.001+T1547.001 (cross-tactic EQL) |
| `detections/credential_access/t1110_001_brute_force_threshold.yml` | T1110.001 |
| `detections/impact/t1486_file_encryption_threshold.yml` | T1486 (threshold variant) |
| `detections/impact/t1489_mass_service_stop_threshold.yml` | T1489 |

**Why**: Phase 6 added EQL/threshold rules directly as content pack deliverables, bypassing the intel → red-team → author pipeline. The detection-request YAML creation step was skipped.

**Impact**: These 8 rules are **invisible to the pipeline**. The validation agent, deployment agent, and coverage agent all query the state machine — none of these rules will be validated, deployed, or counted in coverage metrics.

**Fix plan**: For each of the 8 missing techniques, create a `autonomous/detection-requests/<id>.yml` in AUTHORED state (rule already written, just needs state machine registration). Then let the validation agent pick them up normally. Will also need to decide how to handle EQL/threshold types in the state machine schema (currently only Sigma is modeled — see ISSUE-002).

---

## ISSUE-002 — State machine doesn't model rule type variants (EQL, threshold, cross-tactic)

**Step**: Step 1 (`cli.py status`)
**What**: Two separate issues with duplicate technique IDs:

1. `t1562_006.yml` (auditpol) and `t1562_006_registry.yml` (registry) both have technique ID T1562.006 — only one state machine entry exists.
2. `t1087_002_discovery_burst_eql.yml` and `t1087_002_discovery_threshold.yml` both use T1087.002 — no state machine entry for either.
3. The cross-tactic EQL `t1059_001_t1547_001_*` has no clean technique ID to key off.

**Why**: The state machine uses technique ID as primary key. A technique with multiple rules (one Sigma + one threshold, or two Sigma variants) cannot be represented — the second rule has nowhere to live.

**Impact**:
- Deployment agent could deploy either variant but not track both.
- Coverage metrics undercount rules per technique.
- Future multi-rule techniques will hit the same wall.

**Fix plan**: Two options — (a) use a compound key `technique_id + rule_type` (e.g., `T1087.002:eql`, `T1087.002:threshold`), or (b) track a `rules` list within each detection request. Option (b) is less disruptive to existing tooling. For cross-tactic EQL, define a primary technique ID with a `secondary_techniques` field.

---

## ISSUE-003 — STATUS.md rule counts are out of sync with state machine

**Step**: Step 1 (`cli.py status`)
**What**:
- STATUS.md: "10 AUTHORED" — state machine: 3 AUTHORED
- STATUS.md: "12 VALIDATED" — state machine: 14 VALIDATED
- STATUS.md: "4 needs rework" — no such state exists in the state machine

**Why**: STATUS.md is manually maintained and counts rule files on disk. The state machine counts detection-request files. They diverged during Phase 6 (8 new rules added to disk, never registered). The "needs rework" label in STATUS.md is editorial — it maps to AUTHORED in the state machine (T1003.001, T1021.001, T1105 are AUTHORED because they failed validation) but isn't surfaced as a distinct state.

**Impact**: Documentation drift — two sources of truth that disagree. Anyone reading STATUS.md gets a different picture than running `cli.py status`.

**Fix plan**: After registering the 8 missing detection requests (ISSUE-001 fix), regenerate STATUS.md counts from the state machine programmatically. Consider adding a `cli.py export-status` command that writes STATUS.md from ground truth rather than maintaining it by hand.

---

<!-- Additional issues appended as walkthrough continues -->

