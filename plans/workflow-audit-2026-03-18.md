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

---

## ISSUE-004 — Intel web search fails: `claude -p` hits max-turns (6) before completing

**Step**: Step 2 (Intel agent)
**What**:
```
[intel] Failed to parse Claude web search response: Expecting value: line 1 column 1 (char 0)
[intel] Raw response (first 500 chars): Error: Reached max turns (6)
```
Claude CLI is invoked with `--max-turns 6` and `--allowed-tools Bash(curl:*)`. It exhausts all 6 turns before returning a result. When it hits the limit, Claude CLI writes `"Error: Reached max turns (6)"` to stdout instead of the expected JSON. The agent then tries `json.loads()` on that string and fails with a parse error.

**Where**: `autonomous/orchestration/claude_llm.py:393` (`max_turns=6` in `ask_with_web_search()`)

**Why**: The web search task instructs Claude to run 5 separate queries and synthesize results. Each query needs at minimum: 1 turn to run curl + 1 turn to process = 10 turns minimum for 5 queries. 6 turns is insufficient for the full task. The error output from CLI is also not handled gracefully — the agent doesn't check if the raw response starts with "Error:" before attempting JSON parse.

**Impact**: Web search (the primary value of the intel agent) fails on every run. The agent silently falls back to 4 hardcoded static reports in `threat-intel/digest.md`. New threat intel is never ingested from the web.

**Fix plan**:
1. Increase `max_turns` to 12-15 for web search tasks, or reduce search queries per run from 5 to 2.
2. Add a pre-parse check: `if response.startswith("Error:"): return {"success": False, "error": response}` before calling `json.loads()`.
3. Consider using `WebSearch`/`WebFetch` tools (available in Claude Code context) instead of `Bash(curl:*)` — cleaner and more reliable than curl scraping.

---

## ISSUE-005 — Retrospective prompt printed but never executed

**Step**: Step 2 (Intel agent) — affects all agents
**What**: At the end of every agent run, `agent_runner.py` prints a retrospective prompt to stdout (asking Claude to record lessons learned). The output is only text — no Claude invocation happens:

```
## Retrospective — intel run 20260318-70bddf
Before finishing, review what happened this run. Record any errors...
Use: learnings.record("intel", "20260318-70bddf", ...)
```

**Where**: `autonomous/orchestration/agent_runner.py:323-325` — `retro = learnings.get_retrospective_prompt()` → `print(f"\n {retro}\n")`

**Why**: This was designed to work as a prompt for the human operator running Claude Code interactively — the idea being Claude Code reads the printed output and responds to it. When running agents as standalone CLI scripts from a terminal, the retrospective is just printed text with no actor to respond to it. No learnings are ever recorded automatically.

**Impact**: `learnings/intel.jsonl` (and other agent learnings files) are never populated from real agent runs. The briefing system at the start of each run reads from these files — since they're empty, every run starts with "Clean slate." Feedback loops for improving agent behavior are broken.

**Fix plan**: The retrospective needs to either (a) be invoked as a real Claude CLI call within the agent itself (separate `ask()` call after the main run), or (b) be documented clearly as "manual review prompt — only works interactively." Option (a) costs tokens; option (b) is honest about the limitation. A middle ground: auto-record a minimal machine-generated summary (timestamps, errors, state transitions) without requiring Claude reasoning.

---

## ISSUE-006 — Intel agent creates PR even when no detection work was produced

**Step**: Step 2 (Intel agent)
**What**: PR #71 was created on branch `agent/intel/20260318-70bddf` even though the run produced **zero new detection requests** and **zero Fawkes overlaps**. The only committed changes were `threat-intel/digest.md` (updated timestamp) and `monitoring/pipeline-metrics.jsonl` (run metrics append).

**Where**: `autonomous/orchestration/agent_runner.py:327-350` — PR is created unconditionally after any commit

**Why**: `_commit_and_push()` commits any changed files (including metadata files that always change on every run). Then `_create_pr()` is called without checking whether the commit contained substantive detection work.

**Impact**: GitHub gets noisy PRs for bookkeeping-only runs. Each no-op intel run creates a PR that a human must review and merge (or close). After 30 days of daily runs with no new detection requests, there would be 30 low-value PRs.

**Fix plan**: Add a `substantive_changes` flag to the agent result dict. If the intel agent produced 0 new detection requests, skip PR creation and just push the branch (or skip the branch entirely). Bookkeeping files like `digest.md` and `pipeline-metrics.jsonl` could be committed directly to main via a separate lightweight mechanism, or simply not committed on no-op runs.

---

---

## ISSUE-007 — Agent runner crashes on dirty working tree

**Step**: Step 5 (Validation agent) — affects all agents
**What**:
```
RuntimeError: git checkout main failed: error: Your local changes to the following files
would be overwritten by checkout:
        plans/workflow-audit-2026-03-18.md
Please commit your changes or stash them before you switch branches.
```
`_create_branch()` calls `git checkout main` unconditionally as its first step. Any uncommitted file in the working tree — regardless of whether it conflicts with the target branch — causes a hard crash before the agent does any work.

**Where**: `autonomous/orchestration/agent_runner.py:131-137` (`_create_branch()`)

**Why**: The function assumes a clean working tree. No guard checks for uncommitted changes before attempting the checkout. `git checkout main` fails even for simple additions (new files) when they'd be overwritten — which is any file tracked by git.

**Impact**: Any in-progress work (notes, config changes, report files) left uncommitted will silently block all agents from running. The error surfaces as an unhandled `RuntimeError` that terminates the entire runner without cleanup — no budget log entry, no metrics emit, no retrospective.

**Fix plan**: Before `git checkout main`, run `git status --porcelain` and either:
- (a) Auto-stash with `git stash --include-untracked`, run the agent, then `git stash pop` on completion
- (b) Check for uncommitted changes and print a clear human-readable error: "Working tree is dirty — commit or stash changes before running agents"
- (c) Accept that operator workflow files shouldn't live in the repo root and document this as a usage constraint

Option (b) is safest — auto-stash risks popping stash onto a branch that has conflicting changes.

**Compounding issue (observed)**: After the agent run, the user is left on the agent's feature branch (`agent/validation/20260318-18c951`), not on main. `git stash pop` on the agent branch produces a modify/delete conflict because the file doesn't exist in the agent's commit history. User must manually `git add <file> && git stash drop && git checkout main` to recover. The agent runner should always return the user to main after completing.

---

---

## ISSUE-008 — Claude rule refinement returns invalid YAML/Sigma in 4/5 attempts

**Step**: Step 5 (Validation agent)
**What**: Of 5 total refinement attempts across the 3 techniques, 4 failed to produce parseable output:
```
Retry 1: Claude output was not valid YAML         (T1003.001 retry 1)
Retry 2: output is not a valid Sigma rule         (T1003.001 retry 2)
Retry 1: output is not a valid Sigma rule         (T1105 retry 1)
Retry 2: output is not a valid Sigma rule         (T1105 retry 2)
```
Only T1021.001 retry 1 succeeded (2773 chars returned), but it made the rule worse (see ISSUE-010).

**Why**: The refinement prompt asks Claude to return a Sigma rule but doesn't enforce output format. Claude typically wraps YAML in markdown fences (` ```yaml ... ``` `) with explanatory text before/after. The validation agent does `yaml.safe_load(raw_output)` directly — this fails on any response that isn't pure YAML from line 1.

**Fix plan** (directly answers user question — yes, more structured output is needed):
1. **Add markdown fence stripper** in the refinement parser — extract content between ` ```yaml` and ` ``` ` before passing to yaml.safe_load. This fixes the majority of failures with minimal code change.
2. **Use `--output-format json` + structured prompt** — ask Claude to return `{"sigma_rule": "...", "changes_made": "..."}` as JSON, then extract `sigma_rule` field. More robust but requires updating the prompt.
3. **Add schema validation** after parse — verify required Sigma fields (title, logsource, detection) are present before accepting as valid.

---

## ISSUE-009 — Claude CLI times out during rule refinement (150s limit)

**Step**: Step 5 (Validation agent)
**What**: T1021.001 retry 2 timed out:
```
Retry 2: Claude error: Claude CLI timed out after 150s
```
The validation agent sets `timeout_seconds=150` for refinement calls (`validation_agent.py:432`). Refining a complex multi-condition Sigma rule — reading the existing rule, understanding why TPs failed, generating an improved version — exceeds 150s.

**Why**: 150s was set as a reasonable baseline but doesn't account for slower model responses on complex rules with long context (the refined T1021.001 was already 2773 chars). The timeout is a hard kill with no partial result recovery.

**Impact**: A timeout on retry 2 means the rule stays at whatever F1 score it had after retry 1 (0.0 for T1021.001). 150s is also too short for the Opus model (`config.yml` sets validation agent to sonnet, but if overridden to opus, timeouts will be more frequent).

**Fix plan**: Increase timeout to 240-300s for refinement calls. Add partial result handling — if Claude times out but produced output before the kill, attempt to parse what's available.

---

## ISSUE-010 — Refinement loop degrades rule quality (T1021.001 F1: 0.5 → 0.0)

**Step**: Step 5 (Validation agent)
**What**: T1021.001 started at F1=0.5 (TP=1/3). After Claude's refinement, F1 dropped to 0.0 (TP=0/3). The refined rule broke the one true positive that was working.

**Why**: The refinement prompt sends Claude the current rule and the F1 score but does not include:
- The actual TP/FP event samples that failed (what Claude is trying to match against)
- The exact field values from events that DID match vs. DIDN'T match
- The Lucene query output or error (what did the SIEM actually return?)

Without seeing the failing events, Claude is guessing at why TPs missed. It likely tightened a condition to reduce FPs but inadvertently broke the TP match logic.

**Fix plan**: The retry prompt MUST include the raw false negative events — the specific log entries the rule failed to match. This is the minimum context needed for informed refinement. Format: "Rule returned 0 matches for these events: [event JSON]. Here is the current Lucene query: [query]. Identify which field/value mismatches and produce a corrected rule." This directly answers whether the fix is detections-side or data-side.

---

## ISSUE-011 — Validation uses synthetic events only; does not cross-check live SIEM data

**Step**: Step 5 (Validation agent) — also Step 4 (design gap)
**What**: The validation agent uses `validate_against_elasticsearch()` which:
1. Ingests synthetic test events from `tests/true_positives/<technique>.json` into a temp `sim-validation-*` index
2. Runs the rule's Lucene query against those events
3. Computes F1 from match counts

The lab is running with populated indices (`sim-attack`, `sim-baseline`) containing realistic simulated telemetry. The validation agent never queries these.

**Why**: Phase 2 implemented validation-by-ingestion as the primary method because it gives deterministic, repeatable results with controlled event sets. Cross-checking against live SIEM data was not built.

**Impact** (directly answers user question — yes, local infra should be used):
- A rule can score F1=0.0 against its 3 synthetic test events but would fire correctly against the 1000s of events in `sim-attack` (or vice versa — fires on everything in sim-baseline = high FP rate in production)
- T1003.001 TP=0/3 may mean the synthetic events don't match the index template schema, not that the rule is wrong
- The lab's actual sim data is the most realistic validation surface available and it's completely unused by the pipeline

**Fix plan**:
1. Add a secondary validation pass: after synthetic-event validation, run the rule's compiled Lucene query against `sim-attack` (expect hits) and `sim-baseline` (expect no hits or low count)
2. Report: `synthetic_f1`, `siem_tp_count` (hits in sim-attack), `siem_fp_count` (hits in sim-baseline)
3. This makes validation a two-signal check: (a) rule structure matches test events, (b) rule fires correctly in the real SIEM
4. Could be implemented as a `validate_against_live_siem()` function in `validation.py` alongside the existing function

---

<!-- Additional issues appended as walkthrough continues -->

