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

**Compounding issue (recurring)**: After every agent run, the user is left on the agent's feature branch, not on main. Attempting `git stash pop` on the agent branch produces a modify/delete conflict because uncommitted files don't exist in the agent branch's history. Workaround: always `git checkout main` before `git stash pop`. This recurred on every subsequent agent run (tuning, coverage, etc.). The agent runner should always `git checkout main` on exit to return the operator to a known state.

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

---

## ISSUE-012 — T1569.002 skipped with vague "missing artifacts" error

**Step**: Step 6 (Deployment agent)
**What**:
```
[deployment] Skipping T1569.002 -- missing artifacts
```
T1569.002 has both compiled artifacts on disk:
```
detections/execution/compiled/t1569_002.lucene  ✓
detections/execution/compiled/t1569_002.spl     ✓
```
No `_elastic.json` exists for T1569.002 — but none of the other 5 successfully-deployed rules have `_elastic.json` either. The deployment agent constructs the Elastic rule JSON from Lucene + metadata for those rules. Something specific about T1569.002 triggers the "missing artifacts" check that the others don't.

**Why**: Unknown — the error message is opaque and doesn't specify which artifact is missing or which check failed. Likely a mismatch between the rule filename pattern the deployment agent expects and what's on disk, or a missing test file the agent checks for before deploying.

**Fix plan**: The deployment agent should log the specific missing file path (e.g., "missing: detections/execution/compiled/t1569_002_elastic.json" or "missing: tests/true_positives/t1569_002.json") rather than a generic message. Add diagnostic logging to `deployment_agent.py`'s artifact check.

---

## ISSUE-013 — 8 VALIDATED rules stuck in pipeline dead zone (F1 0.75-0.89, never auto-deployed)

**Step**: Step 6 (Deployment agent)
**What**: The deployment agent found 14 VALIDATED items but only 6 were eligible for deployment. The other 8 — T1055.001, T1059.003, T1082, T1133, T1190, T1204.002, T1543.003, T1562.004 — were skipped without explanation. These rules have F1 scores between 0.75 and 0.89 ("validated" tier, not "auto_deploy" tier).

**Why**: The deployment agent applies `auto_deploy_threshold: 0.90` from config, so only F1 >= 0.90 rules are auto-deployed. Rules in the 0.75-0.89 range are permanently stuck: they passed validation (not sent back for rework) but will never be auto-deployed. The only path forward for them is `cli.py deploy --validated` run manually.

**Impact**: 8 rules that are "good enough" for production exist in a state they can never exit automatically. This gap — between "validated" and "auto_deploy" — is not documented or surfaced anywhere. An operator has to know to run `deploy --validated` manually.

**Fix plan**: Two options:
- (a) Lower `auto_deploy_threshold` to 0.75 so all validated rules are auto-deployed (with a human review step for 0.75-0.89)
- (b) Have the deployment agent list the skipped rules and their F1 scores explicitly so the operator knows to run `deploy --validated` for them
- (c) Add a scheduled weekly deploy that includes all VALIDATED rules regardless of tier

---

## ISSUE-014 — Compiled `_elastic.json` artifacts for Phase 6 rules are orphaned

**Step**: Step 6 (Deployment agent) — cross-reference with ISSUE-001
**What**: 11 `_elastic.json` files exist on disk (all Phase 6 rules), but NONE of those rules have detection-request YAML entries, so the deployment agent never sees them. Meanwhile, the 5 successfully deployed older Sigma rules have no `_elastic.json` — the agent constructs the Elastic JSON inline from Lucene.

```
Has _elastic.json (Phase 6 — no state machine entry, never deployed):
  T1110.001, T1087.002 EQL, T1087.002 threshold, T1059+T1547 EQL,
  T1486 threshold, T1489, T1055.004, T1055 EQL

No _elastic.json (older Sigma — deployed successfully inline):
  T1027, T1046, T1083, T1490, T1562.006 ← deployed this run
```

**Why**: Phase 6 pre-built `_elastic.json` for EQL/threshold rules (they require specific JSON structure Sigma can't transpile). The older Sigma rules rely on `siem.py` constructing Elastic JSON at deploy time. These two deployment paths are inconsistent and not documented.

**Impact**: The 8 Phase 6 rules with `_elastic.json` have fully built deploy artifacts but no pipeline path to reach Elastic. Fixing ISSUE-001 (registering them in the state machine) would unblock this — but the deployment agent needs to know which path to use (inline construction vs. reading `_elastic.json`).

**Fix plan**: When fixing ISSUE-001, ensure the detection-request YAML for EQL/threshold rules includes a `compiled_artifact` field pointing to the `_elastic.json` path. The deployment agent should prefer the pre-built JSON when that field is present, fall back to inline construction for Sigma rules.

---

---

## ISSUE-015 — Newly DEPLOYED rules not processed by tuning agent (state gap)

**Step**: Step 7 (Tuning agent)
**What**: The deployment agent deployed 5 rules this session (T1027, T1046, T1083, T1490, T1562.006) and set their state to DEPLOYED. The tuning agent found all 5 as "pending" but then reported:
```
Found 11 active detections (0 DEPLOYED, 11 MONITORING)
```
The 5 DEPLOYED rules were completely skipped — only the 11 pre-existing MONITORING rules were analyzed.

**Why**: The tuning agent's active detection filter only processes MONITORING state, not DEPLOYED state. DEPLOYED is supposed to be a transient state (rule is live but not yet confirmed active), and normally the deployment agent or a post-deploy health check would transition it to MONITORING. That transition never happened in this run — the deployment agent set state to DEPLOYED and stopped there.

**Impact**: Rules freshly deployed in a session are in a dead zone: they're live in the SIEM but invisible to health monitoring. They'll stay DEPLOYED indefinitely until something transitions them to MONITORING.

**Fix plan**: Either (a) the deployment agent should transition DEPLOYED → MONITORING after confirming the rule is active in the SIEM (via a rule status API call), or (b) the tuning agent should include DEPLOYED rules in its fleet scan and promote them to MONITORING after the first successful health check.

---

## ISSUE-016 — Health scores appear static/hardcoded rather than dynamically computed

**Step**: Step 7 (Tuning agent)
**What**: 10 of 11 MONITORING rules scored exactly 0.915, and one scored 0.907. These are the same scores shown in STATUS.md from Phase 6. The tuning agent logged `Claude analysis received` but reported "8 healthy, 0 tune, 0 review, 0 retire" — no tuning actions triggered despite 3 INVESTIGATE flags.

**Why**: The health scores are likely being read from the stored values in each detection-request YAML (set at validation time) rather than computed live from current Elastic/Splunk alert telemetry. A real fleet health check would query Elastic for alert counts, last-fired timestamps, FP feedback verdicts, and compute a fresh score.

**Impact**: The tuning agent provides no signal about whether rules are actually firing in production. A rule could be broken in the SIEM (wrong query, deleted index) and still show health=0.915 because the stored score never changes. The 3 INVESTIGATE flags ("no alerts for 14+ days") contradict the healthy scores — if rules haven't fired in 2 weeks the health score should not be 0.915.

**Fix plan**: Health scoring should query the live SIEM: `GET .alerts-security.alerts-default/_search` with a date filter to get recent alert counts per rule. Zero alerts over 14 days on an active rule = significantly reduced health score. This would make the 3 INVESTIGATE flags reflect actual health degradation.

---

## ISSUE-017 — 3 INVESTIGATE flags (no alerts 14+ days) with no tuning actions taken

**Step**: Step 7 (Tuning agent)
**What**: T1059.001, T1134.001, and T1547.001 were flagged as INVESTIGATE ("No alerts for 14+ days — may be broken or unnecessary") but the tuning agent's summary shows "0 review, 0 retire". The INVESTIGATE flags generated no downstream action.

**Why**: The tuning agent identifies issues (no alerts = potentially broken) but doesn't escalate them. There's no mechanism to:
- Create a GitHub Issue for operator review
- Reduce the health score to reflect the signal gap
- Schedule a re-validation run for the suspected broken rules

**Impact**: Silent rules go undetected. If sim data isn't generating T1059.001/T1134.001/T1547.001 attack events, these rules will perpetually sit at INVESTIGATE with no resolution. The "operational feedback loop" that Phase 7 was meant to build isn't closing.

**Fix plan**: INVESTIGATE flags should auto-create a GitHub Issue (`[Health] Rule T1059.001 — no alerts 14+ days`) and reduce the stored health score. Alternatively, the tuning agent should trigger the validation agent to re-run the rule against fresh sim data to confirm whether it's broken or just quiet.

---

---

## ISSUE-018 — Coverage metric understates actual coverage (28 rules counted, 37 exist)

**Step**: Step 8 (Coverage agent)
**What**: Coverage agent reports 22/39 techniques (56%) based on 28 detection requests. 9 rules are not in the state machine (ISSUE-001), so they contribute zero coverage. CLAUDE.md states 67% Fawkes coverage (14/21) while the coverage agent reports 56% (22/39) — different denominators, but neither number is surfaced with context about which metric it represents.

**Why**: Direct downstream consequence of ISSUE-001. Coverage agent reads from the state machine (28 entries), not `detections/` (37 rules). The 8 Phase 6 rules cover T1055.004, T1087.002, T1110.001, T1489 — registering them would improve the reported number.

**Fix plan**: Fix ISSUE-001 first. After registering the 8 Phase 6 rules, re-run coverage. Document in gap report header which metric is being reported (Fawkes-only vs. all 4 threat models).

---

## ISSUE-019 — Coverage agent did not create GitHub Issues for 6 actionable gaps

**Step**: Step 8 (Coverage agent)
**What**: 6 actionable gaps identified, but no GitHub Issue creation logged. Phase 5 docs describe auto GitHub Issue creation for coverage gaps as a delivered capability.

**Why**: Either (a) silent failure (token/rate limit), (b) gated behind a disabled config flag, or (c) only triggers for data-source gaps, not detection-content gaps.

**Impact**: Actionable coverage gaps are not tracked in GitHub. The automated gap → issue → detection pipeline is broken at this link.

**Fix plan**: Add explicit log output per gap ("Creating issue..." / "Created #N" / "Skipped: already open #N"). Verify GITHUB_TOKEN is available and issue creation logic is invoked for actionable gaps.

---

## ISSUE-020 — 34 stale local branches accumulating from agent runs

**Step**: Observed during Step 1 git check
**What**: 34 local branches from previous runs (`agent/intel/20260307-*`, `agent/blue-team/20260308-*`, etc.) exist locally, never cleaned up. Every agent run adds one more.

**Why**: Agent runner creates a branch per run and pushes it. After PR merge, GitHub deletes the remote but local branches persist. No cleanup step exists.

**Fix plan**: Add `git fetch --prune` to `_create_branch()`. Add `make clean-branches` Makefile target: `git branch --merged main | grep "agent/" | xargs git branch -d`.

---

---

## ISSUE-021 — Security agent creates its own PR even when its only output is a review comment

**Step**: Step 9 (Security agent)
**What**: The security agent reviewed PR #73, posted a review comment, then created PR #76 for its own branch `agent/security/20260318-cbab8d`. PR #76 has no substantive changes — only pipeline metrics and budget log appends.

**Why**: Agent runner unconditionally creates a PR at the end of any run that produces commits (same root cause as ISSUE-006). The security agent's job is reviewing other PRs, not producing mergeable content.

**Impact**: Every security gate run generates a noise PR. If security runs on every agent PR (design intent = 5 agent PRs per cycle), that's 5 extra PRs per cycle that can never be meaningfully merged.

**Fix plan**: Suppress PR creation for the security agent role. Its output is the review comment on the target PR. If state tracking is needed, commit directly to the agent branch with no PR.

---

## ISSUE-022 — Security scan is pure regex pattern matching; no Claude-assisted rule quality review

**Step**: Step 9 (Security agent)
**What**: Scan completed in 1.6s, 0 Claude calls, 0 findings. Config specifies `model: sonnet` and `auto_fix_enabled: true` but Claude was never invoked — it only fires when findings need explanation. The gate passes or fails entirely on `scan-patterns.yml` regex matches.

**Impact**: No qualitative review of deployed detection rules: no test coverage check, no logic review for overly broad conditions, no evasion analysis, no check that SIEM API calls use auth correctly. A syntactically valid but analytically weak rule passes the gate without any scrutiny.

**Fix plan**: Add a mandatory Claude reasoning step for every PR touching `detections/` — even with 0 pattern findings. Prompt should cover: (1) FP risk from overly broad conditions, (2) evasion by simple technique variants, (3) missing test cases, (4) coverage gaps vs. stated MITRE technique. Turns the gate from a lint check into a real quality review.

---

## Summary — Full Walkthrough Complete

**Date**: 2026-03-18
**Steps completed**: 0 (infra) → 1 (status) → 2 (intel) → 3 (red-team) → 4 (author) → 5 (validation) → 6 (deployment) → 7 (tuning) → 8 (coverage) → 9 (security)
**PRs created by pipeline**: #71 (intel), #72 (validation), #73 (deployment), #74 (tuning), #75 (coverage), #76 (security)
**Rules deployed this session**: 5 (T1027, T1046, T1083, T1490, T1562.006 → Elastic + Splunk)

### Issue Registry

| # | Severity | Step | Summary |
|---|----------|------|---------|
| 001 | High | 1 | 8 Phase 6 rules have no detection-request YAML — invisible to entire pipeline |
| 002 | Medium | 1 | State machine primary key is technique ID — can't model multiple rule variants per technique |
| 003 | Low | 1 | STATUS.md rule counts disagree with `cli.py status` (manually maintained, drifted) |
| 004 | High | 2 | Intel web search always fails — `claude -p` hits max-turns (6) before completing |
| 005 | Medium | 2 | Retrospective prompt printed but never executed — learnings files always empty |
| 006 | Low | 2 | No-op agent runs (0 new detections) still create PRs |
| 007 | Medium | 5+ | Agent runner crashes on dirty working tree; leaves operator on agent branch after every run |
| 008 | Critical | 5 | Claude rule refinement returns invalid YAML/Sigma 4/5 times — needs markdown fence stripper + structured output format |
| 009 | Medium | 5 | 150s timeout too short for complex rule refinement |
| 010 | Critical | 5 | Refinement loop degrades rule quality — Claude refines without seeing the failing events |
| 011 | High | 5 | Validation never cross-checks against live SIEM data (sim-attack / sim-baseline) |
| 012 | Low | 6 | T1569.002 skipped with vague "missing artifacts" — no detail on which file is absent |
| 013 | Medium | 6 | 8 VALIDATED rules (F1 0.75-0.89) stuck in pipeline dead zone — never auto-deployed |
| 014 | Medium | 6 | Phase 6 `_elastic.json` artifacts orphaned — no pipeline path to deployment |
| 015 | Medium | 7 | Newly DEPLOYED rules not transitioned to MONITORING — invisible to tuning agent |
| 016 | High | 7 | Health scores are static/stored values, not computed from live SIEM alert queries |
| 017 | Medium | 7 | INVESTIGATE flags (3 rules, no alerts 14+ days) produce no downstream action |
| 018 | Medium | 8 | Coverage reports 56% (22/39) — understated because 9 unregistered rules not counted |
| 019 | Medium | 8 | Coverage agent does not create GitHub Issues for 6 actionable gaps |
| 020 | Low | 1 | 34 stale local branches accumulating from agent runs — never cleaned up |
| 021 | Low | 9 | Security agent creates its own PR even though its only output is a review comment |
| 022 | Medium | 9 | Security scan is pure regex — no Claude-assisted rule quality or evasion review |

### Cluster Analysis

**Cluster A — Pipeline integrity (highest impact, fix first)**
ISSUE-001, 002, 018: Phase 6 rules outside the pipeline. Fix: register 8 detection-request YAMLs.

**Cluster B — Claude integration quality**
ISSUE-004, 008, 009, 010, 022: Claude invocations either fail, return malformed output, or do superficial work.
Root cause: `max_turns` too low, no output format enforcement, no event context in refinement prompts.

**Cluster C — Operational feedback loop**
ISSUE-011, 015, 016, 017, 019: The pipeline produces detections but doesn't close the loop.
Live SIEM data unused in validation, health scores static, INVESTIGATE flags unanswered, gaps not tracked.

**Cluster D — Developer experience**
ISSUE-005, 006, 007, 020, 021: Retrospectives dead, no-op PRs, branch cleanup missing, dirty working tree crash.
Low-severity individually, but collectively make the pipeline rough to operate manually.

**Cluster E — Minor gaps**
ISSUE-003, 012, 013, 014: STATUS.md drift, vague error messages, VALIDATED dead zone, orphaned artifacts.

### Recommended Priority for Phase 8 (or Phase 7.1)

1. **Fix Cluster A** (30 min) — register 8 detection-request YAMLs, re-run coverage to get accurate numbers
2. **Fix ISSUE-008 + 010** (2h) — markdown fence stripper + pass failing events to refinement prompt; unblocks the 3 stuck AUTHORED rules
3. **Fix ISSUE-007** (30 min) — add `git checkout main` at agent runner exit; eliminates every stash/conflict issue
4. **Fix ISSUE-011 + 016** (4h) — live SIEM cross-check in validation + dynamic health scoring; closes the operational loop
5. **Fix Cluster D** (2h) — retrospective auto-recording, suppress no-op PRs, branch cleanup

