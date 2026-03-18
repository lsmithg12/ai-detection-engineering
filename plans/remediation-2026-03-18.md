# Pipeline Remediation Plan — 2026-03-18

Post-Phase 7 workflow audit uncovered 22 issues across the full detection lifecycle.
This plan groups them into 5 targeted fix packs, ordered by impact and dependency chain.

**Source**: `plans/workflow-audit-2026-03-18.md`
**Approach**: Fix packs, not phases. Each pack is independently mergeable.
**Corrections**: Code review found 3 audit inaccuracies (noted inline with CORRECTION tags).

---

## Fix Pack 1: Pipeline Integrity

> Register the 8 orphaned Phase 6 rules so the entire pipeline can see them.
> This unblocks coverage metrics, deployment, and validation for those rules.

| Issue | Summary | Severity |
|-------|---------|----------|
| 001 | 8 Phase 6 rules have no detection-request YAML | High |
| 002 | State machine can't model multiple rule variants per technique | Medium |
| 003 | STATUS.md counts diverge from `cli.py status` | Low |
| 014 | Phase 6 `_elastic.json` artifacts have no deployment path | Medium |
| 018 | Coverage reports 56% instead of actual ~67% | Medium |

### 1.1 — Create 8 detection-request YAMLs

For each missing rule, create `autonomous/detection-requests/<id>.yml` in AUTHORED state.

| Rule File | Request File | technique_id | rule_type |
|-----------|-------------|--------------|-----------|
| `t1055_004_apc_injection.yml` | `t1055_004.yml` | T1055.004 | sigma |
| `t1055_sequence_eql.yml` | `t1055_eql.yml` | T1055 | eql |
| `t1087_002_discovery_burst_eql.yml` | `t1087_002_eql.yml` | T1087.002 | eql |
| `t1087_002_discovery_threshold.yml` | `t1087_002_threshold.yml` | T1087.002 | threshold |
| `t1059_001_t1547_001_persistence_after_exec_eql.yml` | `t1059_001_t1547_001_eql.yml` | T1059.001 | eql |
| `t1110_001_brute_force_threshold.yml` | `t1110_001.yml` | T1110.001 | threshold |
| `t1486_file_encryption_threshold.yml` | `t1486_threshold.yml` | T1486 | threshold |
| `t1489_mass_service_stop_threshold.yml` | `t1489.yml` | T1489 | threshold |

Note: `t1486.yml` already exists (Sigma variant). The threshold variant needs a distinct filename
(`t1486_threshold.yml`) to avoid collision. Same for `t1087_002` which gets two new files.

### 1.2 — Add `rule_type` field to detection-request schema

Add to `_template.yml` and all new requests:

```yaml
rule_type: sigma | eql | threshold    # New field — default "sigma" for existing rules
compiled_artifact: ""                  # Path to pre-built _elastic.json (EQL/threshold only)
secondary_techniques: []               # For cross-tactic rules (e.g., T1059.001+T1547.001)
```

**State machine key**: Keep `technique_id` as primary key for Sigma rules. For EQL/threshold
variants, use filename stem as the key (e.g., `t1087_002_eql`, `t1087_002_threshold`).
This avoids breaking the 28 existing requests that all use technique_id as key.

### 1.3 — Update deployment agent to read `compiled_artifact`

In `deployment_agent.py`, after the existing artifact check:

```python
# Prefer pre-built _elastic.json for EQL/threshold rules
compiled_artifact = request.get("compiled_artifact", "")
if compiled_artifact and Path(compiled_artifact).exists():
    with open(compiled_artifact) as f:
        elastic_payload = json.load(f)
    # Deploy directly — skip inline construction
else:
    # Existing inline construction path for Sigma rules
```

### 1.4 — Add `cli.py export-status` command

Generate STATUS.md counts from state machine ground truth. Run after any pipeline change.
Replaces manual STATUS.md maintenance.

### 1.5 — Re-run coverage after registration

After creating the 8 requests, run `cli.py status` and coverage agent to get accurate numbers.

### Files changed
- `autonomous/detection-requests/` — 8 new files
- `autonomous/detection-requests/_template.yml` — add rule_type, compiled_artifact, secondary_techniques
- `autonomous/orchestration/agents/deployment_agent.py` — prefer compiled_artifact
- `autonomous/orchestration/cli.py` — add export-status command

---

## Fix Pack 2: Validation & Refinement Quality

> Make the refinement loop actually work. Currently 4/5 attempts produce invalid output
> and the one "success" degraded rule quality. Also add live SIEM cross-validation.

| Issue | Summary | Severity |
|-------|---------|----------|
| 008 | Claude refinement returns invalid YAML 4/5 times | Critical |
| 009 | 150s timeout too short for complex refinement | Medium |
| 010 | Refinement degrades quality — refines without full context | Critical |
| 011 | Validation never cross-checks live SIEM data | High |

### 2.1 — Fix the YAML fence stripper (ISSUE-008)

**CORRECTION**: A markdown fence stripper already exists at `validation_agent.py:439-445`.
It fails because:
- It likely only handles ` ```yaml ` but not ` ``` ` or ` ```yml `
- Claude sometimes wraps in triple backticks with extra text before/after the fence block
- The regex may not handle Windows-style line endings

**Fix**: Replace the existing stripper with a robust version:

```python
import re

def extract_yaml_from_response(raw: str) -> str:
    """Extract YAML from Claude response, handling markdown fences and surrounding text."""
    # Try to find fenced block first
    match = re.search(r'```(?:ya?ml)?\s*\n(.*?)```', raw, re.DOTALL)
    if match:
        return match.group(1).strip()
    # If no fence, try to find YAML by looking for 'title:' as first significant line
    lines = raw.strip().split('\n')
    yaml_start = None
    for i, line in enumerate(lines):
        if line.strip().startswith('title:') or line.strip().startswith('logsource:'):
            yaml_start = i
            break
    if yaml_start is not None:
        return '\n'.join(lines[yaml_start:]).strip()
    # Last resort: return as-is
    return raw.strip()
```

Add Sigma schema validation after parse:

```python
parsed = yaml.safe_load(extracted)
required_keys = {"title", "logsource", "detection"}
if not required_keys.issubset(set(parsed.keys())):
    missing = required_keys - set(parsed.keys())
    raise ValueError(f"Missing Sigma fields: {missing}")
```

### 2.2 — Increase refinement timeout (ISSUE-009)

In `validation_agent.py:432`, change `timeout_seconds=150` to `timeout_seconds=300`.
Also update `config.yml` to make this configurable:

```yaml
validation:
  refinement_timeout_seconds: 300
```

### 2.3 — Enrich refinement prompt with full context (ISSUE-010)

**CORRECTION**: The refinement prompt already includes FN/FP event summaries (lines 396-397).
The problem is insufficient context — add:

1. **The compiled Lucene query** — so Claude can see what the SIEM is actually matching against
2. **Exact field mismatches** — compare rule conditions vs. event field values
3. **The SIEM error response** (if any) — already partially there (lines 400-407), verify it's populated

Updated prompt structure:

```python
refine_prompt = f"""This Sigma rule scored F1={metrics['f1_score']}.

## Compiled Lucene Query (what the SIEM actually runs)
{compiled_lucene}

## False Negatives — events that SHOULD match but DON'T
{json.dumps(fn_events[:3], indent=2)}

## False Positives — events that SHOULD NOT match but DO
{json.dumps(fp_events[:3], indent=2)}

## Field Comparison (rule expects vs. event has)
{field_mismatch_table}

## SIEM Query Errors (if any)
{siem_error_context}

## Current Sigma Rule
{current_rule_yaml}

Diagnose why the false negatives don't match the Lucene query. Common causes:
- Field name mismatch (e.g., rule uses process.name but event has process.executable)
- Wildcard pattern too narrow (e.g., *\\cmd.exe won't match C:\\Windows\\System32\\cmd.exe)
- Missing OR condition for variant field values

Return ONLY the corrected Sigma YAML. No markdown fences, no explanation."""
```

Add a **quality gate**: if refined rule scores LOWER than original, revert to original:

```python
if new_f1 < original_f1:
    # Revert — refinement made it worse
    rule_path.write_text(original_rule_yaml)
    break
```

### 2.4 — Add live SIEM cross-validation (ISSUE-011)

Add `validate_against_live_siem()` to `validation.py`:

```python
def validate_against_live_siem(
    compiled_lucene: str,
    technique_id: str,
    es_url: str = None,
    es_auth: tuple = None,
) -> dict:
    """Run compiled query against sim-attack and sim-baseline indices."""
    attack_hits = _run_query(compiled_lucene, "sim-attack", es_url, es_auth)
    baseline_hits = _run_query(compiled_lucene, "sim-baseline", es_url, es_auth)
    return {
        "siem_tp_count": attack_hits,
        "siem_fp_count": baseline_hits,
        "siem_precision": attack_hits / (attack_hits + baseline_hits) if (attack_hits + baseline_hits) > 0 else 0,
    }
```

Call this as a secondary validation pass after the synthetic-event validation.
Store results in the detection-request YAML alongside existing F1 scores.

### Files changed
- `autonomous/orchestration/agents/validation_agent.py` — fence stripper, timeout, prompt, quality gate
- `autonomous/orchestration/validation.py` — add validate_against_live_siem()
- `autonomous/orchestration/config.yml` — add refinement_timeout_seconds

---

## Fix Pack 3: Agent Runner Robustness

> Make the agent runner safe to operate in a real working environment.
> Dirty trees, stale branches, noise PRs, and dead retrospectives.

| Issue | Summary | Severity |
|-------|---------|----------|
| 005 | Retrospective prompt printed but never executed | Medium |
| 006 | No-op agent runs still create PRs | Low |
| 007 | Agent runner crashes on dirty working tree | Medium |
| 020 | 34 stale local branches accumulating | Low |
| 021 | Security agent creates PR for review-only output | Low |

### 3.1 — Dirty working tree handling (ISSUE-007)

In `_create_branch()`, before `git checkout main`:

```python
def _create_branch(agent_name: str, run_id: str) -> str:
    branch = f"agent/{agent_name}/{run_id}"

    # Guard: check for dirty working tree
    status = _run_git(["status", "--porcelain"])
    if status.strip():
        _run_git(["stash", "--include-untracked", "-m", f"auto-stash-before-{agent_name}-{run_id}"])

    _run_git(["checkout", "main"])
    _run_git(["pull", "origin", "main"])
    _run_git(["checkout", "-b", branch])
    return branch
```

On exit (new `_cleanup()` function called in finally block):

```python
def _cleanup(original_branch: str = "main", had_stash: bool = False):
    """Return to main and restore stash."""
    try:
        _run_git(["checkout", original_branch])
        if had_stash:
            _run_git(["stash", "pop"])
    except Exception as e:
        print(f"  [runner] Cleanup warning: {e}")
```

Wrap the entire agent run in try/finally to guarantee cleanup.

### 3.2 — Suppress no-op PRs (ISSUE-006, ISSUE-021)

Add a `substantive_changes()` check before PR creation:

```python
BOOKKEEPING_FILES = {
    "threat-intel/digest.md",
    "monitoring/pipeline-metrics.jsonl",
    "autonomous/budget-log.jsonl",
    "autonomous/security/audit-log.jsonl",
}

def _has_substantive_changes(branch: str) -> bool:
    """Check if the branch has changes beyond bookkeeping files."""
    diff = _run_git(["diff", "--name-only", "main..." + branch])
    changed = {f.strip() for f in diff.strip().split('\n') if f.strip()}
    substantive = changed - BOOKKEEPING_FILES
    return len(substantive) > 0
```

For the security agent specifically, suppress PR creation entirely — its output
is the review comment on the target PR, not mergeable content.

Add to config.yml:
```yaml
agents:
  security:
    create_pr: false    # Output is PR review comment, not mergeable content
```

### 3.3 — Machine-generated retrospective (ISSUE-005)

Replace the printed prompt with an auto-recorded summary. No Claude call needed.

```python
def record_run_summary(agent_name: str, run_id: str, result: dict):
    """Auto-record a machine-generated run summary to learnings file."""
    summary = {
        "run_id": run_id,
        "timestamp": datetime.utcnow().isoformat(),
        "agent": agent_name,
        "duration_s": result.get("duration_s", 0),
        "errors": result.get("errors", []),
        "state_transitions": result.get("transitions", []),
        "items_processed": result.get("items_processed", 0),
        "items_succeeded": result.get("items_succeeded", 0),
    }
    learnings_path = LEARNINGS_DIR / f"{agent_name}.jsonl"
    with open(learnings_path, "a") as f:
        f.write(json.dumps(summary) + "\n")
```

This populates the learnings files that the briefing system reads on startup —
closing the feedback loop without spending tokens on a Claude retrospective call.

### 3.4 — Branch cleanup (ISSUE-020)

Add `git fetch --prune` to the start of `_create_branch()`.
Add Makefile target:

```makefile
clean-branches:
	git fetch --prune
	git branch --merged main | grep "agent/" | xargs -r git branch -d
	@echo "Cleaned merged agent branches"
```

### Files changed
- `autonomous/orchestration/agent_runner.py` — stash/cleanup, substantive check, auto-retrospective, prune
- `autonomous/orchestration/config.yml` — security.create_pr: false
- `Makefile` — add clean-branches target

---

## Fix Pack 4: Operational Feedback Loop

> Close the loop between deployed rules and operational health.
> Live health scoring, state transitions, and escalation to GitHub.

| Issue | Summary | Severity |
|-------|---------|----------|
| 015 | DEPLOYED rules not transitioned to MONITORING | Medium |
| 016 | Health scores are static stored values, not live | High |
| 017 | INVESTIGATE flags produce no downstream action | Medium |
| 019 | Coverage agent doesn't create GitHub Issues for gaps | Medium |

### 4.1 — DEPLOYED → MONITORING transition (ISSUE-015)

**CORRECTION**: The tuning agent already queries DEPLOYED + MONITORING (lines 273-276).
The audit observed "0 DEPLOYED" because of a timing issue — the deployment agent wrote state
to disk, but the tuning agent (running in the same pipeline session) didn't re-read the file.

**Root cause**: State manager caches in memory. When agents run in sequence within `run_pipeline()`,
the tuning agent's state manager instance was initialized before deployment wrote new states.

**Fix**: Add `state_manager.reload()` at the start of each agent's `run()` function:

```python
def run(config: dict) -> dict:
    state_manager.reload()  # Re-read all detection-request YAMLs from disk
    ...
```

Also: after deployment confirms a rule is live in the SIEM (via rule status API), immediately
transition to MONITORING:

```python
# In deployment_agent.py, after successful deploy
rule_status = siem.check_rule_status(elastic_rule_id)
if rule_status == "active":
    state_manager.transition(tid, "MONITORING", agent=AGENT_NAME,
        details=f"Rule confirmed active in SIEM")
```

### 4.2 — Live health scoring from SIEM (ISSUE-016)

Replace stored-value health scoring with live SIEM queries in `tuning_agent.py`:

```python
def compute_live_health(request: dict, es_url: str, es_auth: tuple) -> dict:
    """Query Elastic for actual alert telemetry."""
    rule_name = request.get("title", "")
    # Get alert count for last 24h
    alerts_24h = _query_alert_count(rule_name, "now-24h", es_url, es_auth)
    # Get alert count for last 7d
    alerts_7d = _query_alert_count(rule_name, "now-7d", es_url, es_auth)
    # Get last fired timestamp
    last_fired = _query_last_alert_time(rule_name, es_url, es_auth)

    return {
        "alert_volume_24h": alerts_24h,
        "alert_volume_7d": alerts_7d,
        "last_fired": last_fired,
        "days_since_last_alert": _days_since(last_fired),
    }

def _query_alert_count(rule_name, time_range, es_url, es_auth):
    """GET .alerts-security.alerts-default/_count with rule name + time filter."""
    query = {
        "query": {"bool": {"must": [
            {"term": {"kibana.alert.rule.name": rule_name}},
            {"range": {"@timestamp": {"gte": time_range}}}
        ]}}
    }
    # ... ES query execution
```

Feed live metrics into the existing weighted health formula. Override stored values
with live data when ES is reachable; fall back to stored values when offline.

### 4.3 — INVESTIGATE escalation (ISSUE-017)

When a rule is flagged INVESTIGATE, auto-create a GitHub Issue:

```python
if recommendation == "INVESTIGATE":
    issue_title = f"[Health] {request['title']} ({tid}) — no alerts {days_inactive}+ days"
    issue_body = f"""Rule has not fired in {days_inactive} days.

**Possible causes:**
- Rule query doesn't match current index schema
- Attack simulation data doesn't cover this technique
- Rule was disabled in the SIEM

**Action required:** Re-validate rule against current sim data, check SIEM rule status.

**Detection request:** `autonomous/detection-requests/{tid}.yml`
**Health score:** {health_score}
"""
    # Create issue via GitHub MCP or gh CLI
    _create_github_issue(issue_title, issue_body, labels=["health-check", "needs-review"])
```

Also: reduce stored health_score by 0.1 per week of inactivity (floor 0.4).

### 4.4 — Coverage gap → GitHub Issue (ISSUE-019)

In `coverage_agent.py`, after generating `gap-report.md`, iterate actionable gaps
and create GitHub Issues:

```python
for gap in actionable_gaps:
    if not _issue_already_open(gap["technique_id"]):
        _create_github_issue(
            title=f"[Gap] No detection for {gap['technique_name']} ({gap['technique_id']})",
            body=f"Priority: {gap['priority_score']}\nData sources: {gap['required_sources']}\n...",
            labels=["coverage-gap", gap["tactic"]],
        )
```

Check for existing open issues before creating duplicates.

### Files changed
- `autonomous/orchestration/agents/tuning_agent.py` — live health, INVESTIGATE escalation, state reload
- `autonomous/orchestration/agents/deployment_agent.py` — DEPLOYED → MONITORING after confirmation
- `autonomous/orchestration/agents/coverage_agent.py` — GitHub Issue creation for gaps
- `autonomous/orchestration/state_manager.py` — add reload() method

---

## Fix Pack 5: Agent Intelligence

> Improve the quality of Claude-powered agent steps.
> Web search, security review, and deployment diagnostics.

| Issue | Summary | Severity |
|-------|---------|----------|
| 004 | Intel web search hits max-turns before completing | High |
| 012 | T1569.002 skipped with vague "missing artifacts" error | Low |
| 013 | 8 VALIDATED rules stuck in 0.75-0.89 dead zone | Medium |
| 022 | Security scan is pure regex — no quality review | Medium |

### 5.1 — Fix intel web search (ISSUE-004)

Two changes:

1. Increase `max_turns` from 6 to 15 in `ask_with_web_search()`:
   ```python
   max_turns=15,  # 5 queries x ~3 turns each
   ```

2. Add error-string guard before JSON parse:
   ```python
   response = result["response"].strip()
   if response.startswith("Error:"):
       print(f"  [intel] Claude CLI error: {response}")
       return []
   ```

3. Reduce default queries from 5 to 3 per run to stay within budget.

### 5.2 — Improve deployment error messages (ISSUE-012)

In `deployment_agent.py`, replace generic "missing artifacts" with specific diagnostics:

```python
missing = []
if not sigma_path_rel:
    missing.append("sigma_rule field empty in detection-request")
if not lucene_path_rel:
    missing.append("compiled_lucene field empty in detection-request")
if sigma_path_rel and not Path(sigma_path_rel).exists():
    missing.append(f"sigma file not found: {sigma_path_rel}")
if lucene_path_rel and not Path(lucene_path_rel).exists():
    missing.append(f"lucene file not found: {lucene_path_rel}")

if missing:
    details = "; ".join(missing)
    print(f"    [deployment] Skipping {tid} -- {details}")
    result["error"] = details
    return result
```

### 5.3 — Surface the VALIDATED dead zone (ISSUE-013)

The 0.75-0.89 gap between "validated" and "auto_deploy" is a design decision, not a bug.
Make it visible:

1. `cli.py status` should show a separate "VALIDATED (manual deploy)" count for F1 0.75-0.89
2. Deployment agent log should list skipped rules with their F1: `Skipping T1055.001 (F1=0.80 < auto_deploy threshold 0.90) — deploy manually with: cli.py deploy --validated`
3. Add to `deploy --validated` output: a summary of what would be deployed

### 5.4 — Claude-assisted security review (ISSUE-022)

Add a mandatory Claude analysis step for PRs touching `detections/`:

```python
def claude_quality_review(changed_rules: list[dict]) -> list[dict]:
    """Ask Claude to review detection rule quality."""
    prompt = f"""Review these detection rules for quality issues:

{json.dumps(changed_rules, indent=2)}

Check for:
1. Overly broad conditions that would cause false positives in production
2. Simple evasion techniques (rename binary, change path, encode command)
3. Missing test cases for documented false positive scenarios
4. Field names that don't match ECS schema
5. Wildcard patterns that are too narrow or too broad

Return a JSON array of findings, each with: rule_file, severity (CRITICAL/WARN/INFO), description."""

    result = claude_llm.ask(prompt, agent_name="security", max_turns=1, timeout_seconds=120)
    # Parse and return findings
```

Gate: run Claude review only when PR modifies files in `detections/`. Skip for
infrastructure-only or docs-only PRs.

### Files changed
- `autonomous/orchestration/claude_llm.py` — max_turns for web search
- `autonomous/orchestration/agents/intel_agent.py` — error guard before JSON parse
- `autonomous/orchestration/agents/deployment_agent.py` — diagnostic error messages, dead zone surfacing
- `autonomous/orchestration/agents/security_agent.py` — Claude quality review for detection PRs
- `autonomous/orchestration/cli.py` — status shows manual-deploy tier

---

## Dependency Graph

```
Fix Pack 1 (Pipeline Integrity)
    ↓
Fix Pack 2 (Validation Quality)     ← can start in parallel with Pack 1
    ↓
Fix Pack 4 (Feedback Loop)          ← depends on Pack 1 (needs registered rules)
    ↓
Fix Pack 3 (Runner Robustness)      ← independent, can start anytime
    ↓
Fix Pack 5 (Agent Intelligence)     ← independent, can start anytime
```

**Critical path**: Pack 1 → Pack 4 (registration must happen before live health scoring makes sense)

**Parallelizable**: Packs 2, 3, and 5 are fully independent of each other and of Pack 1.

---

## Issue-to-Pack Cross-Reference

| Issue | Pack | Section |
|-------|------|---------|
| 001 | 1 | 1.1 |
| 002 | 1 | 1.2 |
| 003 | 1 | 1.4 |
| 004 | 5 | 5.1 |
| 005 | 3 | 3.3 |
| 006 | 3 | 3.2 |
| 007 | 3 | 3.1 |
| 008 | 2 | 2.1 |
| 009 | 2 | 2.2 |
| 010 | 2 | 2.3 |
| 011 | 2 | 2.4 |
| 012 | 5 | 5.2 |
| 013 | 5 | 5.3 |
| 014 | 1 | 1.3 |
| 015 | 4 | 4.1 |
| 016 | 4 | 4.2 |
| 017 | 4 | 4.3 |
| 018 | 1 | 1.5 |
| 019 | 4 | 4.4 |
| 020 | 3 | 3.4 |
| 021 | 3 | 3.2 |
| 022 | 5 | 5.4 |

---

## Completed Phases (archived)

All completed phase plans have been moved to `plans/archive/`:
- Phase 1: Detection Quality (PR #52)
- Phase 2: SIEM Validation (PR #54)
- Phase 3: Data Pipeline (PR #58)
- Phase 4: Scalable Architecture (PR #62)
- Phase 5: Data Engineering (PR #63)
- Phase 6: Detection Content (PR #65)
- Phase 7: Operational Excellence (PR #68)

Phase 8 (Advanced Capabilities) remains at `plans/phase8-advanced-capabilities.md` as a stretch goal.
