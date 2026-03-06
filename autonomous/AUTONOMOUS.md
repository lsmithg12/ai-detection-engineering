# Autonomous Detection Engineering Pipeline — Build Guide

This document is your build plan for turning Patronus from a single interactive agent
into a continuously running, five-agent autonomous detection engineering operation.

**Architecture**: Git repo as shared brain → Agents communicate via PRs → Human merges
once daily → GitHub Actions trigger downstream agents → Pipeline runs indefinitely.
A dedicated security agent gates every PR before human review.

**Constraint**: Claude Pro plan. Every design decision optimizes for minimal token usage.

---

## Phase 1: Foundation — State Machine & Orchestration Scaffolding

### Prompt 1.1: Build the Detection Lifecycle State Machine

```
I'm building an autonomous multi-agent detection engineering pipeline.
The core mechanism is a state machine where each detection progresses
through stages, and different agents own different transitions.

Create the following:

1. A file `orchestration/schema.yml` that defines the detection lifecycle:
   REQUESTED → SCENARIO_BUILT → AUTHORED → VALIDATED → DEPLOYED → MONITORING → TUNED → RETIRED
   Each state should define: who owns it, what triggers transition, 
   what artifacts must exist to move forward.

2. A Python module `orchestration/state.py` that:
   - Reads/writes detection request YAML files in `detection-requests/`
   - Can query: "what detections are in state X?"
   - Can transition: move a detection from one state to another
   - Validates: all required artifacts exist before allowing transition
   - Tracks timestamps, agent name, PR numbers for audit trail

3. A template `detection-requests/_template.yml` with this structure:
   technique_id, title, status, priority (critical/high/medium/low),
   requested_by, requested_date, intel_report (path), 
   scenario_file (path), sigma_rule (path), deployed_date,
   last_quality_review, quality_score (0-1), fp_rate, tp_rate,
   alert_volume_24h, cost_estimate (low/medium/high),
   auto_deploy_eligible (bool), changelog (list of dated entries)

4. A CLI wrapper `orchestration/cli.py` that agents can call:
   python orchestration/cli.py status                    # show all detections by state
   python orchestration/cli.py pending --agent blue      # what needs blue team work?
   python orchestration/cli.py transition T1055.001 VALIDATED --agent blue-team
   python orchestration/cli.py create T1055.012 --intel threat-intel/reports/2025-03-01.md

Test it by creating 3 sample detection requests in different states.
Commit everything on branch orchestration/state-machine.
```

### Prompt 1.2: Build the Agent Runner Framework

```
Create a lightweight agent runner framework that all four agents share.
This handles the common boilerplate so each agent only implements its
core logic.

Create `orchestration/agent_runner.py` that:

1. Reads which agent to run from CLI args (intel, red, blue, quality)
2. Creates a git branch automatically: `agent/<agent-name>/<date>-<run-id>`
3. Checks for pending work using the state machine CLI:
   - If no pending work, exits immediately (saves tokens)
   - If work exists, logs what it found and proceeds
4. After the agent completes, stages all changed files, commits with
   a conventional commit message, pushes the branch
5. Creates a PR via GitHub CLI (`gh pr create`) with:
   - Title: `[<Agent Name>] <summary of work>`
   - Body: structured summary of what was done, what changed, metrics
   - Labels: agent-intel, agent-red, agent-blue, agent-quality
6. Handles errors gracefully — if something fails, commit partial
   work with a clear error message so it can be debugged

Each agent will be a separate Python script that the runner imports:
  orchestration/agents/intel_agent.py
  orchestration/agents/red_team_agent.py  
  orchestration/agents/blue_team_agent.py
  orchestration/agents/quality_agent.py
  orchestration/agents/security_agent.py

Create stub files for each agent with a `run(state_manager)` function.
The security agent stub should also accept a `pr_number` argument
since it operates on a specific PR rather than the general pipeline state.

3. A self-improvement module `orchestration/learnings.py` that:
   - Reads a JSONL journal file per agent from `learnings/<agent>.jsonl`
   - Provides: `get_relevant_lessons(agent, category, technique_id=None)`
     Returns the most relevant past lessons for the current task —
     filtered by category, technique, and recency. Max 10 entries
     to keep context window small.
   - Provides: `record(agent, run_id, type, category, title, description, ...)`
     Appends a new entry to the journal
   - Provides: `get_retrospective_prompt(agent, run_id)`
     Returns a prompt string the agent runner injects at the END
     of every agent session that says:
     "Before finishing, review what happened this run. Record any
      errors, inefficiencies, workarounds, or improvement ideas
      to learnings/<agent>.jsonl using the learnings module.
      Check: Did anything fail that shouldn't have? Did you waste
      tokens on something you could have avoided? Did you discover
      a better approach? Did you resolve a previously open issue?"
   - Provides: `get_briefing(agent)`
     Returns a condensed summary of the top 5 most relevant open
     lessons for this agent — injected at the START of every run
     so the agent knows what to watch out for.

4. Update the agent_runner.py flow to:
   a. At start: load briefing via `get_briefing(agent_name)`
      and include it in the agent's context
   b. At end: inject retrospective prompt, let agent record learnings
   c. Include learning entries in PR body under a "Learnings" section

Also create a config file `orchestration/config.yml`:
  agents:
    intel:
      schedule: "daily"
      model: "sonnet"      # cheaper for structured extraction
      max_reports: 5        # cap intel reports per run
      max_tokens_estimate: 50000
    red:
      trigger: "intel_merge"
      model: "sonnet"      # log generation is structured
      max_scenarios_per_run: 5
      max_tokens_estimate: 30000
    blue:
      trigger: "intel_merge OR red_merge"
      model: "opus"        # needs best reasoning for detection logic
      max_detections_per_run: 5
      max_tokens_estimate: 100000
      auto_deploy_threshold: 0.90  # quality score for auto-deploy
    quality:
      schedule: "daily"
      model: "sonnet"
      max_tokens_estimate: 40000
    security:
      trigger: "every_agent_pr"
      model: "sonnet"      # pattern matching + structured analysis
      max_tokens_estimate: 20000
      block_on_critical: true
      auto_fix_enabled: true
      scan_patterns_file: "security/scan-patterns.yml"

Commit on branch orchestration/agent-runner.
```

---

## Phase 2: Intel Agent — The Starting Point of the Chain

### Prompt 2.1: Build the Threat Intel Agent

```
Build the intel agent at `orchestration/agents/intel_agent.py`.

This agent searches the internet for recent threat intelligence,
extracts TTPs, and creates structured detection requests.

Design constraints (Pro plan token optimization):
- Cap at 5 new intel reports per run
- Use web search to find reports, then extract structured data
- Don't summarize entire reports — extract ONLY: techniques used,
  platforms affected, data sources needed, detection opportunity
- Skip any technique we already have a detection for (check state machine)
- Skip any technique we already have a pending request for

The agent should:

1. LEARN FIRST — Before doing anything:
   - Read your briefing from `learnings/intel.jsonl` via the learnings module
   - Check for open lessons tagged with category "search" or "parsing"
   - If a past run noted that a source was low-quality, skip it
   - If a past run found a more efficient search query pattern, use it

2. Search for recent threat intel using these query patterns:
   - "threat actor TTPs [current month] [current year]"
   - "MITRE ATT&CK technique used in the wild [current month]"
   - "malware analysis report [current week]"
   - "CISA advisory [current month]"
   - "detection engineering blog [current month]"
   Sources to prioritize: CISA, Mandiant/Google TAG, CrowdStrike,
   Microsoft Threat Intelligence, Unit42, Red Canary, Elastic Security Labs,
   Splunk Threat Research, The DFIR Report

3. For each relevant report found (max 5), produce a structured
   intel file at `threat-intel/reports/YYYY-MM-DD-<slug>.yml`:
   ```yaml
   title: <report title>
   source: <url>
   date_published: <date>
   date_ingested: <today>
   threat_actors: [<if named>]
   platforms: [windows, linux, macos]
   techniques:
     - id: T1055.012
       name: Process Hollowing
       description: <1-2 sentences on how it was used>
       data_sources_needed: [Sysmon EventID 1, Sysmon EventID 25]
       detection_opportunity: <1-2 sentences on what to look for>
       priority: high
   iocs:
     - type: hash
       value: <sha256>
     - type: domain
       value: <domain>
   raw_summary: <3-5 sentence summary of the report>
   ```

3. For each NEW technique found (not already in detection-requests/),
   create a detection request via the state machine CLI:
   `python orchestration/cli.py create <technique_id> --intel <report_path>`

4. Cross-reference with Fawkes capabilities — if a technique maps to
   a Fawkes command, bump its priority to critical.

5. Update `threat-intel/digest.md` — a running weekly digest of
   all intel processed, with links to reports and technique counts.

6. Produce a run summary for the PR body:
   - Reports processed: N
   - New techniques found: N
   - Detection requests created: N (list them)
   - Techniques skipped (already covered): N
   - Fawkes overlap found: N

7. RETROSPECTIVE — Before finishing:
   - Record learnings to `learnings/intel.jsonl`:
     * Which search queries returned useful results vs noise?
     * Which sources had parseable structured data vs messy prose?
     * Did any technique extraction fail? Why?
     * Any ideas for better search strategies?
     * If a previously noted issue was resolved, mark it resolved
   - Include a "Learnings" section in the PR body

Keep the agent focused on STRUCTURED OUTPUT. No prose analysis.
The cheaper the output, the more runs we get on Pro.

Commit on branch agent/intel-agent-v1.
```

---

## Phase 3: Red Team / Scenario Agent

### Prompt 3.1: Build the Red Team Log Scenario Agent

```
Build the red team agent at `orchestration/agents/red_team_agent.py`.

This agent takes detection requests and builds synthetic log scenarios
that simulate the attack technique, producing both malicious and benign
event sequences that can be ingested into Splunk/Elastic.

Design constraints:
- Max 5 scenarios per run
- Only process detection requests in REQUESTED state
- Output is structured JSON — very predictable token usage
- Use Sonnet (cheaper) — this is structured generation, not reasoning

The agent should:

1. LEARN FIRST — Before doing anything:
   - Read your briefing from `learnings/red-team.jsonl`
   - Check for past schema mismatches or event format corrections
   - If a past run noted that a specific Sysmon event structure was wrong,
     use the corrected version
   - Build on the library of verified-good event templates from past runs

2. Query state machine for all detections in REQUESTED state
3. For each (up to 5), read the detection request and intel report
4. Determine the required log sources and event types:
   - Map MITRE technique → Sysmon event IDs, Windows Security events,
     Linux auditd events, network events
   - Use the data source mapping in threat-intel/fawkes/fawkes-ttp-mapping.md
     as a reference for event structures

4. Generate a scenario file at `simulator/scenarios/<technique_id>.json`:
   ```json
   {
     "technique_id": "T1055.012",
     "technique_name": "Process Hollowing",
     "description": "Simulates process hollowing attack sequence",
     "mitre_tactic": "defense_evasion",
     "events": {
       "attack_sequence": [
         {
           "_comment": "Each event is a complete ECS/CIM-compatible log",
           "@timestamp": "{{now}}",
           "event": {"category": "process", "type": "start", "code": "1"},
           "process": { ... },
           "_simulation": {
             "type": "attack",
             "technique": "T1055.012",
             "sequence_order": 1,
             "sequence_total": 4,
             "description": "Legitimate process spawned in suspended state"
           }
         }
       ],
       "benign_similar": [
         {
           "_comment": "Events that look similar but are legitimate",
           ...
           "_simulation": {"type": "benign_similar", "technique": "T1055.012"}
         }
       ]
     },
     "expected_detection": {
       "should_alert_on": "attack_sequence",
       "should_not_alert_on": "benign_similar",
       "key_fields": ["process.name", "event.code"],
       "notes": "Detection should distinguish hollowed process from normal suspended-then-resumed process creation"
     },
     "log_sources_used": ["sysmon_1", "sysmon_25"],
     "platforms": ["windows"]
   }
   ```

5. Update the simulator to load and replay scenario files:
   - Add a mode to simulator.py: `SIM_MODE=scenario`
   - Reads from simulator/scenarios/ and replays specific technique events
   - Sends to both Splunk and Elastic via existing sinks

6. Transition the detection request: REQUESTED → SCENARIO_BUILT

7. PR summary:
   - Scenarios built: N (list technique IDs)
   - Event counts: N attack events, N benign events per scenario
   - Platforms covered: windows/linux
   - Log sources simulated: list

8. RETROSPECTIVE — Before finishing:
   - Record learnings to `learnings/red-team.jsonl`:
     * Were any event schemas rejected by the SIEM on ingest?
     * Did any scenario produce unrealistic field combinations?
     * Which event templates worked well and should be reused?
     * Ideas for more realistic simulation patterns?
   - Include a "Learnings" section in the PR body

Commit on branch agent/red-team-scenarios.
```

---

## Phase 4: Blue Team Agent Enhancements for Autonomous Operation

### Prompt 4.1: Enhance Blue Team Agent for Pipeline Integration

```
Enhance the blue team agent (the existing Patronus CLAUDE.md logic) to
work within the autonomous pipeline. Create `orchestration/agents/blue_team_agent.py`.

This agent processes detection requests that have scenarios ready,
writes detections, validates them, and optionally auto-deploys.

The blue team agent should:

1. LEARN FIRST — Before doing anything:
   - Read your briefing from `learnings/blue-team.jsonl`
   - Check for: Sigma transpilation gotchas, detection patterns that
     consistently cause FPs, MCP query patterns that work well,
     tuning approaches that reliably improve scores
   - If a past run noted a Sigma backend bug, apply the workaround
   - If a past run found that a certain exclusion pattern works for
     a category of technique, pre-apply it

2. Query state machine for detections in SCENARIO_BUILT state
3. For each (up to 5 per run, using Opus for quality):

   a. AUTHOR phase:
      - Read the intel report and scenario file
      - Check data availability via Splunk MCP (preferred) or Elastic MCP
      - Write Sigma rule following templates/sigma-template.yml
      - Transpile to SPL AND KQL (store both)
      - Create triage playbook from template
      - Transition: SCENARIO_BUILT → AUTHORED

   b. VALIDATE phase:
      - Trigger scenario replay: load the technique's scenario into the simulator
      - Wait 30 seconds for log ingestion
      - Run the detection query via MCP
      - Calculate metrics:
        * TP count: hits on attack_sequence events
        * FP count: hits on benign_similar events
        * TN count: benign events NOT matched
        * FN count: attack events NOT matched
        * Precision: TP / (TP + FP)
        * Recall: TP / (TP + FN)
        * Quality score: F1 score = 2 * (precision * recall) / (precision + recall)
      - Record all metrics in the detection request YAML
      - If quality score < 0.70: attempt ONE tuning iteration, re-validate
      - If still < 0.70 after tuning: mark as AUTHORED with note "needs human review"
      - If quality score >= 0.70: transition AUTHORED → VALIDATED

   c. DEPLOY phase (conditional auto-deploy):
      - Check config: auto_deploy_threshold (default 0.90)
      - If quality_score >= threshold AND fp_rate <= 0.05:
        * Deploy to SIEM via API
        * Transition: VALIDATED → DEPLOYED
        * Mark auto_deploy_eligible: true in request YAML
        * Log: "Auto-deployed: quality_score=X, fp_rate=Y"
      - If quality_score >= 0.70 but < threshold:
        * Transition: VALIDATED (stays here, awaits human review to deploy)
        * Mark: "Recommended for deployment, pending human review"
        * Include quality metrics in PR for human decision

3. Quality scoring methodology (document this in the PR):
   ```
   Quality Score = F1(precision, recall)
   
   Auto-deploy criteria (ALL must be true):
   - F1 score >= 0.90
   - FP rate <= 5%
   - At least 3 true positive test events validated
   - At least 3 true negative test events validated
   - No reliance on exclusions (clean logic only)
   - Detection covers at least one known Fawkes command OR
     one technique from a recent (< 30 day) intel report
   
   Human review recommended when:
   - F1 between 0.70 and 0.90 (decent but not auto-deploy quality)
   - FP rate between 5% and 20%
   - Detection required tuning iteration
   - Technique is novel (no prior community Sigma rules found)
   
   Needs rework when:
   - F1 below 0.70
   - FP rate above 20%
   - Required data source not available
   ```

4. PR summary:
   - Detections authored: N
   - Detections validated: N (with quality scores)
   - Detections auto-deployed: N (list with scores)
   - Detections pending human review: N (list with scores and reasoning)
   - Detections needing rework: N (list with failure reasons)
   - Coverage matrix diff: show before/after technique counts

5. RETROSPECTIVE — Before finishing:
   - Record learnings to `learnings/blue-team.jsonl`:
     * Which Sigma constructs failed to transpile correctly?
     * Which detection patterns produced unexpected FP/FN?
     * Were any MCP queries slow, empty, or malformed?
     * What tuning approach worked best this run?
     * Did the auto-deploy threshold feel right? Too aggressive? Too conservative?
     * Any detection engineering insights worth remembering?
     * If a red team scenario had bad data that caused validation issues, note it
       (cross-agent learning — quality monitor will relay this)
   - Include a "Learnings" section in the PR body

Commit on branch agent/blue-team-autonomous.
```

---

## Phase 5: Quality Monitor Agent

### Prompt 5.1: Build the Quality & Cost Monitor

```
Build the quality monitor at `orchestration/agents/quality_agent.py`.

This agent runs daily, reviews all DEPLOYED detections, tracks
performance over time, and makes tuning/retirement recommendations.

Runs on Sonnet (cheaper — this is analytical work, not creative).

The agent should:

1. LEARN FIRST — Before doing anything:
   - Read your briefing from `learnings/quality.jsonl`
   - Also read ALL other agents' journals (unique to this agent)
   - Look for cross-agent issues: did the blue team note bad scenario data?
     Did the intel agent flag a source that keeps producing unusable reports?
   - Create cross-agent learning entries when patterns span agents:
     "Blue team consistently struggles with T1055 scenarios from red team —
      event schemas missing parent process fields"
   - Check: which tuning recommendations were accepted vs rejected by
     the human in past PRs? Learn from that feedback.

2. Query all detections in DEPLOYED or MONITORING state

2. For each deployed detection, via Splunk/Elastic MCP:
   a. Pull alert count (last 24h)
   b. Pull alert count (last 7d)
   c. Sample 5 recent alerts and assess:
      - Does this look like a true positive or false positive?
      - Use the _simulation metadata if present to auto-classify
      - For non-simulated events, use heuristic assessment
   d. Estimate cost:
      - Query complexity (field count, regex usage, lookups)
      - Search frequency (how often does the saved search run)
      - Data volume scanned
      - Classify: low / medium / high cost

3. Calculate per-detection health metrics:
   ```yaml
   health:
     alert_volume_24h: 47
     alert_volume_7d: 312
     estimated_fp_rate: 0.15
     estimated_tp_rate: 0.85
     cost_estimate: medium
     signal_to_noise: 5.67     # TP / FP ratio
     trend: increasing          # increasing / stable / decreasing / dead
     days_since_last_alert: 0
     days_deployed: 14
     tuning_iterations: 2
     health_score: 0.78         # composite score
   ```

4. Health score calculation:
   ```
   health_score = weighted average of:
     - signal_to_noise (weight: 0.3) — normalized 0-1
     - tp_rate (weight: 0.3) — direct
     - 1 - cost_normalized (weight: 0.15) — lower cost = better
     - recency (weight: 0.10) — has it fired recently?
     - stability (weight: 0.15) — low variance in daily alert counts
   ```

5. Action recommendations based on health:
   - health >= 0.80: HEALTHY — no action, transition to MONITORING
   - health 0.60-0.79: TUNE — propose specific tuning changes
   - health 0.40-0.59: REVIEW — flag for human review, may need rework
   - health < 0.40: RETIRE — recommend disabling, explain why
   - dead (0 alerts for 14+ days with active data): investigate — broken or unnecessary?

6. For TUNE recommendations, propose specific changes:
   - "Add exclusion for process.parent.name: svchost.exe (accounts for 60% of FPs)"
   - "Consider moving pre-filter to Cribl pipeline instead of SIEM exclusion"
   - "Tighten time window from 5m to 2m to reduce false correlations"
   - Apply tuning automatically ONLY if it improves health score AND
     the detection was originally auto-deployed. Otherwise, PR for review.

7. Research component (lightweight, 1-2 searches per run):
   - Search for "detection engineering best practices [current year]"
   - Search for improvements to specific detection approaches
   - Add any relevant findings to `monitoring/research-notes.md`
   - This keeps the pipeline learning and evolving

8. Generate daily report at `monitoring/reports/YYYY-MM-DD.md`:
   - Detection fleet summary: total deployed, healthy, needs tuning, flagged
   - Top 3 noisiest detections with tuning recommendations
   - Top 3 highest-quality detections (celebrate wins)
   - Any dead detections
   - Cost summary: estimated total SIEM compute load
   - Coverage trend: technique count over time
   - Research notes: anything interesting found

9. Update all detection request YAMLs with latest metrics

10. PR summary:
    - Fleet health: N healthy, N needs tuning, N flagged, N retired
    - Auto-tuning applied: N detections (list changes)
    - Human review needed: N detections (list with reasons)
    - Coverage: X/Y Fawkes techniques detected

12. RETROSPECTIVE — Before finishing:
    - Record learnings to `learnings/quality.jsonl`:
      * Which health score components were most predictive of real problems?
      * Were any tuning recommendations from past runs later rejected by human?
        If so, adjust approach.
      * Did the cost estimates prove accurate?
      * Any patterns in detection decay (time-based, data-volume-based)?
      * Cross-agent issues to flag for other agents' journals
    - CROSS-POLLINATE: If you found issues that originated in another
      agent's work (bad scenario data, weak intel extraction, etc.),
      write an entry to THAT agent's journal too, tagged as
      `{"source_agent": "quality", "cross_agent": true}`
    - Include a "Learnings" section in the PR body

Commit on branch agent/quality-monitor.
```

---

## Phase 6: Security Review Agent — Pipeline Guardian

### Prompt 6.1: Build the Security Review Agent

```
Build a security review agent at `orchestration/agents/security_agent.py`.

This agent is the gatekeeper. It runs on EVERY PR created by any other
agent BEFORE human review. Its job is to ensure no agent accidentally
introduces secrets, insecure code, dangerous configurations, or
data leakage into the repo. It posts its findings as a PR comment
and can block merges by requesting changes.

Runs on Sonnet (structured scanning, not creative reasoning).

This agent acts as a SECURITY GATE — it should be paranoid.
False positives are acceptable. False negatives are not.

The agent should:

1. LEARN FIRST — Before scanning:
   - Read your briefing from `learnings/security.jsonl`
   - Check for: patterns that were false positives in past scans,
     allowlist entries that should have been added, findings that
     the human dismissed (learn to not flag those again)
   - If a past run noted that a specific regex pattern was too broad,
     check if scan-patterns.yml was updated — if not, note it again
   - Track which agents produce the most real findings vs noise

2. TRIGGER: Fires on every PR from branches matching `agent/*`
   Runs BEFORE human review so the human sees security findings
   alongside the PR diff.

3. SECRET SCANNING — check all changed files for:
   a. Hardcoded credentials:
      - API keys (patterns: sk-, pk-, api_key, apikey, api-key, token)
      - Passwords in plaintext (password=, passwd=, SPLUNK_PASSWORD in code)
      - AWS credentials (AKIA, aws_secret, aws_access_key)
      - Private keys (BEGIN RSA PRIVATE KEY, BEGIN OPENSSH PRIVATE KEY)
      - GitHub tokens (ghp_, gho_, ghs_, github_pat_)
      - Bearer tokens, JWTs in code
      - Connection strings with embedded credentials
      - .env file contents committed (should be in .gitignore)
   b. Internal infrastructure details:
      - Internal IP addresses (10.x, 172.16-31.x, 192.168.x) in non-config files
      - Internal hostnames or domain names
      - Splunk/Elastic URLs pointing to non-localhost addresses
   c. PII or sensitive data in test cases / log samples:
      - Real email addresses (not @example.com)
      - Real names that don't look like test data
      - Social security numbers, credit card patterns
      - Real IP addresses in test fixtures (should use RFC 5737 ranges)

4. CODE SECURITY REVIEW — check agent-produced code for:
   a. Injection vulnerabilities:
      - Shell injection: unsanitized input passed to subprocess/os.system
      - SPL injection: user-controlled strings concatenated into SPL queries
      - Query injection: unsanitized values in Elasticsearch DSL
      - Command injection via curl commands with unescaped variables
   b. Insecure configurations:
      - SSL verification disabled (verify=False, -k flag) outside of lab config
      - Overly permissive file permissions (chmod 777, world-writable)
      - Docker containers running as root unnecessarily
      - Ports exposed to 0.0.0.0 that should be localhost
   c. Dangerous operations:
      - Destructive Elasticsearch/Splunk operations (DELETE index, drop)
      - Recursive file deletions (rm -rf) with variable paths
      - Unrestricted network fetches (SSRF potential)
      - Execution of downloaded content without verification

5. DETECTION RULE SECURITY — check Sigma/SPL/KQL rules for:
   a. Rules that could cause operational impact:
      - Overly broad queries that would scan entire indexes
      - Queries without time bounds (could crush the SIEM)
      - Extremely high-frequency scheduled searches (< 1 minute intervals)
   b. Rules that could leak information:
      - Detections that log/alert sensitive field values unnecessarily
      - Triage playbooks that instruct analysts to export bulk data
   c. Rule logic issues:
      - Detection exclusions that are too broad (essentially disabling the rule)
      - Rules that exclude based on process name alone (easily evaded)

6. SUPPLY CHAIN / DEPENDENCY CHECK:
   a. New pip/npm packages added — flag for human review
   b. Docker images changed — flag for human review
   c. External URLs added to any script — verify they're legitimate
   d. MCP server configurations changed — flag for human review
   e. GitHub Actions workflow changes — ALWAYS flag (these run with repo secrets)

7. PIPELINE INTEGRITY:
   a. Verify no agent modified another agent's core logic
      (intel agent shouldn't touch blue team code, etc.)
   b. Verify orchestration/config.yml hasn't been modified to
      disable security checks or raise auto-deploy thresholds
   c. Verify .gitignore still excludes .env, *.key, *.pem
   d. Verify CODEOWNERS file hasn't been weakened

8. OUTPUT FORMAT — post a PR comment with structured findings:

   ```markdown
   ## 🛡️ Security Review — Agent PR Gate

   **Scan status**: PASS / WARN / BLOCK
   **Files scanned**: N
   **Agent**: <which agent created this PR>

   ### Findings

   | Severity | Category | File | Line | Finding |
   |----------|----------|------|------|---------|
   | 🔴 CRITICAL | Secret | pipeline/deploy.sh | 42 | Hardcoded Splunk password |
   | 🟡 WARN | Config | docker-compose.yml | 18 | Port 8089 exposed to 0.0.0.0 |
   | 🟢 INFO | Dependency | requirements.txt | 5 | New package: pyyaml (known safe) |

   ### Verdict

   **BLOCK**: 1 critical finding must be resolved before merge.

   ### Recommendations
   - Line 42 in deploy.sh: Replace hardcoded password with environment variable
   - Consider using Docker secrets or a .env file (already in .gitignore)
   ```

9. BLOCKING BEHAVIOR:
   - CRITICAL findings (secrets, credentials, injection vulns):
     → Request changes on the PR — blocks merge
     → Also attempt AUTO-FIX: create a fixup commit on the PR branch
       that removes the secret / replaces with env var reference
   - WARNING findings (insecure configs, broad queries):
     → Comment on PR but don't block
     → Human decides whether to address
   - INFO findings (new dependencies, config changes):
     → Comment for awareness only

10. AUTO-REMEDIATION for common issues:
   - Hardcoded passwords → replace with ${ENV_VAR} and add to .env.example
   - SSL verify disabled → add comment "# Lab only — enable in production"
   - Missing .gitignore entries → append them
   - Overly broad queries → add time bounds suggestion
   - If auto-fix is applied, push the fixup commit and re-scan

11. HISTORICAL TRACKING:
    - Log all findings to `security/audit-log.jsonl`:
      {timestamp, pr_number, agent, severity, category, file, finding, resolved}
    - Weekly summary in `security/weekly-report.md`:
      * Total PRs scanned
      * Findings by severity
      * Most common finding categories
      * Agents with most findings (helps identify which agent needs prompt tuning)
      * Auto-fixes applied
    - Track finding trends — if one agent keeps producing the same
      type of finding, note it for prompt improvement

12. RETROSPECTIVE — Before finishing:
    - Record learnings to `learnings/security.jsonl`:
      * Which scan patterns triggered on non-issues? (FP rate per pattern)
      * Which findings were real vs dismissed by human review?
      * Were any auto-fixes incorrect or incomplete?
      * Should any new patterns be added to scan-patterns.yml?
      * Which agent produced the most findings this scan?
    - If you notice a PATTERN of the same agent repeatedly producing
      the same type of security issue, write a cross-agent entry to
      that agent's journal suggesting a prompt improvement
    - Include findings summary in the PR comment

Also create `security/scan-patterns.yml` — a configurable list of
regex patterns, file paths, and rules the scanner uses. This makes
it easy to add new patterns without modifying agent code:

```yaml
secrets:
  - name: api_key_generic
    pattern: '(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9]{20,}'
    severity: critical
    message: "Potential API key detected"
  - name: aws_access_key
    pattern: 'AKIA[0-9A-Z]{16}'
    severity: critical
    message: "AWS access key ID detected"
  - name: private_key
    pattern: '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
    severity: critical
    message: "Private key detected"
  - name: splunk_password
    pattern: '(?i)splunk.*password\s*[=:]\s*["\']?(?!<|{|\$|BlueTeamLab)[^\s"'']{6,}'
    severity: critical
    message: "Splunk password outside of lab default"
    exclude_files: ['docker-compose.yml', 'splunk/default.yml']
  - name: connection_string
    pattern: '(?i)(mongodb|postgres|mysql|redis)://[^:]+:[^@]+@'
    severity: critical
    message: "Connection string with embedded credentials"

infrastructure:
  - name: internal_ip
    pattern: '(?<!\d)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)'
    severity: warning
    message: "Internal IP address — verify this is intentional"
    exclude_files: ['simulator/*', 'docker-compose.yml', '*.md']

code_security:
  - name: shell_injection
    pattern: 'os\.system\(.*\+|subprocess\.(call|run|Popen)\(.*\+.*shell\s*=\s*True'
    severity: critical
    message: "Potential shell injection — unsanitized input in command"
  - name: ssl_disabled
    pattern: 'verify\s*=\s*False|VERIFY_SSL.*false|-k\s'
    severity: warning
    message: "SSL verification disabled"
    exclude_files: ['docker-compose.yml', 'splunk/*']

allowlist:
  # Known safe values that match patterns but aren't secrets
  - 'BlueTeamLab1!'           # Lab default Splunk password
  - 'blue-team-lab-hec-token' # Lab default HEC token
  - 'localhost'
  - '127.0.0.1'
  - 'http://elasticsearch:9200'  # Docker internal
```

Commit on branch agent/security-review-agent.
```

---

## Phase 7: GitHub Actions Orchestration

### Prompt 7.1: Wire Up the Automation

```
Create GitHub Actions workflows that orchestrate the five agents.
These are the triggers that make the pipeline run autonomously.

Design for Pro plan: stagger agents across the day, exit early
when no work is pending, use the cheapest model per agent.

Create these workflow files:

1. `.github/workflows/intel-agent.yml`
   - Trigger: cron schedule (once daily, 6 AM UTC) + manual dispatch
   - Steps:
     a. Checkout repo
     b. Install deps (sigma-cli, python requirements)
     c. Run: python orchestration/agent_runner.py intel
     d. (agent_runner handles branch, commit, PR creation)
   - Timeout: 15 minutes (kill if stuck — saves tokens)
   - Concurrency: cancel any already-running intel agent

2. `.github/workflows/red-team-agent.yml`
   - Trigger: PR merged with label 'agent-intel' OR paths 'detection-requests/**'
   - Condition: only run if there are REQUESTED detections pending
   - Steps: same pattern, run red team agent
   - Timeout: 10 minutes
   - Delay: wait 5 minutes after trigger (let git settle)

3. `.github/workflows/blue-team-agent.yml`
   - Trigger: PR merged with label 'agent-red' OR label 'agent-intel'
     OR paths 'simulator/scenarios/**'
   - Condition: only run if SCENARIO_BUILT or REQUESTED detections exist
   - Steps: same pattern, run blue team agent
   - Timeout: 20 minutes (this agent does the most work)
   - Note: blue team can also trigger directly from intel merge
     if enough info exists to write detection without waiting for scenarios

4. `.github/workflows/quality-monitor.yml`
   - Trigger: cron (once daily, 6 PM UTC) + manual dispatch
   - Condition: only run if DEPLOYED detections exist
   - Steps: same pattern, run quality agent
   - Timeout: 15 minutes

5. `.github/workflows/security-gate.yml`
   - Trigger: pull_request opened/synchronize on branches 'agent/**'
   - MUST run before any merge — this is the security gate
   - Steps:
     a. Checkout PR branch
     b. Run: python orchestration/agent_runner.py security
     c. Agent posts findings as PR comment via `gh pr comment`
     d. If CRITICAL findings: `gh pr review --request-changes`
     e. If auto-fix applied: push fixup commit, re-run scan
     f. If clean: `gh pr review --approve` with security-cleared label
   - Timeout: 10 minutes
   - Runs on Sonnet (pattern matching + structured analysis)
   - ALSO trigger on manual re-request of review (after fixes)

6. `.github/workflows/security-review-claude.yml`
   - Trigger: any PR from agent branches
   - Steps: run Claude Code /security-review on changed files
   - This is the SECOND layer — Anthropic's built-in security scanner
     on top of our custom security agent
   - Both must pass before human review

Also add branch protection rules documentation for the human to enable:
  Create `docs/branch-protection.md` explaining:
  - Require PR reviews before merge (at least 1 — the human)
  - Require status checks: security-gate, security-review-claude
  - Do NOT allow bypassing for agent branches
  - This ensures NO agent PR merges without passing security scan
    AND human approval

Also create `orchestration/requirements.txt` with all Python deps.

Also create a `.github/CODEOWNERS` file:
  # Human must review all agent PRs
  * @<your-github-username>

  # Agent-specific reviewers (optional, for team scenarios)
  orchestration/ @<your-github-username>
  detections/ @<your-github-username>

Create a status dashboard as a simple markdown file that gets
updated by each agent run: `STATUS.md`
  - Last intel run: <timestamp> — <N reports processed>
  - Last red team run: <timestamp> — <N scenarios built>
  - Last blue team run: <timestamp> — <N detections authored>
  - Last quality review: <timestamp> — fleet health summary
  - Last security scan: <timestamp> — <N PRs scanned, N findings>
  - Security posture: <clean / warnings / blocked PRs>
  - Pipeline state: <active / stalled / needs attention>
  - Token budget: <estimated usage this period>
  - Next expected run: <agent name> at <time>

Commit on branch orchestration/github-actions.
```

---

## Phase 8: Token Budget & Self-Throttling

### Prompt 8.1: Build Token Awareness

```
Create a token budget tracking system at `orchestration/budget.py`.

The Pro plan has shared limits across Claude and Claude Code.
The pipeline must be self-aware about its consumption.

Build a module that:

1. Tracks estimated token usage per agent run:
   - Before each run, estimate cost based on pending work count
   - After each run, log actual duration and approximate tokens
   - Store in `orchestration/budget-log.jsonl` (append-only)

2. Implements throttling rules:
   - If estimated daily usage exceeds 80% of estimated Pro budget,
     skip non-critical agents (quality monitor can wait)
   - If approaching limits, switch remaining agents to "light mode":
     * Intel agent: 2 reports instead of 5
     * Blue team: 2 detections instead of 5
     * Quality: metrics only, skip research component
   - If at limit, all agents exit immediately with "budget exceeded" status

3. Weekly budget summary appended to STATUS.md:
   - Estimated tokens used per agent
   - Runs completed vs skipped
   - Most expensive operations
   - Recommendation: "Pipeline is within budget" or "Consider reducing
     intel agent frequency to 3x/week"

4. Config in orchestration/config.yml:
   ```yaml
   budget:
     daily_target: 200000    # estimated comfortable Pro daily tokens
     critical_threshold: 0.80 # throttle at 80%
     models:
       opus: 1.0              # cost multiplier (baseline)
       sonnet: 0.2            # ~5x cheaper than opus
     light_mode:
       intel_max_reports: 2
       blue_max_detections: 2
       quality_skip_research: true
   ```

This doesn't need to be exact — rough estimation is fine.
The goal is preventing surprise limit hits, not precise accounting.

Commit on branch orchestration/budget-tracking.
```

---

## Build Order

When you're at your IDE, build these in order. Each phase builds on the previous.
Merge each to main before starting the next.

```
Phase 1: State machine + agent runner framework     ← foundation
Phase 2: Intel agent                                ← starts the chain
Phase 3: Red team scenario agent                    ← feeds the blue team
Phase 4: Blue team autonomous enhancements          ← core detection work
Phase 5: Quality monitor                            ← closes the loop
Phase 6: Security review agent                      ← gates every PR
Phase 7: GitHub Actions orchestration               ← makes it run forever
Phase 8: Token budget tracking                      ← keeps it sustainable
```

After all phases are merged, the pipeline is live. Push a manual trigger
on the intel agent workflow and watch the chain execute.

---

## Verification Checklist

After the full pipeline is running, verify:

- [ ] Intel agent finds reports and creates detection requests
- [ ] Red team agent builds scenarios for new requests
- [ ] Blue team agent writes and validates detections
- [ ] Auto-deploy works for high-quality detections (F1 >= 0.90)
- [ ] Quality monitor tracks fleet health daily
- [ ] Security agent scans every agent PR before human review
- [ ] Security agent blocks PRs with hardcoded secrets
- [ ] Security agent auto-fixes common issues (env var replacement)
- [ ] Security agent posts structured findings as PR comments
- [ ] Both security layers pass (custom agent + Claude /security-review)
- [ ] Branch protection requires security checks before merge
- [ ] No secrets exist in repo history (run git-secrets or trufflehog)
- [ ] Agents exit early when no work is pending
- [ ] Token budget tracking prevents limit surprises
- [ ] STATUS.md updates reflect actual pipeline state
- [ ] Human can review and merge PRs on a once-daily cadence
- [ ] Pipeline recovers gracefully if an agent fails mid-run
- [ ] Coverage matrix grows over time
- [ ] Detection quality scores are tracked historically
- [ ] Security audit log tracks all findings over time

---

## Future Enhancements (Post-MVP)

Once the basic pipeline is running smoothly:

- **Cribl integration**: Quality monitor recommends pre-SIEM filtering
  via Cribl when it detects patterns that are better handled at ingest
- **Attack Range integration**: Red team agent can trigger live
  simulations for techniques where synthetic logs aren't sufficient
- **Multi-SIEM validation**: Blue team validates detections in BOTH
  Splunk and Elastic, flags any that work in one but not the other
- **Detection retirement automation**: Quality monitor can auto-retire
  detections that have been unhealthy for 30+ consecutive days
- **Threat landscape dashboard**: Intel agent maintains a trend view
  of which MITRE tactics are most active in the wild
- **Fawkes sync**: Intel agent watches galoryber/fawkes repo for new
  commits and auto-creates detection requests for new capabilities
- **Security posture scoring**: Security agent maintains an overall
  pipeline security score and trends it over time
- **Git history scanning**: Periodic deep scan of full git history
  for any secrets that were committed and then removed (they're still
  in history) — recommend BFG Repo-Cleaner or git-filter-repo if found
- **Agent prompt hardening**: Security agent analyzes other agents'
  CLAUDE.md prompts for injection risks or prompt leakage
- **Dependency pinning enforcement**: Security agent verifies all
  pip/npm dependencies are pinned to exact versions, not ranges
