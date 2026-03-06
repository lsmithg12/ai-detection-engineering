# KICKOFF.md — Start Here

Paste this entire prompt into Claude Code when you open the project for the first time.
It will assess your environment, identify what's running, what's missing, and begin
building the autonomous pipeline.

---

## Kickoff Prompt

```
You are bootstrapping an autonomous detection engineering pipeline called Patronus.
Before building anything, you need to understand the current state of the environment.

=== PHASE 0: RECONNAISSANCE ===

Perform a full environment assessment. Report findings before taking any action.

1. FILESYSTEM RECON
   - What directory are we in? List the full project structure.
   - Does CLAUDE.md exist? Read it if so — this is your identity.
   - Does AUTONOMOUS.md exist? Read it — this is your build plan.
   - Does orchestration/ exist? If so, what's been built already?
   - Does detection-requests/ exist and contain any files?
   - Does detections/ contain any Sigma rules?
   - Count: total files, detection rules, test cases, scenarios
   - Is there a .git directory? Check: current branch, remote, last commit
   - Is there a .mcp.json? Read it — what MCP servers are configured?
   - Is there a .env or any credentials visible? FLAG IMMEDIATELY.

2. INFRASTRUCTURE RECON
   - Is Docker running? What containers are up? (docker ps)
   - Is Elasticsearch reachable? (curl localhost:9200)
     If yes: cluster health, index count, document counts
   - Is Splunk reachable? (curl -k https://localhost:8089 -u admin:BlueTeamLab1!)
     If yes: list indexes, check HEC status, count events per index
   - Is Kibana reachable? (curl localhost:5601/api/status)
   - Is the log simulator running? Check container logs.
   - Is Cribl Stream reachable? (curl localhost:9420 if running)
   - Are any MCP servers responsive? Test each one configured in .mcp.json

3. TOOLING RECON
   - Is sigma-cli installed? What version? What backends?
     (sigma version; sigma plugin list)
   - Is Python 3.10+ available? (python3 --version)
   - Is Node.js available? (node --version) — needed for GitHub MCP
   - Is gh CLI installed? (gh --version) — needed for PR automation
   - Is git configured with a user? (git config user.name; git config user.email)

4. DATA RECON (only if SIEMs are running)
   - Elasticsearch: list all indices, doc counts, newest timestamp per index
   - Splunk: list all indexes, event counts, time range per index
   - Are there attack simulation events? Search for _simulation.type=attack
   - Are there baseline events? Search for _simulation.type=baseline
   - What Sysmon event codes are present? (aggregate by event.code)
   - What MITRE techniques are represented in the data?
     (aggregate by _simulation.technique if present)

5. DETECTION RECON (only if detections/ has content)
   - List all Sigma rules with their technique IDs and status
   - Check if any are deployed to Splunk/Elastic
   - Run the coverage matrix — how many Fawkes TTPs are covered?

6. PIPELINE RECON (only if orchestration/ exists)
   - What agents have been built? Check for non-stub agent files
   - What state are detection requests in? Run: python orchestration/cli.py status
   - When did each agent last run? Check STATUS.md or git log
   - Any failed runs? Check for error commits or stale branches
   - Is the token budget tracking active? Check budget-log.jsonl

=== REPORT FORMAT ===

Present your findings as a structured status report:

```markdown
# Patronus — Environment Assessment

## Infrastructure Status
| Component | Status | Details |
|-----------|--------|---------|
| Docker | ✅/❌ | version, containers running |
| Elasticsearch | ✅/❌/N/A | health, index count, doc count |
| Splunk | ✅/❌/N/A | version, index count, event count |
| Kibana | ✅/❌/N/A | status |
| Cribl Stream | ✅/❌/N/A | status |
| Log Simulator | ✅/❌/N/A | mode, events generated |
| Elastic MCP | ✅/❌/N/A | connected |
| Splunk MCP | ✅/❌/N/A | connected |
| GitHub MCP | ✅/❌/N/A | connected |

## Tooling Status
| Tool | Status | Version |
|------|--------|---------|
| sigma-cli | ✅/❌ | version |
| Python | ✅/❌ | version |
| Node.js | ✅/❌ | version |
| gh CLI | ✅/❌ | version |
| Git | ✅/❌ | configured user |

## Data Status
| Source | Index/Events | Time Range | Techniques |
|--------|-------------|------------|------------|
| ... | ... | ... | ... |

## Detection Coverage
- Sigma rules: N
- Deployed rules: N
- Fawkes techniques covered: N / 45
- Coverage %: X%

## Pipeline Status
- Agents built: [list]
- Detection requests: N (by state)
- Last agent runs: [dates]
- Token budget: [status]

## Gaps & Recommendations
1. [Most critical gap — what to fix first]
2. [Second priority]
3. ...
```

=== NEXT STEPS ===

After presenting the report, recommend which phase from AUTONOMOUS.md
to start building (or which to resume if partially built).

If nothing is set up yet (fresh clone):
  1. Recommend running `make setup` or `./setup.sh` first
  2. Wait for infrastructure before building pipeline

If infrastructure is running but pipeline isn't built:
  1. Start with Phase 1 from AUTONOMOUS.md
  2. Paste the Phase 1 prompt

If pipeline is partially built:
  1. Identify the furthest completed phase
  2. Check for any broken state
  3. Recommend resuming from the next incomplete phase

If pipeline is fully built and running:
  1. Show current fleet health
  2. Suggest maintenance tasks or improvements from the learnings journal

Do NOT start building anything until I confirm the recon report
looks correct and give you the go-ahead.
```
