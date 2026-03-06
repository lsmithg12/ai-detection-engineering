# Agent Learnings & Self-Improvement

This directory contains each agent's learning journal. Agents record errors,
inefficiencies, workarounds, and improvement ideas during every run.
Future runs read these notes to avoid repeating mistakes and to adopt
proven solutions.

## How It Works

1. **Every agent run** reads its own journal before starting work
2. **During the run**, the agent appends entries for anything notable
3. **After the run**, the agent writes a brief retrospective
4. **Future runs** check the journal for relevant lessons before each task
5. **Periodically**, the quality monitor reviews ALL journals and
   cross-pollinates lessons between agents

## Journal Format

Each agent has its own file: `learnings/<agent-name>.jsonl`

Entries are append-only JSONL (one JSON object per line):

```json
{
  "timestamp": "2025-03-15T10:30:00Z",
  "agent": "blue-team",
  "run_id": "blue-2025-03-15-001",
  "type": "error | inefficiency | workaround | idea | resolved",
  "category": "sigma | splunk | elastic | mcp | git | data | tuning | process",
  "technique_id": "T1055.001",
  "title": "Sigma wildcard syntax doesn't transpile to SPL correctly",
  "description": "When using |endswith modifier in Sigma, the Splunk backend generates `field=\"*value\"` instead of `field=*value`. This causes zero results in Splunk.",
  "resolution": "Use |contains instead of |endswith for Splunk compatibility, or post-process the SPL output to fix quoting.",
  "status": "resolved | open | wontfix",
  "references": ["detections/defense_evasion/t1055_001.yml", "PR #42"],
  "impact": "high | medium | low",
  "tokens_wasted": 5000,
  "reusable": true
}
```

## Entry Types

| Type | When to Record |
|------|---------------|
| **error** | Something failed — query syntax, API error, deployment failure |
| **inefficiency** | Something worked but wasted tokens/time — unnecessary MCP calls, redundant searches, overly verbose output |
| **workaround** | Found a non-obvious solution to a recurring problem |
| **idea** | Thought of a better approach but didn't implement it this run |
| **resolved** | A previously open issue was fixed — link to the fix |

## Agent-Specific Guidance

### Intel Agent Journal
- Track: sources that consistently yield good/bad results
- Track: search queries that return noise vs signal
- Track: report formats that are hard to parse vs easy
- Improve: which query patterns find the most relevant TTPs per token

### Red Team Agent Journal
- Track: log schema mismatches between scenario output and SIEM expectations
- Track: event sequences that are unrealistic (caught during blue team validation)
- Track: which Sysmon event codes are hardest to simulate accurately
- Improve: build a library of verified-good event templates per technique

### Blue Team Agent Journal
- Track: Sigma transpilation failures per backend (Splunk vs Elastic)
- Track: detection logic patterns that consistently produce FPs
- Track: MCP queries that returned unexpected results
- Track: tuning patterns that consistently improve quality scores
- Improve: build a "don't do this" list for detection authoring

### Quality Monitor Journal
- Track: detection decay patterns (rules that degrade over time)
- Track: cost vs value outliers
- Track: tuning recommendations that were accepted vs rejected by human
- Improve: refine health score weights based on which metrics predict problems

### Security Agent Journal
- Track: false positive patterns (what triggers secrets scan but isn't a secret)
- Track: findings that were legitimate vs noise
- Track: which agents produce the most security issues
- Improve: refine scan-patterns.yml to reduce FP rate
