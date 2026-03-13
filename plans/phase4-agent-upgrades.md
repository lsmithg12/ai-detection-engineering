# Phase 4: Agent Intelligence Upgrades

**Priority**: MEDIUM
**Estimated effort**: 12-16 hours (multi-session)
**Dependencies**: Phases 1-2 recommended first
**Branch**: `infra/phase4-agent-upgrades` (or per-agent branches)

---

## Context

All 5 agents are functional but operate at a basic level. Each has clear upgrade paths
that would improve detection quality, reduce manual intervention, and enable more
sophisticated threat coverage.

## Agent 1: Intel Agent Upgrades

### 1A: Structured Report Parsing

**Current**: Claude summarizes reports into free-text, extracts techniques by keyword matching.
**Upgrade**: Parse reports into structured threat profiles.

**Steps**:
1. Define threat report schema:
   ```yaml
   report:
     source: "DFIR Report"
     url: "https://..."
     date: "2026-03-08"
     threat_actor: "LockBit"
     campaign: "Apache ActiveMQ exploitation"
     techniques:
       - id: T1190
         phase: initial_access
         tools_used: ["CVE-2023-46604 exploit"]
         iocs: ["185.220.101.42"]
         data_sources_needed: ["network_connection", "process_create"]
       - id: T1059.001
         phase: execution
         tools_used: ["PowerShell downloader"]
         command_examples: ["powershell -ep bypass -e <base64>"]
   ```
2. Modify Claude prompt to output this structured format
3. Store in `threat-intel/reports/<date>-<slug>.yml`
4. Auto-cross-reference techniques against existing detection coverage

### 1B: Source Diversity Scoring

**Current**: Intel agent searches same sources repeatedly (DFIR Report, CISA).
**Upgrade**: Track which sources have been queried, prioritize diverse sources.

**Steps**:
1. Create `threat-intel/source-tracker.yml`:
   ```yaml
   sources:
     dfir_report:
       last_queried: 2026-03-08
       reports_found: 4
       techniques_discovered: 17
     cisa:
       last_queried: 2026-03-06
       reports_found: 1
       techniques_discovered: 4
     mandiant:
       last_queried: null
       reports_found: 0
   ```
2. Intel agent reads tracker, prioritizes least-recently-queried sources
3. After each run, updates tracker with results

### 1C: Auto-Prioritization Based on Threat Landscape

**Current**: All detection requests get same priority unless manually adjusted.
**Upgrade**: Auto-score priority based on multiple signals.

**Scoring formula**:
```
priority_score = (
    fawkes_overlap * 3 +         # Directly relevant to primary threat
    exploit_in_wild * 2 +         # Active exploitation (CISA KEV)
    multiple_sources * 2 +        # Reported by 2+ intel sources
    coverage_gap * 1 +            # No existing detection
    data_available * 1            # Required data sources exist
)
# >= 7: critical, >= 5: high, >= 3: medium, else: low
```

---

## Agent 2: Red-Team Agent Upgrades

### 2A: Multi-Stage Kill Chain Scenarios

**Current**: Single-technique scenarios with 1-3 events.
**Upgrade**: Generate realistic kill chains spanning multiple techniques.

**Steps**:
1. Define kill chain templates:
   ```yaml
   kill_chains:
     ransomware:
       stages:
         - technique: T1566.001  # Phishing
           events: [process_create_outlook, file_write_attachment]
         - technique: T1059.001  # PowerShell
           events: [process_create_powershell, network_connection]
         - technique: T1055.001  # Injection
           events: [create_remote_thread]
         - technique: T1486     # Encryption
           events: [mass_file_modify, ransom_note_create]
   ```
2. Red-team generates full kill chain as a connected scenario
3. Each event references `kill_chain_id` and `stage_number`
4. Blue-team can validate individual rules AND correlation sequences

### 2B: Evasion Variant Generation

**Current**: One attack variant per technique.
**Upgrade**: Generate multiple variants including evasion attempts.

**Steps**:
1. For each technique, generate 3 variants:
   - **Standard**: Direct implementation (catches basic detection)
   - **Obfuscated**: Same technique with evasion (tests detection resilience)
   - **Living-off-the-land**: Using legitimate tools (tests false positive tuning)
2. Example for T1059.001 (PowerShell):
   - Standard: `powershell.exe -ExecutionPolicy Bypass -File evil.ps1`
   - Obfuscated: `p^ow^er^sh^ell -e <base64>` (caret insertion)
   - LOTL: `powershell.exe -Command "Get-Process | Export-CSV"` (benign-looking)
3. Quality agent tracks which variants are caught vs missed

### 2C: Realistic Process Trees

**Current**: Events have flat parent-child relationships.
**Upgrade**: Generate realistic Windows process trees.

**Steps**:
1. Define common process tree templates:
   ```
   explorer.exe → cmd.exe → powershell.exe → malware.exe
   services.exe → svchost.exe → wmiprvse.exe → evil.exe
   winlogon.exe → userinit.exe → explorer.exe → phishing_doc.exe → cmd.exe
   ```
2. Each event includes full ancestor chain
3. Events share consistent PIDs within a scenario
4. Add `process.parent.pid`, `process.parent.command_line`

---

## Agent 3: Blue-Team Agent Upgrades

### 3A: EQL/Correlation Rule Support

**Current**: Single-event Sigma rules only.
**Upgrade**: Support Elastic EQL for multi-event correlation.

**Steps**:
1. Identify techniques requiring correlation:
   - T1087.002: Discovery burst (5+ recon commands in 60 seconds)
   - T1055.001: Process injection chain (alloc → write → thread)
   - T1021.001: RDP brute force (multiple failed logons → success)
2. Add EQL rule template to `templates/eql-template.yml`:
   ```yaml
   type: eql
   language: eql
   query: |
     sequence by host.name with maxspan=60s
       [process where process.name == "whoami.exe"]
       [process where process.name == "net.exe"]
       [process where process.name == "systeminfo.exe"]
   ```
3. Blue-team agent generates EQL rules for multi-event techniques
4. Validation uses Elasticsearch EQL API: `POST /{index}/_eql/search`

### 3B: Threshold Rule Support

**Current**: All rules are simple match rules.
**Upgrade**: Support threshold/aggregation rules.

**Examples**:
- Failed logon threshold: >5 failed logons from same source in 10 minutes
- Discovery burst: >3 recon commands by same user in 60 seconds
- File encryption: >10 file modifications by same process in 30 seconds

**Steps**:
1. Add threshold template:
   ```json
   {
     "type": "threshold",
     "threshold": {
       "field": ["source.ip"],
       "value": 5
     },
     "query": "event.code: 4625",
     "from": "now-10m"
   }
   ```
2. Transpile threshold rules to both Elastic Detection Engine and Splunk format
3. Validate threshold triggers against scenario event volumes

### 3C: Automated Exclusion Suggestions

**Current**: FP reduction requires manual tuning.
**Upgrade**: Blue-team agent suggests exclusions during validation.

**Steps**:
1. During validation, collect all false positive events
2. Analyze common patterns in FP events:
   - Same parent process? → exclude parent
   - Same user context? → exclude user
   - Same path pattern? → exclude path
3. Generate exclusion candidates ranked by FP reduction impact
4. Apply top exclusion, re-validate, measure improvement
5. Record in tuning changelog
6. Enforce guardrail: max 3 auto-exclusions per rule

---

## Agent 4: Quality Agent Upgrades

### 4A: Live SIEM Alert Metrics

**Current**: Quality agent uses hardcoded `alert_volume_24h` from request YAML.
**Upgrade**: Query actual alert counts from Elasticsearch/Splunk.

**Steps**:
1. Query Elastic alerts index:
   ```python
   response = requests.post(f"{ES_URL}/.alerts-security.alerts-default/_search", json={
       "query": {"bool": {"must": [
           {"term": {"kibana.alert.rule.name": rule_name}},
           {"range": {"@timestamp": {"gte": "now-24h"}}}
       ]}},
       "size": 0,
       "aggs": {
           "by_status": {"terms": {"field": "kibana.alert.workflow_status"}},
           "by_severity": {"terms": {"field": "kibana.alert.severity"}}
       }
   })
   ```
2. Update detection request with actual metrics:
   - `alert_volume_24h`: total alerts
   - `alert_acknowledged_24h`: human-reviewed alerts
   - `alert_false_positive_24h`: dismissed alerts
3. Quality score uses real data instead of estimates

### 4B: Automated Tuning PRs

**Current**: Quality agent recommends tuning but doesn't implement changes.
**Upgrade**: Generate tuning PRs automatically.

**Steps**:
1. When quality agent identifies TUNE-worthy detection:
   - Read current Sigma rule
   - Identify specific FP pattern (from alert details or scenario analysis)
   - Add targeted exclusion to filter block
   - Re-validate with SIEM
2. Create tuning branch: `tuning/{date}-{technique_id}`
3. Commit modified rule + updated test results
4. Create PR with:
   - Title: `[Tuning] Reduce FP on <rule name> (<technique>)`
   - Body: before/after FP rate, exclusion justification, re-validation results
5. Link to quality report for context

### 4C: Regression Detection

**Current**: No automated check when a rule change degrades performance.
**Upgrade**: Track F1/FP history and alert on regression.

**Steps**:
1. Store historical metrics in `monitoring/metrics/<technique_id>.jsonl`:
   ```jsonl
   {"date": "2026-03-08", "f1": 0.95, "fp_rate": 0.03, "tp_rate": 1.0, "method": "local"}
   {"date": "2026-03-10", "f1": 0.90, "fp_rate": 0.05, "tp_rate": 0.95, "method": "elasticsearch"}
   ```
2. Quality agent reads history, flags regressions:
   - F1 dropped >0.10 since last measurement → REGRESSION
   - FP rate increased >5% → REGRESSION
3. Create GitHub issue for regressions:
   - Title: `[Regression] <rule name> F1 dropped from X to Y`
   - Label: `regression`, `needs-review`

---

## Agent 5: Security Agent Upgrades

### 5A: Auto-Fix Capability

**Current**: Security agent reports findings but doesn't fix them.
**Upgrade**: Fix low-risk issues automatically, flag high-risk for human review.

**Auto-fixable issues**:
- Trailing whitespace in YAML
- Missing `modified` date in Sigma metadata
- Non-UUID `rule_id` in compiled JSON
- Missing MITRE tags

**Steps**:
1. Add `auto_fix()` method to security agent
2. For each finding, check if it's in the auto-fixable list
3. Apply fix, add to commit
4. PR comment notes: "Auto-fixed 3 low-risk issues, 1 issue requires human review"

### 5B: Detection Rule Quality Checks

**Current**: Security agent checks for secrets and code issues.
**Upgrade**: Add detection-specific quality checks.

**New checks**:
- Rule uses hard-coded process name without path context → WARN
- Rule has no filter block (all-or-nothing detection) → WARN
- Rule severity doesn't match risk_score in compiled output → ERROR
- Rule uses `|re` modifier (regex) without testing compilation → WARN
- Rule references EID not available in lab data sources → INFO
- Rule condition is just `selection` with no filter → WARN for high-severity rules

---

## Verification Checklist

- [ ] Intel agent produces structured report YAML
- [ ] Intel agent tracks source diversity
- [ ] Red-team generates 3 variants per technique (standard, obfuscated, LOTL)
- [ ] Blue-team can author EQL correlation rules
- [ ] Blue-team suggests exclusions during validation
- [ ] Quality agent queries real alert counts from SIEM
- [ ] Quality agent creates tuning PRs
- [ ] Quality agent tracks F1 history and detects regressions
- [ ] Security agent auto-fixes low-risk issues
- [ ] Security agent checks detection rule quality

---

## Commit Strategy

Per-agent branches recommended (parallel work possible):
- `infra/intel-upgrades` — Tasks 1A, 1B, 1C
- `infra/redteam-upgrades` — Tasks 2A, 2B, 2C
- `infra/blueteam-upgrades` — Tasks 3A, 3B, 3C
- `infra/quality-upgrades` — Tasks 4A, 4B, 4C
- `infra/security-upgrades` — Tasks 5A, 5B
