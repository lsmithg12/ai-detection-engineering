# Phase 7: Advanced Capabilities

**Status**: NOT STARTED
**Priority**: LOW — STRATEGIC (research and innovation)
**Estimated effort**: 40+ hours (multi-week)
**Dependencies**: Phases 1-4 complete, stable pipeline. Phase 1-2 DONE.
**Branch**: Various per feature

---

## Context

These are next-generation capabilities that push the lab from a functional demo into
a research-grade platform. Each is independently valuable and can be pursued based on interest.

## Capability 1: Claude Agent SDK Integration

**Current**: Agents use `claude -p` CLI wrapper with subprocess calls.
**Upgrade**: Use the Claude Agent SDK for proper agent orchestration.

### Why
- Native tool use (no subprocess/stdin/stdout parsing)
- Streaming responses (faster feedback)
- Proper error handling and retry logic
- Multi-turn conversations within an agent run
- Token counting built-in (replace manual estimates)
- Sub-agent spawning for parallel work

### Implementation Plan

1. **Install SDK**: `pip install claude-agent-sdk` (or `anthropic` with agent extensions)
2. **Replace `claude_llm.py`** with SDK-based wrapper:
   ```python
   from anthropic import Anthropic

   client = Anthropic()

   def ask_claude(prompt, tools=None, model="claude-sonnet-4-6"):
       response = client.messages.create(
           model=model,
           max_tokens=4096,
           messages=[{"role": "user", "content": prompt}],
           tools=tools or []
       )
       return response.content[0].text
   ```
3. **Define agent-specific tools**: Each agent gets MCP-compatible tool definitions
   - Blue-team: `validate_rule`, `transpile_sigma`, `search_elasticsearch`
   - Red-team: `generate_scenario`, `check_data_sources`
   - Intel: `search_web`, `parse_report`, `check_coverage`
4. **Multi-turn refinement**: Blue-team agent can have iterative conversations
   for rule improvement (vs single-shot + retry loop)
5. **Token tracking**: Use SDK's built-in usage reporting instead of estimates

### Key Consideration
- Requires API key (not Claude Pro subscription)
- Cost model changes: per-token billing vs flat subscription
- May need to keep CLI fallback for users without API access

---

## Capability 2: Live Adversary Simulation

**Current**: Static JSON events simulating attack behavior.
**Upgrade**: Connect real C2 framework for live detection validation.

### Architecture
```
Mythic C2 Server (Docker)
  ↓ Fawkes agent callback
Target VM (Docker container with Sysmon)
  ↓ Real Sysmon events
Cribl / Direct → Elasticsearch
  ↓
Detection rules fire on REAL telemetry
  ↓
Validation agent checks: did the detection fire?
```

### Implementation Plan

1. **Add Mythic C2 container** to docker-compose:
   ```yaml
   mythic:
     image: mythicmeta/mythic-docker-latest
     ports:
       - "7443:7443"  # Mythic UI
     networks:
       - blue-team-lab
   ```
2. **Add Fawkes agent container**: Build from `github.com/galoryber/fawkes`
3. **Add target container**: Windows or Linux container with Sysmon installed
4. **Orchestration**: Red-team agent triggers Fawkes commands via Mythic API
5. **Validation**: Blue-team agent checks Elasticsearch alerts after each command

### Safety Guardrails
- All containers on isolated Docker network (no external access)
- Mythic API credentials in `.env` (gitignored)
- Rate limiting on C2 commands (max 1 per minute)
- Auto-cleanup: kill agent process after validation completes

### Key Consideration
- Significantly increases Docker resource requirements (16GB+ RAM)
- Fawkes may not have pre-built Docker image — may need to build from source
- Windows containers may not work on all host OS (Linux alternative with wine?)

---

## Capability 3: Multi-SIEM Abstraction Layer

**Current**: Hard-coded Elasticsearch and Splunk integration in `siem.py`.
**Upgrade**: Abstract SIEM interface for pluggable backends.

### Target SIEMs
- Elasticsearch (current — primary, with SIEM validation from Phase 2)
- Splunk Free (current — basic saved searches, no Enterprise Security)
- Microsoft Sentinel (Azure Log Analytics)
- Google Chronicle (BigQuery backend)

### Implementation Plan

1. **Define SIEM interface**:
   ```python
   class SIEMBackend:
       def deploy_rule(self, rule: dict) -> str: ...
       def search(self, query: str, index: str, time_range: str) -> list: ...
       def get_alert_count(self, rule_name: str, hours: int) -> int: ...
       def health_check(self) -> bool: ...
       def get_available_fields(self, index: str) -> list: ...
   ```
2. **Implement per-backend**:
   - `backends/elasticsearch.py`
   - `backends/splunk.py`
   - `backends/sentinel.py` (uses Azure Monitor API)
3. **Sigma transpilation targets**:
   - Elasticsearch: `sigma convert -t lucene -p ecs_windows`
   - Splunk: `sigma convert -t splunk --without-pipeline`
   - Sentinel: `sigma convert -t kusto` (Sigma KQL backend)
   - Chronicle: `sigma convert -t chronicle` (YARA-L)
4. **Config-driven**: `config.yml` specifies active backends
5. **Parallel deployment**: Deploy to all active backends simultaneously

---

## Capability 4: Detection Marketplace

**Current**: Detections live only in this repo.
**Upgrade**: Package and publish validated detections for community use.

### Implementation Plan

1. **Detection Package Format**:
   ```
   packages/
   └── t1059-001-powershell-bypass/
       ├── rule.yml              # Sigma rule
       ├── compiled/
       │   ├── elasticsearch.json
       │   ├── splunk.spl
       │   └── sentinel.kql
       ├── tests/
       │   ├── tp.json
       │   └── tn.json
       ├── metadata.yml          # Version, author, MITRE mapping, F1 score
       └── README.md             # Usage instructions
   ```
2. **Versioning**: Semantic versioning per detection (1.0.0, 1.1.0 for tuning)
3. **Publishing**: GitHub Releases with detection packages as artifacts
4. **Quality gate**: Only publish detections with F1 >= 0.90, validated on 2+ SIEMs
5. **Community contributions**: Accept PRs with new Sigma rules, run through pipeline

---

## Capability 5: SOAR Integration (Response Automation)

**Current**: Detections fire alerts, no automated response.
**Upgrade**: Link detections to response playbooks.

### Implementation Plan

1. **Playbook templates** in `playbooks/`:
   ```yaml
   # playbooks/t1055_001_process_injection.yml
   name: "Process Injection Response"
   trigger:
     rule: "Fawkes CreateRemoteThread Injection"
     severity: high
   actions:
     - type: isolate_host
       target: "{{ alert.host.name }}"
       condition: "alert.risk_score >= 75"
     - type: collect_evidence
       target: "{{ alert.host.name }}"
       artifacts: ["memory_dump", "process_list", "network_connections"]
     - type: notify
       channel: "#soc-alerts"
       message: "Process injection detected on {{ alert.host.name }}"
     - type: create_ticket
       system: "jira"
       project: "INCIDENT"
       summary: "T1055.001 — Process injection on {{ alert.host.name }}"
   ```
2. **Playbook validation**: Check that referenced fields exist in alert schema
3. **Integration options**: Shuffle SOAR, Tines, or custom webhook-based automation
4. **Metric tracking**: Response time from alert to containment

---

## Capability 6: Threat Model Hot-Swapping

**Current**: Hard-coded Fawkes C2 as primary threat.
**Upgrade**: Support swapping threat models without rebuilding pipeline.

### Implementation Plan

1. **Threat model definition** in `threat-intel/models/`:
   ```yaml
   # threat-intel/models/fawkes.yml
   name: "Fawkes C2 Agent"
   type: "c2_framework"
   source: "https://github.com/galoryber/fawkes"
   techniques:
     T1055.001:
       commands: ["vanilla-injection"]
       priority: critical
       data_sources: ["sysmon_eid_8", "sysmon_eid_10"]
     T1059.001:
       commands: ["powershell"]
       priority: high
       data_sources: ["sysmon_eid_1", "windows_4104"]
   ```
2. **Create alternative models**:
   - `scattered-spider.yml` — social engineering + cloud-focused
   - `lockbit.yml` — ransomware-focused
   - `apt28.yml` — espionage-focused
   - `generic-rat.yml` — commodity RAT baseline
3. **Config switch**: `config.yml` specifies active threat model
4. **Intel agent adapts**: Searches for intel relevant to active model
5. **Coverage matrix adapts**: Shows coverage relative to active model

---

## Capability 7: Behavioral Analytics Engine

**Current**: All detections are rule-based (signature matching).
**Upgrade**: Add statistical/ML-based anomaly detection.

### Implementation Plan

1. **Baseline profiling**: Build normal behavior profiles from `sim-baseline` data
   - Process creation frequency per user
   - Network connection patterns per host
   - Registry modification frequency
   - File access patterns
2. **Anomaly rules**:
   - "User X ran 10x more processes than their 30-day average" → suspicious
   - "Host Y made connections to 50 new IPs in 1 hour" → potential C2
   - "Process Z accessed 100 files in 30 seconds" → potential ransomware
3. **Implementation options**:
   - Elasticsearch ML jobs (built-in anomaly detection)
   - Splunk MLTK (Machine Learning Toolkit)
   - Custom Python scoring (run as batch job)
4. **Integration**: Behavioral scores augment rule-based detections
   - Rule fires + behavioral anomaly = high confidence
   - Rule fires + normal behavior = potential FP
   - No rule + behavioral anomaly = coverage gap indicator

---

## Priority Assessment

| Capability | Value | Effort | Risk | Recommendation |
|-----------|-------|--------|------|----------------|
| 1. Agent SDK | High | Medium | Low | Start when API access available |
| 2. Live C2 | Very High | Very High | Medium | Research project — requires significant infra |
| 3. Multi-SIEM | Medium | High | Low | Only if users request specific SIEM support (no Splunk ES) |
| 4. Marketplace | Medium | Medium | Low | Good for portfolio/community value |
| 5. SOAR | Medium | High | Medium | Only valuable with real SOC workflow |
| 6. Threat Swap | High | Low | Low | Quick win — mostly config changes |
| 7. Behavioral | Very High | Very High | High | Research-grade — significant ML work |

**Recommended order**: 6 (threat swap) → 1 (Agent SDK) → 4 (marketplace) → 2 (live C2)

---

## Notes for Future Sessions

- Each capability is independent — pick what interests you
- Capabilities 1 and 6 are the quickest wins
- Capability 2 (live C2) is the most impressive for demos but requires the most infrastructure
- Capability 7 (behavioral analytics) is the most technically ambitious
- All capabilities build on the foundation from Phases 1-5
