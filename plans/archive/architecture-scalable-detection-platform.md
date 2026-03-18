# Scalable Detection Engineering Platform — Architecture

**Author**: Detection Engineering Team
**Date**: 2026-03-15
**Status**: DRAFT — Pending team review
**Scope**: Redesign from lab-scale (29 rules, 1 threat actor) to enterprise-scale (500+ rules, N threat actors, M platforms)

---

## Executive Summary

The current Patronus detection engineering lab works. It has 29 Sigma rules, 5 role-based agents, a YAML state machine, Elasticsearch-based validation, Cribl normalization, and a CI/CD pipeline that deploys to both Elastic and Splunk. For a lab focused on detecting one C2 framework (Fawkes) using Windows telemetry, this architecture is sufficient.

It will not survive contact with enterprise reality.

Enterprise detection engineering is not "write more Sigma rules." It is a data engineering problem wrapped in a threat intelligence problem wrapped in an operational feedback problem. The hardest parts — log source onboarding, data quality monitoring, analyst feedback loops, multi-platform coverage, and detection performance at scale — are entirely absent from the current design.

This document redesigns the platform for enterprise scale. It preserves every existing detection and agent while restructuring the architecture around the problems that actually dominate detection engineering work: data availability, content lifecycle management, operational feedback, and multi-threat-actor prioritization.

---

## The Real-World Scaling Problem

Detection engineering at enterprise scale looks nothing like a lab. Here is what the work actually consists of:

### Log Source Management Is 60% of the Work

In a real SOC, the detection engineer's biggest enemy is not the adversary — it is the data. New log sources arrive weekly: a team deploys a new SaaS product, the cloud team migrates a workload, a vendor changes their log schema, an agent stops reporting. Each source needs field mapping, quality validation, volume estimation, and integration testing before any detection can be written against it.

The current lab has exactly one log source pipeline: Sysmon on Windows, normalized through Cribl or ingested directly. There is no framework for onboarding a new source, no health monitoring for existing sources, and no way to know when a source breaks silently.

### Threat-Agnostic Detection

The lab is built around detecting Fawkes. Every priority calculation, every scenario generator, every coverage metric is Fawkes-centric. But in the real world, process injection is process injection regardless of whether Fawkes, Cobalt Strike, Brute Ratel, or a novel implant performs it. Detections must target behaviors, not tools.

A CreateRemoteThread detection should catch any tool that calls `VirtualAllocEx` followed by `WriteProcessMemory` followed by `CreateRemoteThread` — not just the specific way Fawkes does it. The threat model informs priority, but the detection logic must be tool-agnostic.

### Detection Content as a Product

At 29 rules, you can track state in YAML files and coverage in a markdown table. At 300 rules, you need version control per rule, ownership assignment, SLAs for response to new intel, deprecation policies for stale rules, and a content catalog that analysts can search and filter. Detection rules are a product with a lifecycle: authored, tested, deployed, tuned, and eventually retired.

### Multi-Platform Reality

The lab covers Windows. Enterprises run Windows, Linux, macOS, AWS, Azure, GCP, Kubernetes, Office 365, Okta, GitHub, Slack, and dozens of SaaS platforms. Each platform has different log sources, different field schemas, different detection patterns. A "process creation" detection on Linux looks nothing like one on Windows. Cloud detections often involve API call sequences rather than endpoint telemetry.

### Correlation Over Single-Event Rules

Every rule in the current lab is a single-event pattern match: "does this one log event match this Lucene query?" Real attacks generate chains of events. A single failed logon is noise. Five failed logons from different source IPs to the same service account in 10 minutes is credential stuffing. Detecting the pattern requires event correlation, threshold aggregation, or sequence detection — none of which the current architecture supports.

### Analyst Feedback Loops

The current pipeline has no mechanism for operational experience to flow back into detection improvement. When an analyst marks an alert as a false positive in the SIEM, nothing happens to the detection rule. When a true positive is missed, nobody learns about it until the next breach review. Without feedback loops, detections degrade over time as the environment changes around them.

---

## Current Architecture (Phases 1-3)

### What Exists Today

**Five role-based agents** running through a shared state machine:

| Agent | Responsibility | Key Files |
|-------|---------------|-----------|
| Intel | Ingest threat reports, extract TTPs, create detection requests | `intel_agent.py` — reads from `threat-intel/reports/`, web search fallback |
| Red Team | Generate attack + benign scenarios per technique | `red_team_agent.py` — produces JSON scenario files in `simulator/scenarios/` |
| Blue Team | Author Sigma rules, validate against ES, transpile to Lucene/SPL | `blue_team_agent.py` — the workhorse, handles authoring + validation + deployment |
| Quality | Health scoring, daily monitoring reports | `quality_agent.py` — generates reports in `monitoring/reports/` |
| Security | PR gate — secrets scan, code security, rule quality | `security_agent.py` — runs on every PR to main |

**State machine** (`state.py` + `schema.yml`): YAML files in `autonomous/detection-requests/` track each detection through states: `REQUESTED` -> `SCENARIO_BUILT` -> `AUTHORED` -> `VALIDATED` -> `DEPLOYED` -> `MONITORING`. Transitions are validated against a schema. Changelog entries are appended to each YAML file.

**Validation pipeline** (`validation.py`): Bulk-ingests scenario events into ephemeral `sim-validation-{uuid}` Elasticsearch indices, runs compiled Lucene queries, calculates F1 scores, and deletes the index. Falls back to local JSON matching when ES is offline.

**SIEM deployment** (`siem.py`): Pushes rules to Elastic Detection Engine API and Splunk Saved Searches API. Reads credentials from `config.yml`.

**Simulation** (`simulator.py`): Generates ECS-formatted Windows security events (baseline enterprise activity + Fawkes attack scenarios) and streams to ES/Splunk/Cribl.

**Cribl normalization** (Phase 3): Raw vendor-format events (Windows Event XML, syslog) flow through Cribl's `cim_normalize` pipeline for field extraction and ECS mapping before reaching the SIEM.

**CI/CD**: 6 GitHub Actions workflows handle daily agent runs, deployment on merge to main, and security gate checks on PRs.

### What It Has Achieved

- 29 Sigma rules across 8 MITRE tactics, all with compiled Lucene and SPL
- 11 rules deployed and monitoring in both Elastic and Splunk
- 12 rules validated with F1 >= 0.75 and ready for deployment
- 62% coverage of Fawkes' 21 core techniques
- Elasticsearch-based SIEM validation with retry-and-refine loop
- Cribl streaming validation path for raw log normalization testing
- Automated PR creation, security gate, and post-merge deployment

This is a solid lab. The problems start when you try to make it real.

---

## Where It Breaks at Scale

### 1. Fawkes-Centric Design

The entire system assumes a single threat actor. The Intel agent has hardcoded `FAWKES_TTP_PATH`. The Red Team agent generates scenarios based on Fawkes command-to-artifact mappings. The coverage matrix is titled "Fawkes C2 Detections." Priority scoring includes a Fawkes overlap bonus. Adding a second threat actor requires modifying every agent, every priority calculation, and every coverage metric.

**Impact**: Cannot track coverage against multiple adversaries. Cannot prioritize based on organizational threat landscape. Cannot support industry-specific threat models.

### 2. YAML State Store

Each detection's lifecycle state lives in a single YAML file in `autonomous/detection-requests/`. The `StateManager` reads and writes these files with no locking, no transactions, and no concurrent write safety. The changelog section of each file grows unbounded — a rule that gets tuned 50 times accumulates 50 changelog entries in the same YAML file.

**Impact**: At 100+ rules, file I/O becomes slow. At 10+ concurrent agent runs, race conditions corrupt state. No way to query "all rules in VALIDATED state with F1 > 0.90" without reading every file.

### 3. Single Scenario Per Technique

Each technique gets one true positive test case and one true negative test case. Real adversaries use multiple variants of the same technique: different tools, different evasion wrappers, different execution contexts. A detection validated against one variant of process injection may miss three others.

**Impact**: False confidence in detection quality. Real-world FP/FN rates are worse than test results suggest. Evasion gaps are invisible.

### 4. Manual Coverage Matrix

The coverage matrix in `coverage/attack-matrix.md` is a hand-maintained markdown table. Every time a detection's state changes, someone must manually update the matrix. The matrix has already drifted from code — the "Last updated" date sometimes lags behind actual state changes.

**Impact**: Coverage reporting is unreliable. Decision-makers get stale data. Priority calculations based on coverage gaps may be wrong.

### 5. No Log Onboarding Framework

The lab has Sysmon data and simulated Windows events. There is no framework for answering: "We just deployed CrowdStrike Falcon — how do we onboard it?" No field mapping templates, no health checks, no volume estimation, no integration testing. The `gaps/data-sources/` directory (Phase 3) identifies what is missing but provides no path to onboard it.

**Impact**: The #1 bottleneck in enterprise detection engineering has no tooling. Every new log source is a manual, ad-hoc effort.

### 6. No Data Quality Monitoring

Log sources break silently. A Sysmon agent stops reporting from a critical server. A vendor updates their log schema and half the fields change names. Event volume drops 80% because a firewall rule changed. The current system has no way to detect any of these failures until a detection stops firing.

**Impact**: Detections that depend on broken data sources produce no alerts, giving a false sense of security. The absence of alerts is indistinguishable from the absence of attacks.

### 7. Windows-Only

Every scenario generator, every field mapping, every test case assumes Windows. The ECS fields used are Windows-centric (`process.executable`, `winlog.event_id`, `process.pe.original_file_name`). There are no Linux auditd scenarios, no macOS Endpoint Security scenarios, no cloud API call scenarios, no Kubernetes audit log scenarios.

**Impact**: Cannot detect attacks on 60-80% of a typical enterprise's attack surface.

### 8. No Detection Performance Testing

A rule that works perfectly against 100 test events may take 30 seconds to execute against 100 million production events. Wildcard queries on high-cardinality text fields, complex regex patterns, and broad time ranges can crush a SIEM cluster. The current system measures accuracy (F1 score) but not performance (query cost, alert latency).

**Impact**: Deploying an expensive rule to production can degrade SIEM performance for all users. No way to catch this before deployment.

### 9. No Analyst Feedback Loop

When an analyst triages an alert in the SIEM and marks it as a false positive, that information stays in the SIEM. It never flows back to the detection rule, the tuning agent, or the coverage metrics. The Quality agent generates health reports but cannot incorporate operational experience.

**Impact**: Detection quality degrades over time. The same false positives fire repeatedly. Analysts lose trust in detections and start ignoring alerts.

### 10. Monolithic Blue Team Agent

The Blue Team agent (`blue_team_agent.py`) handles authoring, transpilation, validation, and deployment tracking. These are four distinct concerns with different scaling characteristics, different failure modes, and different security boundaries. Authoring is creative work that benefits from LLM reasoning. Validation is mechanical work that benefits from parallelism. Deployment is high-risk work that benefits from isolation and audit.

**Impact**: Cannot scale authoring and validation independently. A validation failure blocks authoring. A deployment bug puts the entire Blue Team agent at risk.

---

## Redesigned Agent Topology

### Design Principles

1. **Separation of concerns**: Each agent owns exactly one scaling problem. No agent does two fundamentally different kinds of work.
2. **Threat-agnostic content**: Detections target behaviors (API call patterns, process relationships, file system artifacts), not specific tools. Threat models inform priority, not logic.
3. **Data-first**: Log source onboarding is a first-class pipeline with its own agent, its own state, and its own quality metrics. No data, no detection.
4. **Continuous validation**: Detections are tested at authoring time, at deployment time, and on a recurring schedule. Drift is caught automatically.
5. **Feedback-driven**: Operational experience (analyst TP/FP markings, alert volume trends, environmental changes) flows back into detection improvement automatically.
6. **Budget-aware**: LLM token costs constrain parallelism. The coordinator allocates budget across agents based on priority.

### Agent Overview

```
Tier 1 — Foundation (Always Running)
  1. Data Onboarding Agent    — Log source lifecycle
  2. Threat Intel Agent       — Multi-source intel, threat model registry
  3. Coverage Analyst Agent   — Gap analysis, prioritization

Tier 2 — Content (On-Demand, Parallelizable)
  4. Scenario Engineer Agent  — Attack variants, kill chains, evasion tests
  5. Detection Author Agent   — Multi-format rule authoring
  6. Validation Agent         — Multi-SIEM testing, performance profiling

Tier 3 — Operations (Continuous)
  7. Deployment Agent         — Multi-SIEM deployment, rollback, versioning
  8. Tuning Agent             — Alert health, auto-tune, analyst feedback
  9. Security Gate Agent      — PR review, compliance, conflict detection

Orchestrator
  10. Coordinator             — Route work, manage priorities, resolve conflicts
```

---

### Tier 1: Foundation Agents (Always Running)

#### 1. Data Onboarding Agent (`data_onboarding_agent.py`)

**Responsibility**: Log source lifecycle — discover, map, validate, monitor, alert on degradation.

**Why it exists**: In enterprise detection engineering, data availability is the #1 bottleneck. You cannot detect what you cannot see. This agent makes log onboarding a repeatable, measurable process instead of ad-hoc firefighting.

**Key capabilities**:

| Capability | Description | Current State |
|-----------|-------------|---------------|
| Schema analysis | Analyze a new data source's fields, types, cardinality | Not implemented |
| Field mapping | Generate vendor-to-ECS mapping for new sources | Partially in Cribl pipeline |
| Data quality scoring | Score each source on freshness, completeness, volume, schema compliance | Not implemented |
| Source health monitoring | Detect stale sources, schema drift, volume anomalies | Not implemented |
| Cribl pipeline management | Generate Cribl pipeline functions for new sources | Manual via MCP tools |
| Gap tracking | Maintain structured gap records per technique | Phase 3 YAML files in `gaps/data-sources/` |

**Interface**:
```python
class DataOnboardingAgent:
    def discover_source(self, index_pattern: str) -> SourceProfile:
        """Analyze an ES index and produce a source profile (fields, types, volume)."""

    def map_fields(self, source_profile: SourceProfile) -> FieldMapping:
        """Generate vendor-to-ECS field mapping for a source."""

    def score_health(self, source_id: str) -> HealthScore:
        """Calculate freshness, completeness, volume, schema compliance scores."""

    def monitor_all(self) -> list[HealthAlert]:
        """Check all registered sources, return alerts for degraded/offline sources."""

    def generate_cribl_pipeline(self, source_profile: SourceProfile) -> dict:
        """Generate Cribl pipeline functions for a new source."""
```

**State artifacts**:
- Source registry YAML files in `data-sources/registry/` (one per source type)
- Health score history in state DB (for trend detection)
- Alert records for degraded sources

**Trigger**: Runs daily for health monitoring. On-demand for new source onboarding.

---

#### 2. Threat Intel Agent (`intel_agent.py`) — Refactored

**Responsibility**: Multi-source intelligence ingestion, threat model management, environment-aware prioritization.

**What changes from current**:

| Aspect | Current | Redesigned |
|--------|---------|-----------|
| Threat model | Hardcoded Fawkes TTP path | Pluggable Threat Model Registry |
| Sources | Web search + local reports | Multi-source with diversity scoring |
| Prioritization | Fawkes overlap bonus | Weighted by environment relevance |
| Output | Detection requests | Detection requests + threat model updates |
| Intel aging | None | Automatic deprecation of stale intel |

**Key capabilities**:

- **Threat Model Registry**: Each adversary, malware family, or threat category is a YAML file in `threat-intel/models/`. The Fawkes TTP mapping becomes one entry among many. Models are versioned and track confidence levels per technique.
- **Multi-source ingestion**: OSINT feeds, commercial threat intel, ISAC reports, internal incident data. Each source is tagged with a reliability rating.
- **Source diversity scoring**: A technique reported by 5 independent sources is higher confidence than one reported by a single vendor blog. The agent tracks source overlap and flags single-source intelligence.
- **Environment-aware prioritization**: Priority is weighted by: (a) which platforms exist in our environment, (b) which data sources are available, (c) which threat actors target our industry, (d) current coverage gaps. A high-priority technique with no data source is deprioritized until the source is onboarded.
- **Intel aging**: Intelligence older than 12 months is flagged for review. TTPs confirmed by recent incidents are refreshed. Deprecated intel is archived, not deleted.

**Interface**:
```python
class IntelAgent:
    def ingest_report(self, report_path: str) -> list[DetectionRequest]:
        """Extract TTPs from a threat report, create detection requests."""

    def update_threat_model(self, model_id: str, techniques: dict) -> ThreatModel:
        """Add or update techniques in a threat model."""

    def prioritize_backlog(self, available_sources: list[str]) -> list[PrioritizedTechnique]:
        """Rank detection backlog by environment relevance and data availability."""

    def age_intel(self) -> list[IntelRecord]:
        """Flag stale intel for review, archive deprecated entries."""
```

---

#### 3. Coverage Analyst Agent (`coverage_agent.py`) — New

**Responsibility**: Automated gap analysis, multi-dimensional coverage tracking, prioritized backlog generation.

**Why it is new**: The current coverage matrix is a hand-maintained markdown table. At scale, coverage must be computed from state, not documented by hand. This agent replaces `coverage/attack-matrix.md` as a static file with a dynamic, queryable coverage model.

**Key capabilities**:

- **Auto-generated ATT&CK matrix**: Reads detection state DB, computes coverage per technique, generates the matrix. No manual updates. The markdown file becomes an output, not an input.
- **Multi-dimensional coverage**: Track coverage across three axes simultaneously:
  - **Technique x Platform**: T1055.001 covered on Windows but not Linux
  - **Technique x Threat Actor**: T1486 covered for LockBit scenarios but not for BlackCat
  - **Technique x Data Source**: T1078.004 detectable with Azure AD logs but not with Okta
- **Data source availability mapping**: Cross-reference technique data requirements with Data Onboarding Agent's source registry. Compute "what can we detect" vs "what do we want to detect."
- **Prioritized detection backlog**: Weighted scoring:
  - Threat relevance (from Intel agent models): 0-30 points
  - Data availability (from source registry): 0-25 points
  - Coverage gap severity (uncovered critical technique): 0-25 points
  - Implementation effort estimate: 0-20 points
- **ATT&CK Navigator export**: Generate JSON for the MITRE ATT&CK Navigator visualization tool, color-coded by coverage depth (monitored / validated / authored / gap).

**Interface**:
```python
class CoverageAnalystAgent:
    def compute_matrix(self) -> CoverageMatrix:
        """Generate full ATT&CK coverage matrix from detection state."""

    def find_gaps(self, threat_model_id: str = None) -> list[CoverageGap]:
        """Identify uncovered techniques, optionally filtered by threat model."""

    def prioritize_backlog(self) -> list[BacklogItem]:
        """Rank all gaps by weighted priority score."""

    def export_navigator(self, output_path: str) -> None:
        """Export ATT&CK Navigator JSON layer."""

    def coverage_report(self) -> CoverageReport:
        """Generate summary report: coverage %, trends, top gaps."""
```

**Trigger**: Runs after every state transition (detection authored, validated, deployed, retired). Also runs daily for trend tracking.

---

### Tier 2: Content Agents (On-Demand, Parallelizable)

#### 4. Scenario Engineer Agent (`scenario_agent.py`) — Refactored from Red Team

**Responsibility**: Generate attack scenarios with multiple variants, kill chain sequences, and evasion tests across platforms.

**What changes from current**:

| Aspect | Current (Red Team) | Redesigned (Scenario Engineer) |
|--------|-------------------|-------------------------------|
| Variants per technique | 1 TP + 1 TN | 5-10 variants (base, obfuscated, LOLBin, API-direct, evasion) |
| Platform | Windows only | Windows, Linux, macOS, cloud, container |
| Scenario type | Single-event | Single-event + multi-event kill chains |
| Threat actor binding | Fawkes artifact mappings | Per-model variants from threat model registry |
| Evasion testing | None | Documented evasion catalog per detection |

**Key capabilities**:

- **Multi-variant generation**: For each technique, produce multiple scenario variants:
  - `base`: Standard implementation (e.g., `CreateRemoteThread` with obvious parameters)
  - `obfuscated`: Same technique with string obfuscation, indirect calls, or encoding
  - `lolbin`: Living-off-the-land implementation using built-in OS tools
  - `api_direct`: Direct syscall or low-level API variant that bypasses userland hooks
  - `evasion_*`: Specific evasion techniques (e.g., unhooking, PPID spoofing, argument tampering)

- **Kill chain scenarios**: Multi-technique sequences with realistic timing:
  ```yaml
  scenario: ransomware_kill_chain
  steps:
    - technique: T1566.001  # Phishing attachment
      delay: 0s
    - technique: T1059.001  # PowerShell download
      delay: 30s
    - technique: T1082      # System discovery
      delay: 120s
    - technique: T1486      # Encryption
      delay: 600s
  ```

- **Per-threat-actor variants**: The Fawkes model generates scenarios that match Fawkes' specific implementation. The Scattered Spider model generates scenarios that match their known TTPs. The detection must catch both.

- **Multi-platform support**: Each variant specifies its platform:
  ```yaml
  variant: t1055_001_base_linux
  platform: linux
  event:
    event.category: process
    event.type: access
    process.executable: /usr/bin/python3
    process.args: ["inject.py", "--pid", "1234"]
    # Linux ptrace-based injection looks different from Windows CRT
  ```

- **Realistic process trees**: Generate process ancestor chains that look like real execution:
  ```yaml
  process_tree:
    - process.executable: C:\Windows\explorer.exe
      process.pid: 1000
    - process.executable: C:\Program Files\Microsoft Office\WINWORD.EXE
      process.pid: 2000
      process.parent.pid: 1000
    - process.executable: C:\Windows\System32\cmd.exe
      process.pid: 3000
      process.parent.pid: 2000  # Word spawning cmd.exe — suspicious
  ```

**Scale factor**: Stateless and embarrassingly parallel. Can run N instances for different threat actors or platforms simultaneously. Each instance produces scenario files without needing to coordinate with others.

---

#### 5. Detection Author Agent (`author_agent.py`) — Refactored from Blue Team

**Responsibility**: Write detection rules in multiple formats. Nothing else — no validation, no deployment.

**What changes from current**:

| Aspect | Current (Blue Team) | Redesigned (Author) |
|--------|-------------------|---------------------|
| Rule formats | Sigma only | Sigma, EQL, threshold, ML baseline |
| Transpilation | Lucene + SPL | Lucene + SPL + KQL (Sentinel) + YARA-L (Chronicle) |
| Organization | Individual rules by tactic | Content packs (grouped by use case) |
| Versioning | None (git history only) | Explicit version field, changelog per rule |

**Key capabilities**:

- **Multi-format authoring**: Different detection patterns require different rule types:

  | Format | Use Case | Example |
  |--------|----------|---------|
  | Sigma (single-event) | Pattern matching on individual events | "Process created with `-ep bypass` flag" |
  | EQL (sequence) | Ordered event sequences with timing | "File created, then executed, within 30 seconds" |
  | Threshold (aggregation) | Count-based alerting | "5+ failed logons to same account in 10 minutes" |
  | ML baseline | Statistical anomaly | "Process network connections deviating from 30-day baseline" |

- **Content packs**: Group related detections into versioned packs:
  ```yaml
  # detections/packs/process-injection/pack.yml
  name: Process Injection Detection Pack
  version: 2.1.0
  author: Detection Engineering Team
  description: Comprehensive process injection detection across all known variants
  data_requirements:
    - sysmon_eid_1   # Process creation
    - sysmon_eid_8   # CreateRemoteThread
    - sysmon_eid_10  # Process access
    - sysmon_eid_25  # Process tampering
  rules:
    - t1055_001_crt.yml       # CreateRemoteThread (4 variants)
    - t1055_004_apc.yml       # APC injection (3 variants)
    - t1055_012_hollowing.yml # Process hollowing (2 variants)
    - t1055_threadless.yml    # Threadless injection (2 variants)
    - t1055_poolparty.yml     # PoolParty variants (3 variants)
  platforms: [windows]
  mitre_tactics: [privilege_escalation, defense_evasion]
  ```

- **Automated transpilation**: Author writes Sigma; transpilation to all target formats happens automatically:
  ```
  Sigma rule (.yml)
    ├── sigma convert -t lucene -p ecs_windows  → .lucene
    ├── sigma convert -t splunk --without-pipeline → .spl
    ├── sigma convert -t kusto -p microsoft365defender → .kql
    └── Custom transform → _elastic.json (Detection Engine format)
  ```

- **Rule versioning**: Each rule carries an explicit version:
  ```yaml
  version: 3
  version_history:
    - version: 1
      date: 2026-03-01
      change: Initial authoring
    - version: 2
      date: 2026-03-10
      change: Added exclusion for SCCM updater process
    - version: 3
      date: 2026-03-15
      change: Broadened to catch renamed binaries via PE metadata
  ```

- **Triage brief** (not full runbook): Detection Authors know the attack technique best and
  should provide lightweight analyst guidance. Full playbooks are a SOC analyst/IR function.
  ```yaml
  custom:
    triage_notes:
      what_this_detects: "CreateRemoteThread injection into a target process"
      key_fields_to_examine:
        - "process.executable (the injector — check if signed, in temp dir)"
        - "winlog.event_data.TargetImage (the victim — lsass/explorer = high severity)"
      known_false_positives:
        - "AV memory scanning (McAfee, Defender real-time protection)"
      related_techniques:
        - "T1055.004 — APC injection often follows failed CRT attempt"
      investigation_hint: "Check if source process is unsigned or in a temp directory"
    compliance_controls:           # Regulatory requirements satisfied
      - "PCI-DSS-10.6.1"
      - "SOC2-CC7.2"
  ```
  **Role boundary**: Author writes triage_notes. A future Playbook Agent (Phase 7/8) would
  consume triage_notes + environment context to generate full response SOPs.

**Scale factor**: Stateless per rule. Can run N instances for batch authoring across different packs or techniques.

---

#### 6. Validation Agent (`validation_agent.py`) — Extracted from Blue Team

**Responsibility**: Test detections against SIEMs, measure performance, run continuous regression.

**What changes from current**:

| Aspect | Current (in Blue Team) | Redesigned (Validation Agent) |
|--------|----------------------|-------------------------------|
| Scope | One-time at authoring | Continuous (authoring + periodic regression) |
| SIEMs | Elasticsearch only | Elasticsearch + Splunk + future targets |
| Metrics | F1 score only | F1 + query cost + alert latency + evasion resilience |
| Variants | 1 TP scenario | All scenario variants from Scenario Engineer |
| Scale testing | None | Simulated production-volume performance profiling |

**Key capabilities**:

- **Multi-SIEM validation**: Test the same detection against every target SIEM:
  ```
  Detection: T1055.001 CreateRemoteThread
    ├── Elasticsearch (Lucene): F1=1.00, query_time=12ms
    ├── Splunk (SPL):           F1=1.00, query_time=45ms
    └── Sentinel (KQL):         F1=0.95, query_time=89ms  ← KQL variant needs tuning
  ```

- **Evasion resilience testing**: Run all scenario variants (base, obfuscated, LOLBin, API-direct, evasion) and report per-variant results:
  ```
  T1055.001 Evasion Report:
    base:       DETECTED (TP)
    obfuscated: DETECTED (TP)
    lolbin:     MISSED (FN) ← Detection doesn't cover rundll32-based injection
    api_direct: DETECTED (TP)
    ppid_spoof: MISSED (FN) ← PPID spoofing bypasses parent process check
  ```

- **Performance profiling**: Measure query cost at simulated production scale:
  ```
  T1055.001 Performance Profile:
    Test volume: 100 events        → 12ms
    Simulated 1M events/day:       → estimated 340ms (PASS, budget: 500ms)
    Simulated 10M events/day:      → estimated 3.4s (FAIL, budget: 500ms)
    Recommendation: Add index filter on event.code to reduce scan scope
  ```

- **Continuous regression testing**: Re-validate deployed rules on a schedule (weekly) to catch:
  - Schema changes that break field references
  - Index template updates that change field types
  - Environmental drift that increases FP rates
  - New evasion variants added by Scenario Engineer

- **Cross-rule correlation testing**: For kill chain scenarios, verify that all expected rules fire in the correct sequence:
  ```
  Kill Chain: ransomware_standard
    Step 1 (T1566.001): DETECTED by "Phishing Attachment" rule ✓
    Step 2 (T1059.001): DETECTED by "PowerShell Bypass" rule ✓
    Step 3 (T1082):     NOT DETECTED ← "System Info Discovery" rule didn't fire
    Step 4 (T1486):     DETECTED by "Ransomware Encryption" rule ✓
    Kill chain coverage: 3/4 (75%)
  ```

- **F1 scoring with confidence intervals**: At 1 TP + 1 TN, confidence is low. With 10 variants, we can compute meaningful confidence intervals:
  ```
  T1055.001: F1 = 0.92 (95% CI: 0.85-0.98, n=24 test cases)
  ```

**Scale factor**: Can validate against multiple SIEMs in parallel. Can run N instances for batch validation.

---

### Tier 3: Operations Agents (Continuous)

#### 7. Deployment Agent (`deployment_agent.py`) — Extracted from Blue Team

**Responsibility**: Rule deployment, version management, rollback, and deployment verification.

**Why separated**: Deployment is the highest-risk operation in the pipeline. A bad rule can generate thousands of false positive alerts, degrade SIEM performance, or miss real attacks. Isolating deployment into its own agent allows focused guardrails, audit trails, and rollback capabilities.

**Key capabilities**:

- **Multi-SIEM deployment**: Deploy to all active SIEMs with format-appropriate packaging:
  ```
  Deploying T1055.001 v3:
    Elastic Detection Engine: POST /api/detection_engine/rules → rule_id: abc123 ✓
    Splunk Saved Search:      POST /servicesNS/admin/search/saved/searches → sid: def456 ✓
    Sentinel Analytics Rule:  PUT /providers/Microsoft.SecurityInsights/alertRules → id: ghi789 ✓
  ```

- **Canary deployments**: For high-risk rules (new, broadly-scoped, or high-volume indices), deploy to a subset of indices first:
  ```yaml
  deployment_strategy:
    phase_1:  # Canary — 24 hours
      indices: ["sim-attack", "sim-baseline"]
      alert_action: log_only  # No notification, just log
    phase_2:  # Staged — 48 hours
      indices: ["prod-endpoints-pilot"]
      alert_action: notify_channel
    phase_3:  # Full
      indices: ["prod-endpoints-*"]
      alert_action: full_response
  ```

- **Rollback capability**: Revert to any previous rule version:
  ```
  Rollback T1055.001 from v3 to v2:
    Reason: v3 introduced 50+ FP/day from SCCM client
    Elastic: Updated rule query to v2 Lucene ✓
    Splunk: Updated saved search to v2 SPL ✓
    State: MONITORING (v2) — tuning PR created for v3 fix
  ```

- **Deployment verification**: After deploying, confirm the rule is active and executing:
  1. Query SIEM API to verify rule exists and is enabled
  2. Wait for one scheduling interval
  3. Check that the rule executed (even if it produced zero alerts)
  4. Log deployment confirmation in state DB

- **Version tracking**: Every deployment records which version of the rule is live in which SIEM:
  ```sql
  -- "What's deployed where?"
  SELECT rule_id, siem_type, version, deployed_at, status
  FROM deployments
  WHERE status = 'active'
  ORDER BY deployed_at DESC;
  ```

**Guardrails**:
- Never deploy a rule that has not passed validation (F1 >= 0.75)
- Never deploy more than 5 rules in a single batch (limit blast radius)
- Always require human PR approval before deployment to production
- Maintain deployment audit log with who/what/when/why

---

#### 8. Tuning Agent (`tuning_agent.py`) — Refactored from Quality

**Responsibility**: Monitor alert health, integrate analyst feedback, auto-tune rules, and recommend retirements.

**What changes from current**:

| Aspect | Current (Quality) | Redesigned (Tuning) |
|--------|-------------------|---------------------|
| Scope | Health scoring + reports | Active tuning + feedback integration |
| Input | Detection state files | SIEM alert data + analyst markings + state DB |
| Output | Markdown reports | Tuning PRs with before/after metrics |
| Feedback | None | Analyst TP/FP markings flow back to rules |

**Key capabilities**:

- **Alert volume monitoring**: Track alerts per rule per day. Flag anomalies:
  - **Spike**: Rule suddenly generating 10x normal volume → possible FP burst or real attack
  - **Silence**: Rule that normally fires 5x/day has fired 0x for 3 days → possible data source issue
  - **Trend**: Gradual increase over weeks → environmental drift increasing FP rate

- **FP trend detection**: Correlate analyst FP markings with rule identity:
  ```
  T1059.001 PowerShell Bypass:
    Week 1: 12 alerts, 2 FP (17%)
    Week 2: 15 alerts, 5 FP (33%)  ← trending up
    Week 3: 18 alerts, 9 FP (50%)  ← FLAGGED: FP rate doubled in 3 weeks
    Recommendation: Add exclusion for new SCCM PowerShell scripts
  ```

- **Analyst feedback integration**: When analysts mark alerts as TP or FP in the SIEM, the Tuning Agent collects these markings and uses them to improve detections:
  ```
  Feedback pipeline:
    SIEM alert → Analyst triages → Marks TP/FP → Tuning Agent reads markings
    → If FP pattern detected → Generate exclusion PR
    → If FN reported → Flag to Scenario Engineer for new variant
  ```

- **Exclusion management**: Add exclusions to rules while enforcing the 3-max guardrail:
  ```yaml
  exclusions:
    - field: process.executable
      value: "C:\\ProgramData\\SCCM\\Client\\SCClient.exe"
      reason: "Legitimate SCCM client PowerShell invocations"
      added: 2026-03-15
      added_by: tuning_agent
    - field: user.name
      value: "svc_backup"
      reason: "Backup service account runs scheduled PowerShell tasks"
      added: 2026-03-15
      added_by: tuning_agent
    # MAX 3 — if a 4th is needed, flag for human review
  ```

- **Rule retirement recommendations**: Flag rules that should be retired:
  - **Silent rules**: No alerts in 90 days + data source confirmed active → detection is too narrow
  - **Noisy rules**: FP rate > 80% despite 3 exclusions → detection is fundamentally flawed
  - **Superseded rules**: A better detection covers the same technique → merge and retire

**Trigger**: Runs daily for monitoring. On-demand when analyst feedback is received.

---

#### 9. Security Gate Agent (`security_agent.py`) — Existing, Enhanced

**Responsibility**: PR review, secrets scanning, quality gates, compliance checks, cross-rule conflict detection.

**New capabilities** (in addition to existing secrets scan, code security, and rule quality checks):

- **Detection content compliance**: Every PR that adds or modifies a detection must include:
  - [ ] Complete Sigma metadata (title, description, author, date, status, references, tags)
  - [ ] At least 3 test case variants (not just 1 TP + 1 TN)
  - [ ] MITRE ATT&CK mapping with tactic + technique + sub-technique
  - [ ] False positive documentation
  - [ ] Data source requirements
  - [ ] Compiled outputs for all active SIEMs
  - Fail the PR if any are missing.

- **Performance budget enforcement**: Reject rules that exceed query cost thresholds:
  ```
  FAILED: T1059.001 v4 query estimated at 2.3s per execution
  Budget: 500ms per execution at 1M events/day
  Suggestion: Add index filter (event.code:1) to reduce scan scope
  ```

- **Cross-rule conflict detection**: Identify problems across the rule set:
  - **Overlapping rules**: Two rules that fire on the same events (wasted SIEM resources)
  - **Contradictory exclusions**: Rule A excludes a process that Rule B specifically detects
  - **Dependency conflicts**: Rule A depends on a data source that Rule B's exclusions filter out

---

### Orchestrator

#### 10. Coordinator (`coordinator.py`) — New

**Responsibility**: Route work across all agents, manage priorities, track pipeline throughput, resolve conflicts, allocate budget.

**Why needed**: With 9 specialized agents, someone must decide what runs when, with what priority, and with what budget. Without coordination, agents duplicate work, fight over shared state, or starve important tasks.

**Key capabilities**:

- **Work queue management**: Maintain a priority queue of tasks (detection requests, validation runs, tuning cycles). Assign tasks to appropriate agents based on type and current load.

- **Pipeline orchestration**: Define and enforce the workflow:
  ```
  Intel produces detection request
    → Coordinator assigns to Scenario Engineer
      → Scenario produces variants
        → Coordinator assigns to Detection Author
          → Author produces rules
            → Coordinator assigns to Validation Agent
              → Validation passes (F1 >= threshold)
                → Coordinator queues for Deployment (post-merge)
  ```

- **Priority management**: Support different urgency levels:
  | Priority | Trigger | SLA | Example |
  |----------|---------|-----|---------|
  | P0 — Emergency | Active incident, CISA KEV | 4 hours | Log4Shell, zero-day exploitation |
  | P1 — Urgent | New threat intel, coverage gap in critical area | 24 hours | New ransomware variant |
  | P2 — Standard | Routine backlog, coverage expansion | 1 week | Expanding Linux detection coverage |
  | P3 — Improvement | Tuning, variant expansion, documentation | 2 weeks | Adding evasion variants |

- **Conflict resolution**: When two agents need to modify the same detection (e.g., Author writing v2 while Tuning agent adds an exclusion to v1), the Coordinator serializes the changes and manages merge conflicts.

- **Status dashboard data**: Track and expose metrics:
  - Pipeline throughput: detections authored/validated/deployed per week
  - Agent health: success rate, error rate, average completion time
  - SLA compliance: % of tasks completed within priority SLA
  - Coverage trend: techniques covered over time

- **Budget management**: Allocate LLM token budget across agents:
  ```yaml
  daily_budget:
    total_tokens: 500000
    allocation:
      intel: 50000       # 10% — lightweight analysis
      scenario: 100000   # 20% — scenario generation is creative work
      author: 150000     # 30% — rule authoring is the core LLM task
      validation: 50000  # 10% — mostly mechanical
      tuning: 50000      # 10% — feedback analysis
      coverage: 25000    # 5%  — gap computation
      coordinator: 25000 # 5%  — routing decisions
      reserve: 50000     # 10% — P0 emergencies
  ```

---

## Multi-Threat-Actor Support

### Threat Model Registry

The current system hardcodes Fawkes throughout the codebase. The redesign introduces a **Threat Model Registry** — a directory of pluggable adversary definitions that any agent can query.

**Location**: `threat-intel/models/`

**Structure**: One YAML file per adversary, malware family, or threat category.

```yaml
# threat-intel/models/fawkes.yml
id: fawkes
name: Fawkes C2 Agent
type: c2_framework
source_url: https://github.com/galoryber/fawkes
platforms: [windows, macos, linux]
priority: critical
confidence: high
last_updated: 2026-03-15
description: >
  Golang-based Mythic C2 agent with 59 commands spanning process injection,
  credential access, persistence, defense evasion, and lateral movement.
techniques:
  T1055.001:
    name: CreateRemoteThread Injection
    commands: [vanilla-injection]
    artifacts: [process_create, process_inject]
    data_sources: [sysmon_eid_8, sysmon_eid_10]
    implementation_notes: >
      Uses VirtualAllocEx/WriteProcessMemory/CreateRemoteThread classic pattern.
      Targets explorer.exe by default.
  T1055.004:
    name: APC Injection
    commands: [apc-injection]
    artifacts: [process_create, process_inject]
    data_sources: [sysmon_eid_8, sysmon_eid_10]
  T1059.001:
    name: PowerShell Execution
    commands: [powershell]
    artifacts: [process_create, script_block_log]
    data_sources: [sysmon_eid_1, powershell_4104]
  T1547.001:
    name: Registry Run Keys
    commands: [persist]
    artifacts: [registry_write]
    data_sources: [sysmon_eid_13]
  # ... all 21 core techniques
```

```yaml
# threat-intel/models/scattered-spider.yml
id: scattered_spider
name: Scattered Spider (UNC3944 / Octo Tempest)
type: apt_group
platforms: [windows, cloud, identity, saas]
priority: high
confidence: high
last_updated: 2026-03-15
industry_targeting: [telecom, finance, technology, hospitality]
description: >
  Financially motivated threat group specializing in social engineering,
  SIM swapping, MFA fatigue, and cloud/identity compromise. Known for
  targeting helpdesks and using legitimate remote access tools.
techniques:
  T1621:
    name: Multi-Factor Authentication Request Generation
    description: MFA fatigue / push bombing attacks
    artifacts: [authentication_log, mfa_challenge_log]
    data_sources: [azure_ad_sign_in, okta_system_log, duo_auth_log]
    implementation_notes: >
      Rapid repeated MFA push notifications to exhaust user into approving.
      Detect via high-frequency MFA challenges from same user in short window.
  T1566.004:
    name: Spearphishing Voice (Vishing)
    description: Social engineering via phone calls to helpdesk
    artifacts: [helpdesk_ticket, password_reset, mfa_reset]
    data_sources: [itsm_log, azure_ad_audit, okta_system_log]
  T1078.004:
    name: Cloud Account Compromise
    description: Access via compromised cloud credentials
    artifacts: [cloud_sign_in, token_use]
    data_sources: [azure_ad_sign_in, aws_cloudtrail, gcp_audit]
  T1098:
    name: Account Manipulation
    description: Adding credentials, MFA devices, or permissions
    artifacts: [directory_change, role_assignment]
    data_sources: [azure_ad_audit, aws_iam, gcp_admin_activity]
  T1199:
    name: Trusted Relationship Abuse
    description: Leverage MSP/vendor access for initial entry
    artifacts: [vpn_log, remote_access_log]
    data_sources: [vpn_log, remote_access_tool_log]
```

```yaml
# threat-intel/models/lockbit.yml
id: lockbit
name: LockBit Ransomware
type: ransomware
platforms: [windows, linux, vmware_esxi]
priority: critical
confidence: high
last_updated: 2026-03-15
description: >
  Ransomware-as-a-Service operation. Affiliates use varied initial access
  methods but follow consistent encryption and extortion patterns.
techniques:
  T1486:
    name: Data Encrypted for Impact
    description: File encryption with .lockbit extension
    artifacts: [file_modify, file_create, process_create]
    data_sources: [sysmon_eid_11, sysmon_eid_1, file_integrity_monitoring]
    implementation_notes: >
      High-volume file modification events. Detect via rate of file extension
      changes or entropy increase in file headers.
  T1489:
    name: Service Stop
    description: Stop security and backup services before encryption
    artifacts: [service_change, process_create]
    data_sources: [windows_7036, sysmon_eid_1]
    implementation_notes: >
      sc.exe stop, net.exe stop, or WMI-based service termination targeting
      known security/backup service names.
  T1490:
    name: Inhibit System Recovery
    description: Delete shadow copies and disable recovery
    artifacts: [process_create, vss_event]
    data_sources: [sysmon_eid_1, windows_security]
  T1048:
    name: Exfiltration Over Alternative Protocol
    description: Data staging before encryption (double extortion)
    artifacts: [network_connection, file_access]
    data_sources: [sysmon_eid_3, proxy_log, firewall_log]
  T1021.002:
    name: SMB/Windows Admin Shares
    description: Lateral movement via admin shares for ransomware deployment
    artifacts: [logon_event, share_access, file_create]
    data_sources: [windows_security_4624, sysmon_eid_11]
```

```yaml
# threat-intel/models/generic-rat.yml
id: generic_rat
name: Generic Remote Access Trojan Behaviors
type: behavior_category
platforms: [windows, linux, macos]
priority: medium
confidence: high
last_updated: 2026-03-15
description: >
  Common behaviors shared by most RATs/C2 frameworks regardless of specific
  tooling. Detecting these provides broad coverage against unknown tools.
techniques:
  T1071.001:
    name: Web Protocols for C2
    description: HTTP/HTTPS beaconing with regular intervals
    artifacts: [network_connection]
    data_sources: [proxy_log, sysmon_eid_3, zeek_http]
    implementation_notes: >
      Detect via jitter analysis, unusual user-agents, long-lived connections,
      or domain age/reputation.
  T1055:
    name: Process Injection (any variant)
    description: Code execution in the address space of another process
    artifacts: [process_inject, process_access]
    data_sources: [sysmon_eid_8, sysmon_eid_10, etw_microsoft_windows_threat_intelligence]
  T1059:
    name: Command and Scripting Interpreter (any)
    description: Execution via cmd, PowerShell, bash, Python, etc.
    artifacts: [process_create, script_execution]
    data_sources: [sysmon_eid_1, powershell_4104, auditd_execve]
  T1082:
    name: System Information Discovery
    description: Enumeration of host details (OS, arch, hostname, etc.)
    artifacts: [process_create]
    data_sources: [sysmon_eid_1, auditd_execve]
```

### How Agents Use the Registry

| Agent | Usage |
|-------|-------|
| Intel | Reads all models to check for technique overlap with new intel. Updates models with new source information. |
| Coverage Analyst | Computes per-model coverage matrix. Generates "Fawkes coverage: 62%, Scattered Spider coverage: 15%, LockBit coverage: 40%." |
| Scenario Engineer | Reads model-specific implementation notes to generate realistic variants per threat actor. |
| Detection Author | Checks if a new rule covers techniques claimed by multiple models (broad impact = higher priority). |
| Coordinator | Weights task priority by threat model priority and coverage gap severity. |

---

## Log Source Onboarding Framework

### The Problem

Enterprise detection engineering teams report spending 50-70% of their time on data engineering: getting the right logs, in the right format, with the right fields, reliably delivered. The current lab completely skips this problem — it has one hardcoded data source (Sysmon on Windows) and a simulator that produces pre-formatted events.

### Source Registry

**Location**: `data-sources/registry/`

Each log source type gets a YAML definition describing its fields, detection value, health check method, and normalization requirements.

```yaml
# data-sources/registry/sysmon.yml
source_id: sysmon
vendor: Microsoft
product: Sysmon (System Monitor)
version: "15.13"
platform: windows
transport: [wef, cribl_forwarder, nxlog, hec]
documentation: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
event_types:
  eid_1:
    description: Process Creation
    ecs_category: process
    ecs_type: start
    detection_value: critical
    volume_estimate: "500-2000/host/day"
    fields:
      - raw: Image
        ecs: process.executable
        type: keyword
        required: true
      - raw: CommandLine
        ecs: process.command_line
        type: keyword  # MUST be keyword, not text — wildcards break on text
        required: true
      - raw: ParentImage
        ecs: process.parent.executable
        type: keyword
        required: true
      - raw: ParentCommandLine
        ecs: process.parent.command_line
        type: keyword
        required: false
      - raw: User
        ecs: user.name
        type: keyword
        required: true
      - raw: ProcessId
        ecs: process.pid
        type: long
        required: true
      - raw: ParentProcessId
        ecs: process.parent.pid
        type: long
        required: true
      - raw: Hashes
        ecs: process.hash.*
        type: keyword
        required: false
      - raw: OriginalFileName
        ecs: process.pe.original_file_name
        type: keyword
        required: false
  eid_3:
    description: Network Connection
    ecs_category: network
    ecs_type: connection
    detection_value: high
    volume_estimate: "2000-10000/host/day"
    fields:
      - raw: Image
        ecs: process.executable
        type: keyword
        required: true
      - raw: DestinationIp
        ecs: destination.ip
        type: ip
        required: true
      - raw: DestinationPort
        ecs: destination.port
        type: long
        required: true
      - raw: SourceIp
        ecs: source.ip
        type: ip
        required: true
  eid_8:
    description: CreateRemoteThread Detected
    ecs_category: process
    ecs_type: access
    detection_value: critical
    volume_estimate: "5-50/host/day"
    fields:
      - raw: SourceImage
        ecs: process.executable
        type: keyword
        required: true
      - raw: TargetImage
        ecs: process.target.executable
        type: keyword
        required: true
      - raw: StartFunction
        ecs: dll.function_name
        type: keyword
        required: false
  eid_10:
    description: Process Accessed
    ecs_category: process
    ecs_type: access
    detection_value: critical
    volume_estimate: "100-1000/host/day"
    fields:
      - raw: SourceImage
        ecs: process.executable
        type: keyword
        required: true
      - raw: TargetImage
        ecs: process.target.executable
        type: keyword
        required: true
      - raw: GrantedAccess
        ecs: winlog.event_data.GrantedAccess
        type: keyword
        required: true
  eid_11:
    description: File Created
    ecs_category: file
    ecs_type: creation
    detection_value: medium
    volume_estimate: "1000-5000/host/day"
    fields:
      - raw: TargetFilename
        ecs: file.path
        type: keyword
        required: true
      - raw: Image
        ecs: process.executable
        type: keyword
        required: true
  eid_13:
    description: Registry Value Set
    ecs_category: registry
    ecs_type: change
    detection_value: high
    volume_estimate: "200-1000/host/day"
    fields:
      - raw: TargetObject
        ecs: registry.path
        type: keyword
        required: true
      - raw: Details
        ecs: registry.data.strings
        type: keyword
        required: true
health_check:
  method: query_latest_event
  query: "event.provider:Microsoft-Windows-Sysmon AND event.code:1"
  stale_threshold: 15m
  expected_volume_per_day: 5000
```

```yaml
# data-sources/registry/azure-ad-sign-in.yml
source_id: azure_ad_sign_in
vendor: Microsoft
product: Azure Active Directory
version: "2.0"
platform: cloud
transport: [diagnostic_settings, graph_api, event_hub]
documentation: https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/
event_types:
  sign_in:
    description: User Sign-In Event
    ecs_category: authentication
    ecs_type: start
    detection_value: critical
    volume_estimate: "1000-50000/tenant/day"
    fields:
      - raw: userPrincipalName
        ecs: user.name
        type: keyword
        required: true
      - raw: ipAddress
        ecs: source.ip
        type: ip
        required: true
      - raw: status.errorCode
        ecs: event.outcome
        type: keyword
        required: true
      - raw: appDisplayName
        ecs: cloud.service.name
        type: keyword
        required: true
      - raw: conditionalAccessStatus
        ecs: azure.signinlogs.properties.conditional_access_status
        type: keyword
        required: false
      - raw: mfaDetail.authMethod
        ecs: azure.signinlogs.properties.mfa_detail.auth_method
        type: keyword
        required: false
      - raw: location.city
        ecs: source.geo.city_name
        type: keyword
        required: false
      - raw: riskLevelDuringSignIn
        ecs: azure.signinlogs.properties.risk_level_during_signin
        type: keyword
        required: false
health_check:
  method: query_latest_event
  query: "event.dataset:azure.signinlogs"
  stale_threshold: 30m
  expected_volume_per_day: 10000
```

```yaml
# data-sources/registry/linux-auditd.yml
source_id: linux_auditd
vendor: Linux
product: auditd
version: "3.1"
platform: linux
transport: [auditbeat, rsyslog, cribl_forwarder]
documentation: https://man7.org/linux/man-pages/man8/auditd.8.html
event_types:
  execve:
    description: Process Execution
    ecs_category: process
    ecs_type: start
    detection_value: critical
    volume_estimate: "1000-5000/host/day"
    fields:
      - raw: exe
        ecs: process.executable
        type: keyword
        required: true
      - raw: comm
        ecs: process.name
        type: keyword
        required: true
      - raw: a0, a1, a2
        ecs: process.args
        type: keyword
        required: false
      - raw: ppid
        ecs: process.parent.pid
        type: long
        required: true
      - raw: uid
        ecs: user.id
        type: keyword
        required: true
      - raw: auid
        ecs: user.audit.id
        type: keyword
        required: true
health_check:
  method: query_latest_event
  query: "event.module:auditd AND event.action:executed"
  stale_threshold: 15m
  expected_volume_per_day: 3000
```

### Data Quality Scoring

Every registered source receives a health score computed from four dimensions:

| Dimension | Metric | Green | Yellow | Red |
|-----------|--------|-------|--------|-----|
| **Freshness** | Time since last event received | < 5 min | 5-15 min | > 15 min |
| **Completeness** | % of `required: true` fields populated | > 95% | 80-95% | < 80% |
| **Volume** | Events/day vs `expected_volume_per_day` | within 20% | within 50% | > 50% deviation |
| **Schema Compliance** | % of events matching expected field types | > 99% | 95-99% | < 95% |

**Composite health score**: Weighted average (freshness 30%, completeness 30%, volume 20%, schema 20%), normalized to 0.0-1.0.

**Alerting thresholds**:
- Score > 0.8: Healthy (no action)
- Score 0.6-0.8: Degraded (notify detection engineering team)
- Score < 0.6: Critical (block new detection deployment against this source, escalate)

**History tracking**: Store daily health scores in state DB to detect trends (gradual degradation that stays just above threshold).

### Onboarding Workflow

When a new log source needs to be onboarded:

```
1. Data Onboarding Agent receives request (manual or auto-discovered)
2. Agent queries ES for sample events: GET /<index>/_search?size=100
3. Agent analyzes fields, types, cardinality, volume
4. Agent generates source registry YAML (or updates existing)
5. Agent generates Cribl pipeline functions for normalization
6. Agent validates normalization via cribl_preview_pipeline
7. Agent runs health check and computes initial quality score
8. Agent creates PR with registry YAML + Cribl pipeline + health config
9. After merge, source is monitored by daily health checks
10. Coverage Analyst updates "detectable techniques" based on new source
```

---

## Detection Content Lifecycle

### Content Packs

Individual rules work at 29 detections. At 300+, grouping related detections into versioned content packs provides better management.

**Directory structure**:
```
detections/
├── packs/
│   ├── process-injection/
│   │   ├── pack.yml               # Pack metadata, version, data requirements
│   │   ├── t1055_001_crt.yml      # CreateRemoteThread
│   │   ├── t1055_004_apc.yml      # APC Injection
│   │   ├── t1055_012_hollowing.yml
│   │   ├── t1055_threadless.yml
│   │   ├── t1055_poolparty.yml
│   │   └── tests/
│   │       ├── t1055_001_variants.json  # 5-10 TP variants + TNs
│   │       ├── t1055_004_variants.json
│   │       └── kill_chain_injection_to_c2.json
│   ├── ransomware-behavior/
│   │   ├── pack.yml
│   │   ├── t1486_encryption.yml
│   │   ├── t1489_service_stop.yml
│   │   ├── t1490_recovery_disable.yml
│   │   ├── t1048_exfil.yml
│   │   └── tests/
│   ├── identity-compromise/
│   │   ├── pack.yml
│   │   ├── t1621_mfa_fatigue.yml
│   │   ├── t1078_004_cloud_account.yml
│   │   ├── t1098_account_manipulation.yml
│   │   └── tests/
│   └── initial-access-web/
│       ├── pack.yml
│       ├── t1190_exploit_app.yml
│       ├── t1133_remote_services.yml
│       └── tests/
├── standalone/                      # Rules not yet in a pack
│   ├── ... (migration period: existing 29 rules start here)
└── retired/                         # Deprecated rules (kept for audit)
```

**Pack metadata** (`pack.yml`):
```yaml
name: Process Injection Detection Pack
id: pack-process-injection
version: 2.1.0
author: Detection Engineering Team
status: active  # active, draft, deprecated
description: >
  Comprehensive process injection detection covering CreateRemoteThread,
  APC injection, process hollowing, threadless injection, and PoolParty variants.
platforms: [windows]
mitre_tactics: [privilege_escalation, defense_evasion]
mitre_techniques: [T1055.001, T1055.004, T1055.012, T1055.xxx, T1055.xxx]
data_requirements:
  required:
    - sysmon_eid_1   # Process creation (for injector process)
    - sysmon_eid_8   # CreateRemoteThread
    - sysmon_eid_10  # Process access
  optional:
    - sysmon_eid_25  # Process tampering
    - etw_threat_intel # Kernel-level injection telemetry
threat_models: [fawkes, generic_rat]  # Which models this pack covers
rules:
  - file: t1055_001_crt.yml
    version: 3
    status: monitoring
    f1: 0.97
  - file: t1055_004_apc.yml
    version: 1
    status: validated
    f1: 0.92
  - file: t1055_012_hollowing.yml
    version: 1
    status: authored
    f1: null
  - file: t1055_threadless.yml
    version: 1
    status: validated
    f1: 0.88
  - file: t1055_poolparty.yml
    version: 1
    status: authored
    f1: null
update_policy:
  review_interval: 30d  # Review pack health every 30 days
  min_test_cases_per_rule: 5
  required_variant_types: [base, obfuscated, lolbin]
```

### Rule Versioning

Every detection rule tracks its version explicitly in the Sigma YAML:

```yaml
# Inside the Sigma rule file
custom:
  version: 3
  version_history:
    - version: 1
      date: 2026-03-01
      author: blue-team-agent
      change: Initial authoring from Fawkes TTP mapping
      f1_at_release: 0.85
    - version: 2
      date: 2026-03-10
      author: tuning-agent
      change: >
        Added exclusion for SCCM client (C:\ProgramData\SCCM\Client\SCClient.exe).
        FP rate dropped from 15% to 3%.
      f1_at_release: 0.92
    - version: 3
      date: 2026-03-15
      author: author-agent
      change: >
        Broadened to catch renamed binaries using process.pe.original_file_name.
        Added 3 evasion test variants (renamed binary, path spoofing, argument obfuscation).
      f1_at_release: 0.97
  deployment_history:
    - siem: elasticsearch
      version_deployed: 3
      deployed_at: 2026-03-15T14:30:00Z
      siem_rule_id: abc-123-def
    - siem: splunk
      version_deployed: 3
      deployed_at: 2026-03-15T14:31:00Z
      siem_rule_id: T1055.001_CreateRemoteThread_v3
```

### Detection Performance Profiles

Each rule gets a performance budget defined alongside its detection logic:

```yaml
custom:
  performance:
    query_cost_estimate: low    # low (<100ms), medium (100-500ms), high (>500ms)
    index_scope: "event.code:8" # Narrow the search to relevant events
    alert_sla:
      expected_alerts_per_day: 2-10
      max_acceptable: 50       # Above this = likely FP burst
      zero_after_days: 7       # If zero alerts for 7 days, flag as stale
    latency_budget_ms: 500     # Max acceptable query execution time
    scalability_notes: >
      Query uses event.code filter which limits scan to ~50 events/host/day.
      Wildcard on process.executable is on keyword field (indexed, not analyzed).
      Safe for 10M events/day environments.
```

---

## State Management Evolution

### Why Migrate from YAML

The current `StateManager` in `autonomous/orchestration/state.py` reads and writes individual YAML files in `autonomous/detection-requests/`. This works because:

- 29 rules fit comfortably in individual files
- Only one agent writes at a time (sequential pipeline)
- Queries are simple (list all, filter by state)

It will break because:

| Problem | Threshold | Impact |
|---------|-----------|--------|
| File I/O overhead | ~100 rules | Reading all files to answer "which rules are VALIDATED?" takes seconds |
| No concurrent writes | 2+ agents | Two agents updating different rules can corrupt YAML if running simultaneously |
| No transactions | Any scale | A crash mid-write leaves a partially written YAML file |
| No relational queries | ~50 rules | "All rules covering T1055 with F1 > 0.90 on Windows" requires loading every file |
| Unbounded changelog | ~50 tuning cycles | Changelog section grows forever, making files large and slow to parse |

### Migration Path: YAML to SQLite

SQLite is the right choice for this scale. It is file-based (no server), supports transactions and concurrent reads, handles queries efficiently, and works in both the Docker lab and CI environments.

**Schema**:

```sql
-- Detection rules — one row per rule (replaces individual YAML files)
CREATE TABLE detection_rules (
    id TEXT PRIMARY KEY,              -- e.g., "T1055.001"
    title TEXT NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'REQUESTED',
    -- REQUESTED | SCENARIO_BUILT | AUTHORED | VALIDATED | DEPLOYED | MONITORING | TUNED | RETIRED
    version INTEGER NOT NULL DEFAULT 1,
    priority TEXT DEFAULT 'medium',   -- critical | high | medium | low
    severity TEXT DEFAULT 'medium',   -- critical | high | medium | low | informational
    threat_actors TEXT,               -- JSON array: ["fawkes", "scattered_spider"]
    platforms TEXT,                    -- JSON array: ["windows", "linux"]
    mitre_tactic TEXT,                -- e.g., "privilege_escalation"
    mitre_technique TEXT,             -- e.g., "T1055.001"
    sigma_rule_path TEXT,             -- relative path to Sigma YAML
    pack_id TEXT,                     -- FK to content pack (nullable)
    f1_score REAL,
    fp_rate REAL,
    tp_rate REAL,
    evasion_resilience REAL,          -- % of evasion variants caught
    query_cost_ms INTEGER,            -- estimated query time at 1M events/day
    data_sources TEXT,                -- JSON array of required source IDs
    exclusion_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT,                  -- which agent created this
    last_modified_by TEXT             -- which agent last modified this
);

-- Test cases — multiple per rule (replaces single TP/TN JSON files)
CREATE TABLE test_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL REFERENCES detection_rules(id),
    type TEXT NOT NULL,                -- TP | TN | evasion | kill_chain
    variant TEXT DEFAULT 'base',       -- base | obfuscated | lolbin | api_direct | evasion_*
    platform TEXT DEFAULT 'windows',
    threat_actor TEXT,                 -- which threat model this variant represents
    event_json TEXT NOT NULL,          -- the test event as JSON
    expected_result TEXT NOT NULL,      -- should_match | should_not_match
    actual_result TEXT,                -- matched | not_matched | error
    last_validated TIMESTAMP,
    validated_on_siem TEXT,            -- elasticsearch | splunk | sentinel
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Deployments — track what is live where (replaces deployment notes in YAML)
CREATE TABLE deployments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL REFERENCES detection_rules(id),
    siem_type TEXT NOT NULL,           -- elasticsearch | splunk | sentinel
    siem_rule_id TEXT,                 -- the ID assigned by the SIEM
    rule_version INTEGER NOT NULL,     -- which version of the rule is deployed
    deployed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deployed_by TEXT,                  -- which agent performed the deployment
    status TEXT NOT NULL DEFAULT 'active',  -- active | disabled | rolled_back
    rollback_reason TEXT,
    canary_phase INTEGER DEFAULT 0     -- 0=full, 1=canary, 2=staged
);

-- State transitions — audit log (replaces changelog in YAML)
CREATE TABLE state_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL REFERENCES detection_rules(id),
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    agent TEXT NOT NULL,                -- which agent made the transition
    details TEXT,                       -- human-readable description
    metadata TEXT,                      -- JSON blob with extra context
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Data sources — track source health (new)
CREATE TABLE data_sources (
    id TEXT PRIMARY KEY,               -- e.g., "sysmon"
    vendor TEXT,
    product TEXT,
    platform TEXT,
    registry_path TEXT,                -- path to source registry YAML
    health_score REAL,
    freshness_score REAL,
    completeness_score REAL,
    volume_score REAL,
    schema_score REAL,
    last_event TIMESTAMP,
    expected_volume_per_day INTEGER,
    actual_volume_today INTEGER,
    status TEXT DEFAULT 'unknown',     -- healthy | degraded | offline | unknown
    last_checked TIMESTAMP
);

-- Health score history — for trend detection (new)
CREATE TABLE health_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL REFERENCES data_sources(id),
    health_score REAL,
    freshness_score REAL,
    completeness_score REAL,
    volume_score REAL,
    schema_score REAL,
    recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Analyst feedback — from SIEM alert triage (new)
CREATE TABLE analyst_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL REFERENCES detection_rules(id),
    siem_alert_id TEXT,                -- the SIEM's alert ID
    verdict TEXT NOT NULL,             -- true_positive | false_positive | unknown
    analyst TEXT,                       -- who triaged
    notes TEXT,                         -- free-text explanation
    event_summary TEXT,                 -- JSON summary of the triggering event
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for common queries
CREATE INDEX idx_rules_status ON detection_rules(status);
CREATE INDEX idx_rules_technique ON detection_rules(mitre_technique);
CREATE INDEX idx_rules_tactic ON detection_rules(mitre_tactic);
CREATE INDEX idx_rules_pack ON detection_rules(pack_id);
CREATE INDEX idx_tests_rule ON test_cases(rule_id);
CREATE INDEX idx_tests_type ON test_cases(type);
CREATE INDEX idx_deployments_rule ON deployments(rule_id);
CREATE INDEX idx_deployments_status ON deployments(status);
CREATE INDEX idx_transitions_rule ON state_transitions(rule_id);
CREATE INDEX idx_feedback_rule ON analyst_feedback(rule_id);
CREATE INDEX idx_health_source ON health_history(source_id);
```

### Dual-Write Migration Strategy

Migration from YAML to SQLite happens gradually over Phase 4, not as a big-bang cutover:

1. **Week 1-2**: Implement SQLite schema and `StateManagerV2` class that wraps `StateManager`
2. **Week 2-3**: Dual-write period — every state change writes to both YAML and SQLite
3. **Week 3-4**: Validation — run queries against both backends, compare results
4. **Week 4**: Switch primary reads to SQLite, keep YAML writes as backup
5. **Week 5+**: Remove YAML writes after confidence period

**Backward compatibility**: The `StateManager` interface (`list_all()`, `get()`, `transition()`, etc.) stays the same. Only the storage backend changes.

---

## Data Flow at Enterprise Scale

### Overview

```
                        ┌──────────────────────────────────────────────────┐
                        │              Threat Intel Sources                 │
                        │    OSINT  ·  Commercial  ·  ISAC  ·  Internal    │
                        └────────────────────┬─────────────────────────────┘
                                             │
                                   ┌─────────▼──────────┐
                                   │    Intel Agent      │
                                   │   (Multi-model)     │
                                   │                     │
                                   │  Threat Model       │
                                   │  Registry CRUD      │
                                   └─────────┬──────────┘
                                             │ Detection Requests
                                             │
              ┌──────────────────────────────▼──────────────────────────────┐
              │                    Coordinator                              │
              │                                                             │
              │   Work Queue  ·  Priority Routing  ·  Budget Allocation     │
              │   Conflict Resolution  ·  SLA Tracking  ·  Agent Health     │
              └──┬──────┬──────┬──────┬──────┬──────┬──────┬──────┬────────┘
                 │      │      │      │      │      │      │      │
     ┌───────────▼┐  ┌──▼───┐ ┌▼─────┐ ┌───▼──┐ ┌─▼─────┐│  ┌───▼────────┐
     │ Coverage   │  │Scen. │ │Author│ │Valid.│ │Deploy ││  │ Security   │
     │ Analyst    │  │Eng.  │ │Agent │ │Agent │ │Agent  ││  │ Gate       │
     │            │  │      │ │      │ │      │ │       ││  │            │
     │ Gap        │  │Multi-│ │Sigma │ │Multi-│ │Canary ││  │ PR review  │
     │ analysis   │  │vari- │ │EQL   │ │SIEM  │ │Roll-  ││  │ Compliance │
     │ ATT&CK     │  │ant   │ │Thres-│ │F1+   │ │back   ││  │ Conflicts  │
     │ Navigator  │  │Kill  │ │hold  │ │Perf  │ │Verify ││  │ Perf gates │
     │ Backlog    │  │chain │ │ML    │ │Regr. │ │       ││  │            │
     └────────────┘  └──────┘ └──────┘ └──────┘ └───────┘│  └────────────┘
                                                          │
                     ┌────────────────────────────────────▼───────────────┐
                     │              Multi-SIEM Targets                     │
                     │                                                     │
                     │  Elasticsearch  ·  Splunk  ·  Sentinel  ·  Chronicle│
                     └────────────────────────┬──────────────────────────┘
                                              │ Alerts + Analyst Feedback
                                              │
                                    ┌─────────▼──────────┐
                                    │   Tuning Agent     │
                                    │                    │
                                    │  Alert monitoring  │
                                    │  FP trend detect   │
                                    │  Exclusion mgmt    │
                                    │  Retirement recs   │
                                    └─────────┬──────────┘
                                              │ Tuning PRs + Retirement Recs
                                              │
                     ┌────────────────────────▼──────────────────────────┐
                     │                Data Onboarding Agent               │
                     │                                                     │
                     │  Source registry  ·  Health monitoring  ·  Quality  │
                     │  Schema mapping  ·  Cribl pipeline mgmt  ·  Alerts │
                     └─────────────────────────────────────────────────────┘
```

### Pipeline Flow for a New Detection (End-to-End)

```
Time    Agent                Action
─────   ──────────────       ──────────────────────────────────────────────
T+0     Intel Agent          Ingests new threat report about LockBit variant
T+0     Intel Agent          Extracts T1489 (Service Stop) as high-priority gap
T+0     Intel Agent          Creates detection request: T1489, priority=high, model=lockbit
T+1     Coordinator          Receives request, checks data source availability
T+1     Coordinator          Data Onboarding confirms: sysmon_eid_1 healthy, windows_7036 available
T+1     Coordinator          Routes to Scenario Engineer (priority: P1)
T+2     Scenario Engineer    Generates 7 variants for T1489:
                               - base: sc.exe stop <service>
                               - lolbin: net.exe stop <service>
                               - wmi: wmic service call stopservice
                               - powershell: Stop-Service
                               - obfuscated: encoded PowerShell
                               - kill_chain: T1489 → T1490 → T1486 sequence
                               - benign: legitimate service restart
T+3     Coordinator          Routes to Detection Author (priority: P1)
T+4     Detection Author     Writes Sigma rule covering all variant patterns
T+4     Detection Author     Transpiles to Lucene + SPL + KQL
T+4     Detection Author     Packages as part of ransomware-behavior pack
T+5     Coordinator          Routes to Validation Agent
T+6     Validation Agent     Tests against Elasticsearch:
                               - 6/6 TP variants detected (F1=1.0 on ES)
                               - 0/1 TN incorrectly matched (FP=0%)
T+6     Validation Agent     Tests against Splunk:
                               - 6/6 TP variants detected (F1=1.0 on Splunk)
T+6     Validation Agent     Performance profile:
                               - Query cost: 45ms at 1M events/day (within budget)
T+7     Coordinator          Queues for deployment (requires PR + human review)
T+8     Detection Author     Creates PR: "[Detection] Service Stop (T1489) v1"
T+8     Security Gate        Reviews PR: metadata complete, tests sufficient, no conflicts
T+9     Human Reviewer       Approves and merges PR
T+10    Deployment Agent     Deploys to Elastic + Splunk (canary phase)
T+11    Deployment Agent     Verifies rule is active and executing
T+12    Coverage Analyst     Updates matrix: T1489 now MONITORING, LockBit coverage +1
T+14    Tuning Agent         Day 2 report: 3 alerts, 0 FP — healthy
T+21    Tuning Agent         Day 7 report: 18 alerts, 1 FP (legitimate Oracle restart) — monitoring
```

---

## Phased Implementation

The redesign is implemented incrementally across Phases 4-8. Each phase is self-contained and delivers value independently. Phases can be reordered based on operational priority.

### Phase 4: Scalable Architecture Foundation

**Duration**: 4-6 weeks
**Focus**: Multi-threat-actor support, state management migration, agent refactoring
**Prerequisites**: Phases 1-3 complete (they are)

**Deliverables**:

| # | Deliverable | Details |
|---|-------------|---------|
| 4.1 | Threat Model Registry | `threat-intel/models/` with Fawkes, Scattered Spider, LockBit, Generic RAT YAMLs. Intel agent refactored to read registry. |
| 4.2 | SQLite State Manager | `StateManagerV2` with schema above. Dual-write migration from YAML. |
| 4.3 | Coordinator Agent | `coordinator.py` with work queue, priority routing, and sequential pipeline orchestration. |
| 4.4 | Agent Refactor — Split Blue Team | Extract `validation_agent.py` and `deployment_agent.py` from `blue_team_agent.py`. Author agent retains rule writing only. |
| 4.5 | Coverage Analyst Agent | `coverage_agent.py` generating matrix from state DB. Replaces manual `coverage/attack-matrix.md` updates. |
| 4.6 | Existing Rule Migration | All 29 rules migrated to SQLite state DB. YAML dual-write for backward compat. |

**Success criteria**:
- Intel agent can create detection requests tagged with multiple threat models
- Coverage analyst computes per-model coverage without manual updates
- All 29 existing rules function correctly with new state backend
- Coordinator routes a detection through the full pipeline (intel -> scenario -> author -> validate)

**Risk**: Agent refactoring may introduce regressions. Mitigate with integration tests that replay the existing 29-rule pipeline through the new architecture.

### Phase 5: Data Engineering at Scale

**Duration**: 4-6 weeks
**Focus**: Log source onboarding, data quality monitoring, multi-platform simulation
**Prerequisites**: Phase 4 (Coordinator + state DB must exist)

**Deliverables**:

| # | Deliverable | Details |
|---|-------------|---------|
| 5.1 | Source Registry Framework | `data-sources/registry/` with Sysmon, Azure AD, Linux auditd, AWS CloudTrail YAMLs |
| 5.2 | Data Onboarding Agent | `data_onboarding_agent.py` with schema analysis, field mapping, health scoring |
| 5.3 | Data Quality Monitoring | Daily health checks for all registered sources, alerting on degradation |
| 5.4 | Linux Simulation | Extend `simulator.py` with Linux auditd process execution, file operations, network connections |
| 5.5 | Cloud Simulation | Extend `simulator.py` with Azure AD sign-in, AWS CloudTrail API call scenarios |
| 5.6 | Network Telemetry | Extend `simulator.py` with Zeek-style connection logs, DNS queries |

**Success criteria**:
- Data Onboarding Agent can analyze a new index and generate a source registry YAML
- Health monitoring detects a simulated data source failure within 15 minutes
- Scenario Engineer produces Linux and cloud variants for at least 5 techniques
- Coverage Analyst correctly reports "T1078.004 detectable on Azure AD but not on AWS"

### Phase 6: Detection Content at Scale

**Duration**: 4-6 weeks
**Focus**: Content packs, multi-format rules, evasion testing, continuous validation
**Prerequisites**: Phase 5 (multi-platform scenarios must exist)

**Deliverables**:

| # | Deliverable | Details |
|---|-------------|---------|
| 6.1 | Content Pack Framework | Pack YAML schema, directory structure, pack-level validation |
| 6.2 | EQL Rule Authoring | Detection Author supports EQL sequence rules (multi-event correlation) |
| 6.3 | Threshold Rule Authoring | Detection Author supports count-based aggregation rules |
| 6.4 | Evasion Test Suite | Scenario Engineer produces 5+ variants per technique with evasion catalog |
| 6.5 | Continuous Validation | Weekly regression testing of all deployed rules |
| 6.6 | Performance Profiling | Validation Agent measures query cost and flags expensive rules |
| 6.7 | Migrate Existing Rules to Packs | Group 29 rules into content packs by use case |

**Success criteria**:
- At least 3 EQL sequence rules authored and validated (e.g., ransomware kill chain, lateral movement sequence, credential dumping sequence)
- At least 3 threshold rules authored and validated (e.g., brute force, MFA fatigue, port scan)
- Evasion resilience score computed for all detection packs
- Weekly regression catches at least one rule degradation in simulated test

### Phase 7: Operational Excellence

**Duration**: 4-6 weeks
**Focus**: Feedback loops, analyst integration, tuning automation, operational dashboards
**Prerequisites**: Phase 6 (content packs and continuous validation must exist)

**Deliverables**:

| # | Deliverable | Details |
|---|-------------|---------|
| 7.1 | Analyst Feedback Pipeline | Ingest TP/FP markings from SIEM, store in state DB, route to Tuning Agent |
| 7.2 | Automated Tuning PRs | Tuning Agent generates exclusion PRs with before/after metrics |
| 7.3 | Rule Retirement Process | Automated identification of stale/noisy rules, retirement recommendations |
| 7.4 | SLA Tracking | Time-to-detect metrics per priority level (P0: 4h, P1: 24h, P2: 1w) |
| 7.5 | Health Dashboard Data | Pipeline throughput, coverage trends, agent health, alert volume per rule |
| 7.6 | Canary Deployment | Staged rollout for new rules (canary -> pilot -> full) |

**Success criteria**:
- Analyst FP markings result in automated exclusion PRs within 24 hours
- At least one rule retired through the automated process
- SLA compliance tracked and reported for all priority levels
- Canary deployment tested for at least 3 new rules

### Phase 8: Advanced Capabilities

**Duration**: Ongoing
**Focus**: Research-grade capabilities, ecosystem integration, behavioral analytics
**Prerequisites**: Phases 4-7 (mature platform required)

**Deliverables**:

| # | Deliverable | Details |
|---|-------------|---------|
| 8.1 | Agent SDK | Pluggable agent framework — community can write custom agents |
| 8.2 | Live C2 Testing | Deploy Fawkes in isolated lab, validate detections against real C2 traffic |
| 8.3 | ML Anomaly Baselines | Statistical anomaly detection for process behavior, network patterns |
| 8.4 | SOAR Integration | Auto-response playbooks triggered by high-confidence detections |
| 8.5 | Detection Marketplace | Share and consume detection packs across teams/organizations |
| 8.6 | Multi-Tenant Support | Manage detections across multiple SIEM instances / environments |

**Success criteria**: Phase 8 is research-grade. Success is defined per deliverable, not as a phase gate.

---

## Design Constraints

These constraints apply across all phases and cannot be violated without explicit team agreement.

### 1. Backward Compatibility

All 29 existing detection rules must continue to work throughout the migration. No rule can be broken by architecture changes. The existing CI pipeline must pass at every commit.

**Enforcement**: Integration test suite replays all 29 rules through the new architecture before any PR is merged.

### 2. Incremental Migration

No big-bang cutovers. Every change is incremental and reversible.

- YAML to SQLite: dual-write period with validation
- Blue Team agent split: new agents coexist with old agent during transition
- Content pack migration: rules can exist in `standalone/` indefinitely
- Threat model registry: Fawkes-specific code removed only after registry is validated

### 3. Lab-First

Everything must work in the Docker lab (`docker-compose.yml`) before any production claims are made. No capability is "designed for production" unless it has been tested locally.

**Enforcement**: `make test` runs the full pipeline in Docker. CI runs the same tests.

### 4. Budget-Aware

LLM token costs are real. Agent parallelism is constrained by budget.

- Coordinator tracks token usage per agent per day
- P0 emergency tasks get reserved budget (10% of daily allocation)
- Agents that exceed budget are paused until the next cycle
- Batch operations (validate 10 rules in one search) are preferred over individual calls

### 5. Human-in-the-Loop

Deployment of detection rules to any SIEM always requires human PR review. No agent can autonomously push rules to production.

**Enforcement**: Deployment Agent reads from state DB and only deploys rules that have:
1. A merged PR (verified via GitHub API)
2. Status = VALIDATED with F1 >= 0.75
3. Security Gate approval

### 6. Git-Native

All configuration is code. All changes go through PRs. No out-of-band modifications.

- Threat models: YAML in `threat-intel/models/`
- Source registry: YAML in `data-sources/registry/`
- Detection rules: Sigma YAML in `detections/`
- Pack definitions: YAML in `detections/packs/`
- Agent configuration: YAML in `autonomous/orchestration/config.yml`
- State DB (SQLite): file in `autonomous/detection-state.db` (tracked via migrations, not binary commits)

### 7. No Secrets in Code

Credentials live in environment variables or `autonomous/orchestration/config.yml` (which is `.gitignore`d in production). The Security Gate agent blocks any PR that introduces credentials, API keys, or tokens.

---

## Open Questions

These questions need team input before implementation begins:

1. **SQLite vs PostgreSQL**: SQLite works for single-machine lab and CI. If we need multi-machine agents (e.g., agents running on different servers), PostgreSQL may be needed. Decision point: Phase 4 start.

2. **Agent communication protocol**: Agents currently communicate through shared filesystem (YAML files). With the Coordinator, should they use a message queue (Redis, RabbitMQ) or keep using filesystem + polling? Decision point: Phase 4 coordinator design.

3. **SIEM API rate limits**: Elasticsearch and Splunk have API rate limits. How do we handle them when validating 300+ rules? Batching strategy needs definition. Decision point: Phase 6 continuous validation design.

4. **Analyst feedback ingestion**: How do analysts mark alerts in the SIEM? Elastic has alert status fields, Splunk has notable event status. Need to define the extraction mechanism per SIEM. Decision point: Phase 7 feedback pipeline design.

5. **Content pack granularity**: How granular should packs be? Per-technique (many small packs) vs per-use-case (fewer large packs) vs per-threat-actor? Decision point: Phase 6 pack framework design.

6. **Multi-tenant scope**: Is multi-tenant a real requirement or theoretical? If real, it changes the state DB design significantly (tenant isolation, per-tenant config). Decision point: Phase 8 scoping.

---

## Appendix A: Migration Checklist for Existing 29 Rules

When Phase 4 begins, each existing rule needs:

- [ ] Entry in SQLite `detection_rules` table
- [ ] Existing test cases migrated to `test_cases` table
- [ ] Deployment records migrated to `deployments` table
- [ ] State transition history migrated to `state_transitions` table
- [ ] Threat actor tags added (most will get `["fawkes"]`)
- [ ] Platform tags added (all will get `["windows"]`)
- [ ] Data source requirements documented
- [ ] Pack assignment (or explicit `standalone/` placement)
- [ ] Performance profile added (can be estimated initially)

## Appendix B: Agent Comparison — Current vs Redesigned

| Current Agent | Responsibility | Redesigned Agent(s) | Change |
|--------------|----------------|---------------------|--------|
| Intel | Single-source intel, Fawkes-centric | Intel Agent (multi-model) | Refactored |
| Red Team | Single-variant scenarios | Scenario Engineer (multi-variant, multi-platform) | Refactored |
| Blue Team | Author + validate + deploy | Author + Validation + Deployment (3 agents) | Split |
| Quality | Health reports | Tuning Agent (active tuning) + Coverage Analyst (gap analysis) | Split + enhanced |
| Security | PR gate | Security Gate (enhanced compliance + conflict detection) | Enhanced |
| — | — | Data Onboarding Agent | New |
| — | — | Coordinator | New |

**Total**: 5 agents -> 10 agents. Net new: 5 (Data Onboarding, Coverage Analyst, Validation, Deployment, Coordinator).

## Appendix C: File Locations for New Components

```
threat-intel/
  models/                           # NEW — Threat Model Registry
    fawkes.yml
    scattered_spider.yml
    lockbit.yml
    generic_rat.yml

data-sources/
  registry/                         # NEW — Source Registry
    sysmon.yml
    azure_ad_sign_in.yml
    linux_auditd.yml
    aws_cloudtrail.yml

autonomous/
  orchestration/
    agents/
      data_onboarding_agent.py      # NEW
      coverage_agent.py             # NEW
      scenario_agent.py             # RENAMED from red_team_agent.py
      author_agent.py               # RENAMED from blue_team_agent.py (authoring only)
      validation_agent.py           # NEW (extracted from blue_team_agent.py)
      deployment_agent.py           # NEW (extracted from blue_team_agent.py)
      tuning_agent.py               # RENAMED from quality_agent.py (enhanced)
      security_agent.py             # EXISTING (enhanced)
      intel_agent.py                # EXISTING (refactored)
    coordinator.py                  # NEW
    state_v2.py                     # NEW — SQLite-backed StateManager
    state.py                        # EXISTING — kept during dual-write period

detections/
  packs/                            # NEW — Content Pack structure
    process-injection/
    ransomware-behavior/
    identity-compromise/
  standalone/                       # NEW — rules not yet in packs
  retired/                          # NEW — deprecated rules
```
