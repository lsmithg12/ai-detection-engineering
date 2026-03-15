# Phase 4: Scalable Architecture Foundation

**Status**: NOT STARTED
**Priority**: HIGH
**Estimated effort**: 16-24 hours (multi-session)
**Dependencies**: Phase 3 (Cribl streaming validation) -- COMPLETED
**Branch**: `infra/phase4-scalable-architecture` (primary), sub-branches for parallel work
**Replaces**: `plans/phase4-agent-upgrades.md` (old scope folded into Tasks 4.4-4.5)

---

## Goal

Transform the detection engineering platform from a single-threat-actor lab into a scalable,
multi-threat, multi-platform architecture that mirrors real-world detection engineering operations.

## Why This Matters

Detection engineering at scale is fundamentally different from writing rules for one C2 agent.
Real teams handle:

- **5-20 active threat models simultaneously** -- not just Fawkes
- **50+ log sources with different schemas** -- Windows, Linux, cloud, network
- **200+ detection rules across all platforms** -- organized, versioned, tested
- **Continuous log source onboarding** -- new sources added weekly as infrastructure grows
- **Schema drift** -- vendors change field names, types, and formats across updates
- **Detection lifecycle management** -- version, tune, retire, replace

Today, everything is hardcoded around Fawkes C2:

| Component | Current (Fawkes-only) | Target (Multi-threat) |
|---|---|---|
| Intel agent | Reads only `threat-intel/fawkes/fawkes-ttp-mapping.md` | Loads all models from `threat-intel/models/*.yml` |
| Detection requests | `fawkes_overlap` field is hardcoded | `threat_actors: [fawkes, lockbit, ...]` array |
| Coverage matrix | Hand-maintained Markdown | Auto-generated from detection state + all threat models |
| Log sources | Implicit (whatever Sysmon EIDs the simulator generates) | Explicit registry with health checks |
| Blue team agent | Monolith: authors + validates + deploys | Split: author, validation, deployment agents |
| Orchestration | Flat: agent_runner dispatches by name | Coordinator routes work by priority + state |
| State machine | YAML files in `detection-requests/` | YAML (Phase 4) with SQLite schema ready (Phase 5 flip) |

## Dependencies

- Phase 3 (Cribl streaming validation) -- COMPLETED
- No external dependencies. All work is local refactoring + new files.

## Estimated Effort: 16-24 hours

| Task | Hours | Can Parallelize? |
|---|---|---|
| 4.1 Threat Model Registry | 4 | Yes (independent) |
| 4.2 Log Source Registry | 4 | Yes (independent) |
| 4.3 Coverage Analyst Agent | 3 | After 4.1 + 4.2 |
| 4.4 Refactor Agent Architecture | 4 | After 4.3 |
| 4.5 Coordinator Agent | 3 | After 4.4 |
| 4.6 State Management Foundation | 2 | Yes (independent) |
| 4.7 Update Templates and Documentation | 2 | After 4.4 + 4.5 |
| 4.8 Cross-Check: Compliance, Triage Briefs, Feedback | 2 | After 4.7 |

Suggested session breakdown:
- **Session 1** (6-8h): Tasks 4.1 + 4.2 + 4.6 (registries + schema, all independent)
- **Session 2** (6-8h): Tasks 4.3 + 4.4 (coverage agent + agent split)
- **Session 3** (4-6h): Tasks 4.5 + 4.7 (coordinator + docs)
- **Session 4** (2h): Task 4.8 (cross-check findings: compliance, triage, feedback)

---

## Task 4.1: Threat Model Registry (4h)

### Objective

Create a pluggable threat model registry at `threat-intel/models/` so the intel agent,
coverage analysis, and detection requests can reason about multiple adversaries simultaneously.

### Deliverables

| File | Description |
|---|---|
| `threat-intel/models/schema.yml` | JSON Schema defining the threat model format |
| `threat-intel/models/fawkes.yml` | Migrate existing Fawkes TTP mapping to registry format |
| `threat-intel/models/scattered-spider.yml` | Cloud/identity-focused APT (from `threat-intel/analysis/`) |
| `threat-intel/models/lockbit.yml` | Ransomware-focused threat model |
| `threat-intel/models/generic-rat.yml` | Baseline commodity RAT threat model |
| `templates/threat-model-template.yml` | Empty template for adding new threat models |

### Schema Definition (`threat-intel/models/schema.yml`)

```yaml
# Threat Model Registry Schema
# All threat model files in threat-intel/models/ MUST conform to this structure.
# Used by intel_agent.py, coverage_agent.py, and cli.py for multi-threat analysis.

version: "1.0"
description: "Schema for threat model definitions"

required_fields:
  - name
  - type
  - platform
  - priority
  - techniques

field_definitions:
  name:
    type: string
    description: "Human-readable name of the threat model"
    examples: ["Fawkes C2 Agent", "Scattered Spider", "LockBit 3.0"]

  type:
    type: string
    enum: [c2_framework, apt_group, ransomware, commodity, insider_threat]
    description: "Category of threat actor or tooling"

  platform:
    type: list
    items: [windows, linux, macos, cloud, identity, network]
    description: "Platforms this threat operates on"

  priority:
    type: string
    enum: [critical, high, medium, low]
    description: "Organizational priority for detection coverage"

  source:
    type: string
    description: "Primary reference URL"

  last_updated:
    type: date
    description: "ISO date when this model was last reviewed"

  techniques:
    type: map
    description: "Map of MITRE ATT&CK technique IDs to technique details"
    key_pattern: "T\\d{4}(\\.\\d{3})?"
    value_fields:
      description:
        type: string
        required: true
      commands:
        type: list
        description: "Tool-specific commands (optional, for C2 frameworks)"
      artifacts:
        type: list
        items: [process_create, process_access, process_inject, create_remote_thread,
                image_load, file_write, file_create, file_delete, file_modify,
                registry_write, network_connection, logon, token_steal, dns_query,
                named_pipe, service_install, script_block, wmi_event]
      data_sources:
        type: list
        description: "Required data sources as source_id:event_type (e.g., sysmon:eid_8)"
      detection_complexity:
        type: string
        enum: [low, medium, high, expert]
        description: "How difficult it is to write a reliable detection"
      priority_override:
        type: string
        enum: [critical, high, medium, low]
        description: "Per-technique priority (overrides model default if set)"
```

### Fawkes Threat Model (`threat-intel/models/fawkes.yml`)

Migrate the existing `threat-intel/fawkes/fawkes-ttp-mapping.md` into structured YAML.
The original Markdown file stays as a human-readable reference; the YAML file becomes
the machine-readable source of truth.

```yaml
name: "Fawkes C2 Agent"
type: c2_framework
platform: [windows, linux, macos]
priority: critical
source: "https://github.com/galoryber/fawkes"
last_updated: "2026-03-15"
version: "latest"
description: >
  Golang-based Mythic C2 agent with 59 commands spanning the full ATT&CK kill chain.
  Primary adversary for this detection engineering lab.

techniques:
  T1055.001:
    description: "CreateRemoteThread Process Injection"
    commands: [vanilla-injection]
    artifacts: [process_access, create_remote_thread]
    data_sources: ["sysmon:eid_8", "sysmon:eid_10"]
    detection_complexity: medium

  T1055.004:
    description: "Asynchronous Procedure Call (APC) Injection"
    commands: [apc-injection]
    artifacts: [process_access]
    data_sources: ["sysmon:eid_10"]
    detection_complexity: high

  T1055.012:
    description: "Threadless Process Injection"
    commands: [threadless-inject]
    artifacts: [image_load]
    data_sources: ["sysmon:eid_7", "etw:microsoft-windows-threat-intelligence"]
    detection_complexity: expert

  T1055.013:
    description: "Opus Injection (KernelCallbackTable)"
    commands: [opus-injection]
    artifacts: [process_access]
    data_sources: ["etw:microsoft-windows-threat-intelligence"]
    detection_complexity: expert

  T1055.015:
    description: "PoolParty Injection (Thread Pool Variants)"
    commands: [poolparty-injection]
    artifacts: [process_access]
    data_sources: ["etw:microsoft-windows-threat-intelligence"]
    detection_complexity: expert

  T1059.001:
    description: "PowerShell Execution with Bypass Flags"
    commands: [powershell]
    artifacts: [process_create, script_block]
    data_sources: ["sysmon:eid_1", "windows_security:eid_4104"]
    detection_complexity: low

  T1059.003:
    description: "Windows Command Shell Execution"
    commands: [run, shell, spawn, inline-execute]
    artifacts: [process_create]
    data_sources: ["sysmon:eid_1"]
    detection_complexity: low

  T1047:
    description: "WMI Execution"
    commands: [wmi]
    artifacts: [process_create, wmi_event]
    data_sources: ["sysmon:eid_1", "sysmon:eid_19", "sysmon:eid_20", "sysmon:eid_21"]
    detection_complexity: medium

  T1053.005:
    description: "Scheduled Task Persistence"
    commands: [schtask]
    artifacts: [process_create]
    data_sources: ["sysmon:eid_1"]
    detection_complexity: low

  T1547.001:
    description: "Registry Run Key Persistence"
    commands: ["persist -method registry"]
    artifacts: [registry_write]
    data_sources: ["sysmon:eid_13"]
    detection_complexity: low

  T1543.003:
    description: "Windows Service Persistence"
    commands: ["service -action create"]
    artifacts: [service_install, process_create]
    data_sources: ["windows_system:eid_7045", "sysmon:eid_1"]
    detection_complexity: low

  T1562.001:
    description: "AMSI/ETW Patching"
    commands: [autopatch, start-clr]
    artifacts: [image_load]
    data_sources: ["sysmon:eid_7"]
    detection_complexity: medium

  T1134.001:
    description: "Token Impersonation/Theft"
    commands: [steal-token]
    artifacts: [process_access, token_steal]
    data_sources: ["sysmon:eid_10"]
    detection_complexity: medium

  T1134.003:
    description: "Make and Impersonate Token"
    commands: [make-token]
    artifacts: [logon]
    data_sources: ["windows_security:eid_4624"]
    detection_complexity: medium

  T1056.001:
    description: "Keylogging via Low-Level Hook"
    commands: [keylog]
    artifacts: []
    data_sources: ["elastic_endpoint:api_hook"]
    detection_complexity: high

  T1070.006:
    description: "Timestomping"
    commands: [timestomp]
    artifacts: [file_modify]
    data_sources: ["sysmon:eid_2"]
    detection_complexity: medium

  T1071.001:
    description: "HTTP/HTTPS C2 Beaconing"
    commands: [sleep]
    artifacts: [network_connection]
    data_sources: ["sysmon:eid_3", "sysmon:eid_22"]
    detection_complexity: medium

  T1090.001:
    description: "SOCKS5 Proxy for Lateral Movement"
    commands: [socks5]
    artifacts: [network_connection]
    data_sources: ["sysmon:eid_3", "network:zeek_conn"]
    detection_complexity: high

  T1115:
    description: "Clipboard Data Collection"
    commands: [clipboard]
    artifacts: []
    data_sources: ["elastic_endpoint:api_hook"]
    detection_complexity: high

  T1113:
    description: "Screen Capture"
    commands: [screenshot]
    artifacts: []
    data_sources: ["elastic_endpoint:api_hook"]
    detection_complexity: high

  T1027.001:
    description: "Binary Padding/Inflation"
    commands: [binary-inflate]
    artifacts: [file_write]
    data_sources: ["sysmon:eid_11"]
    detection_complexity: medium
```

### Scattered Spider Threat Model (`threat-intel/models/scattered-spider.yml`)

Source: existing `threat-intel/analysis/2026-03-01-scattered-spider.md` plus public
CISA advisory AA23-320A and Mandiant UNC3944 reporting.

```yaml
name: "Scattered Spider (UNC3944)"
type: apt_group
platform: [windows, cloud, identity]
priority: high
source: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a"
last_updated: "2026-03-15"
description: >
  Financially motivated threat group targeting large organizations via
  social engineering, SIM swapping, MFA fatigue, and cloud/identity abuse.
  Known for ransomware deployment (ALPHV/BlackCat) and data extortion.

techniques:
  T1566.004:
    description: "Spearphishing Voice (Vishing)"
    commands: []
    artifacts: []
    data_sources: ["identity:okta_logs", "identity:azure_ad_signin"]
    detection_complexity: high
    priority_override: critical

  T1078.004:
    description: "Cloud Account Abuse (Compromised Credentials)"
    commands: []
    artifacts: [logon]
    data_sources: ["aws:cloudtrail", "identity:azure_ad_signin", "identity:okta_logs"]
    detection_complexity: medium

  T1621:
    description: "MFA Request Generation (MFA Fatigue/Bombing)"
    commands: []
    artifacts: []
    data_sources: ["identity:okta_logs", "identity:azure_ad_mfa"]
    detection_complexity: medium
    priority_override: high

  T1059.001:
    description: "PowerShell for Reconnaissance and Tool Deployment"
    commands: []
    artifacts: [process_create, script_block]
    data_sources: ["sysmon:eid_1", "windows_security:eid_4104"]
    detection_complexity: low

  T1219:
    description: "Remote Access Software (AnyDesk, ScreenConnect, Splashtop)"
    commands: []
    artifacts: [process_create, network_connection]
    data_sources: ["sysmon:eid_1", "sysmon:eid_3"]
    detection_complexity: low

  T1003.001:
    description: "LSASS Credential Dumping"
    commands: []
    artifacts: [process_access]
    data_sources: ["sysmon:eid_10"]
    detection_complexity: medium

  T1484.002:
    description: "Domain Trust Modification"
    commands: []
    artifacts: []
    data_sources: ["identity:azure_ad_audit", "windows_security:eid_4706"]
    detection_complexity: high

  T1098:
    description: "Account Manipulation (Privilege Escalation in Cloud)"
    commands: []
    artifacts: []
    data_sources: ["aws:cloudtrail", "identity:azure_ad_audit"]
    detection_complexity: medium

  T1486:
    description: "Data Encrypted for Impact (ALPHV/BlackCat Ransomware)"
    commands: []
    artifacts: [file_write, process_create]
    data_sources: ["sysmon:eid_1", "sysmon:eid_11"]
    detection_complexity: medium

  T1567.002:
    description: "Exfiltration to Cloud Storage"
    commands: []
    artifacts: [network_connection]
    data_sources: ["sysmon:eid_3", "network:proxy_logs"]
    detection_complexity: high
```

### LockBit Threat Model (`threat-intel/models/lockbit.yml`)

```yaml
name: "LockBit 3.0 (Black)"
type: ransomware
platform: [windows, linux]
priority: high
source: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a"
last_updated: "2026-03-15"
description: >
  Ransomware-as-a-Service (RaaS) operation. Most prolific ransomware group
  by victim count. Affiliates use diverse initial access methods.
  LockBit 3.0 (Black) variant includes anti-analysis, self-propagation,
  and ESXi targeting.

techniques:
  T1190:
    description: "Exploit Public-Facing Application (common affiliate entry)"
    commands: []
    artifacts: [process_create, network_connection]
    data_sources: ["sysmon:eid_1", "sysmon:eid_3", "network:zeek_conn"]
    detection_complexity: medium

  T1133:
    description: "External Remote Services (RDP/VPN with stolen creds)"
    commands: []
    artifacts: [logon, network_connection]
    data_sources: ["windows_security:eid_4624", "sysmon:eid_3"]
    detection_complexity: medium

  T1059.001:
    description: "PowerShell for Cobalt Strike Beacon Deployment"
    commands: []
    artifacts: [process_create, script_block]
    data_sources: ["sysmon:eid_1", "windows_security:eid_4104"]
    detection_complexity: low

  T1059.003:
    description: "cmd.exe for Batch Script Execution"
    commands: []
    artifacts: [process_create]
    data_sources: ["sysmon:eid_1"]
    detection_complexity: low

  T1047:
    description: "WMI for Lateral Execution"
    commands: []
    artifacts: [process_create]
    data_sources: ["sysmon:eid_1"]
    detection_complexity: medium

  T1053.005:
    description: "Scheduled Task for Persistence and Execution"
    commands: []
    artifacts: [process_create]
    data_sources: ["sysmon:eid_1"]
    detection_complexity: low

  T1070.001:
    description: "Clear Windows Event Logs"
    commands: []
    artifacts: [process_create]
    data_sources: ["sysmon:eid_1"]
    detection_complexity: low

  T1490:
    description: "Inhibit System Recovery (vssadmin, bcdedit, wbadmin)"
    commands: []
    artifacts: [process_create]
    data_sources: ["sysmon:eid_1"]
    detection_complexity: low

  T1486:
    description: "Data Encrypted for Impact (LockBit 3.0 encryptor)"
    commands: []
    artifacts: [file_write, process_create]
    data_sources: ["sysmon:eid_1", "sysmon:eid_11"]
    detection_complexity: medium

  T1027:
    description: "Obfuscated Files (packed/encrypted payloads)"
    commands: []
    artifacts: [file_write, process_create]
    data_sources: ["sysmon:eid_1", "sysmon:eid_11"]
    detection_complexity: medium

  T1562.001:
    description: "Disable or Modify Tools (kill AV/EDR processes)"
    commands: []
    artifacts: [process_create]
    data_sources: ["sysmon:eid_1"]
    detection_complexity: medium

  T1021.002:
    description: "SMB/Windows Admin Shares for Lateral Movement"
    commands: []
    artifacts: [logon, network_connection]
    data_sources: ["windows_security:eid_4624", "sysmon:eid_3"]
    detection_complexity: medium
```

### Generic RAT Threat Model (`threat-intel/models/generic-rat.yml`)

```yaml
name: "Generic Remote Access Trojan"
type: commodity
platform: [windows]
priority: medium
source: "https://attack.mitre.org/software/"
last_updated: "2026-03-15"
description: >
  Baseline commodity RAT capabilities shared across most remote access trojans
  (AsyncRAT, QuasarRAT, njRAT, DarkComet, etc.). Represents the minimum
  detection coverage needed against commodity threats.

techniques:
  T1059.001:
    description: "PowerShell Downloader/Stager"
    commands: []
    artifacts: [process_create, script_block, network_connection]
    data_sources: ["sysmon:eid_1", "sysmon:eid_3", "windows_security:eid_4104"]
    detection_complexity: low

  T1059.003:
    description: "cmd.exe Execution"
    commands: []
    artifacts: [process_create]
    data_sources: ["sysmon:eid_1"]
    detection_complexity: low

  T1547.001:
    description: "Registry Run Key Persistence"
    commands: []
    artifacts: [registry_write]
    data_sources: ["sysmon:eid_13"]
    detection_complexity: low

  T1053.005:
    description: "Scheduled Task Persistence"
    commands: []
    artifacts: [process_create]
    data_sources: ["sysmon:eid_1"]
    detection_complexity: low

  T1082:
    description: "System Information Discovery"
    commands: []
    artifacts: [process_create]
    data_sources: ["sysmon:eid_1"]
    detection_complexity: low

  T1071.001:
    description: "HTTP/HTTPS C2 Communication"
    commands: []
    artifacts: [network_connection, dns_query]
    data_sources: ["sysmon:eid_3", "sysmon:eid_22"]
    detection_complexity: medium

  T1105:
    description: "Ingress Tool Transfer"
    commands: []
    artifacts: [network_connection, file_write]
    data_sources: ["sysmon:eid_3", "sysmon:eid_11"]
    detection_complexity: medium

  T1056.001:
    description: "Keylogging"
    commands: []
    artifacts: []
    data_sources: ["elastic_endpoint:api_hook"]
    detection_complexity: high

  T1113:
    description: "Screen Capture"
    commands: []
    artifacts: []
    data_sources: ["elastic_endpoint:api_hook"]
    detection_complexity: high

  T1115:
    description: "Clipboard Data Collection"
    commands: []
    artifacts: []
    data_sources: ["elastic_endpoint:api_hook"]
    detection_complexity: high

  T1204.002:
    description: "Malicious File Execution (User Execution)"
    commands: []
    artifacts: [process_create, file_write]
    data_sources: ["sysmon:eid_1", "sysmon:eid_11"]
    detection_complexity: low
```

### Refactor Intel Agent (`autonomous/orchestration/agents/intel_agent.py`)

Current code loads only the Fawkes TTP mapping:

```python
# Current (line 31-32)
FAWKES_TTP_PATH = REPO_ROOT / "threat-intel" / "fawkes" / "fawkes-ttp-mapping.md"
```

Refactor to:

```python
# New: load all threat models from registry
MODELS_DIR = REPO_ROOT / "threat-intel" / "models"

def load_threat_models() -> list[dict]:
    """Load all threat model YAML files from the registry."""
    models = []
    if not MODELS_DIR.exists():
        return models
    for model_file in sorted(MODELS_DIR.glob("*.yml")):
        if model_file.name == "schema.yml":
            continue
        with open(model_file) as f:
            model = yaml.safe_load(f)
        if model and "techniques" in model:
            model["_file"] = str(model_file)
            models.append(model)
    return models

def get_threat_actors_for_technique(technique_id: str, models: list[dict]) -> list[str]:
    """Return list of threat model names that use a given technique."""
    actors = []
    for model in models:
        if technique_id in model.get("techniques", {}):
            actors.append(model["name"])
    return actors

def calculate_priority_score(technique_id: str, models: list[dict],
                             existing_detections: set[str],
                             available_sources: set[str]) -> tuple[float, str]:
    """
    Multi-signal priority scoring.

    Returns (score, priority_label).

    Formula:
      priority_score = (
        threat_relevance * 3   # How many threat models reference this technique
        + data_available * 2   # Do we have the required log sources?
        + no_detection * 2     # Is there currently no detection for this?
        + technique_severity * 1  # Average detection complexity across models
      ) / 8
    """
    threat_relevance = min(len(get_threat_actors_for_technique(technique_id, models)) / 4.0, 1.0)
    has_detection = technique_id in existing_detections
    no_detection = 0.0 if has_detection else 1.0

    # Check data availability across all models that reference this technique
    required_sources = set()
    complexities = []
    for model in models:
        tech = model.get("techniques", {}).get(technique_id)
        if tech:
            for ds in tech.get("data_sources", []):
                required_sources.add(ds.split(":")[0])  # source_id only
            complexity_map = {"low": 0.25, "medium": 0.5, "high": 0.75, "expert": 1.0}
            complexities.append(complexity_map.get(tech.get("detection_complexity", "medium"), 0.5))

    data_available = 1.0 if required_sources and required_sources.issubset(available_sources) else 0.0
    technique_severity = 1.0 - (sum(complexities) / len(complexities) if complexities else 0.5)

    score = (threat_relevance * 3 + data_available * 2 + no_detection * 2 + technique_severity * 1) / 8.0

    if score >= 0.875:
        label = "critical"
    elif score >= 0.625:
        label = "high"
    elif score >= 0.375:
        label = "medium"
    else:
        label = "low"

    return (score, label)
```

Detection request creation must include `threat_actors` field:

```python
# When creating a detection request, populate threat_actors from all matching models
request["threat_actors"] = get_threat_actors_for_technique(technique_id, all_models)
request["priority"] = calculate_priority_score(technique_id, all_models, ...)[1]
```

**Source diversity tracking** (from old Phase 4 Task 1B -- carry forward):

Add source rotation to the intel agent. After each query, update `threat-intel/source-tracker.yml`:

```yaml
sources:
  dfir_report:
    last_queried: "2026-03-15"
    reports_found: 4
    techniques_discovered: 17
  cisa:
    last_queried: "2026-03-06"
    reports_found: 1
    techniques_discovered: 4
  mandiant:
    last_queried: null
    reports_found: 0
```

The intel agent should query the least-recently-queried source first each run.

---

## Task 4.2: Log Source Registry (4h)

### Objective

Create a structured log source registry at `data-sources/registry/` that tracks
what data we have, its health, schema, and detection value. This replaces the
implicit "whatever Sysmon EIDs the simulator happens to generate" model.

### Deliverables

| File | Description |
|---|---|
| `data-sources/registry/schema.yml` | JSON Schema for source definitions |
| `data-sources/registry/sysmon.yml` | Full Sysmon source (all supported EIDs) |
| `data-sources/registry/windows-security.yml` | Windows Security events |
| `data-sources/registry/powershell.yml` | PowerShell ScriptBlock logging |
| `data-sources/registry/linux-auditd.yml` | Linux audit log (NEW platform) |
| `data-sources/registry/aws-cloudtrail.yml` | AWS CloudTrail (NEW platform) |
| `data-sources/registry/network-zeek.yml` | Zeek network monitor (NEW platform) |
| `templates/source-registry-template.yml` | Empty template for adding new sources |

### Schema Definition (`data-sources/registry/schema.yml`)

```yaml
# Log Source Registry Schema
# All source definition files in data-sources/registry/ MUST conform to this structure.
# Used by coverage_agent.py, validation.py, and quality_agent.py for source health checks.

version: "1.0"
description: "Schema for log source definitions"

required_fields:
  - source_id
  - vendor
  - product
  - platform
  - event_types

field_definitions:
  source_id:
    type: string
    description: "Unique identifier, matches data_sources references in threat models"
    examples: ["sysmon", "windows_security", "aws_cloudtrail"]
    pattern: "[a-z][a-z0-9_]+"

  vendor:
    type: string
    description: "Vendor or project name"

  product:
    type: string
    description: "Product name"

  version:
    type: string
    description: "Minimum version for listed capabilities"

  platform:
    type: string
    enum: [windows, linux, macos, cloud, network, identity]

  transport:
    type: list
    items: [wef, syslog, cribl_forwarder, hec, s3, api_poll, filebeat, winlogbeat]
    description: "How events get to the SIEM"

  normalization:
    type: string
    enum: [ecs, cim, raw, custom]
    description: "Schema normalization standard"

  status:
    type: string
    enum: [active, planned, degraded, retired]
    description: "Current operational status in the lab"

  event_types:
    type: map
    description: "Map of event type IDs to their definitions"
    value_fields:
      description:
        type: string
        required: true
      ecs_category:
        type: string
        description: "ECS event.category value"
      ecs_type:
        type: string
        description: "ECS event.type value"
      fields:
        type: list
        description: "Field mappings from raw to normalized"
        items:
          raw: string
          ecs: string
          type: [keyword, text, ip, long, date, boolean, nested]
      detection_value:
        type: string
        enum: [critical, high, medium, low, informational]
      volume_estimate:
        type: string
        description: "Rough events per host per day"

  health_check:
    type: map
    fields:
      method:
        type: string
        enum: [query_latest_event, index_exists, api_check]
      query:
        type: string
        description: "ES query to find latest event for this source"
      stale_threshold:
        type: string
        description: "Duration after which source is considered stale"
        examples: ["15m", "1h", "24h"]
```

### Sysmon Source Definition (`data-sources/registry/sysmon.yml`)

```yaml
source_id: sysmon
vendor: Microsoft
product: Sysmon
version: "15.0"
platform: windows
transport: [wef, winlogbeat, cribl_forwarder]
normalization: ecs
status: active
description: >
  System Monitor (Sysmon) provides detailed information about process creations,
  network connections, file changes, registry modifications, and more. Primary
  endpoint telemetry source for Windows detection engineering.

event_types:
  eid_1:
    description: "Process Creation"
    ecs_category: process
    ecs_type: start
    fields:
      - { raw: Image, ecs: process.executable, type: keyword }
      - { raw: CommandLine, ecs: process.command_line, type: keyword }
      - { raw: ParentImage, ecs: process.parent.executable, type: keyword }
      - { raw: ParentCommandLine, ecs: process.parent.command_line, type: keyword }
      - { raw: User, ecs: user.name, type: keyword }
      - { raw: ProcessId, ecs: process.pid, type: long }
      - { raw: ParentProcessId, ecs: process.parent.pid, type: long }
      - { raw: Hashes, ecs: process.hash.sha256, type: keyword }
      - { raw: OriginalFileName, ecs: process.pe.original_file_name, type: keyword }
      - { raw: IntegrityLevel, ecs: winlog.event_data.IntegrityLevel, type: keyword }
    detection_value: critical
    volume_estimate: "500/host/day"

  eid_2:
    description: "File Creation Time Changed"
    ecs_category: file
    ecs_type: change
    fields:
      - { raw: Image, ecs: process.executable, type: keyword }
      - { raw: TargetFilename, ecs: file.path, type: keyword }
      - { raw: CreationUtcTime, ecs: file.created, type: date }
      - { raw: PreviousCreationUtcTime, ecs: file.mtime, type: date }
    detection_value: high
    volume_estimate: "10/host/day"

  eid_3:
    description: "Network Connection"
    ecs_category: network
    ecs_type: connection
    fields:
      - { raw: Image, ecs: process.executable, type: keyword }
      - { raw: DestinationIp, ecs: destination.ip, type: ip }
      - { raw: DestinationPort, ecs: destination.port, type: long }
      - { raw: SourceIp, ecs: source.ip, type: ip }
      - { raw: SourcePort, ecs: source.port, type: long }
      - { raw: Protocol, ecs: network.transport, type: keyword }
    detection_value: high
    volume_estimate: "2000/host/day"

  eid_7:
    description: "Image Loaded"
    ecs_category: library
    ecs_type: start
    fields:
      - { raw: Image, ecs: process.executable, type: keyword }
      - { raw: ImageLoaded, ecs: file.name, type: keyword }
      - { raw: Hashes, ecs: file.hash.sha256, type: keyword }
      - { raw: Signed, ecs: file.code_signature.valid, type: boolean }
      - { raw: Signature, ecs: file.code_signature.subject_name, type: keyword }
    detection_value: high
    volume_estimate: "5000/host/day"

  eid_8:
    description: "CreateRemoteThread"
    ecs_category: process
    ecs_type: start
    fields:
      - { raw: SourceImage, ecs: process.executable, type: keyword }
      - { raw: TargetImage, ecs: winlog.event_data.TargetImage, type: keyword }
      - { raw: StartAddress, ecs: winlog.event_data.StartAddress, type: keyword }
      - { raw: StartModule, ecs: winlog.event_data.StartModule, type: keyword }
      - { raw: StartFunction, ecs: winlog.event_data.StartFunction, type: keyword }
    detection_value: critical
    volume_estimate: "5/host/day"

  eid_10:
    description: "Process Access"
    ecs_category: process
    ecs_type: access
    fields:
      - { raw: SourceImage, ecs: process.executable, type: keyword }
      - { raw: TargetImage, ecs: winlog.event_data.TargetImage, type: keyword }
      - { raw: GrantedAccess, ecs: winlog.event_data.GrantedAccess, type: keyword }
      - { raw: CallTrace, ecs: winlog.event_data.CallTrace, type: keyword }
    detection_value: critical
    volume_estimate: "200/host/day"

  eid_11:
    description: "File Created"
    ecs_category: file
    ecs_type: creation
    fields:
      - { raw: Image, ecs: process.executable, type: keyword }
      - { raw: TargetFilename, ecs: file.path, type: keyword }
    detection_value: medium
    volume_estimate: "1000/host/day"

  eid_13:
    description: "Registry Value Set"
    ecs_category: registry
    ecs_type: change
    fields:
      - { raw: Image, ecs: process.executable, type: keyword }
      - { raw: TargetObject, ecs: registry.path, type: keyword }
      - { raw: Details, ecs: registry.data.strings, type: keyword }
      - { raw: EventType, ecs: registry.data.type, type: keyword }
    detection_value: high
    volume_estimate: "300/host/day"

  eid_17:
    description: "Pipe Created"
    ecs_category: file
    ecs_type: creation
    fields:
      - { raw: Image, ecs: process.executable, type: keyword }
      - { raw: PipeName, ecs: file.name, type: keyword }
    detection_value: medium
    volume_estimate: "50/host/day"

  eid_18:
    description: "Pipe Connected"
    ecs_category: file
    ecs_type: access
    fields:
      - { raw: Image, ecs: process.executable, type: keyword }
      - { raw: PipeName, ecs: file.name, type: keyword }
    detection_value: medium
    volume_estimate: "50/host/day"

  eid_22:
    description: "DNS Query"
    ecs_category: network
    ecs_type: protocol
    fields:
      - { raw: Image, ecs: process.executable, type: keyword }
      - { raw: QueryName, ecs: dns.question.name, type: keyword }
      - { raw: QueryResults, ecs: dns.answers.data, type: keyword }
    detection_value: high
    volume_estimate: "500/host/day"

  eid_23:
    description: "File Delete (Archived)"
    ecs_category: file
    ecs_type: deletion
    fields:
      - { raw: Image, ecs: process.executable, type: keyword }
      - { raw: TargetFilename, ecs: file.path, type: keyword }
    detection_value: medium
    volume_estimate: "100/host/day"

  eid_25:
    description: "Process Tampering"
    ecs_category: process
    ecs_type: change
    fields:
      - { raw: Image, ecs: process.executable, type: keyword }
      - { raw: Type, ecs: winlog.event_data.Type, type: keyword }
    detection_value: critical
    volume_estimate: "1/host/day"

health_check:
  method: query_latest_event
  query: "agent.type:winlogbeat AND winlog.channel:\"Microsoft-Windows-Sysmon/Operational\""
  stale_threshold: "15m"
```

### Additional Source Definitions (Abbreviated)

**`data-sources/registry/windows-security.yml`**:
```yaml
source_id: windows_security
vendor: Microsoft
product: "Windows Security Audit"
platform: windows
transport: [wef, winlogbeat]
normalization: ecs
status: active
event_types:
  eid_4624: { description: "Successful Logon", ecs_category: authentication, ecs_type: start, detection_value: high }
  eid_4625: { description: "Failed Logon", ecs_category: authentication, ecs_type: start, detection_value: high }
  eid_4648: { description: "Explicit Credential Logon", ecs_category: authentication, detection_value: high }
  eid_4672: { description: "Special Privileges Assigned", ecs_category: iam, detection_value: medium }
  eid_4688: { description: "Process Creation (legacy)", ecs_category: process, ecs_type: start, detection_value: medium }
  eid_4706: { description: "New Trust Created", ecs_category: iam, detection_value: critical }
  eid_4720: { description: "User Account Created", ecs_category: iam, detection_value: high }
  eid_4732: { description: "Member Added to Local Group", ecs_category: iam, detection_value: high }
health_check:
  method: query_latest_event
  query: "winlog.channel:Security"
  stale_threshold: "15m"
```

**`data-sources/registry/powershell.yml`**:
```yaml
source_id: powershell
vendor: Microsoft
product: "PowerShell"
platform: windows
transport: [wef, winlogbeat]
normalization: ecs
status: active
event_types:
  eid_4104: { description: "ScriptBlock Logging", ecs_category: process, detection_value: critical }
  eid_4103: { description: "Module Logging", ecs_category: process, detection_value: medium }
health_check:
  method: query_latest_event
  query: "winlog.channel:\"Microsoft-Windows-PowerShell/Operational\" AND event.code:4104"
  stale_threshold: "1h"
```

**`data-sources/registry/linux-auditd.yml`**:
```yaml
source_id: linux_auditd
vendor: Linux
product: "auditd"
platform: linux
transport: [syslog, filebeat, cribl_forwarder]
normalization: ecs
status: planned  # Not yet in lab -- NEW platform
event_types:
  execve: { description: "Process Execution", ecs_category: process, ecs_type: start, detection_value: critical }
  connect: { description: "Network Connection", ecs_category: network, ecs_type: connection, detection_value: high }
  open: { description: "File Open", ecs_category: file, ecs_type: access, detection_value: medium }
  user_auth: { description: "User Authentication", ecs_category: authentication, detection_value: high }
  anom_promiscuous: { description: "Promiscuous Mode", ecs_category: network, detection_value: high }
health_check:
  method: query_latest_event
  query: "event.module:auditd"
  stale_threshold: "15m"
```

**`data-sources/registry/aws-cloudtrail.yml`**:
```yaml
source_id: aws_cloudtrail
vendor: Amazon Web Services
product: "CloudTrail"
platform: cloud
transport: [s3, api_poll, filebeat]
normalization: ecs
status: planned  # Not yet in lab -- NEW platform
event_types:
  console_login: { description: "AWS Console Sign-In", ecs_category: authentication, detection_value: high }
  assume_role: { description: "STS AssumeRole", ecs_category: iam, detection_value: high }
  create_user: { description: "IAM CreateUser", ecs_category: iam, detection_value: critical }
  run_instances: { description: "EC2 RunInstances", ecs_category: host, detection_value: medium }
  put_bucket_policy: { description: "S3 PutBucketPolicy", ecs_category: configuration, detection_value: high }
  stop_logging: { description: "CloudTrail StopLogging", ecs_category: configuration, detection_value: critical }
health_check:
  method: query_latest_event
  query: "event.module:aws AND event.dataset:aws.cloudtrail"
  stale_threshold: "24h"
```

**`data-sources/registry/network-zeek.yml`**:
```yaml
source_id: network_zeek
vendor: "Zeek Project"
product: "Zeek (Bro)"
platform: network
transport: [syslog, filebeat, cribl_forwarder]
normalization: ecs
status: planned  # Not yet in lab -- NEW platform
event_types:
  conn: { description: "Connection Log", ecs_category: network, ecs_type: connection, detection_value: high }
  dns: { description: "DNS Queries", ecs_category: network, ecs_type: protocol, detection_value: high }
  http: { description: "HTTP Requests", ecs_category: network, ecs_type: protocol, detection_value: high }
  ssl: { description: "TLS/SSL Sessions", ecs_category: network, ecs_type: protocol, detection_value: high }
  files: { description: "File Transfer Metadata", ecs_category: file, detection_value: medium }
  notice: { description: "Zeek Notices/Alerts", ecs_category: intrusion_detection, detection_value: critical }
health_check:
  method: query_latest_event
  query: "event.module:zeek"
  stale_threshold: "15m"
```

### Source Health Check Integration

Add to `autonomous/orchestration/validation.py`:

```python
def check_source_health(source_def: dict, es_url: str = None, auth: tuple = None) -> dict:
    """
    Check the health of a registered log source against Elasticsearch.

    Returns:
      {
        "source_id": "sysmon",
        "status": "healthy" | "stale" | "missing" | "degraded" | "unreachable",
        "latest_event": "2026-03-15T10:30:00Z" | null,
        "event_count_24h": 1234,
        "missing_fields": ["process.hash.sha256"],
        "checked_at": "2026-03-15T12:00:00Z"
      }
    """
    # Implementation:
    # 1. Run health_check.query against ES
    # 2. Check latest event timestamp against stale_threshold
    # 3. Sample 10 events, check which defined fields are present
    # 4. Return structured health report
```

---

## Task 4.3: Coverage Analyst Agent (3h)

### Objective

Create a new agent that auto-generates coverage analysis from detection state + all threat
models. This replaces the manually-maintained `coverage/attack-matrix.md`.

### Deliverables

| File | Description |
|---|---|
| `autonomous/orchestration/agents/coverage_agent.py` | New agent |
| `coverage/attack-matrix.md` | Now auto-generated (no manual edits) |
| `coverage/gap-report.md` | Prioritized detection backlog |
| `coverage/navigator.json` | ATT&CK Navigator layer (JSON import) |

### Coverage Agent Design

```python
"""
Coverage Analyst Agent -- Generates multi-dimensional coverage analysis.

Reads:
  - threat-intel/models/*.yml    (all threat models)
  - data-sources/registry/*.yml  (all log source definitions)
  - autonomous/detection-requests/*.yml  (detection state)
  - detections/**/*.yml           (authored Sigma rules)
  - tests/results/*.json          (validation F1 scores)

Produces:
  - coverage/attack-matrix.md     (auto-generated)
  - coverage/gap-report.md        (prioritized backlog)
  - coverage/navigator.json       (ATT&CK Navigator layer)

Trigger: daily (after quality agent), or on-demand via cli.py coverage
"""
```

### Coverage Scoring Algorithm

```python
def calculate_gap_priority(technique_id: str, models: list[dict],
                           detections: dict, sources: dict) -> float:
    """
    Weighted priority score for detection gaps.

    Inputs:
      - models: loaded threat models
      - detections: {technique_id: {status, f1, tier}}
      - sources: {source_id: {status, health}}

    Returns float 0.0-1.0, higher = more urgent.
    """
    # threat_relevance: How many threat models reference this technique (0-1)
    actors = [m["name"] for m in models if technique_id in m.get("techniques", {})]
    threat_relevance = min(len(actors) / 4.0, 1.0)

    # data_available: Do we have the required log sources? (0 or 1)
    required = set()
    for m in models:
        tech = m.get("techniques", {}).get(technique_id, {})
        for ds in tech.get("data_sources", []):
            required.add(ds.split(":")[0])
    available = {sid for sid, s in sources.items() if s.get("status") == "active"}
    data_available = 1.0 if required and required.issubset(available) else 0.0

    # no_detection: Is there currently no detection? (0 or 1)
    det = detections.get(technique_id)
    no_detection = 0.0 if det and det.get("status") not in [None, "RETIRED"] else 1.0

    # technique_severity: Inverse of average detection_complexity across models (0-1)
    complexities = []
    for m in models:
        tech = m.get("techniques", {}).get(technique_id, {})
        cmap = {"low": 0.25, "medium": 0.5, "high": 0.75, "expert": 1.0}
        if tech:
            complexities.append(cmap.get(tech.get("detection_complexity", "medium"), 0.5))
    technique_severity = 1.0 - (sum(complexities) / len(complexities) if complexities else 0.5)

    score = (
        threat_relevance * 3
        + data_available * 2
        + no_detection * 2
        + technique_severity * 1
    ) / 8.0

    return score
```

### Auto-Generated Outputs

**`coverage/attack-matrix.md`** -- regenerated every run:

```markdown
# MITRE ATT&CK Coverage Matrix
# AUTO-GENERATED by coverage_agent.py -- DO NOT EDIT MANUALLY
# Last generated: 2026-03-15T12:00:00Z

## Coverage Summary

| Metric | Value |
|---|---|
| Total techniques tracked | 45 |
| Techniques with detection | 29 |
| Techniques monitoring | 11 |
| Threat models loaded | 4 |
| Active log sources | 3 |
| Planned log sources | 3 |

## Coverage by Threat Model

| Threat Model | Techniques | Detected | Monitoring | Coverage % |
|---|---|---|---|---|
| Fawkes C2 Agent | 21 | 13 | 11 | 62% |
| Scattered Spider | 10 | 5 | 3 | 50% |
| LockBit 3.0 | 12 | 9 | 7 | 75% |
| Generic RAT | 11 | 7 | 4 | 64% |

## Multi-Dimensional Coverage (Technique x Threat Actor)

| Technique | Status | F1 | Fawkes | Scattered Spider | LockBit | Generic RAT |
|---|---|---|---|---|---|---|
| T1059.001 | MONITORING | 0.95 | X | X | X | X |
| T1547.001 | MONITORING | 1.00 | X | | | X |
| T1621 | -- | -- | | X | | |
...
```

**`coverage/gap-report.md`** -- prioritized backlog:

```markdown
# Detection Gap Report
# AUTO-GENERATED by coverage_agent.py -- DO NOT EDIT MANUALLY

## Priority Queue (Top 10 Gaps)

| Rank | Technique | Score | Threat Actors | Data Available | Blocker |
|---|---|---|---|---|---|
| 1 | T1621 | 0.88 | Scattered Spider | No (need identity logs) | Data gap |
| 2 | T1055.004 | 0.81 | Fawkes | Partial (EID 10) | No rule |
| 3 | T1098 | 0.75 | Scattered Spider | No (need cloud logs) | Data gap |
...
```

**`coverage/navigator.json`** -- ATT&CK Navigator layer for visualization:

```python
def generate_navigator_layer(detections: dict, models: list[dict]) -> dict:
    """Generate ATT&CK Navigator JSON layer."""
    techniques = []
    for tid, det in detections.items():
        color_map = {
            "MONITORING": "#00ff00",   # green
            "DEPLOYED": "#90ee90",     # light green
            "VALIDATED": "#ffff00",    # yellow
            "AUTHORED": "#ffa500",     # orange
            "REQUESTED": "#ff6347",    # red-orange
        }
        status = det.get("status", "REQUESTED")
        techniques.append({
            "techniqueID": tid,
            "color": color_map.get(status, "#ff0000"),
            "comment": f"Status: {status}, F1: {det.get('f1', 'N/A')}",
            "enabled": True,
            "score": det.get("f1", 0) * 100
        })
    return {
        "name": "Patronus Lab Detection Coverage",
        "version": "4.5",
        "domain": "enterprise-attack",
        "description": "Auto-generated coverage layer",
        "techniques": techniques,
        "gradient": {
            "colors": ["#ff0000", "#ffff00", "#00ff00"],
            "minValue": 0,
            "maxValue": 100
        }
    }
```

### CLI Integration

Add `coverage` command to `autonomous/orchestration/cli.py`:

```python
def cmd_coverage(args):
    """Generate and display coverage analysis."""
    from orchestration.agents.coverage_agent import run_coverage_analysis
    report = run_coverage_analysis()
    print(f"  Coverage report generated:")
    print(f"    - coverage/attack-matrix.md")
    print(f"    - coverage/gap-report.md")
    print(f"    - coverage/navigator.json")
    print(f"  Techniques tracked: {report['total_techniques']}")
    print(f"  Detection coverage: {report['coverage_pct']:.0f}%")
    print(f"  Top gap: {report['top_gap']}")
```

Usage: `python orchestration/cli.py coverage`

---

## Task 4.4: Refactor Agent Architecture (4h)

### Objective

Split the monolithic Blue Team agent into three specialized agents with clear
single-responsibility boundaries. Rename the Quality agent to Tuning agent.

### Current State

The Blue Team agent (`autonomous/orchestration/agents/blue_team_agent.py`, ~450 lines)
currently handles three distinct concerns:

1. **Authoring** -- Read detection requests, generate Sigma rules, transpile to Lucene/SPL
2. **Validation** -- Ingest scenarios into ES, run queries, calculate F1 scores
3. **Deployment** -- POST rules to Elastic Security API and Splunk saved searches

This makes the agent large, hard to test, and impossible to run validation independently
of authoring.

### New Agent Topology

```
BEFORE (5 agents):                    AFTER (8 agents):
  intel_agent.py                        intel_agent.py (updated)
  red_team_agent.py                     red_team_agent.py (unchanged)
  blue_team_agent.py  ----SPLIT---->    author_agent.py
                                        validation_agent.py
                                        deployment_agent.py
  quality_agent.py  ----RENAME---->     tuning_agent.py
  security_agent.py                     security_agent.py (unchanged)
                                        coverage_agent.py (NEW, from Task 4.3)
                                        coordinator.py (NEW, from Task 4.5)
```

### Step 1: Extract Validation Agent

Create `autonomous/orchestration/agents/validation_agent.py`:

```python
"""
Validation Agent -- Tests detection rules against simulated data.

Processes detections in AUTHORED state:
  AUTHORED -> VALIDATED (if F1 >= 0.75)
  AUTHORED -> AUTHORED  (if F1 < 0.75, with feedback for retry)

Capabilities:
  - ES-based validation (primary): ingest scenarios, run Lucene queries, score
  - Cribl streaming validation: route through Cribl pipeline first
  - Local JSON fallback: for CI environments without ES
  - Continuous re-validation: re-test MONITORING rules on schedule
  - Retry loop: up to MAX_TUNE_RETRIES refinements per rule

Called by agent_runner.py or coordinator.py.
"""

AGENT_NAME = "validation"

# Functions to extract from blue_team_agent.py:
#   - validate_detection()       (local JSON matching)
#   - All calls to validate_against_elasticsearch()
#   - F1 scoring and quality tier assignment
#   - Result file writing to tests/results/
#   - Retry loop logic (MAX_TUNE_RETRIES iterations)

def run(state_manager):
    """Process all AUTHORED detections through validation."""
    pending = state_manager.query_by_state("AUTHORED")
    for request in pending:
        technique_id = request["technique_id"]
        # 1. Load scenario from tests/true_positives/ and tests/true_negatives/
        # 2. Load compiled Lucene query from detections/<tactic>/compiled/
        # 3. Run validate_against_elasticsearch() or local fallback
        # 4. Score results (F1, TP, FP, FN, TN)
        # 5. Write results to tests/results/<technique>.json
        # 6. Transition state: AUTHORED -> VALIDATED (if F1 >= 0.75)
        # 7. If F1 < 0.75 and retries remaining: feed FP/FN back for refinement
        pass

def revalidate_monitoring(state_manager):
    """Re-test all MONITORING rules to detect regressions."""
    monitoring = state_manager.query_by_state("MONITORING")
    for request in monitoring:
        # Re-run validation, compare to last known F1
        # Flag regressions (F1 drop > 0.10)
        pass
```

### Step 2: Extract Deployment Agent

Create `autonomous/orchestration/agents/deployment_agent.py`:

```python
"""
Deployment Agent -- Deploys validated rules to Elastic Security and Splunk.

Processes detections in VALIDATED state (F1 >= auto_deploy_threshold):
  VALIDATED -> DEPLOYED (rule created/updated in SIEM)
  DEPLOYED -> MONITORING (confirmed active and healthy)

Capabilities:
  - Elastic Detection Engine API deployment
  - Splunk saved search deployment
  - Version tracking (detection version history)
  - Canary deployment (deploy to test space first)
  - Rollback capability (revert to previous version)

Only runs post-merge to main (CI) or manually (local lab).
"""

AGENT_NAME = "deployment"

# Functions to extract from blue_team_agent.py (and siem.py):
#   - deploy_to_elastic()
#   - deploy_to_splunk()
#   - Rule version management
#   - Health check after deployment

def run(state_manager):
    """Deploy all validated detections meeting auto_deploy_threshold."""
    validated = state_manager.query_by_state("VALIDATED")
    for request in validated:
        f1 = request.get("f1_score", 0)
        if f1 < AUTO_DEPLOY_THRESHOLD:
            continue
        # 1. Load compiled rule from detections/<tactic>/compiled/
        # 2. Check if rule already exists in SIEM (update vs create)
        # 3. Deploy to Elastic (if running)
        # 4. Deploy to Splunk (if running)
        # 5. Transition state: VALIDATED -> DEPLOYED
        # 6. Verify rule is active: DEPLOYED -> MONITORING
        pass

def rollback(state_manager, technique_id: str):
    """Rollback a deployed rule to its previous version."""
    # 1. Load previous version from git history
    # 2. Re-deploy previous version
    # 3. Log rollback in tuning/changelog/
    pass
```

### Step 3: Refactor Author Agent

Rename and simplify `blue_team_agent.py` -> `author_agent.py`:

```python
"""
Author Agent -- Writes detection rules from attack scenarios.

Processes detections in SCENARIO_BUILT state:
  SCENARIO_BUILT -> AUTHORED (Sigma rule + compiled outputs created)

Capabilities:
  - Sigma rule generation from scenario events
  - Lucene transpilation (sigma-cli)
  - SPL transpilation (sigma-cli)
  - Elastic Detection Engine JSON compilation
  - EQL rule authoring (stub for Phase 5)

After authoring, validation_agent.py takes over.
"""

AGENT_NAME = "author"

# Keep from blue_team_agent.py:
#   - generate_sigma_rule()
#   - determine_logsource()
#   - Sigma transpilation logic
#   - Elastic JSON compilation
#   - Template loading

# Remove from blue_team_agent.py:
#   - All validation logic -> validation_agent.py
#   - All deployment logic -> deployment_agent.py
#   - validate_detection() function
#   - deploy_to_*() calls
```

### Step 4: Rename Quality Agent -> Tuning Agent

Rename `quality_agent.py` -> `tuning_agent.py`. Update responsibilities:

```python
"""
Tuning Agent -- Monitors deployed detections and applies tuning.

Processes detections in DEPLOYED and MONITORING states:
  MONITORING -> TUNED (when exclusions applied)
  MONITORING -> MONITORING (when healthy, no changes)

Capabilities:
  - Health scoring (alert volume, FP rate, TP rate)
  - Daily monitoring reports
  - Auto-tuning: suggest and apply exclusions (max 3 per rule)
  - Regression detection (F1 history tracking)
  - Automated tuning PRs with before/after metrics

Renamed from quality_agent.py. Quality REPORTING is now in coverage_agent.py.
"""

AGENT_NAME = "tuning"
```

### Step 5: Update Agent Runner

Update `autonomous/orchestration/agent_runner.py` `AGENT_MODULES` mapping:

```python
AGENT_MODULES = {
    "intel":       "orchestration.agents.intel_agent",
    "red-team":    "orchestration.agents.red_team_agent",
    "author":      "orchestration.agents.author_agent",       # was blue-team
    "validation":  "orchestration.agents.validation_agent",    # new
    "deployment":  "orchestration.agents.deployment_agent",    # new
    "tuning":      "orchestration.agents.tuning_agent",        # was quality
    "coverage":    "orchestration.agents.coverage_agent",      # new
    "security":    "orchestration.agents.security_agent",
}

# Backward compatibility aliases (deprecation warnings)
AGENT_ALIASES = {
    "blue-team": "author",
    "quality": "tuning",
}
```

### Step 6: Update State Machine Transitions

Update `autonomous/orchestration/schema.yml` pending states:

```yaml
agent_pending_states:
  intel: [REQUESTED]
  red-team: [REQUESTED]
  author: [SCENARIO_BUILT]           # was blue-team
  validation: [AUTHORED]             # new -- handles AUTHORED -> VALIDATED
  deployment: [VALIDATED]            # new -- handles VALIDATED -> DEPLOYED
  tuning: [DEPLOYED, MONITORING]     # was quality
  coverage: []                       # runs on-demand, no pending state
  security: []                       # runs on PRs, no pending state
```

### Step 7: Update Config

Update `autonomous/orchestration/config.yml`:

```yaml
agents:
  intel:
    schedule: "daily"
    model: "sonnet"
    max_reports: 5
    max_tokens_estimate: 50000

  red-team:
    trigger: "intel_merge"
    model: "sonnet"
    max_scenarios_per_run: 5
    max_tokens_estimate: 30000

  author:                              # renamed from blue-team
    trigger: "red_merge"
    model: "opus"
    max_detections_per_run: 5
    max_tokens_estimate: 80000         # reduced -- no validation/deploy overhead
    claude_tasks:
      - "Author Sigma detection rules from attack/benign event data"

  validation:                          # new
    trigger: "author_merge"
    model: "sonnet"                    # scoring is deterministic, Claude only for retry feedback
    max_tokens_estimate: 30000
    auto_deploy_threshold: 0.90
    max_tune_retries: 2
    claude_tasks:
      - "Suggest rule improvements when F1 < threshold"

  deployment:                          # new
    trigger: "validation_merge OR manual"
    model: "sonnet"
    max_tokens_estimate: 10000         # mostly API calls, minimal reasoning

  tuning:                              # renamed from quality
    schedule: "daily"
    model: "sonnet"
    max_tokens_estimate: 40000
    max_exclusions_per_rule: 3
    claude_tasks:
      - "Analyze fleet health and recommend tuning actions"

  coverage:                            # new
    schedule: "daily"
    model: "sonnet"
    max_tokens_estimate: 20000

  security:
    trigger: "every_agent_pr"
    model: "sonnet"
    max_tokens_estimate: 20000
    block_on_critical: true
```

### Backward Compatibility

- Keep `blue_team_agent.py` as a thin wrapper that imports from `author_agent.py`
  with a deprecation warning. Remove in Phase 6.
- Keep `quality_agent.py` as a thin wrapper that imports from `tuning_agent.py`
  with a deprecation warning. Remove in Phase 6.
- CLI `--agent blue-team` and `--agent quality` still work via `AGENT_ALIASES`.
- Pipeline preset `--pipeline red-blue-quality` maps to `red-team -> author -> validation -> tuning`.

---

## Task 4.5: Coordinator Agent (3h)

### Objective

Create an orchestrator that routes work between agents based on detection state,
priority, and available budget.

### Deliverables

| File | Description |
|---|---|
| `autonomous/orchestration/coordinator.py` | Work routing + priority management |

### Coordinator Design

```python
"""
Coordinator -- Routes work between agents based on state + priority.

The coordinator is NOT an agent itself. It's the orchestration layer that
decides which agent to invoke next and in what order.

Responsibilities:
  1. Scan all detection requests, determine next action for each
  2. Build a priority queue ordered by gap_priority_score
  3. Route each item to the correct agent
  4. Track agent success/failure rates
  5. Enforce daily token budget allocation
  6. Provide queue status for cli.py

Usage:
  python orchestration/coordinator.py --dry-run        # show planned actions
  python orchestration/coordinator.py --run            # execute full pipeline
  python orchestration/coordinator.py --agent author   # run just one agent via coordinator
"""

import yaml
from pathlib import Path
from orchestration.state import StateManager
from orchestration import budget

PIPELINE_ORDER = [
    "intel",
    "red-team",
    "author",
    "validation",
    "deployment",
    "tuning",
    "coverage",
]

class WorkItem:
    """A single unit of work to be routed to an agent."""
    def __init__(self, technique_id: str, current_state: str,
                 target_agent: str, priority: float, threat_actors: list[str]):
        self.technique_id = technique_id
        self.current_state = current_state
        self.target_agent = target_agent
        self.priority = priority
        self.threat_actors = threat_actors

class Coordinator:
    def __init__(self, state_manager: StateManager, dry_run: bool = False):
        self.sm = state_manager
        self.dry_run = dry_run
        self.queue: list[WorkItem] = []
        self.results: list[dict] = []

    def build_queue(self) -> list[WorkItem]:
        """Scan all detection requests and build prioritized work queue."""
        STATE_TO_AGENT = {
            "REQUESTED": "red-team",       # needs scenario generation
            "SCENARIO_BUILT": "author",    # needs rule authoring
            "AUTHORED": "validation",      # needs testing
            "VALIDATED": "deployment",     # needs deployment (if F1 >= threshold)
            "DEPLOYED": "tuning",          # needs health monitoring
            "MONITORING": "tuning",        # ongoing monitoring
        }

        all_requests = self.sm.list_all()
        for req in all_requests:
            state = req.get("status")
            agent = STATE_TO_AGENT.get(state)
            if not agent:
                continue
            priority = req.get("priority_score", 0.5)
            actors = req.get("threat_actors", [])
            self.queue.append(WorkItem(
                technique_id=req["technique_id"],
                current_state=state,
                target_agent=agent,
                priority=priority,
                threat_actors=actors,
            ))

        # Sort by priority descending (highest priority first)
        self.queue.sort(key=lambda w: w.priority, reverse=True)
        return self.queue

    def allocate_budget(self) -> dict[str, int]:
        """Distribute daily token budget across agents."""
        daily_cap = budget.get_daily_cap()
        used = budget.get_used_today()
        remaining = daily_cap - used

        # Budget allocation weights
        weights = {
            "intel": 0.10,
            "red-team": 0.05,
            "author": 0.30,
            "validation": 0.20,
            "deployment": 0.05,
            "tuning": 0.15,
            "coverage": 0.05,
            "security": 0.10,
        }

        return {agent: int(remaining * w) for agent, w in weights.items()}

    def execute(self):
        """Execute the work queue, routing each item to its target agent."""
        if not self.queue:
            self.build_queue()

        budgets = self.allocate_budget()

        for item in self.queue:
            if self.dry_run:
                print(f"  [DRY-RUN] {item.technique_id} ({item.current_state}) "
                      f"-> {item.target_agent} (priority: {item.priority:.2f})")
                continue

            # Check budget
            agent_budget = budgets.get(item.target_agent, 0)
            if agent_budget <= 0:
                print(f"  [SKIP] {item.technique_id} -- {item.target_agent} budget exhausted")
                continue

            # Route to agent
            result = self._invoke_agent(item)
            self.results.append(result)

    def _invoke_agent(self, item: WorkItem) -> dict:
        """Invoke the target agent for a single work item."""
        import importlib
        from orchestration.agent_runner import AGENT_MODULES

        module_name = AGENT_MODULES.get(item.target_agent)
        if not module_name:
            return {"technique_id": item.technique_id, "status": "error",
                    "message": f"Unknown agent: {item.target_agent}"}

        module = importlib.import_module(module_name)
        try:
            result = module.run(self.sm)
            return {"technique_id": item.technique_id, "status": "success",
                    "agent": item.target_agent}
        except Exception as e:
            return {"technique_id": item.technique_id, "status": "error",
                    "agent": item.target_agent, "message": str(e)}

    def status(self) -> dict:
        """Return coordinator queue status for cli.py."""
        if not self.queue:
            self.build_queue()

        by_agent = {}
        for item in self.queue:
            by_agent.setdefault(item.target_agent, []).append(item.technique_id)

        return {
            "queue_size": len(self.queue),
            "by_agent": {k: len(v) for k, v in by_agent.items()},
            "top_priority": self.queue[0].technique_id if self.queue else None,
            "budget_remaining": self.allocate_budget(),
        }
```

### CLI Integration

Update `autonomous/orchestration/cli.py` with coordinator commands:

```python
def cmd_queue(args):
    """Show coordinator work queue."""
    from orchestration.coordinator import Coordinator
    sm = StateManager()
    coord = Coordinator(sm)
    status = coord.status()
    print(f"\n  Work Queue: {status['queue_size']} items")
    for agent, count in status["by_agent"].items():
        print(f"    {agent}: {count} items")
    if status["top_priority"]:
        print(f"  Top priority: {status['top_priority']}")

def cmd_run_pipeline(args):
    """Run the full pipeline via coordinator."""
    from orchestration.coordinator import Coordinator
    sm = StateManager()
    coord = Coordinator(sm, dry_run=args.dry_run)
    coord.execute()
```

Usage:
```bash
python orchestration/cli.py queue                    # show work queue
python orchestration/cli.py run --dry-run            # preview pipeline execution
python orchestration/cli.py run                      # execute full pipeline
python orchestration/cli.py run --agent author       # run just author via coordinator
```

---

## Task 4.6: State Management Foundation (2h)

### Objective

Define the SQLite schema and build a migration tool. Phase 4 defines and tests;
Phase 5 flips the switch when rule count makes YAML untenable.

### Deliverables

| File | Description |
|---|---|
| `autonomous/orchestration/state_schema.sql` | SQLite schema definition |
| `autonomous/orchestration/migrate_yaml_to_sqlite.py` | Migration script |

### SQLite Schema (`autonomous/orchestration/state_schema.sql`)

```sql
-- Patronus Detection Engineering State Database
-- Phase 4: Schema definition. Phase 5: Production cutover.
-- Compatible with Python sqlite3 standard library (no dependencies).

CREATE TABLE IF NOT EXISTS detections (
    technique_id    TEXT PRIMARY KEY,         -- e.g., "T1055.001"
    title           TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'REQUESTED',
    priority        TEXT DEFAULT 'medium',
    priority_score  REAL DEFAULT 0.5,
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    f1_score        REAL,
    tp_count        INTEGER DEFAULT 0,
    fp_count        INTEGER DEFAULT 0,
    fn_count        INTEGER DEFAULT 0,
    tn_count        INTEGER DEFAULT 0,
    fp_rate         REAL,
    tp_rate         REAL,
    validation_method TEXT,                   -- 'elasticsearch', 'local_json', 'cribl'
    rule_file       TEXT,                     -- relative path to Sigma YAML
    scenario_file   TEXT,                     -- relative path to scenario JSON
    result_file     TEXT,                     -- relative path to result JSON
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    created_by      TEXT,
    updated_by      TEXT,

    CHECK (status IN ('REQUESTED', 'SCENARIO_BUILT', 'AUTHORED', 'VALIDATED',
                      'DEPLOYED', 'MONITORING', 'TUNED', 'RETIRED'))
);

CREATE TABLE IF NOT EXISTS detection_threat_actors (
    technique_id    TEXT NOT NULL,
    threat_actor    TEXT NOT NULL,            -- e.g., "Fawkes C2 Agent"
    PRIMARY KEY (technique_id, threat_actor),
    FOREIGN KEY (technique_id) REFERENCES detections(technique_id)
);

CREATE TABLE IF NOT EXISTS detection_data_sources (
    technique_id    TEXT NOT NULL,
    source_id       TEXT NOT NULL,            -- e.g., "sysmon"
    event_type      TEXT,                     -- e.g., "eid_8"
    PRIMARY KEY (technique_id, source_id, event_type),
    FOREIGN KEY (technique_id) REFERENCES detections(technique_id)
);

CREATE TABLE IF NOT EXISTS state_transitions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id    TEXT NOT NULL,
    from_state      TEXT NOT NULL,
    to_state        TEXT NOT NULL,
    agent           TEXT NOT NULL,
    details         TEXT,
    timestamp       TEXT NOT NULL,
    FOREIGN KEY (technique_id) REFERENCES detections(technique_id)
);

CREATE TABLE IF NOT EXISTS deployments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id    TEXT NOT NULL,
    siem            TEXT NOT NULL,            -- 'elastic' or 'splunk'
    rule_id         TEXT,                     -- SIEM-assigned rule ID
    version         INTEGER DEFAULT 1,
    deployed_at     TEXT NOT NULL,
    deployed_by     TEXT,
    status          TEXT DEFAULT 'active',    -- 'active', 'disabled', 'rolled_back'
    FOREIGN KEY (technique_id) REFERENCES detections(technique_id)
);

CREATE TABLE IF NOT EXISTS validation_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id    TEXT NOT NULL,
    f1_score        REAL,
    tp_count        INTEGER,
    fp_count        INTEGER,
    fn_count        INTEGER,
    tn_count        INTEGER,
    method          TEXT,                     -- 'elasticsearch', 'local_json', 'cribl'
    agent           TEXT,
    timestamp       TEXT NOT NULL,
    FOREIGN KEY (technique_id) REFERENCES detections(technique_id)
);

CREATE TABLE IF NOT EXISTS source_health (
    source_id       TEXT NOT NULL,
    status          TEXT NOT NULL,            -- 'healthy', 'stale', 'missing', 'degraded'
    latest_event    TEXT,
    event_count_24h INTEGER,
    missing_fields  TEXT,                     -- JSON array
    checked_at      TEXT NOT NULL,
    PRIMARY KEY (source_id, checked_at)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_detections_status ON detections(status);
CREATE INDEX IF NOT EXISTS idx_transitions_technique ON state_transitions(technique_id);
CREATE INDEX IF NOT EXISTS idx_deployments_technique ON deployments(technique_id);
CREATE INDEX IF NOT EXISTS idx_validation_technique ON validation_history(technique_id);
```

### Migration Script (`autonomous/orchestration/migrate_yaml_to_sqlite.py`)

```python
#!/usr/bin/env python3
"""
Migrate detection request YAML files to SQLite database.

Usage:
  python orchestration/migrate_yaml_to_sqlite.py              # migrate
  python orchestration/migrate_yaml_to_sqlite.py --verify     # verify migration
  python orchestration/migrate_yaml_to_sqlite.py --dry-run    # preview only

The migration is idempotent -- safe to run multiple times.
YAML files are NOT deleted (dual-write period).
"""

import argparse
import json
import sqlite3
from pathlib import Path

import yaml

AUTONOMOUS_DIR = Path(__file__).resolve().parent.parent
DB_PATH = AUTONOMOUS_DIR / "orchestration" / "state.db"
SCHEMA_PATH = AUTONOMOUS_DIR / "orchestration" / "state_schema.sql"
REQUESTS_DIR = AUTONOMOUS_DIR / "detection-requests"

def migrate():
    """Read all YAML detection requests, insert into SQLite."""
    conn = sqlite3.connect(str(DB_PATH))

    # Create schema
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())

    for yml_file in sorted(REQUESTS_DIR.glob("*.yml")):
        if yml_file.name.startswith("_"):
            continue
        with open(yml_file) as f:
            data = yaml.safe_load(f)
        if not data or "technique_id" not in data:
            continue

        # Insert or replace detection
        conn.execute("""
            INSERT OR REPLACE INTO detections
            (technique_id, title, status, priority, priority_score, mitre_tactic,
             f1_score, tp_count, fp_count, fn_count, tn_count, fp_rate, tp_rate,
             validation_method, rule_file, scenario_file, result_file,
             created_at, updated_at, created_by, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            data["technique_id"],
            data.get("title", ""),
            data.get("status", "REQUESTED"),
            data.get("priority", "medium"),
            data.get("priority_score", 0.5),
            data.get("mitre_tactic", ""),
            data.get("f1_score"),
            data.get("tp_count", 0),
            data.get("fp_count", 0),
            data.get("fn_count", 0),
            data.get("tn_count", 0),
            data.get("fp_rate"),
            data.get("tp_rate"),
            data.get("validation_method"),
            data.get("rule_file"),
            data.get("scenario_file"),
            data.get("result_file"),
            data.get("created_at", ""),
            data.get("updated_at", ""),
            data.get("created_by", ""),
            data.get("updated_by", ""),
        ))

        # Insert threat actors
        for actor in data.get("threat_actors", []):
            conn.execute("""
                INSERT OR IGNORE INTO detection_threat_actors
                (technique_id, threat_actor) VALUES (?, ?)
            """, (data["technique_id"], actor))

        # Insert state transitions from history
        for entry in data.get("history", []):
            conn.execute("""
                INSERT INTO state_transitions
                (technique_id, from_state, to_state, agent, details, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                data["technique_id"],
                entry.get("from_state", ""),
                entry.get("to_state", entry.get("status", "")),
                entry.get("agent", ""),
                entry.get("details", ""),
                entry.get("timestamp", ""),
            ))

    conn.commit()
    conn.close()
    print(f"Migration complete. Database: {DB_PATH}")

def verify():
    """Compare YAML and SQLite state, report discrepancies."""
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.execute("SELECT technique_id, status, f1_score FROM detections")
    db_state = {row[0]: {"status": row[1], "f1": row[2]} for row in cursor}
    conn.close()

    discrepancies = 0
    for yml_file in sorted(REQUESTS_DIR.glob("*.yml")):
        if yml_file.name.startswith("_"):
            continue
        with open(yml_file) as f:
            data = yaml.safe_load(f)
        if not data:
            continue
        tid = data.get("technique_id")
        if tid not in db_state:
            print(f"  MISSING in DB: {tid}")
            discrepancies += 1
        elif db_state[tid]["status"] != data.get("status"):
            print(f"  STATUS MISMATCH: {tid} YAML={data.get('status')} DB={db_state[tid]['status']}")
            discrepancies += 1

    if discrepancies == 0:
        print("  Verification passed: YAML and SQLite are in sync.")
    else:
        print(f"  {discrepancies} discrepancies found.")
```

### Dual-Write Period

During Phase 4, `state.py` continues to use YAML as primary. Add a feature flag:

```python
# In state.py
USE_SQLITE = os.environ.get("PATRONUS_USE_SQLITE", "false").lower() == "true"

class StateManager:
    def __init__(self):
        # ... existing YAML init ...
        if USE_SQLITE:
            self._init_sqlite()

    def _save_request(self, path, data):
        _save_request(path, data)  # YAML write (always)
        if USE_SQLITE:
            self._sqlite_upsert(data)  # SQLite shadow write
```

Phase 5 flips `PATRONUS_USE_SQLITE=true` and makes SQLite primary, YAML secondary.

---

## Task 4.7: Update Templates and Documentation (2h)

### Objective

Update all templates, configuration files, and documentation to reflect the new
multi-threat, multi-agent architecture.

### Deliverables

| File | Change |
|---|---|
| `templates/sigma-template.yml` | Add `threat_actors` and `platform` fields |
| `templates/detection-authoring-rules.md` | Document multi-threat-actor patterns |
| `templates/threat-model-template.yml` | New template for threat models |
| `templates/source-registry-template.yml` | New template for log sources |
| `CLAUDE.md` | Update agent table, file organization, workflow |
| `ROADMAP.md` | Update Phase 4 description, add revised Phase 5-7 |
| `STATUS.md` | Update agent summary, add coordinator section |

### Sigma Template Update (`templates/sigma-template.yml`)

Add these fields:

```yaml
# New fields for multi-threat-actor support
custom:
  threat_actors:              # Which threat models use this technique
    - "Fawkes C2 Agent"
    - "LockBit 3.0"
  platform: windows           # Target platform
  data_sources_required:      # Explicit source dependencies
    - "sysmon:eid_1"
    - "sysmon:eid_8"
  validation_method: elasticsearch  # How this was tested
```

### CLAUDE.md Agent Table Update

Replace the current 5-agent table:

```markdown
## Autonomous Pipeline (Patronus)

Eight agents run the detection lifecycle end-to-end:

| Agent | Role | Trigger | Key File |
|-------|------|---------|----------|
| Intel | Ingest threat reports from ALL threat models, create detection requests | Daily | `agents/intel_agent.py` |
| Red Team | Generate attack + benign scenarios per technique | On intel merge | `agents/red_team_agent.py` |
| Author | Author Sigma rules, transpile to Lucene/SPL | On red-team merge | `agents/author_agent.py` |
| Validation | Test rules against ES/Cribl, score F1, retry loop | On author merge | `agents/validation_agent.py` |
| Deployment | Deploy validated rules to Elastic + Splunk | Post-merge to main | `agents/deployment_agent.py` |
| Tuning | Monitor deployed rules, apply exclusions, detect regressions | Daily | `agents/tuning_agent.py` |
| Coverage | Generate coverage matrix, gap reports, Navigator layers | Daily | `agents/coverage_agent.py` |
| Security | PR gate: secrets, code security, rule quality | Every PR | `agents/security_agent.py` |

**Coordinator** (`autonomous/orchestration/coordinator.py`) routes work between agents
based on detection state, priority score, and token budget.
```

### ROADMAP.md Phase 4 Update

Replace the current Phase 4 section:

```markdown
## Phase 4: Scalable Architecture Foundation -- IN PROGRESS

**Status**: IN PROGRESS
**Plan**: [plans/phase4-scalable-architecture.md](plans/phase4-scalable-architecture.md)

**Delivered**:
- Threat model registry (4 models: Fawkes, Scattered Spider, LockBit, Generic RAT)
- Log source registry (7 sources: Sysmon, Windows Security, PowerShell, auditd, CloudTrail, Zeek)
- Coverage analyst agent (auto-generated matrix + gap reports + Navigator layer)
- Agent split: blue-team -> author + validation + deployment
- Coordinator with priority queue and budget allocation
- SQLite schema + migration tool (dual-write period, production cutover in Phase 5)
```

### New Template Files

**`templates/threat-model-template.yml`**:
```yaml
# Threat Model Template
# Copy this file to threat-intel/models/<name>.yml and fill in.
# See threat-intel/models/schema.yml for field definitions.

name: ""
type: ""                    # c2_framework | apt_group | ransomware | commodity | insider_threat
platform: []                # [windows, linux, macos, cloud, identity, network]
priority: medium            # critical | high | medium | low
source: ""                  # Primary reference URL
last_updated: ""            # YYYY-MM-DD
description: ""

techniques:
  # T1059.001:
  #   description: "PowerShell Execution"
  #   commands: []
  #   artifacts: [process_create, script_block]
  #   data_sources: ["sysmon:eid_1", "windows_security:eid_4104"]
  #   detection_complexity: low
```

**`templates/source-registry-template.yml`**:
```yaml
# Log Source Registry Template
# Copy this file to data-sources/registry/<source_id>.yml and fill in.
# See data-sources/registry/schema.yml for field definitions.

source_id: ""               # Unique ID (lowercase, underscores)
vendor: ""
product: ""
version: ""
platform: ""                # windows | linux | macos | cloud | network | identity
transport: []               # [wef, syslog, cribl_forwarder, hec, s3, api_poll, filebeat, winlogbeat]
normalization: ecs           # ecs | cim | raw | custom
status: planned              # active | planned | degraded | retired
description: ""

event_types:
  # event_name:
  #   description: ""
  #   ecs_category: ""
  #   ecs_type: ""
  #   fields:
  #     - { raw: "FieldName", ecs: "field.name", type: keyword }
  #   detection_value: medium
  #   volume_estimate: "100/host/day"

health_check:
  method: query_latest_event
  query: ""
  stale_threshold: "15m"
```

---

## Task 4.8: Cross-Check Findings — Compliance, Triage Briefs, Minimal Feedback (2h)

### Context

Post-design cross-check review identified three gaps that are cheapest to fix in Phase 4
(adding them later requires schema retrofitting and backward-compat work):

### 4.8.1: Compliance Mapping Field

Add `compliance_controls` to the Sigma template and detection request schema:

```yaml
# In templates/sigma-template.yml — custom section
custom:
  compliance_controls:         # Regulatory requirements this detection satisfies
    - "PCI-DSS-10.6.1"        # Review logs daily
    - "SOC2-CC7.2"            # Monitor for anomalies
    - "HIPAA-164.312(b)"      # Audit controls
```

**Why now:** This is a one-line schema change. Retrofitting it after 50+ rules exist requires
updating every rule file. Adding it to the template in Phase 4 means every future rule gets it
automatically. Even if most rules leave it empty initially, the field exists for compliance audits.

Add to `autonomous/orchestration/state_schema.sql`:
```sql
CREATE TABLE detection_compliance (
    technique_id TEXT NOT NULL,
    control_id TEXT NOT NULL,        -- e.g., "PCI-DSS-10.6.1"
    framework TEXT NOT NULL,         -- e.g., "PCI-DSS", "SOC2", "HIPAA"
    PRIMARY KEY (technique_id, control_id)
);
```

Add to `cli.py`: `python orchestration/cli.py compliance --framework PCI-DSS` lists which
detections satisfy which controls, and which controls have no detection.

### 4.8.2: Triage Brief in Detection Metadata

Detection Engineers should NOT write full analyst runbooks — that's a SOC analyst role.
But the Detection Author Agent should produce a **triage brief** alongside each rule:
the engineer understands the attack technique best and can save analysts significant
triage time with a few sentences.

Add to `templates/sigma-template.yml`:
```yaml
custom:
  triage_notes:
    what_this_detects: "CreateRemoteThread injection into a target process"
    key_fields_to_examine:
      - "process.executable (the injector — check if signed, in temp dir)"
      - "winlog.event_data.TargetImage (the victim — should not be lsass/explorer)"
    known_false_positives:
      - "AV memory scanning (McAfee, Defender real-time protection)"
      - "Crash handler injection (WerFault.exe)"
    related_techniques:
      - "T1055.004 — APC injection often follows failed CRT attempt"
    investigation_hint: "Check if source process is unsigned or in a temp directory"
```

**Role boundary:** The Detection Author writes triage_notes. A future **Playbook Agent**
(Phase 7/8) would consume triage_notes + environment context (asset inventory, escalation
matrix) to generate full response playbooks with containment actions and escalation criteria.

Update the Detection Author Agent prompt to always populate `triage_notes` when authoring.

### 4.8.3: Minimal Analyst Feedback Loop (Early)

Don't wait for Phase 7's full ES-based feedback pipeline. Add a minimal CLI-based feedback
mechanism now so tuning decisions can start accumulating data:

```bash
# Record a verdict
python orchestration/cli.py feedback T1055.001 --verdict fp --reason "McAfee memory scan"

# View feedback for a rule
python orchestration/cli.py feedback T1055.001 --show

# Summary: rules ranked by FP rate
python orchestration/cli.py feedback --summary
```

**Storage:** Append-only JSONL at `monitoring/feedback/verdicts.jsonl`:
```jsonl
{"timestamp": "2026-03-15T10:30:00Z", "technique_id": "T1055.001", "verdict": "fp", "reason": "McAfee memory scan", "analyst": "lsmith"}
```

**Integration with Tuning Agent:** Tuning Agent reads this file during daily runs. If 7-day
rolling FP rate > 10% for any rule, it logs a warning in the daily quality report. Full
auto-tuning PR generation moves to Phase 7.

**Why now:** Even manual CLI feedback creates a data asset. When Phase 7 builds the full
feedback pipeline, it has historical data to work with. Without this, Phase 7 starts from zero.

### Deliverables Summary

| File | Change |
|---|---|
| `templates/sigma-template.yml` | Add `compliance_controls` and `triage_notes` fields |
| `autonomous/orchestration/state_schema.sql` | Add `detection_compliance` table |
| `autonomous/orchestration/cli.py` | Add `compliance` and `feedback` subcommands |
| `monitoring/feedback/verdicts.jsonl` | New feedback data store (JSONL, append-only) |
| Detection Author Agent prompt | Add triage_notes generation requirement |

---

## Validation Criteria

All criteria must pass before merging Phase 4 to main:

- [ ] **4+ threat models** in `threat-intel/models/` (Fawkes, Scattered Spider, LockBit, Generic RAT)
- [ ] **Schema files** exist for both registries (`threat-intel/models/schema.yml`, `data-sources/registry/schema.yml`)
- [ ] **7 log source definitions** in `data-sources/registry/` (Sysmon, Windows Security, PowerShell, Linux auditd, AWS CloudTrail, Zeek, plus templates)
- [ ] **Intel agent** loads all threat models from registry, not just Fawkes hardcoded path
- [ ] **Detection requests** include `threat_actors` field listing all matching models
- [ ] **Coverage analyst agent** generates `coverage/attack-matrix.md` automatically
- [ ] **Coverage analyst agent** generates `coverage/gap-report.md` with priority scores
- [ ] **Coverage analyst agent** generates `coverage/navigator.json` for ATT&CK Navigator
- [ ] **Blue team agent** split into `author_agent.py`, `validation_agent.py`, `deployment_agent.py`
- [ ] **Quality agent** renamed to `tuning_agent.py`
- [ ] **Backward compatibility**: `--agent blue-team` and `--agent quality` still work (with deprecation warnings)
- [ ] **Coordinator** routes work between agents based on state + priority
- [ ] **`cli.py status`** shows multi-threat-actor coverage summary
- [ ] **`cli.py queue`** shows coordinator work queue
- [ ] **`cli.py coverage`** generates and displays coverage analysis
- [ ] **SQLite schema** defined in `state_schema.sql`
- [ ] **Migration script** converts all existing YAML to SQLite correctly
- [ ] **Migration verify** shows zero discrepancies
- [ ] **All 29 existing rules** still pass validation (backward compatible)
- [ ] **All existing CI workflows** still pass
- [ ] **Compliance field** exists in Sigma template and SQLite schema
- [ ] **Triage notes** field exists in Sigma template; Detection Author Agent prompt includes it
- [ ] **Feedback CLI** accepts verdicts and stores in `monitoring/feedback/verdicts.jsonl`
- [ ] **Feedback summary** shows per-rule FP rate from accumulated verdicts
- [ ] **All changes** on feature branch `infra/phase4-scalable-architecture` with PR to main

---

## Risk Mitigation

| Risk | Impact | Mitigation |
|---|---|---|
| Breaking existing rules | HIGH -- 29 rules stop working | Run full validation suite before AND after refactor. Git tag `pre-phase4` as rollback point. |
| Agent coordination bugs | MEDIUM -- pipeline hangs | Start coordinator with `--dry-run` mode. Verify routing logic with unit tests before live run. |
| Schema migration data loss | HIGH -- lose detection state | Keep YAML as primary during Phase 4. SQLite is shadow-write only. Migration is idempotent. |
| Import path breakage | MEDIUM -- agents fail to load | Maintain backward-compatible wrapper files (`blue_team_agent.py`, `quality_agent.py`). |
| Config drift between agents | LOW -- inconsistent behavior | Single `config.yml` remains source of truth. All agents read from same file. |
| Token budget overruns | LOW -- daily cap exceeded | Coordinator enforces budget allocation. Each agent has a max_tokens_estimate. |

---

## Files Changed/Created

### New Files (20)

```
threat-intel/models/schema.yml
threat-intel/models/fawkes.yml
threat-intel/models/scattered-spider.yml
threat-intel/models/lockbit.yml
threat-intel/models/generic-rat.yml
data-sources/registry/schema.yml
data-sources/registry/sysmon.yml
data-sources/registry/windows-security.yml
data-sources/registry/powershell.yml
data-sources/registry/linux-auditd.yml
data-sources/registry/aws-cloudtrail.yml
data-sources/registry/network-zeek.yml
autonomous/orchestration/agents/author_agent.py
autonomous/orchestration/agents/validation_agent.py
autonomous/orchestration/agents/deployment_agent.py
autonomous/orchestration/agents/coverage_agent.py
autonomous/orchestration/coordinator.py
autonomous/orchestration/state_schema.sql
autonomous/orchestration/migrate_yaml_to_sqlite.py
templates/threat-model-template.yml
templates/source-registry-template.yml
```

### Modified Files (10)

```
autonomous/orchestration/agents/intel_agent.py        -- Multi-model loading, priority scoring, source tracking
autonomous/orchestration/agents/blue_team_agent.py     -- Thin wrapper -> author_agent.py (backward compat)
autonomous/orchestration/agents/quality_agent.py       -- Thin wrapper -> tuning_agent.py (backward compat)
autonomous/orchestration/agents/tuning_agent.py        -- Renamed from quality_agent.py, updated role
autonomous/orchestration/agent_runner.py               -- New agent topology, AGENT_ALIASES
autonomous/orchestration/config.yml                    -- 8 agent definitions, coordinator section
autonomous/orchestration/cli.py                        -- queue, coverage, run commands
autonomous/orchestration/state.py                      -- Dual-write SQLite support (feature flag)
CLAUDE.md                                              -- Updated agent table, file organization
ROADMAP.md                                             -- Phase 4 description, revised Phase 5-7
STATUS.md                                              -- Updated agent summary
templates/sigma-template.yml                           -- threat_actors, platform, data_sources_required
templates/detection-authoring-rules.md                 -- Multi-threat-actor authoring patterns
```

### Files Retained (Backward Compatibility)

```
autonomous/orchestration/agents/blue_team_agent.py     -- Wrapper with deprecation warning (remove in Phase 6)
autonomous/orchestration/agents/quality_agent.py       -- Wrapper with deprecation warning (remove in Phase 6)
threat-intel/fawkes/fawkes-ttp-mapping.md              -- Original Markdown retained as human reference
```

---

## Commit Strategy

Use a single feature branch with logical commits:

```bash
git checkout -b infra/phase4-scalable-architecture

# Commit 1: Threat model registry
git commit -m "feat(registry): add threat model registry with 4 models (Fawkes, Scattered Spider, LockBit, Generic RAT)"

# Commit 2: Log source registry
git commit -m "feat(registry): add log source registry with 7 source definitions"

# Commit 3: Coverage analyst agent
git commit -m "feat(agent): add coverage analyst agent with auto-generated matrix + gap reports"

# Commit 4: Agent refactor
git commit -m "refactor(agents): split blue-team into author + validation + deployment agents"

# Commit 5: Coordinator
git commit -m "feat(orchestration): add coordinator for priority-based work routing"

# Commit 6: State management
git commit -m "feat(state): add SQLite schema + YAML migration tool (dual-write foundation)"

# Commit 7: Templates and docs
git commit -m "docs: update templates, CLAUDE.md, ROADMAP.md for multi-threat architecture"

# Commit 8: Cross-check findings
git commit -m "feat(schema): add compliance mapping, triage briefs, minimal feedback CLI"

git push -u origin infra/phase4-scalable-architecture
# Create PR: [Infra] Phase 4: Scalable Architecture Foundation
```

---

## What Comes After Phase 4

With the scalable architecture in place, the remaining phases shift focus:

| Phase | New Focus |
|---|---|
| **Phase 5** | Data engineering at scale: multi-platform simulation, data quality monitoring, schema evolution. |
| **Phase 6** | Detection content at scale: content packs, EQL/threshold rules, evasion testing, coverage to 75%+. |
| **Phase 7** | Operational excellence: full feedback loop, health dashboards, regression CI, SLA tracking. |
| **Phase 8** | Advanced capabilities: Agent SDK, live C2, behavioral analytics, multi-SIEM, marketplace. |

Phase 4 is the critical inflection point. Everything before it was "make the lab work."
Everything after it is "make the lab scale."
