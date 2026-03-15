# Phase 8: Advanced Capabilities

**Status**: NOT STARTED
**Priority**: LOW -- STRATEGIC (research and innovation)
**Estimated effort**: 40+ hours (multi-week, capability-independent)
**Dependencies**: Phases 4-7 provide the foundation. Each capability can start once its relevant phase dependencies are met (see per-capability notes below).
**Branch**: Various per capability (see individual sections)

---

## Goal

Push the detection engineering platform into research-grade territory with advanced capabilities: Claude Agent SDK, live adversary simulation, behavioral analytics, multi-SIEM abstraction, a detection marketplace, and SOAR integration. Each capability is independent and can be pursued based on interest and available resources.

## Why This Matters

Phases 4-7 build a production-grade detection engineering platform with scalable architecture, rich data engineering, content at scale, and operational feedback loops. Phase 8 explores what becomes possible when that foundation is solid:

- **Agent SDK** makes agents truly autonomous (not CLI wrappers), enabling faster iteration and real tool use
- **Live C2 validation** is the gold standard for detection testing -- synthetic events can never fully replicate real adversary telemetry
- **Behavioral analytics** catches novel attacks that no signature can anticipate
- **Multi-SIEM** makes the entire detection catalog portable across enterprise environments
- **A marketplace** turns detection content into a shareable, community-driven product
- **SOAR integration** connects detection to response, completing the security operations lifecycle

These capabilities are individually valuable. Implement them in any order based on interest, available resources, and which prior phases are complete.

## Dependency Map

| Capability | Hard Dependencies | Soft Dependencies | Can Start After |
|-----------|------------------|-------------------|-----------------|
| 1. Agent SDK | None | Phase 4 (coordinator) | Anytime |
| 2. Live C2 | Phase 5 (multi-platform sim) | Phase 6 (content at scale) | Phase 5 |
| 3. Behavioral Analytics | Phase 5 (multi-platform data) | Phase 7 (dashboards) | Phase 5 |
| 4. Multi-SIEM | Phase 4 (deployment agent) | Phase 6 (content packs) | Phase 4 |
| 5. Marketplace | Phase 6 (content packs) | Phase 7 (quality metrics) | Phase 6 |
| 6. SOAR | Phase 7 (feedback loop) | Phase 4 (coordinator) | Phase 7 |

---

## Capability 1: Claude Agent SDK Integration (8h)

**Branch**: `infra/agent-sdk-migration`

### Current State

Agents use `claude -p` CLI wrapper via subprocess calls in `agent_runner.py`. This means:
- No native tool use (parsing stdin/stdout as text)
- No streaming (must wait for full response before processing)
- No proper error handling or retry (subprocess crash = unrecoverable)
- No multi-turn conversations within runs (single prompt, single response)
- No sub-agent spawning (everything is sequential)
- Token counting is estimated, not measured

### Target State

Full Agent SDK integration with native tool use, streaming, sub-agent spawning, and real token accounting.

### Deliverables

- `autonomous/orchestration/sdk_runner.py` -- SDK-based agent runner (replaces CLI-based `agent_runner.py`)
- `autonomous/orchestration/sdk_tools.py` -- Tool definitions for each agent (ES queries, file writes, GitHub API, Sigma CLI)
- `autonomous/orchestration/sdk_agents/` -- Per-agent configurations (system prompt, tools, conversation loop)
  - `intel_config.py`
  - `red_team_config.py`
  - `blue_team_config.py`
  - `quality_config.py`
  - `security_config.py`
- Updated `agent_runner.py` to support both CLI and SDK modes (feature flag in `config.yml`)

### Architecture

```
Coordinator (Agent SDK)
  |
  +-- spawn: Intel Agent
  |     Tools: web_search, github_search, file_write, coverage_check
  |     Conversation: multi-turn (ask for clarification on ambiguous intel)
  |
  +-- spawn: Scenario Engineer (Red-Team)
  |     Tools: file_write, simulator_generate, data_source_check
  |     Conversation: single-turn (deterministic scenario generation)
  |
  +-- spawn: Author Agent (Blue-Team)
  |     Tools: sigma_cli, file_write, elasticsearch_search, validate_rule
  |     Conversation: multi-turn (iterative refinement loop built into SDK)
  |
  +-- spawn: Validation Agent
  |     Tools: elasticsearch_bulk_ingest, elasticsearch_search, file_write
  |     Parallelism: validate 5 rules simultaneously via sub-agents
  |
  +-- spawn: Deployment Agent
        Tools: elasticsearch_deploy, splunk_deploy, github_pr, file_write
        Conversation: single-turn (deterministic deployment)
```

### Tool Schema Example

```python
tools = [
    {
        "name": "validate_rule",
        "description": "Validate a Sigma detection rule against test scenarios using Elasticsearch",
        "input_schema": {
            "type": "object",
            "properties": {
                "rule_path": {"type": "string", "description": "Path to Sigma YAML rule file"},
                "tp_path": {"type": "string", "description": "Path to true positive test JSON"},
                "tn_path": {"type": "string", "description": "Path to true negative test JSON"},
                "method": {"type": "string", "enum": ["elasticsearch", "local_json", "auto"]}
            },
            "required": ["rule_path"]
        }
    },
    {
        "name": "search_elasticsearch",
        "description": "Run an Elasticsearch query and return results",
        "input_schema": {
            "type": "object",
            "properties": {
                "index": {"type": "string"},
                "query": {"type": "object", "description": "Elasticsearch DSL query body"},
                "size": {"type": "integer", "default": 10}
            },
            "required": ["index", "query"]
        }
    },
    {
        "name": "transpile_sigma",
        "description": "Convert a Sigma rule to a target query language",
        "input_schema": {
            "type": "object",
            "properties": {
                "rule_path": {"type": "string"},
                "target": {"type": "string", "enum": ["lucene", "splunk", "kusto", "chronicle"]},
                "pipeline": {"type": "string", "default": "ecs_windows"}
            },
            "required": ["rule_path", "target"]
        }
    }
]
```

### Benefits

| Improvement | CLI Mode | SDK Mode |
|------------|---------|---------|
| Agent run speed | 30-60s per prompt | 10-20s (streaming, no process spawn) |
| Error handling | Subprocess crash = failure | SDK retries with exponential backoff |
| Token tracking | Estimated from prompt length | Exact from API response |
| Tool use | Claude outputs text, script parses | Native tool calls with structured I/O |
| Multi-turn | N/A (single prompt) | Agent iterates until task complete |
| Parallelism | Sequential agent runs | Sub-agents for parallel validation |
| Debugging | Read stdout logs | Streaming output with tool call traces |

### Implementation Steps

1. Install `anthropic` Python package (Agent SDK is part of the Anthropic Python client)
2. Define tool schemas for each agent in `sdk_tools.py`
3. Convert agent system prompts from `agents/*.py` to SDK format in `sdk_agents/`
4. Write `sdk_runner.py` with `run_agent()` method using `client.messages.create()` with tool use
5. Add streaming output handler for live progress display
6. Add proper token counting from `response.usage` (replace estimation in `budget-log.jsonl`)
7. Implement sub-agent spawning: coordinator creates child `messages.create()` calls for parallel work
8. Add feature flag in `config.yml`: `agent_backend: sdk | cli` (default: `cli` for backward compat)
9. Test each agent individually with SDK backend, then full pipeline
10. Update `agent_runner.py` to dispatch to either CLI or SDK runner based on config

### Key Considerations

- Requires Anthropic API key (not Claude Pro subscription) -- cost model changes from flat fee to per-token
- Keep CLI fallback for users without API access (feature flag, not replacement)
- SDK mode enables budget enforcement at the API level (stop agent when token budget exhausted)
- Multi-turn conversations mean agents can ask clarifying questions -- need clear termination conditions

---

## Capability 2: Live Adversary Simulation (12h)

**Branch**: `infra/live-c2-lab`

### Current State

Validation uses synthetic JSON events crafted by the simulator (`simulator/simulator.py` and `simulator/raw_events.py`). These approximate what attack telemetry looks like, but real C2 telemetry is different:
- Real process trees have more depth and noise
- Real network connections include protocol negotiation, retries, and jitter
- Real injection leaves artifacts that synthetic events omit (thread context, memory allocations)
- Real evasion techniques produce subtle telemetry differences

### Target State

Deploy a real Mythic C2 server with the Fawkes agent in an isolated Docker network. Run actual attack commands. Collect genuine Sysmon telemetry. Test detections against real adversary artifacts.

### Architecture

```
+-- Isolated Docker Network (no internet) -----------------+
|                                                           |
|  +---------------+         +---------------------------+  |
|  | Mythic C2     |  HTTP   | Target VM                 |  |
|  | Server        |<------->| (Windows container)       |  |
|  | Port 7443     |  C2     |  - Fawkes agent running   |  |
|  +---------------+         |  - Sysmon 15.x installed  |  |
|                             |  - Winlogbeat shipping    |  |
|                             +------------+--------------+  |
|                                          |                 |
|                                   Sysmon events            |
|                                          |                 |
|                             +------------v--------------+  |
|                             | Winlogbeat                |  |
|                             |  -> Cribl (port 9000)     |  |
|                             |  -> Elasticsearch (9200)  |  |
|                             +---------------------------+  |
|                                                           |
+-----------------------------------------------------------+
         |
         | Detection rules fire on REAL telemetry
         v
+-------------------+
| Validation Agent  |
| - Run Fawkes cmd  |
| - Wait for events |
| - Check alerts    |
| - Compare F1      |
+-------------------+
```

### Deliverables

- `docker-compose.c2-lab.yml` -- Isolated C2 lab environment (separate from main lab)
- `c2-lab/mythic/` -- Mythic C2 server configuration
  - `Dockerfile` -- Mythic server with Fawkes agent pre-installed
  - `config.yml` -- Mythic server configuration (ports, credentials)
- `c2-lab/target/` -- Target VM configuration
  - `Dockerfile` -- Windows Server Core with Sysmon, Winlogbeat
  - `sysmon-config.xml` -- Comprehensive Sysmon configuration
  - `winlogbeat.yml` -- Ship Sysmon events to Cribl/ES
- `c2-lab/playbooks/` -- Automated attack sequences
  - `full-kill-chain.yml` -- Complete Fawkes kill chain (recon -> inject -> persist -> exfil)
  - `per-technique/` -- Individual technique playbooks (one per MITRE technique)
- `autonomous/orchestration/live_validation.py` -- Validate detections against live C2 data
- `c2-lab/reports/` -- Comparison reports: synthetic F1 vs live F1

**Attack Playbook Format:**
```yaml
name: "Fawkes Full Kill Chain"
description: "Execute complete Fawkes C2 sequence against target"
steps:
  - name: "Initial callback"
    command: "checkin"
    wait_seconds: 10
    expected_telemetry: ["process_create", "network_connection"]

  - name: "Host reconnaissance"
    commands: ["whoami", "ps", "ifconfig", "drives"]
    wait_seconds: 15
    expected_telemetry: ["process_create x4"]
    detection_target: "T1087.002"

  - name: "Process injection"
    command: "vanilla-injection --pid {target_pid} --shellcode {payload}"
    wait_seconds: 20
    expected_telemetry: ["process_access", "create_remote_thread"]
    detection_target: "T1055.001"

  - name: "Credential access"
    command: "keylog --duration 30"
    wait_seconds: 35
    expected_telemetry: ["api_call"]
    detection_target: "T1056.001"

  - name: "Persistence"
    command: "persist --method registry --key 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' --value 'updater'"
    wait_seconds: 10
    expected_telemetry: ["registry_write"]
    detection_target: "T1547.001"
```

**Live Validation Logic (`live_validation.py`):**
```python
class LiveValidator:
    def __init__(self, mythic_url, es_url):
        self.mythic = MythicClient(mythic_url)
        self.es = ElasticsearchClient(es_url)

    def validate_technique(self, technique_id: str, playbook_step: dict) -> LiveValidationResult:
        """Execute attack command and check if detection fires."""
        # 1. Record pre-attack alert count
        pre_count = self.es.count_alerts(rule_technique=technique_id)

        # 2. Execute Fawkes command via Mythic API
        task = self.mythic.execute_command(playbook_step["command"])
        self.mythic.wait_for_completion(task, timeout=playbook_step["wait_seconds"])

        # 3. Wait for telemetry to flow through pipeline
        time.sleep(30)  # Sysmon -> Winlogbeat -> Cribl -> ES -> Detection rule

        # 4. Check for new alerts
        post_count = self.es.count_alerts(rule_technique=technique_id)
        detected = post_count > pre_count

        # 5. Compare with synthetic validation
        synthetic_f1 = load_synthetic_result(technique_id).get("f1_score", 0)

        return LiveValidationResult(
            technique_id=technique_id,
            detected=detected,
            live_alert_count=post_count - pre_count,
            synthetic_f1=synthetic_f1,
            fidelity_gap=abs(synthetic_f1 - (1.0 if detected else 0.0))
        )
```

**Comparison Report:**
```markdown
# Synthetic vs Live Validation: 2026-03-15

| Technique | Synthetic F1 | Live Detected | Fidelity Gap | Action |
|-----------|-------------|---------------|-------------|--------|
| T1055.001 | 0.95 | YES | 0.05 | None -- detection works |
| T1059.001 | 0.90 | YES | 0.10 | None -- detection works |
| T1547.001 | 0.85 | NO | 0.85 | CRITICAL -- synthetic passes but live misses |
| T1087.002 | 0.80 | YES | 0.20 | None -- detection works |

## Fidelity Assessment
- Synthetic accuracy: 3/4 (75%) -- synthetic results predicted live results
- Action items: T1547.001 synthetic scenario is missing real registry artifacts. Update simulator.
```

### Safety Guardrails

- **Network isolation**: C2 lab on `c2-lab-net` Docker network with no external gateway
- **Rate limiting**: Max 1 C2 command per 10 seconds (prevent accidental DoS)
- **Auto-cleanup**: `docker compose -f docker-compose.c2-lab.yml down --volumes` after validation
- **Credentials**: All C2 credentials in `.env.c2-lab` (gitignored, never committed)
- **Kill switch**: Emergency shutdown script `c2-lab/kill-switch.sh` that stops all C2 containers
- **Resource limits**: Docker memory/CPU limits per container to prevent host impact
- **Logging**: All C2 commands logged to `c2-lab/audit.log` with timestamps

### Requirements

- 16GB+ RAM (Mythic server alone needs 4GB+)
- Docker with Windows container support (Hyper-V isolation for Windows target)
- Mythic C2 Docker image: `mythicmeta/mythic-docker-latest`
- Fawkes agent compiled for target architecture (x64 Windows)
- Alternative: Linux target with Wine for reduced resource requirements

### Implementation Steps

1. Write `docker-compose.c2-lab.yml` with isolated network, Mythic server, target VM
2. Build target container with Sysmon + Winlogbeat configured
3. Install Fawkes agent in Mythic, generate payload for target
4. Write attack playbook YAML for each Fawkes technique
5. Write `live_validation.py` with Mythic API integration
6. Run first live validation against top 5 deployed detections
7. Generate fidelity comparison report
8. Use fidelity gaps to improve simulator accuracy
9. Document resource requirements and setup guide

---

## Capability 3: Behavioral Analytics Engine (12h)

**Branch**: `infra/behavioral-analytics`

### Current State

All 29+ detections are signature-based (pattern matching). They look for specific process names, command-line arguments, registry keys, or network patterns. If an attacker changes their tooling -- different process name, different command syntax, different injection method -- the signature misses.

### Target State

Statistical and ML-based anomaly detection that learns "normal" from baseline data and alerts on deviations. This complements (not replaces) rule-based detection.

### Deliverables

- `autonomous/orchestration/behavioral.py` -- Behavioral analytics engine (baseline profiling + anomaly scoring)
- `autonomous/orchestration/behavioral_rules/` -- Behavioral rule definitions
  - `process_frequency.yml` -- Process creation frequency anomalies
  - `network_pattern.yml` -- Network connection pattern anomalies
  - `registry_modification.yml` -- Registry modification frequency anomalies
  - `file_access.yml` -- File access pattern anomalies
  - `auth_pattern.yml` -- Authentication pattern anomalies
- `templates/behavioral-template.yml` -- Template for authoring behavioral rules
- `tests/behavioral/` -- Test cases for behavioral rules
- Integration with validation agent (test against baseline + attack data)

### Baseline Profiling

Build behavior profiles from `sim-baseline` data (normal enterprise activity):

```python
class BehaviorProfile:
    """Statistical profile of normal behavior for a host/user."""

    def build_from_baseline(self, index="sim-baseline", days=30):
        """Aggregate baseline data into statistical profiles."""
        return {
            "process_creation": {
                "by_user": {
                    "admin": {"mean": 45, "std": 12, "p95": 65},
                    "jdoe": {"mean": 120, "std": 30, "p95": 175}
                },
                "by_host": {
                    "WORKSTATION-01": {"mean": 200, "std": 50, "p95": 290}
                },
                "by_process": {
                    "powershell.exe": {"mean": 5, "std": 3, "p95": 10},
                    "cmd.exe": {"mean": 8, "std": 4, "p95": 15}
                }
            },
            "network_connections": {
                "by_host": {
                    "WORKSTATION-01": {
                        "unique_destinations_per_hour": {"mean": 12, "std": 5, "p95": 22},
                        "unique_ports_per_hour": {"mean": 4, "std": 2, "p95": 8}
                    }
                }
            },
            "registry_modifications": {
                "by_user": {
                    "admin": {"mean": 2, "std": 1, "p95": 5},
                    "SYSTEM": {"mean": 15, "std": 8, "p95": 30}
                }
            },
            "file_access": {
                "by_process": {
                    "explorer.exe": {"mean": 50, "std": 20, "p95": 85},
                    "svchost.exe": {"mean": 10, "std": 5, "p95": 20}
                }
            },
            "authentication": {
                "by_user": {
                    "jdoe": {
                        "login_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                        "source_ips": ["10.0.1.50", "10.0.1.51"],
                        "failed_per_day": {"mean": 0.5, "std": 0.5, "p95": 2}
                    }
                }
            }
        }
```

### Anomaly Detection Rules

**Rule 1: Process Creation Frequency Anomaly**
```yaml
name: "Unusual Process Creation Frequency"
type: behavioral
metric: process_creation_count
group_by: [user.name, host.name]
window: 1h
condition: value > baseline.p95 * 2  # 2x the 95th percentile
severity: medium
mitre:
  tactic: execution
  technique: T1059
description: "User or host is creating significantly more processes than historical baseline"
false_positives:
  - Software deployment
  - System updates
  - Automated testing
```

**Rule 2: Network Destination Explosion**
```yaml
name: "Unusual Network Destination Count"
type: behavioral
metric: unique_destination_ips
group_by: [host.name, process.name]
window: 1h
condition: value > baseline.p95 * 3
severity: high
mitre:
  tactic: command_and_control
  technique: T1071
description: "Process connecting to many more unique destinations than historical norm"
false_positives:
  - CDN prefetch
  - DNS resolver
  - Web crawler
```

**Rule 3: Mass File Modification**
```yaml
name: "Rapid File Modification"
type: behavioral
metric: file_modify_count
group_by: [process.name, user.name]
window: 30s
condition: value > 10 AND process.name NOT IN baseline.known_batch_processes
severity: critical
mitre:
  tactic: impact
  technique: T1486
description: "Process modifying many files rapidly -- possible ransomware encryption"
false_positives:
  - Backup software
  - Archive extraction
  - Build tools (compiler, npm)
```

**Rule 4: Authentication Anomaly**
```yaml
name: "Impossible Travel or Unusual Login"
type: behavioral
metric: auth_source_diversity
group_by: [user.name]
window: 1h
condition: |
  unique_source_ips > baseline.known_sources + 2
  OR login_hour NOT IN baseline.login_hours
  OR failed_count > baseline.p95 * 3
severity: high
mitre:
  tactic: credential_access
  technique: T1110
description: "User authenticating from unusual location, time, or with many failures"
```

**Rule 5: Discovery Burst (Behavioral)**
```yaml
name: "Reconnaissance Command Burst"
type: behavioral
metric: recon_command_count
group_by: [user.name, host.name]
window: 60s
recon_processes: [whoami.exe, net.exe, systeminfo.exe, ipconfig.exe, arp.exe, netstat.exe, nltest.exe, tasklist.exe, query.exe]
condition: value >= 3
severity: high
mitre:
  tactic: discovery
  technique: T1087.002
description: "Multiple reconnaissance commands in rapid succession -- typical post-exploitation behavior"
```

### Implementation Options

**Option A: Elasticsearch ML Jobs (recommended for production)**
```json
{
  "analysis_config": {
    "bucket_span": "15m",
    "detectors": [{
      "function": "high_count",
      "partition_field_name": "user.name",
      "over_field_name": "process.name"
    }],
    "influencers": ["user.name", "host.name", "process.name"]
  },
  "data_description": {
    "time_field": "@timestamp"
  },
  "datafeed_config": {
    "indices": ["sim-baseline", "sim-attack"],
    "query": {"bool": {"must": [{"term": {"event.category": "process"}}]}}
  }
}
```

**Option B: Python-Based Scoring (recommended for lab/CI)**
```python
class AnomalyScorer:
    def __init__(self, baseline_profile: BehaviorProfile):
        self.profile = baseline_profile

    def score_event_window(self, events: list[dict], rule: BehavioralRule) -> float:
        """Compute anomaly score for a window of events."""
        metric_value = self.compute_metric(events, rule.metric, rule.group_by)
        baseline = self.profile.get_baseline(rule.metric, rule.group_by, events[0])

        if baseline is None:
            return 0.5  # Unknown entity -- moderate suspicion

        z_score = (metric_value - baseline["mean"]) / max(baseline["std"], 0.1)
        return min(z_score / 10.0, 1.0)  # Normalize to 0-1
```

**Option C: Hybrid (recommended overall)**
- ES ML jobs for production anomaly detection (real-time)
- Python scoring for validation and CI (offline, deterministic)
- Both feed into the same alert pipeline

### Integration with Rule-Based Detection

Behavioral scores augment rule-based detections:
```
Rule fires + behavioral anomaly = HIGH CONFIDENCE alert (escalate)
Rule fires + normal behavior    = MEDIUM CONFIDENCE (possible FP, investigate)
No rule   + behavioral anomaly  = LOW CONFIDENCE (coverage gap indicator, create issue)
```

### Implementation Steps

1. Write `behavioral.py` with `BehaviorProfile`, `AnomalyScorer`, `BehavioralRule` classes
2. Define 5 behavioral rules in `behavioral_rules/` directory
3. Create baseline profiles from `sim-baseline` data
4. Write Python-based scoring for CI validation
5. Create ES ML job definitions for production use (if ES ML license available)
6. Test against `sim-attack` data -- verify anomaly scores are elevated
7. Integrate anomaly scores with existing alert pipeline
8. Add behavioral rule template to `templates/behavioral-template.yml`
9. Document: when to use rules vs behavioral vs both

---

## Capability 4: Multi-SIEM Abstraction Layer (8h)

**Branch**: `infra/multi-siem-abstraction`

### Current State

Hardcoded Elasticsearch and Splunk integration in `autonomous/orchestration/siem.py`. Adding a new SIEM means modifying core deployment code, duplicating logic, and risking regressions.

### Target State

Pluggable SIEM backend architecture where adding a new SIEM requires only implementing an interface and adding a config entry.

### Deliverables

- `autonomous/orchestration/siem/` -- Refactored SIEM module (replaces monolithic `siem.py`)
  - `base.py` -- Abstract SIEM backend interface
  - `registry.py` -- Backend discovery and instantiation
  - `elasticsearch.py` -- Elasticsearch backend (extracted from current `siem.py`)
  - `splunk.py` -- Splunk backend (extracted from current `siem.py`)
  - `sentinel.py` -- Microsoft Sentinel backend (stub with interface, no implementation)
  - `chronicle.py` -- Google Chronicle/SecOps backend (stub with interface, no implementation)
- Updated `config.yml` with multi-backend configuration
- Updated deployment agent to deploy to all active backends

### Interface Definition

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional

@dataclass
class DetectionRule:
    """Platform-agnostic detection rule representation."""
    rule_id: str
    name: str
    description: str
    sigma_path: str
    compiled_query: str  # Platform-specific query (filled by transpile())
    severity: str
    mitre_tactic: str
    mitre_technique: str
    enabled: bool = True

@dataclass
class DeploymentResult:
    success: bool
    backend: str
    rule_id: str
    message: str
    deployed_at: Optional[str] = None

@dataclass
class Alert:
    rule_id: str
    rule_name: str
    timestamp: str
    severity: str
    host: str
    user: Optional[str]
    raw_event: dict

@dataclass
class ValidationResult:
    valid: bool
    backend: str
    query: str
    error: Optional[str] = None
    sample_results: int = 0

@dataclass
class HealthStatus:
    backend: str
    healthy: bool
    version: str
    message: str
    latency_ms: int


class SIEMBackend(ABC):
    """Abstract interface that all SIEM backends must implement."""

    @abstractmethod
    def deploy_rule(self, rule: DetectionRule) -> DeploymentResult:
        """Deploy a detection rule to this SIEM."""
        ...

    @abstractmethod
    def undeploy_rule(self, rule_id: str) -> DeploymentResult:
        """Remove a detection rule from this SIEM."""
        ...

    @abstractmethod
    def get_alerts(self, rule_id: str, timerange: str = "24h") -> list[Alert]:
        """Retrieve alerts generated by a specific rule."""
        ...

    @abstractmethod
    def get_alert_count(self, rule_id: str, timerange: str = "24h") -> int:
        """Get count of alerts for a rule (more efficient than get_alerts)."""
        ...

    @abstractmethod
    def validate_query(self, query: str, index: str) -> ValidationResult:
        """Test that a query is syntactically valid without executing it."""
        ...

    @abstractmethod
    def search(self, query: str, index: str, size: int = 10) -> list[dict]:
        """Run a search query and return matching documents."""
        ...

    @abstractmethod
    def get_health(self) -> HealthStatus:
        """Check backend connectivity and health."""
        ...

    @abstractmethod
    def transpile(self, sigma_rule_path: str) -> str:
        """Convert Sigma rule to this backend's native query language."""
        ...

    @abstractmethod
    def get_available_fields(self, index: str) -> list[str]:
        """List available fields in an index (for data source validation)."""
        ...
```

### Backend Registry

```python
class SIEMRegistry:
    """Discover and manage active SIEM backends."""

    _backends: dict[str, type[SIEMBackend]] = {}

    @classmethod
    def register(cls, name: str, backend_class: type[SIEMBackend]):
        cls._backends[name] = backend_class

    @classmethod
    def get_active_backends(cls, config: dict) -> list[SIEMBackend]:
        """Instantiate all backends marked as active in config."""
        active = []
        for name, settings in config.get("siem_backends", {}).items():
            if settings.get("enabled", False) and name in cls._backends:
                backend = cls._backends[name](**settings.get("params", {}))
                if backend.get_health().healthy:
                    active.append(backend)
        return active

    @classmethod
    def deploy_to_all(cls, rule: DetectionRule, backends: list[SIEMBackend]) -> list[DeploymentResult]:
        """Deploy a rule to all active backends."""
        results = []
        for backend in backends:
            compiled = backend.transpile(rule.sigma_path)
            rule.compiled_query = compiled
            result = backend.deploy_rule(rule)
            results.append(result)
        return results
```

### Configuration

```yaml
# config.yml
siem_backends:
  elasticsearch:
    enabled: true
    params:
      url: "${ES_URL}"
      username: "${ES_USER}"
      password: "${ES_PASS}"
      kibana_url: "${KIBANA_URL}"
    sigma_target: "lucene"
    sigma_pipeline: "ecs_windows"

  splunk:
    enabled: true
    params:
      url: "${SPLUNK_URL}"
      username: "${SPLUNK_USER}"
      password: "${SPLUNK_PASS}"
      verify_ssl: false
    sigma_target: "splunk"
    sigma_pipeline: null

  sentinel:
    enabled: false
    params:
      workspace_id: ""
      tenant_id: ""
      client_id: ""
      client_secret: ""
    sigma_target: "kusto"
    sigma_pipeline: null

  chronicle:
    enabled: false
    params:
      project_id: ""
      region: ""
      credentials_file: ""
    sigma_target: "chronicle"
    sigma_pipeline: null
```

### Transpilation Targets

| Backend | Sigma Target | Pipeline | Output Format |
|---------|-------------|----------|---------------|
| Elasticsearch | `lucene` | `ecs_windows` | Lucene query string |
| Splunk | `splunk` | (none) | SPL query |
| Sentinel | `kusto` | `azure_monitor` | KQL query |
| Chronicle | `chronicle` | (none) | YARA-L rule |

### Implementation Steps

1. Create `autonomous/orchestration/siem/` directory structure
2. Define `SIEMBackend` ABC in `base.py`
3. Extract Elasticsearch logic from `siem.py` into `elasticsearch.py`
4. Extract Splunk logic from `siem.py` into `splunk.py`
5. Create Sentinel and Chronicle stubs (interface only, raise `NotImplementedError`)
6. Write `registry.py` with backend discovery and multi-deploy
7. Update `config.yml` with backend configuration
8. Update deployment agent to use registry instead of direct `siem.py` calls
9. Add `cli.py backends` command to list active backends and their health
10. Write tests: mock backends for CI, real backends for integration

---

## Capability 5: Detection Marketplace (6h)

**Branch**: `infra/detection-marketplace`

### Current State

Detections exist only in this repository. There is no packaging format for external consumption, no versioning for individual detections, and no way for community members to install or contribute detection content.

### Target State

Validated detection content packaged into distributable packs with quality gates, versioning, and automated publishing.

### Deliverables

- `marketplace/` -- Marketplace directory structure
  - `packs/` -- Published content packs
  - `pack-template/` -- Template for creating new packs
  - `build-pack.py` -- Pack builder (bundle rule + tests + compiled + metadata)
  - `import-pack.py` -- Pack importer (install community pack into lab)
- `marketplace/packs/fawkes-injection/` -- Example pack: Fawkes injection techniques
- `.github/workflows/publish-packs.yml` -- CI workflow to build and publish packs as GitHub Releases
- CLI extensions: `cli.py pack build`, `cli.py pack import`, `cli.py pack list`

### Pack Format

Each pack is a ZIP file containing:
```
fawkes-injection-v1.0.0.zip
  fawkes-injection/
  +-- pack.yml                    # Pack metadata
  +-- rules/
  |   +-- t1055-001-createremotethread.yml    # Sigma rule
  |   +-- t1055-004-apc-injection.yml
  |   +-- t1055-threadless-injection.yml
  +-- compiled/
  |   +-- elasticsearch/
  |   |   +-- t1055-001-createremotethread.lucene
  |   |   +-- t1055-001-createremotethread_elastic.json
  |   +-- splunk/
  |   |   +-- t1055-001-createremotethread.spl
  |   +-- sentinel/
  |       +-- t1055-001-createremotethread.kql
  +-- tests/
  |   +-- true_positives/
  |   |   +-- t1055-001_tp.json
  |   +-- true_negatives/
  |       +-- t1055-001_tn.json
  +-- navigator-layer.json        # ATT&CK Navigator visualization
  +-- README.md                   # Auto-generated from pack.yml
```

### Pack Metadata (`pack.yml`)

```yaml
name: "Fawkes Process Injection"
version: "1.0.0"
description: "Detection rules for Fawkes C2 process injection techniques"
author: "Patronus Lab"
license: "MIT"
created: "2026-03-15"
modified: "2026-03-15"

threat_actor: "Fawkes C2"
mitre_tactics: ["defense-evasion", "privilege-escalation"]
mitre_techniques: ["T1055.001", "T1055.004", "T1055"]

rules:
  - id: "t1055-001-createremotethread"
    name: "Fawkes CreateRemoteThread Injection"
    f1_score: 0.95
    validation_method: "elasticsearch"
    status: "MONITORING"
    severity: "high"

  - id: "t1055-004-apc-injection"
    name: "Fawkes APC Injection"
    f1_score: 0.90
    validation_method: "elasticsearch"
    status: "VALIDATED"
    severity: "high"

data_sources_required:
  - "Sysmon EventID 8 (CreateRemoteThread)"
  - "Sysmon EventID 10 (ProcessAccess)"
  - "Sysmon EventID 1 (ProcessCreate)"

platforms:
  - elasticsearch
  - splunk
  - sentinel
```

### Quality Gate

Only publish packs meeting these criteria:
- ALL rules in the pack have F1 >= 0.90
- ALL rules have both TP and TN test cases
- ALL rules have compiled output for at least Elasticsearch and Splunk
- Pack metadata is complete (no empty fields)
- No secrets or credentials in any file
- README auto-generated and accurate

### Publishing Workflow

```yaml
# .github/workflows/publish-packs.yml
name: Publish Detection Packs
on:
  push:
    branches: [main]
    paths: ['marketplace/packs/**']

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
      - name: Build packs
        run: |
          for pack_dir in marketplace/packs/*/; do
            pack_name=$(basename "$pack_dir")
            python marketplace/build-pack.py "$pack_dir" --output "dist/${pack_name}.zip"
          done
      - name: Quality gate
        run: python marketplace/quality-gate.py dist/*.zip
      - name: Create release
        uses: softprops/action-gh-release@v2
        with:
          tag_name: "packs-${{ github.sha }}"
          files: dist/*.zip
          body: "Detection pack release"
```

### ATT&CK Navigator Layer (per pack)

```json
{
  "name": "Fawkes Process Injection Pack",
  "versions": { "attack": "14", "navigator": "4.9.1", "layer": "4.5" },
  "domain": "enterprise-attack",
  "techniques": [
    {
      "techniqueID": "T1055.001",
      "color": "#00ff00",
      "comment": "MONITORING | F1: 0.95",
      "score": 95,
      "metadata": [{ "name": "pack", "value": "fawkes-injection" }]
    },
    {
      "techniqueID": "T1055.004",
      "color": "#ffff00",
      "comment": "VALIDATED | F1: 0.90",
      "score": 90
    }
  ]
}
```

### CLI Extensions

```bash
# Build a pack from a directory
python orchestration/cli.py pack build marketplace/packs/fawkes-injection/

# Import a community pack
python orchestration/cli.py pack import downloaded-pack.zip

# List available packs
python orchestration/cli.py pack list

# Validate a pack against quality gate
python orchestration/cli.py pack validate marketplace/packs/fawkes-injection/
```

### Implementation Steps

1. Design pack directory structure and `pack.yml` schema
2. Write `build-pack.py` to bundle rules, tests, compiled outputs, and metadata
3. Write `import-pack.py` to extract pack into lab detection directories
4. Write quality gate script to enforce publishing standards
5. Create example pack: `fawkes-injection` with T1055.001 and related rules
6. Generate ATT&CK Navigator layer per pack
7. Write auto-README generator from `pack.yml` metadata
8. Create GitHub Actions workflow for automated publishing
9. Add `pack` subcommand to `cli.py`
10. Test: build pack, import pack into clean lab, verify detections load

---

## Capability 6: SOAR Integration (4h)

**Branch**: `infra/soar-integration`

### Current State

Detections fire alerts. No automated response. Analysts must manually investigate, contain, and remediate every alert. In a production SOC, this does not scale.

### Target State

Link detections to response playbooks for automated or semi-automated incident response. Support dry-run mode for the lab environment.

### Deliverables

- `playbooks/` -- Response playbook directory
  - `templates/` -- Base playbook templates
    - `isolate-host.yml` -- Network isolate compromised endpoint
    - `collect-evidence.yml` -- Pull additional forensic data
    - `disable-account.yml` -- Lock compromised account
    - `notify-soc.yml` -- Alert SOC team via Slack/email/webhook
    - `create-ticket.yml` -- Create incident ticket in external system
  - `mappings/` -- Detection-to-playbook mappings
    - `process-injection.yml` -- Response for T1055.* detections
    - `credential-access.yml` -- Response for T1003.* detections
    - `persistence.yml` -- Response for T1547.* detections
- `autonomous/orchestration/soar.py` -- SOAR execution engine
- `autonomous/orchestration/soar_backends/` -- Integration backends
  - `webhook.py` -- Generic webhook backend (works with any SOAR)
  - `shuffle.py` -- Shuffle SOAR integration (stub)
  - `tines.py` -- Tines integration (stub)

### Playbook Format

```yaml
# playbooks/templates/isolate-host.yml
name: "Isolate Compromised Host"
description: "Network-isolate a host where high-severity malicious activity was detected"
version: "1.0.0"

trigger:
  min_severity: "high"
  mitre_tactics: ["execution", "defense-evasion", "privilege-escalation"]
  conditions:
    - field: "kibana.alert.risk_score"
      operator: ">="
      value: 75

actions:
  - step: 1
    name: "Collect volatile evidence"
    type: "collect_evidence"
    target: "{{ alert.host.name }}"
    params:
      artifacts:
        - process_list
        - network_connections
        - loaded_modules
        - open_files
    timeout: 120
    continue_on_failure: true

  - step: 2
    name: "Isolate host from network"
    type: "isolate_host"
    target: "{{ alert.host.name }}"
    params:
      method: "elastic_endpoint"  # or "firewall_rule" or "vlan_change"
      allow_list:
        - "10.0.0.1"  # Management interface
        - "10.0.0.5"  # SIEM collector
    requires_approval: true  # Pause for human approval in production
    timeout: 60

  - step: 3
    name: "Disable compromised account"
    type: "disable_account"
    target: "{{ alert.user.name }}"
    params:
      method: "active_directory"
    condition: "alert.user.name != 'SYSTEM'"
    requires_approval: true

  - step: 4
    name: "Notify SOC"
    type: "notify"
    params:
      channel: "webhook"
      url: "{{ env.SOC_WEBHOOK_URL }}"
      message: |
        ALERT: {{ alert.rule.name }}
        Host: {{ alert.host.name }}
        User: {{ alert.user.name }}
        Severity: {{ alert.severity }}
        Actions taken: Evidence collected, host isolated
    timeout: 30

  - step: 5
    name: "Create incident ticket"
    type: "create_ticket"
    params:
      system: "github_issue"  # Lab uses GitHub Issues as ticket system
      title: "[Incident] {{ alert.rule.name }} on {{ alert.host.name }}"
      body: |
        ## Incident Summary
        - **Detection**: {{ alert.rule.name }}
        - **Technique**: {{ alert.rule.mitre_technique }}
        - **Host**: {{ alert.host.name }}
        - **User**: {{ alert.user.name }}
        - **Timestamp**: {{ alert.timestamp }}

        ## Automated Actions
        1. Volatile evidence collected
        2. Host network-isolated
        3. User account disabled

        ## Next Steps
        - [ ] Review collected evidence
        - [ ] Determine attack scope
        - [ ] Begin forensic analysis
        - [ ] Plan remediation
      labels: ["incident", "auto-response"]
```

### Detection-to-Playbook Mapping

```yaml
# playbooks/mappings/process-injection.yml
name: "Process Injection Response"
applies_to:
  mitre_techniques: ["T1055.001", "T1055.004", "T1055"]
  rule_name_pattern: "*injection*"

playbook_chain:
  - playbook: "collect-evidence.yml"
    override:
      params:
        artifacts: [process_list, loaded_modules, memory_regions]
  - playbook: "isolate-host.yml"
  - playbook: "notify-soc.yml"
  - playbook: "create-ticket.yml"
```

### SOAR Execution Engine

```python
class SOAREngine:
    def __init__(self, config: dict, dry_run: bool = True):
        self.config = config
        self.dry_run = dry_run
        self.backends = self._load_backends()

    def execute_playbook(self, playbook: Playbook, alert: Alert) -> PlaybookResult:
        """Execute a playbook in response to an alert."""
        results = []
        for action in playbook.actions:
            # Check condition
            if action.condition and not self._evaluate_condition(action.condition, alert):
                results.append(ActionResult(action.name, "SKIPPED", "Condition not met"))
                continue

            # Check approval requirement
            if action.requires_approval and not self.dry_run:
                # In production: pause and wait for human approval
                # In lab: log and continue (dry_run handles this)
                pass

            if self.dry_run:
                # Log what WOULD happen without executing
                results.append(ActionResult(
                    action.name, "DRY_RUN",
                    f"Would execute: {action.type} on {action.target}"
                ))
            else:
                # Execute the action via appropriate backend
                result = self._execute_action(action, alert)
                results.append(result)

                if not result.success and not action.continue_on_failure:
                    break  # Stop playbook on failure

        return PlaybookResult(playbook.name, results)
```

### Dry-Run Mode

Critical for the lab environment. Dry-run mode:
- Logs every action that WOULD be taken
- Does not isolate hosts, disable accounts, or send notifications
- Generates a full execution report showing the playbook flow
- Validates that all template variables resolve correctly
- Measures theoretical response time (sum of action timeouts)

```bash
# Dry run (default in lab)
python orchestration/cli.py soar test T1055.001 --dry-run

# Example output:
# SOAR Dry Run: Process Injection Response
# Alert: Fawkes CreateRemoteThread Injection on WORKSTATION-01
#
# Step 1: Collect volatile evidence -> DRY_RUN (would collect: process_list, loaded_modules, memory_regions)
# Step 2: Isolate host from network -> DRY_RUN (would isolate WORKSTATION-01, allow: 10.0.0.1, 10.0.0.5)
# Step 3: Disable compromised account -> SKIPPED (user is SYSTEM)
# Step 4: Notify SOC -> DRY_RUN (would POST to webhook)
# Step 5: Create incident ticket -> DRY_RUN (would create GitHub Issue)
#
# Theoretical response time: 5m 30s
# Actions: 3 executed, 1 skipped, 0 failed
```

### Metrics

Track response playbook effectiveness:
- **Mean Time to Respond (MTTR)**: Time from alert to last playbook action
- **Playbook Success Rate**: % of playbook executions completing without failure
- **Action Coverage**: % of detections with mapped playbooks
- **Approval Wait Time**: Time spent waiting for human approval (in production mode)

### Implementation Steps

1. Define playbook YAML schema and template format
2. Write `soar.py` with `SOAREngine`, `Playbook`, `PlaybookResult` classes
3. Create 5 base playbook templates (isolate, collect, disable, notify, ticket)
4. Create detection-to-playbook mappings for deployed detections
5. Implement webhook backend for generic SOAR integration
6. Implement dry-run mode with detailed execution logging
7. Add `soar` subcommand to `cli.py` (test, list, validate)
8. Create Shuffle and Tines backend stubs for future integration
9. Test: dry-run each mapped playbook, verify output
10. Document: how to connect a real SOAR platform

---

## Quick Reference: Capability Priority

| # | Capability | Effort | Value | Risk | Recommended Order | Start After |
|---|-----------|--------|-------|------|-------------------|-------------|
| 1 | Agent SDK | 8h | High | Low | 1st | Anytime |
| 2 | Live C2 | 12h | Very High | Medium | 3rd | Phase 5 |
| 3 | Behavioral Analytics | 12h | Very High | High | 4th | Phase 5 |
| 4 | Multi-SIEM | 8h | Medium | Low | 2nd | Phase 4 |
| 5 | Marketplace | 6h | Medium | Low | 5th | Phase 6 |
| 6 | SOAR | 4h | Medium | Medium | 6th | Phase 7 |

**Rationale for ordering:**
- **Agent SDK first**: Quick win that improves every subsequent capability. No phase dependency.
- **Multi-SIEM second**: Makes all detection content portable. Only needs Phase 4.
- **Live C2 third**: Most impressive demonstration of the platform. Needs Phase 5 data engineering.
- **Behavioral analytics fourth**: Most technically ambitious. Needs solid baseline data from Phase 5.
- **Marketplace fifth**: Community value, but requires mature content (Phase 6) and quality metrics (Phase 7).
- **SOAR sixth**: Needs a real SOC or extensive dry-run testing to be meaningful. Benefits from Phase 7 feedback loops.

---

## Validation Criteria

- [ ] At least 2 capabilities implemented end-to-end
- [ ] Agent SDK running at least 1 agent (e.g., quality agent) end-to-end with native tool use
- [ ] Agent SDK showing real token counts instead of estimates
- [ ] Multi-SIEM abstraction supporting Elasticsearch + Splunk backends with shared interface
- [ ] Multi-SIEM deploying same Sigma rule to 2 backends in single command
- [ ] Each implemented capability has:
  - Working code with error handling
  - At least 1 test (unit or integration)
  - CLI integration (`cli.py` subcommand)
  - Documentation in relevant files

---

## Commit Strategy

Per-capability branches (fully independent, can be developed in parallel):

| Capability | Branch | Commits |
|-----------|--------|---------|
| Agent SDK | `infra/agent-sdk-migration` | `feat(agents): add SDK runner with native tool use`, `refactor(agents): convert blue-team agent to SDK format`, `feat(agents): add token counting from API response` |
| Live C2 | `infra/live-c2-lab` | `feat(c2): add Mythic + Fawkes isolated Docker lab`, `feat(validation): add live C2 validation module`, `docs(c2): add safety guardrails and setup guide` |
| Behavioral | `infra/behavioral-analytics` | `feat(behavioral): add baseline profiling from sim-baseline`, `feat(behavioral): add anomaly scoring engine`, `feat(behavioral): add 5 behavioral detection rules` |
| Multi-SIEM | `infra/multi-siem-abstraction` | `refactor(siem): extract backend interface and registry`, `refactor(siem): migrate ES + Splunk to pluggable backends`, `feat(siem): add Sentinel and Chronicle stubs` |
| Marketplace | `infra/detection-marketplace` | `feat(marketplace): add pack format and build tool`, `feat(marketplace): add quality gate and import tool`, `feat(ci): add pack publishing workflow` |
| SOAR | `infra/soar-integration` | `feat(soar): add playbook engine with dry-run mode`, `feat(soar): add 5 response templates`, `feat(soar): add detection-to-playbook mapping` |

---

## Notes for Future Sessions

- Each capability is **fully independent** -- pick what interests you or what aligns with your goals
- Capabilities 1 (Agent SDK) and 4 (Multi-SIEM) are the most practical improvements with lowest risk
- Capability 2 (Live C2) produces the most impressive demo but requires significant infrastructure (16GB+ RAM, Windows containers)
- Capability 3 (Behavioral Analytics) is the most technically ambitious and represents genuine research
- Capability 5 (Marketplace) has the most community value if the project is public
- Capability 6 (SOAR) is most valuable in a production SOC context; dry-run mode makes it useful in a lab
- All capabilities build on the foundation from Phases 4-7 -- the stronger that foundation, the easier these become
