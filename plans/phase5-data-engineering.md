# Phase 5: Data Engineering at Scale

**Status**: NOT STARTED
**Priority**: HIGH
**Estimated effort**: 16-20 hours (multi-session)
**Dependencies**: Phase 4 (log source registry, agent refactoring) should be complete
**Branch**: `infra/phase5-data-engineering` (or per-task branches)

---

## Context

In real detection engineering, 60% of the work is data engineering:
- "Why are 30% of events missing `process.command_line`?"
- "The EDR vendor changed their schema in the latest update"
- "We need Linux auditd but nobody's configured it yet"
- "How do we know if a log source goes offline?"

Without solving these problems, detection rules are worthless. Phase 3 laid the groundwork
with `simulator/raw_events.py` (ECS-to-raw converter for Windows Sysmon and Security events)
and the Cribl streaming validation path. Phase 5 extends this into a full data engineering
platform: multi-platform simulation, schema versioning, data quality monitoring, and automated
gap detection.

### What Previous Phases Built (Leverage Points)

| Phase | Asset | Phase 5 Leverage |
|-------|-------|-----------------|
| Phase 2 | `validation.py` — ES-based SIEM validation | Data quality checks reuse ES query patterns |
| Phase 3 | `raw_events.py` — ECS-to-raw converter (Sysmon/WinSec) | Extend with Linux, cloud, network converters |
| Phase 3 | `gaps/data-sources/*.yml` — 9 structured gap files | Data quality engine reads these as source expectations |
| Phase 3 | `pipeline/configure-cribl.sh` — Cribl pipeline setup | Extend with per-source pipeline creation |
| Phase 3 | `cli.py data-sources` — gap status reporting | Extend with `cli.py data-quality` and `cli.py schema-diff` |
| Phase 4 | Log Source Registry (from agent refactoring) | Data quality engine reads registry for expected sources |
| Phase 4 | Data Onboarding Agent (new agent) | Runs health checks, manages source lifecycle |

---

## Task 5.1: Data Quality Monitoring Engine (4h)

Build automated monitoring for all registered log sources.

### Deliverables

- `autonomous/orchestration/data_quality.py` — Data quality engine (~400 lines)
- Per-source health scoring: freshness, completeness, volume, schema compliance
- Source health dashboard data (JSON export for Kibana visualization)
- Alerting thresholds: stale sources, degraded field completeness, volume anomalies
- Integration with Phase 4's Data Onboarding Agent (agent calls `data_quality.run_checks()`)

### Health Scoring Algorithm

```python
def compute_health_score(source_id: str, es_url: str, auth: tuple) -> dict:
    """
    Compute composite health score for a log source.

    Returns:
        {
            "source_id": "sysmon_eid_1",
            "timestamp": "2026-03-15T12:00:00Z",
            "freshness": {"score": 1.0, "status": "green", "last_event": "2026-03-15T11:58:32Z"},
            "completeness": {"score": 0.85, "status": "yellow", "fields_present": 17, "fields_expected": 20},
            "volume": {"score": 1.0, "status": "green", "events_24h": 4523, "expected_24h": 5000},
            "schema": {"score": 0.98, "status": "green", "conforming_pct": 98.2},
            "composite": 0.93,
            "composite_status": "green"
        }
    """

health_score = (
    freshness_score * 0.3 +      # Time since last event
    completeness_score * 0.3 +   # % of expected fields populated
    volume_score * 0.2 +         # Events/day vs expected baseline
    schema_score * 0.2           # % matching expected schema
)
```

**Thresholds:**

| Dimension | Green (1.0) | Yellow (0.7) | Red (0.3) | Dead (0.0) |
|-----------|------------|-------------|----------|-----------|
| Freshness | < 5 min | < 15 min | > 15 min | > 1 hour |
| Completeness | > 95% | > 80% | < 80% | — |
| Volume | +/- 20% expected | +/- 50% | > +/- 50% | 0 events |
| Schema | > 99% | > 95% | < 95% | — |

### Implementation Detail

**Step 1 — Define source expectations** (from log source registry + gap files):

```yaml
# autonomous/orchestration/source_expectations.yml
# OR: dynamically loaded from Phase 4 log source registry
sources:
  sysmon_eid_1:
    index_pattern: "sim-*"
    filter: {"term": {"event.code": "1"}}
    expected_fields:
      - process.name
      - process.executable
      - process.command_line
      - process.pid
      - process.parent.name
      - process.parent.command_line
      - user.name
      - host.name
      - "@timestamp"
    expected_volume_24h: 5000
    freshness_threshold_minutes: 15
  sysmon_eid_3:
    index_pattern: "sim-*"
    filter: {"term": {"event.code": "3"}}
    expected_fields:
      - process.name
      - source.ip
      - source.port
      - destination.ip
      - destination.port
      - network.protocol
    expected_volume_24h: 8000
    freshness_threshold_minutes: 15
```

**Step 2 — Query Elasticsearch for each source:**

```python
def _check_freshness(self, source: dict) -> dict:
    """Query max(@timestamp) for the source's filter criteria."""
    query = {
        "size": 0,
        "query": source["filter"],
        "aggs": {"latest": {"max": {"field": "@timestamp"}}}
    }
    # POST {es_url}/{index_pattern}/_search
    ...

def _check_completeness(self, source: dict) -> dict:
    """Aggregation: count docs with non-null value for each expected field."""
    aggs = {}
    for field in source["expected_fields"]:
        aggs[f"has_{field.replace('.', '_')}"] = {
            "filter": {"exists": {"field": field}}
        }
    query = {"size": 0, "query": source["filter"], "aggs": aggs}
    # Completeness = fields_with_docs / total_expected_fields
    ...

def _check_volume(self, source: dict) -> dict:
    """Count docs in last 24h, compare to expected baseline."""
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [source["filter"]],
                "filter": [{"range": {"@timestamp": {"gte": "now-24h"}}}]
            }
        }
    }
    ...

def _check_schema(self, source: dict) -> dict:
    """Sample 100 docs, check each has all expected fields with correct types."""
    ...
```

**Step 3 — Store results and alert:**

```
monitoring/data-quality/
  sysmon_eid_1.json       # Latest health check result
  sysmon_eid_3.json
  ...
  history.jsonl           # Append-only history for trending
```

**Alert conditions** (Data Onboarding Agent creates GitHub issues):
- Composite score drops below 0.5 for any source
- Freshness goes to "dead" (> 1 hour since last event)
- Volume drops > 80% from expected (possible data loss)
- New fields appear not in expected schema (possible vendor update)

### CLI Extension

```
python orchestration/cli.py data-quality               # Run all checks, show summary
python orchestration/cli.py data-quality --source sysmon_eid_1  # Single source
python orchestration/cli.py data-quality --export       # Export JSON for Kibana
```

---

## Task 5.2: Multi-Platform Simulation (5h)

Extend the simulator to generate Linux, macOS, cloud, and network events. Currently
`simulator/simulator.py` generates Windows-only ECS events. The generator architecture
needs to support pluggable platform modules.

### Deliverables

- `simulator/generators/` — New directory for platform-specific generators
- `simulator/generators/__init__.py` — Generator registry and dynamic loader
- `simulator/generators/linux.py` — Linux auditd event generators (~300 lines)
- `simulator/generators/cloud.py` — AWS CloudTrail event generators (~250 lines)
- `simulator/generators/network.py` — Zeek-style network flow generators (~250 lines)
- `simulator/generators/macos.py` — macOS unified log generators (~200 lines)
- Updated `simulator/simulator.py` — Dynamic generator loading by platform
- Scenario files per platform: `simulator/scenarios/<platform>/`

### Generator Architecture

```python
# simulator/generators/__init__.py

class PlatformGenerator:
    """Base class for platform-specific event generators."""

    platform: str = ""  # "windows", "linux", "macos", "cloud", "network"
    event_types: list[str] = []  # List of event types this generator handles

    def generate_attack(self, technique_id: str, **kwargs) -> list[dict]:
        """Generate attack events for a given technique. Returns ECS dicts."""
        raise NotImplementedError

    def generate_benign(self, event_type: str, count: int = 5) -> list[dict]:
        """Generate benign/baseline events. Returns ECS dicts."""
        raise NotImplementedError


# Registry
_generators: dict[str, PlatformGenerator] = {}

def register_generator(gen: PlatformGenerator):
    _generators[gen.platform] = gen

def get_generator(platform: str) -> PlatformGenerator:
    return _generators[platform]

def list_platforms() -> list[str]:
    return list(_generators.keys())
```

### Linux auditd Event Generators (`simulator/generators/linux.py`)

**Supported event types:**
- `SYSCALL` + `EXECVE` — Process execution (equivalent to Sysmon EID 1)
- `PATH` — File access/creation (equivalent to Sysmon EID 11)
- `USER_AUTH` / `USER_LOGIN` — Authentication events
- `CRED_ACQ` / `CRED_DISP` — Credential operations
- `CONFIG_CHANGE` — System configuration modifications

**Linux attack scenarios** (stored in `simulator/scenarios/linux/`):

| Technique | File | Description | Key Fields |
|-----------|------|-------------|------------|
| T1053.003 | `t1053_003_crontab.json` | Crontab persistence — `crontab -e` adds reverse shell entry | `process.name=crontab`, `process.args=["-e"]`, `file.path=/var/spool/cron/crontabs/root` |
| T1059.004 | `t1059_004_bash.json` | Unix shell execution — `bash -c` with base64-encoded command | `process.name=bash`, `process.args=["-c", "eval $(echo <b64> \| base64 -d)"]` |
| T1098 | `t1098_ssh_keys.json` | SSH authorized_keys modification | `file.path=/home/*/.ssh/authorized_keys`, `process.name=tee` |
| T1136.001 | `t1136_001_useradd.json` | Local account creation via `useradd` | `process.name=useradd`, `process.args=["--shell", "/bin/bash", "backdoor"]` |

**Linux benign scenarios:**
- Legitimate cron job editing by sysadmin
- Normal SSH key rotation during provisioning
- Package manager processes (apt, yum) creating system accounts
- Standard bash usage for automation scripts

**ECS field mapping for Linux events:**

```python
def _generate_linux_process_create(self, cmd: str, args: list, user: str = "root",
                                    hostname: str = "ubuntu-web-01") -> dict:
    return {
        "@timestamp": _now_iso(),
        "event": {"category": "process", "type": "start", "kind": "event",
                  "module": "auditd", "dataset": "auditd.log"},
        "agent": {"type": "auditbeat"},
        "host": {"name": hostname, "os": {"family": "linux", "platform": "ubuntu"}},
        "process": {
            "name": cmd,
            "executable": f"/usr/bin/{cmd}",
            "args": args,
            "command_line": f"{cmd} {' '.join(args)}",
            "pid": _random_pid(),
            "parent": {"name": "bash", "pid": _random_pid()}
        },
        "user": {"name": user, "id": "0" if user == "root" else str(_random_uid())},
        "auditd": {"log": {"record_type": "SYSCALL"}, "data": {"syscall": "execve"}}
    }
```

### AWS CloudTrail Event Generators (`simulator/generators/cloud.py`)

**Supported event types:**
- `AwsApiCall` — API calls (CreateAccessKey, RunInstances, GetObject, etc.)
- `AwsConsoleSignIn` — Console login events
- `AwsServiceEvent` — Service-initiated events (GuardDuty, Config)

**Cloud attack scenarios** (stored in `simulator/scenarios/cloud/`):

| Technique | File | Description | Key Fields |
|-----------|------|-------------|------------|
| T1078.004 | `t1078_004_cloud_abuse.json` | Unusual API calls from new IP/region | `event.action=ConsoleLogin`, `source.ip=<unusual>`, `cloud.region=<new>` |
| T1530 | `t1530_s3_access.json` | S3 data access from unusual principal | `event.action=GetObject`, `cloud.service.name=s3`, `aws.s3.bucket.name=sensitive-data` |
| T1098.001 | `t1098_001_cloud_creds.json` | Additional IAM credentials created | `event.action=CreateAccessKey`, `aws.iam.target_user=admin` |
| T1537 | `t1537_transfer_data.json` | Data transfer to external account | `event.action=PutBucketPolicy`, `aws.s3.bucket.policy.principal=*` |

**CloudTrail ECS mapping:**

```python
def _generate_cloudtrail_event(self, event_name: str, service: str,
                                 source_ip: str, user_identity: dict,
                                 request_params: dict = None) -> dict:
    return {
        "@timestamp": _now_iso(),
        "event": {
            "category": "iam" if service == "iam" else "configuration",
            "type": "info",
            "kind": "event",
            "action": event_name,
            "outcome": "success",
            "provider": f"{service}.amazonaws.com",
            "dataset": "aws.cloudtrail"
        },
        "cloud": {
            "provider": "aws",
            "account": {"id": "123456789012"},
            "region": "us-east-1",
            "service": {"name": service}
        },
        "source": {"ip": source_ip},
        "user": {
            "name": user_identity.get("user_name", "unknown"),
            "id": user_identity.get("account_id", "123456789012")
        },
        "user_agent": {"original": user_identity.get("user_agent", "aws-cli/2.15.0")},
        "aws": {
            "cloudtrail": {
                "event_type": "AwsApiCall",
                "event_source": f"{service}.amazonaws.com",
                "event_name": event_name,
                "request_parameters": json.dumps(request_params or {}),
                "user_identity": user_identity
            }
        }
    }
```

### Zeek Network Flow Generators (`simulator/generators/network.py`)

**Supported Zeek log types:**
- `conn.log` — TCP/UDP connection summaries
- `http.log` — HTTP request/response metadata
- `ssl.log` — TLS/SSL handshake details (JA3/JA3S hashes)
- `dns.log` — DNS query/response records
- `files.log` — File transfer metadata

**Network attack scenarios** (stored in `simulator/scenarios/network/`):

| Technique | File | Description | Key Fields |
|-----------|------|-------------|------------|
| T1071.001 | `t1071_001_c2_https.json` | C2 over HTTPS with unusual JA3 | `tls.client.ja3=<known-bad>`, `event.dataset=zeek.ssl`, regular beacon interval |
| T1090.001 | `t1090_001_socks5.json` | SOCKS5 proxy tunnel | High fan-out from single source, `network.transport=tcp`, many internal destinations |
| T1048.001 | `t1048_001_dns_exfil.json` | Exfiltration over DNS | High DNS query volume, long subdomain strings (>50 chars), low TTL responses |
| T1573.002 | `t1573_002_encrypted_channel.json` | Asymmetric crypto C2 | Self-signed cert, unusual cipher suite, non-standard port |

**Zeek conn.log ECS mapping:**

```python
def _generate_zeek_conn(self, src_ip: str, dst_ip: str, dst_port: int,
                          proto: str = "tcp", duration: float = 1.2,
                          orig_bytes: int = 500, resp_bytes: int = 12000) -> dict:
    return {
        "@timestamp": _now_iso(),
        "event": {"category": "network", "type": "connection", "kind": "event",
                  "dataset": "zeek.conn", "module": "zeek"},
        "source": {"ip": src_ip, "port": _random_port(), "bytes": orig_bytes},
        "destination": {"ip": dst_ip, "port": dst_port, "bytes": resp_bytes},
        "network": {
            "transport": proto,
            "bytes": orig_bytes + resp_bytes,
            "direction": "outbound",
            "community_id": _compute_community_id(src_ip, dst_ip, dst_port, proto)
        },
        "zeek": {
            "connection": {
                "uid": f"C{uuid4().hex[:16]}",
                "state": "SF",  # Normal close
                "history": "ShADadfF",
                "duration": duration
            }
        }
    }
```

### macOS Unified Log Generators (`simulator/generators/macos.py`)

**Supported event types:**
- Process execution (via `es_notify_exec`)
- Authentication (pam, opendirectoryd)
- Persistence (LaunchAgent/LaunchDaemon plist creation)
- File operations (Endpoint Security Framework events)

**macOS attack scenarios** (stored in `simulator/scenarios/macos/`):

| Technique | File | Description | Key Fields |
|-----------|------|-------------|------------|
| T1543.004 | `t1543_004_launchagent.json` | LaunchAgent persistence plist creation | `file.path=~/Library/LaunchAgents/*.plist`, `process.name=plutil` |
| T1555.001 | `t1555_001_keychain.json` | Keychain credential access | `process.name=security`, `process.args=["dump-keychain"]` |

### Updating `simulator/simulator.py`

Modify the main simulator to dynamically load platform generators:

```python
# At the top of simulator.py
from simulator.generators import get_generator, list_platforms, register_generator
from simulator.generators.linux import LinuxGenerator
from simulator.generators.cloud import CloudGenerator
from simulator.generators.network import NetworkGenerator
from simulator.generators.macos import MacOSGenerator

# Register all generators on import
for gen_cls in [LinuxGenerator, CloudGenerator, NetworkGenerator, MacOSGenerator]:
    register_generator(gen_cls())

def generate_scenario(technique_id: str, platform: str = "windows", **kwargs) -> dict:
    """Generate attack + benign scenario for a technique on a given platform."""
    gen = get_generator(platform)
    attack = gen.generate_attack(technique_id, **kwargs)
    benign = gen.generate_benign(gen.event_types[0])
    return {"attack": attack, "benign": benign, "platform": platform}
```

### Scenario Directory Structure

```
simulator/scenarios/
  t1053_005.json          # Existing Windows scenarios (unchanged)
  t1055_001.json
  ...
  linux/
    t1053_003_crontab.json
    t1059_004_bash.json
    t1098_ssh_keys.json
    t1136_001_useradd.json
  cloud/
    t1078_004_cloud_abuse.json
    t1098_001_cloud_creds.json
    t1530_s3_access.json
    t1537_transfer_data.json
  network/
    t1048_001_dns_exfil.json
    t1071_001_c2_https.json
    t1090_001_socks5.json
    t1573_002_encrypted_channel.json
  macos/
    t1543_004_launchagent.json
    t1555_001_keychain.json
```

---

## Task 5.3: Schema Evolution Management (3h)

Handle field name/type changes across data source versions. When a vendor ships a new
Sysmon version, or AWS changes a CloudTrail field, detections that rely on the old schema
silently break. Schema evolution management catches this before production impact.

### Deliverables

- `data-sources/schemas/` — New directory for versioned schema definitions
- `data-sources/schemas/sysmon_15.13.json` — JSON Schema for Sysmon 15.13 fields
- `data-sources/schemas/sysmon_15.14.json` — Next version placeholder (for testing diff)
- `data-sources/schemas/cloudtrail_1.09.json` — CloudTrail schema
- `data-sources/schemas/zeek_6.0.json` — Zeek log schema
- Schema diff tool: `python orchestration/cli.py schema-diff <source> <v1> <v2>`
- Detection impact analysis: which rules break when a field changes?
- CI gate: `schema-validate.yml` workflow validates rules against registered schemas

### Schema Definition Format

```json
{
  "source": "sysmon",
  "version": "15.13",
  "description": "Sysmon for Windows v15.13 — ECS field mappings",
  "updated": "2026-03-15",
  "event_types": {
    "1": {
      "name": "ProcessCreate",
      "ecs_fields": {
        "process.name": {"type": "keyword", "required": true, "source_field": "Image"},
        "process.executable": {"type": "keyword", "required": true, "source_field": "Image"},
        "process.command_line": {"type": "keyword", "required": true, "source_field": "CommandLine"},
        "process.pid": {"type": "long", "required": true, "source_field": "ProcessId"},
        "process.parent.name": {"type": "keyword", "required": true, "source_field": "ParentImage"},
        "process.parent.command_line": {"type": "keyword", "required": false, "source_field": "ParentCommandLine"},
        "process.parent.pid": {"type": "long", "required": true, "source_field": "ParentProcessId"},
        "user.name": {"type": "keyword", "required": true, "source_field": "User"},
        "host.name": {"type": "keyword", "required": true, "source_field": "Computer"},
        "file.hash.md5": {"type": "keyword", "required": false, "source_field": "Hashes"},
        "file.hash.sha256": {"type": "keyword", "required": false, "source_field": "Hashes"}
      }
    },
    "3": {
      "name": "NetworkConnect",
      "ecs_fields": {
        "process.name": {"type": "keyword", "required": true, "source_field": "Image"},
        "source.ip": {"type": "ip", "required": true, "source_field": "SourceIp"},
        "source.port": {"type": "long", "required": true, "source_field": "SourcePort"},
        "destination.ip": {"type": "ip", "required": true, "source_field": "DestinationIp"},
        "destination.port": {"type": "long", "required": true, "source_field": "DestinationPort"},
        "network.protocol": {"type": "keyword", "required": false, "source_field": "Protocol"}
      }
    },
    "8": {
      "name": "CreateRemoteThread",
      "ecs_fields": {
        "process.name": {"type": "keyword", "required": true, "source_field": "SourceImage"},
        "process.entity_id": {"type": "keyword", "required": false, "source_field": "SourceProcessGuid"},
        "target.process.name": {"type": "keyword", "required": true, "source_field": "TargetImage"},
        "target.process.pid": {"type": "long", "required": true, "source_field": "TargetProcessId"},
        "winlog.event_data.StartAddress": {"type": "keyword", "required": false, "source_field": "StartAddress"},
        "winlog.event_data.StartFunction": {"type": "keyword", "required": false, "source_field": "StartFunction"}
      }
    },
    "10": {
      "name": "ProcessAccess",
      "ecs_fields": {
        "process.name": {"type": "keyword", "required": true, "source_field": "SourceImage"},
        "winlog.event_data.TargetImage": {"type": "keyword", "required": true, "source_field": "TargetImage"},
        "winlog.event_data.GrantedAccess": {"type": "keyword", "required": true, "source_field": "GrantedAccess"},
        "winlog.event_data.CallTrace": {"type": "keyword", "required": false, "source_field": "CallTrace"}
      }
    },
    "13": {
      "name": "RegistryEvent",
      "ecs_fields": {
        "process.name": {"type": "keyword", "required": true, "source_field": "Image"},
        "registry.path": {"type": "keyword", "required": true, "source_field": "TargetObject"},
        "registry.value": {"type": "keyword", "required": false, "source_field": "Details"}
      }
    }
  }
}
```

### Schema Diff Tool

```python
# In cli.py — new subcommand: schema-diff

def cmd_schema_diff(args):
    """Compare two schema versions and report changes.

    Usage: python orchestration/cli.py schema-diff sysmon 15.13 15.14
    """
    schema_dir = Path(__file__).resolve().parent.parent.parent / "data-sources" / "schemas"
    old_path = schema_dir / f"{args.source}_{args.old_version}.json"
    new_path = schema_dir / f"{args.source}_{args.new_version}.json"

    old_schema = json.loads(old_path.read_text())
    new_schema = json.loads(new_path.read_text())

    changes = []
    for eid, old_type in old_schema["event_types"].items():
        new_type = new_schema["event_types"].get(eid)
        if not new_type:
            changes.append({"type": "event_removed", "event_id": eid, "severity": "critical"})
            continue
        for field, old_def in old_type["ecs_fields"].items():
            new_def = new_type["ecs_fields"].get(field)
            if not new_def:
                changes.append({
                    "type": "field_removed", "event_id": eid, "field": field,
                    "severity": "critical"
                })
            elif new_def["type"] != old_def["type"]:
                changes.append({
                    "type": "field_type_changed", "event_id": eid, "field": field,
                    "old_type": old_def["type"], "new_type": new_def["type"],
                    "severity": "high"
                })
            elif new_def.get("source_field") != old_def.get("source_field"):
                changes.append({
                    "type": "field_renamed", "event_id": eid, "field": field,
                    "old_source": old_def["source_field"], "new_source": new_def["source_field"],
                    "severity": "high"
                })
        # Check for new fields (informational only)
        for field in new_type["ecs_fields"]:
            if field not in old_type["ecs_fields"]:
                changes.append({
                    "type": "field_added", "event_id": eid, "field": field,
                    "severity": "info"
                })

    return changes
```

### Detection Impact Analysis

When a schema diff produces changes, cross-reference affected fields against detection rules:

```python
def analyze_detection_impact(schema_changes: list[dict]) -> list[dict]:
    """For each schema change, find detections that use the affected field.

    Scans all YAML files in detections/ for field references matching the
    changed field name. Returns list of (change, affected_rules) pairs.
    """
    affected = []
    detections_dir = Path("detections/")
    for change in schema_changes:
        if change["severity"] in ("critical", "high"):
            field = change["field"]
            # Search all Sigma rules for this field name
            matching_rules = []
            for rule_file in detections_dir.rglob("*.yml"):
                if "compiled" in str(rule_file):
                    continue
                content = rule_file.read_text()
                # Check both ECS dotted notation and pipe-separated Sigma field names
                if field in content or field.replace(".", "|") in content:
                    matching_rules.append(str(rule_file))
            if matching_rules:
                affected.append({
                    "change": change,
                    "affected_rules": matching_rules,
                    "action_required": "Update rule to use new field name/type"
                })
    return affected
```

### Schema Change Scenarios the Tool Must Handle

| Scenario | Example | Severity | Detection Impact |
|----------|---------|----------|-----------------|
| Field renamed | `Image` -> `ProcessImage` in hypothetical Sysmon update | HIGH | All rules using `process.executable` need re-mapping |
| Field type changed | `EventID` integer -> string | HIGH | Numeric comparisons in rules will fail |
| Field removed | `ParentCommandLine` dropped | CRITICAL | Rules using `process.parent.command_line` will produce FN |
| New field added | `process.thread.id` added | INFO | No action needed — backward compatible |
| Source field split | `Hashes` split into `MD5`, `SHA256` | HIGH | Cribl parser + raw_events.py need updating |

### CI Gate

```yaml
# .github/workflows/schema-validate.yml
name: Schema Validation
on:
  pull_request:
    paths: ['detections/**/*.yml']
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
      - run: pip install pyyaml
      - run: |
          python3 -c "
          import yaml, json, sys
          from pathlib import Path
          schema_dir = Path('data-sources/schemas')
          if not schema_dir.exists():
              print('No schemas registered yet — skipping')
              sys.exit(0)
          # Load latest schema for each source
          # Validate each changed Sigma rule uses fields in the schema
          # Exit 1 if a rule references a field not in any schema
          "
```

---

## Task 5.4: Raw Event Converter Expansion (3h)

Extend `simulator/raw_events.py` for multi-platform raw formats. Phase 3 built converters
for Windows Sysmon key=value text and Windows Security XML. Phase 5 adds Linux auditd, AWS
CloudTrail JSON, and Zeek TSV log formats.

### Deliverables

- `simulator/raw_events.py` — Extended with 3 new converter functions:
  - `ecs_to_raw_linux_auditd()` — ECS -> Linux audit log format
  - `ecs_to_raw_cloudtrail()` — ECS -> AWS CloudTrail JSON format
  - `ecs_to_raw_zeek()` — ECS -> Zeek TSV log format
- Per-format Cribl pipeline extensions (parsers for each raw format)
- End-to-end validation: raw -> Cribl -> ES -> detection query -> F1

### Linux auditd Raw Format

```python
def ecs_to_raw_linux_auditd(ecs_event: dict) -> str:
    """Convert ECS process event to Linux auditd log format.

    Example output:
    type=SYSCALL msg=audit(1741862400.123:456): arch=c000003e syscall=59 \
      success=yes exit=0 a0=0x7f... ppid=1234 pid=5678 auid=1000 uid=0 \
      gid=0 euid=0 comm="crontab" exe="/usr/bin/crontab"
    type=EXECVE msg=audit(1741862400.123:456): argc=2 a0="crontab" a1="-e"
    type=PATH msg=audit(1741862400.123:456): item=0 name="/usr/bin/crontab" \
      inode=123456 dev=08:01 mode=0100755 ouid=0 ogid=0
    """
    process = ecs_event.get("process", {})
    user = ecs_event.get("user", {})
    timestamp = _parse_timestamp(ecs_event.get("@timestamp", ""))

    pid = process.get("pid", 1234)
    ppid = process.get("parent", {}).get("pid", 1)
    comm = process.get("name", "unknown")
    exe = process.get("executable", f"/usr/bin/{comm}")
    uid = user.get("id", "0")
    args = process.get("args", [comm])

    lines = []
    # SYSCALL record
    lines.append(
        f'type=SYSCALL msg=audit({timestamp:.3f}:{_random_serial()}): '
        f'arch=c000003e syscall=59 success=yes exit=0 '
        f'ppid={ppid} pid={pid} auid={uid} uid={uid} gid={uid} euid={uid} '
        f'comm="{comm}" exe="{exe}"'
    )
    # EXECVE record
    argc = len(args)
    arg_str = " ".join(f'a{i}="{a}"' for i, a in enumerate(args))
    lines.append(
        f'type=EXECVE msg=audit({timestamp:.3f}:{_random_serial()}): '
        f'argc={argc} {arg_str}'
    )
    # PATH record
    lines.append(
        f'type=PATH msg=audit({timestamp:.3f}:{_random_serial()}): '
        f'item=0 name="{exe}" inode={_random_inode()} dev=08:01 mode=0100755'
    )

    return "\n".join(lines)
```

### AWS CloudTrail Raw Format

```python
def ecs_to_raw_cloudtrail(ecs_event: dict) -> str:
    """Convert ECS cloud event to AWS CloudTrail JSON format.

    Returns a single CloudTrail record (not wrapped in Records array).
    Cribl parses this as JSON and maps to ECS fields.
    """
    cloud = ecs_event.get("cloud", {})
    event_meta = ecs_event.get("event", {})
    source = ecs_event.get("source", {})
    user = ecs_event.get("user", {})
    aws = ecs_event.get("aws", {}).get("cloudtrail", {})

    record = {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": user.get("id", "AIDACKCEVSQ6C2EXAMPLE"),
            "arn": f"arn:aws:iam::{cloud.get('account', {}).get('id', '123456789012')}:user/{user.get('name', 'unknown')}",
            "accountId": cloud.get("account", {}).get("id", "123456789012"),
            "userName": user.get("name", "unknown")
        },
        "eventTime": ecs_event.get("@timestamp", _now_iso()),
        "eventSource": aws.get("event_source", f"{event_meta.get('provider', 'iam')}.amazonaws.com"),
        "eventName": event_meta.get("action", aws.get("event_name", "Unknown")),
        "awsRegion": cloud.get("region", "us-east-1"),
        "sourceIPAddress": source.get("ip", "198.51.100.1"),
        "userAgent": ecs_event.get("user_agent", {}).get("original", "aws-cli/2.15.0"),
        "requestParameters": json.loads(aws.get("request_parameters", "{}")),
        "responseElements": None,
        "eventType": aws.get("event_type", "AwsApiCall"),
        "recipientAccountId": cloud.get("account", {}).get("id", "123456789012")
    }

    return json.dumps(record)
```

### Zeek TSV Raw Format

```python
def ecs_to_raw_zeek(ecs_event: dict) -> str:
    """Convert ECS network event to Zeek tab-separated log format.

    Example conn.log output:
    1741862400.123456\tC1a2b3c4d5\t192.168.1.100\t49152\t10.0.0.1\t443\ttcp\tssl\t1.200\t500\t12000\tSF\tT\tF\t0\tShADadfF\t1\t552\t1\t12052\t(empty)
    """
    source = ecs_event.get("source", {})
    dest = ecs_event.get("destination", {})
    network = ecs_event.get("network", {})
    zeek = ecs_event.get("zeek", {}).get("connection", {})
    dataset = ecs_event.get("event", {}).get("dataset", "zeek.conn")

    timestamp = _parse_timestamp(ecs_event.get("@timestamp", ""))
    uid = zeek.get("uid", f"C{uuid4().hex[:16]}")

    if dataset == "zeek.conn":
        fields = [
            f"{timestamp:.6f}",
            uid,
            source.get("ip", "-"),
            str(source.get("port", "-")),
            dest.get("ip", "-"),
            str(dest.get("port", "-")),
            network.get("transport", "tcp"),
            network.get("protocol", "-"),
            str(zeek.get("duration", "-")),
            str(source.get("bytes", "-")),
            str(dest.get("bytes", "-")),
            zeek.get("state", "SF"),
            "T",  # local_orig
            "F",  # local_resp
            "0",  # missed_bytes
            zeek.get("history", "ShADadfF"),
            "1",  # orig_pkts
            str(source.get("bytes", 0) + 52),  # orig_ip_bytes
            "1",  # resp_pkts
            str(dest.get("bytes", 0) + 52),  # resp_ip_bytes
            "-"   # tunnel_parents
        ]
        return "\t".join(fields)

    elif dataset == "zeek.dns":
        dns = ecs_event.get("dns", {})
        fields = [
            f"{timestamp:.6f}",
            uid,
            source.get("ip", "-"),
            str(source.get("port", "-")),
            dest.get("ip", "-"),
            str(dest.get("port", "53")),
            network.get("transport", "udp"),
            str(dns.get("id", "-")),
            dns.get("question", {}).get("name", "-"),
            str(dns.get("question", {}).get("type_code", 1)),
            dns.get("question", {}).get("class", "C_INTERNET"),
        ]
        return "\t".join(fields)

    return ""  # Unsupported dataset
```

### Cribl Pipeline Extensions

Create per-source Cribl pipelines for each raw format (see Task 5.5). For the raw event
converter, the key integration point is the HEC envelope:

```python
def ecs_to_raw(ecs_event: dict) -> dict:
    """Extended dispatcher — handles all platforms.

    Dispatches based on event.dataset or agent.type:
    - agent.type=winlogbeat / event.dataset=sysmon.* -> Sysmon text
    - agent.type=winlogbeat / event.dataset=windows.security -> Windows XML
    - agent.type=auditbeat / event.dataset=auditd.* -> Linux auditd
    - event.dataset=aws.cloudtrail -> CloudTrail JSON
    - event.dataset=zeek.* -> Zeek TSV
    """
    dataset = ecs_event.get("event", {}).get("dataset", "")
    agent_type = ecs_event.get("agent", {}).get("type", "")

    if agent_type == "auditbeat" or dataset.startswith("auditd"):
        raw = ecs_to_raw_linux_auditd(ecs_event)
        sourcetype = "linux:audit"
    elif dataset.startswith("aws.cloudtrail"):
        raw = ecs_to_raw_cloudtrail(ecs_event)
        sourcetype = "aws:cloudtrail"
    elif dataset.startswith("zeek."):
        raw = ecs_to_raw_zeek(ecs_event)
        sourcetype = f"bro:{dataset.split('.')[1]}"  # bro:conn, bro:dns, etc.
    elif "security" in dataset or str(ecs_event.get("event", {}).get("code", "")) in ("4624", "4688", "7045"):
        raw = ecs_to_raw_windows_security(ecs_event)
        sourcetype = "XmlWinEventLog:Security"
    else:
        raw = ecs_to_raw_sysmon(ecs_event)
        sourcetype = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"

    return {
        "event": raw,
        "sourcetype": sourcetype,
        "host": ecs_event.get("host", {}).get("name", "unknown"),
        "source": f"simulator:{dataset or agent_type}",
        "time": _parse_timestamp(ecs_event.get("@timestamp", "")),
        "_simulation": ecs_event.get("_simulation", {})
    }
```

### End-to-End Validation Path

For each new platform, verify the full round-trip:

```
1. Generate ECS event (generator) →
2. Convert to raw format (raw_events.py) →
3. Send to Cribl HEC (validation.py, ingestion_method="cribl") →
4. Cribl pipeline parses raw → ECS (per-source pipeline) →
5. Events land in ES (sim-validation-* index) →
6. Run detection Lucene query →
7. Calculate F1 score
```

Test with at least 1 detection per new platform to validate the full path works.

---

## Task 5.5: Cribl Pipeline Management at Scale (3h)

Phase 3 built a single monolithic `cim_normalize` pipeline handling all event types. At scale,
a single pipeline becomes unmaintainable. Task 5.5 splits this into per-source pipelines with
dynamic routing based on sourcetype.

### Deliverables

- Per-source Cribl pipelines (replace monolithic `cim_normalize`):
  - `sysmon_normalize` — Windows Sysmon parsing (EIDs 1, 3, 7, 8, 10, 11, 13, 17, 18, 22)
  - `windows_security_normalize` — Windows Security event parsing (EIDs 4624, 4625, 4688, 7045)
  - `linux_auditd_normalize` — Linux audit log parsing (SYSCALL, EXECVE, PATH records)
  - `cloudtrail_normalize` — AWS CloudTrail JSON -> ECS mapping
  - `zeek_normalize` — Zeek TSV log -> ECS mapping (conn, http, ssl, dns)
- Dynamic routing rules: Cribl route table dispatches to correct pipeline by sourcetype
- Reduction metrics per pipeline: track data volume savings individually
- Pipeline testing framework: automated preview tests via `cribl_preview_pipeline` before deploy

### Pipeline Routing Table

```javascript
// Cribl route table — routes events to per-source pipelines by sourcetype
[
  {
    "id": "validation_to_elastic",
    "name": "Validation events → ES (existing Phase 3 route)",
    "filter": "__e._validation_index",
    "pipeline": null,  // Pipeline already applied before routing
    "output": "elastic_validation",
    "final": true
  },
  {
    "id": "sysmon_route",
    "name": "Sysmon events → sysmon_normalize",
    "filter": "sourcetype.startsWith('XmlWinEventLog:Microsoft-Windows-Sysmon')",
    "pipeline": "sysmon_normalize",
    "output": "default"
  },
  {
    "id": "windows_security_route",
    "name": "Windows Security events → windows_security_normalize",
    "filter": "sourcetype == 'XmlWinEventLog:Security' || sourcetype == 'WinEventLog:Security'",
    "pipeline": "windows_security_normalize",
    "output": "default"
  },
  {
    "id": "linux_auditd_route",
    "name": "Linux audit events → linux_auditd_normalize",
    "filter": "sourcetype == 'linux:audit' || sourcetype == 'linux_audit'",
    "pipeline": "linux_auditd_normalize",
    "output": "default"
  },
  {
    "id": "cloudtrail_route",
    "name": "CloudTrail events → cloudtrail_normalize",
    "filter": "sourcetype == 'aws:cloudtrail'",
    "pipeline": "cloudtrail_normalize",
    "output": "default"
  },
  {
    "id": "zeek_route",
    "name": "Zeek events → zeek_normalize",
    "filter": "sourcetype.startsWith('bro:')",
    "pipeline": "zeek_normalize",
    "output": "default"
  },
  {
    "id": "fallback_route",
    "name": "Unrecognized events → passthrough",
    "filter": "true",
    "pipeline": "passthru",
    "output": "default",
    "final": true
  }
]
```

### Pipeline Definitions

**`sysmon_normalize`** (migrated from existing `cim_normalize` Sysmon functions):

```javascript
// Functions: serde (JSON parse) → regex_extract (raw Sysmon) → eval (ECS mapping) → eval (CIM aliases)
// Same functions as Phase 3 cim_normalize, but scoped to Sysmon only
// Remove Windows Security / Linux / cloud parsers from this pipeline
```

**`linux_auditd_normalize`** (new):

```javascript
{
  "id": "linux_auditd_normalize",
  "functions": [
    {
      "id": "parse_auditd",
      "type": "regex_extract",
      "filter": "true",
      "conf": {
        "field": "_raw",
        "iterations": 5,  // Multiple records per audit event
        "regexList": [
          {"regex": "type=SYSCALL.*comm=\"(?<process_name>[^\"]+)\".*exe=\"(?<process_executable>[^\"]+)\""},
          {"regex": "type=SYSCALL.*pid=(?<process_pid>\\d+).*ppid=(?<parent_pid>\\d+)"},
          {"regex": "type=SYSCALL.*uid=(?<user_id>\\d+).*euid=(?<effective_uid>\\d+)"},
          {"regex": "type=EXECVE.*argc=(?<argc>\\d+)(?:\\s+a\\d+=\"([^\"]+)\")+"},
          {"regex": "type=PATH.*name=\"(?<file_path>[^\"]+)\".*mode=(?<file_mode>\\d+)"}
        ]
      }
    },
    {
      "id": "map_ecs",
      "type": "eval",
      "filter": "true",
      "conf": {
        "add": [
          {"name": "process.name", "value": "process_name"},
          {"name": "process.executable", "value": "process_executable"},
          {"name": "process.pid", "value": "Number(process_pid)"},
          {"name": "process.parent.pid", "value": "Number(parent_pid)"},
          {"name": "user.id", "value": "user_id"},
          {"name": "event.category", "value": "'process'"},
          {"name": "event.type", "value": "'start'"},
          {"name": "event.module", "value": "'auditd'"},
          {"name": "event.dataset", "value": "'auditd.log'"},
          {"name": "agent.type", "value": "'auditbeat'"},
          {"name": "host.os.family", "value": "'linux'"}
        ]
      }
    }
  ]
}
```

**`cloudtrail_normalize`** (new):

```javascript
{
  "id": "cloudtrail_normalize",
  "functions": [
    {
      "id": "parse_json",
      "type": "serde",
      "filter": "true",
      "conf": {"mode": "extract", "type": "json", "srcField": "_raw"}
    },
    {
      "id": "map_ecs",
      "type": "eval",
      "filter": "true",
      "conf": {
        "add": [
          {"name": "event.action", "value": "eventName"},
          {"name": "event.provider", "value": "eventSource"},
          {"name": "event.dataset", "value": "'aws.cloudtrail'"},
          {"name": "event.category", "value": "eventSource && eventSource.includes('iam') ? 'iam' : 'configuration'"},
          {"name": "cloud.provider", "value": "'aws'"},
          {"name": "cloud.region", "value": "awsRegion"},
          {"name": "cloud.account.id", "value": "recipientAccountId || userIdentity.accountId"},
          {"name": "source.ip", "value": "sourceIPAddress"},
          {"name": "user.name", "value": "userIdentity.userName || userIdentity.principalId"},
          {"name": "user_agent.original", "value": "userAgent"}
        ]
      }
    }
  ]
}
```

**`zeek_normalize`** (new):

```javascript
{
  "id": "zeek_normalize",
  "functions": [
    {
      "id": "parse_tsv",
      "type": "regex_extract",
      "filter": "sourcetype == 'bro:conn'",
      "conf": {
        "field": "_raw",
        "regexList": [
          {"regex": "^(?<ts>[\\d.]+)\\t(?<uid>[^\\t]+)\\t(?<src_ip>[^\\t]+)\\t(?<src_port>\\d+)\\t(?<dst_ip>[^\\t]+)\\t(?<dst_port>\\d+)\\t(?<proto>[^\\t]+)\\t(?<service>[^\\t]*)\\t(?<duration>[^\\t]*)\\t(?<orig_bytes>[^\\t]*)\\t(?<resp_bytes>[^\\t]*)"}
        ]
      }
    },
    {
      "id": "parse_dns_tsv",
      "type": "regex_extract",
      "filter": "sourcetype == 'bro:dns'",
      "conf": {
        "field": "_raw",
        "regexList": [
          {"regex": "^(?<ts>[\\d.]+)\\t(?<uid>[^\\t]+)\\t(?<src_ip>[^\\t]+)\\t(?<src_port>\\d+)\\t(?<dst_ip>[^\\t]+)\\t(?<dst_port>\\d+)\\t(?<proto>[^\\t]+)\\t(?<trans_id>[^\\t]*)\\t(?<query>[^\\t]*)\\t(?<qtype>\\d+)"}
        ]
      }
    },
    {
      "id": "map_ecs_conn",
      "type": "eval",
      "filter": "sourcetype == 'bro:conn'",
      "conf": {
        "add": [
          {"name": "source.ip", "value": "src_ip"},
          {"name": "source.port", "value": "Number(src_port)"},
          {"name": "source.bytes", "value": "Number(orig_bytes)"},
          {"name": "destination.ip", "value": "dst_ip"},
          {"name": "destination.port", "value": "Number(dst_port)"},
          {"name": "destination.bytes", "value": "Number(resp_bytes)"},
          {"name": "network.transport", "value": "proto"},
          {"name": "network.bytes", "value": "Number(orig_bytes || 0) + Number(resp_bytes || 0)"},
          {"name": "event.category", "value": "'network'"},
          {"name": "event.dataset", "value": "'zeek.conn'"},
          {"name": "event.module", "value": "'zeek'"},
          {"name": "zeek.connection.uid", "value": "uid"},
          {"name": "zeek.connection.duration", "value": "Number(duration)"}
        ]
      }
    },
    {
      "id": "map_ecs_dns",
      "type": "eval",
      "filter": "sourcetype == 'bro:dns'",
      "conf": {
        "add": [
          {"name": "source.ip", "value": "src_ip"},
          {"name": "destination.ip", "value": "dst_ip"},
          {"name": "dns.question.name", "value": "query"},
          {"name": "dns.question.type_code", "value": "Number(qtype)"},
          {"name": "event.category", "value": "'network'"},
          {"name": "event.dataset", "value": "'zeek.dns'"},
          {"name": "event.module", "value": "'zeek'"}
        ]
      }
    }
  ]
}
```

### Reduction Metrics Per Pipeline

Track data volume reduction at the pipeline level:

```python
# Query via Cribl API: cribl_get_metrics()
# Expected output per pipeline:
{
  "sysmon_normalize": {
    "events_in": 10000,
    "events_out": 8500,
    "bytes_in": 25000000,
    "bytes_out": 18000000,
    "reduction_pct": 28.0,
    "avg_processing_time_ms": 0.8
  },
  "linux_auditd_normalize": {
    "events_in": 5000,
    "events_out": 4800,
    "reduction_pct": 4.0,  # Less reduction — audit logs are already lean
    "avg_processing_time_ms": 0.5
  }
}
```

### Pipeline Testing Framework

Before deploying any pipeline change, run automated preview tests:

```python
def test_pipeline(pipeline_id: str, test_events: list[dict]) -> dict:
    """Run preview against sample events, verify expected fields appear.

    Uses cribl_preview_pipeline MCP tool.
    Returns: {"passed": 8, "failed": 2, "errors": ["Missing field source.ip in event 3"]}
    """
    previewed = cribl_preview_pipeline(pipeline_id=pipeline_id, sample_events=test_events)
    results = {"passed": 0, "failed": 0, "errors": []}
    for i, event in enumerate(previewed):
        # Check that all expected ECS fields were populated
        expected_fields = _get_expected_fields_for_sourcetype(event.get("sourcetype", ""))
        for field in expected_fields:
            if not _nested_get(event, field):
                results["failed"] += 1
                results["errors"].append(f"Missing field {field} in event {i}")
                break
        else:
            results["passed"] += 1
    return results
```

### Migration Steps

1. Export existing `cim_normalize` function list via `cribl_get_pipeline(pipeline_id='cim_normalize')`
2. Create `sysmon_normalize` with the Sysmon-specific subset of functions
3. Create `windows_security_normalize` with WinSec-specific functions
4. Create new pipelines for Linux, CloudTrail, Zeek
5. Update route table to dispatch by sourcetype (keep `cim_normalize` as fallback initially)
6. Preview-test each pipeline with sample events
7. Cut over: set `cim_normalize` route to `final: false` (passthrough only)
8. After validation, remove `cim_normalize` route entirely

---

## Task 5.6: Data Source Gap Auto-Detection (2h)

Automatically identify missing data sources needed for detection coverage. Phase 3 created
structured gap files in `gaps/data-sources/` and the `cli.py data-sources` command. Phase 5
extends this with cross-referencing against coverage gaps and auto-issue creation.

### Deliverables

- `autonomous/orchestration/gap_analyzer.py` — Gap analysis engine (~200 lines)
- Cross-reference: coverage gaps (from `coverage/attack-matrix.md`) x source registry x gap files
- For each uncovered technique: required sources, which are available, which are missing
- Auto-create GitHub issues for data source gaps (via GitHub MCP tools)
- Extended CLI: `python orchestration/cli.py data-gaps` shows technique -> source -> status

### Gap Analysis Logic

```python
def analyze_data_gaps() -> list[dict]:
    """Cross-reference detection coverage gaps with data source availability.

    For each technique in the Fawkes capability list:
    1. Check if a detection exists (coverage/attack-matrix.md or detections/ scan)
    2. If no detection: look up required data sources (TECHNIQUE_DATA_SOURCES map)
    3. For each required source: check gap files in gaps/data-sources/*.yml
    4. Classify: AVAILABLE (source exists, detection missing — author it)
                 PARTIALLY_AVAILABLE (some data, may work with limitations)
                 GAP (source missing — onboard it first)

    Returns sorted by actionability: AVAILABLE > PARTIALLY_AVAILABLE > GAP
    """
    results = []
    for technique_id, technique_info in FAWKES_TECHNIQUES.items():
        detection_exists = _has_detection(technique_id)
        if detection_exists:
            continue

        required_sources = TECHNIQUE_DATA_SOURCES.get(technique_id, [])
        source_statuses = []
        for source_id in required_sources:
            gap_file = _find_gap_file(source_id)
            if gap_file:
                status = gap_file.get("status", "gap")
            else:
                # No gap file = assume available (it's in the sim-* indices)
                status = "available"
            source_statuses.append({"source": source_id, "status": status})

        # Determine overall actionability
        all_available = all(s["status"] == "available" for s in source_statuses)
        any_gap = any(s["status"] == "gap" for s in source_statuses)

        results.append({
            "technique_id": technique_id,
            "technique_name": technique_info["name"],
            "fawkes_command": technique_info.get("fawkes_command"),
            "required_sources": source_statuses,
            "actionability": "READY" if all_available else "PARTIAL" if not any_gap else "BLOCKED",
            "recommendation": _generate_recommendation(technique_id, source_statuses)
        })

    # Sort: READY first (can author detection now), then PARTIAL, then BLOCKED
    results.sort(key=lambda r: {"READY": 0, "PARTIAL": 1, "BLOCKED": 2}[r["actionability"]])
    return results
```

### CLI Output Format

```
$ python orchestration/cli.py data-gaps

  Data Source Gap Analysis — Fawkes C2 Techniques
  ================================================

  READY (data available — detection can be authored now):
    T1055.004 APC Injection [apc-injection]
      Required: sysmon_eid_8 (available), sysmon_eid_10 (available)
      → Recommendation: Author detection. EID 8 + EID 10 data exists.

    T1053.003 Crontab Persistence [crontab] (Linux)
      Required: linux_auditd (available after Task 5.2)
      → Recommendation: Author detection after multi-platform simulator.

  PARTIAL (some data available — detection possible with limitations):
    T1070.006 Timestomping [timestomp]
      Required: sysmon_eid_2 (partially_available)
      → Recommendation: Sysmon EID 2 generator exists but limited. Test coverage.

  BLOCKED (data source missing — onboard source first):
    T1056.001 Keylogging [keylog]
      Required: etw_telemetry (gap)
      → Recommendation: ETW provider needed. Consider Elastic Endpoint agent.

    T1115 Clipboard Data [clipboard]
      Required: etw_telemetry (gap)
      → Recommendation: Same ETW dependency as keylogging. Bundle onboarding.

  Summary: 3 READY | 2 PARTIAL | 3 BLOCKED
```

### Auto-Issue Creation

When gap analysis runs, create GitHub issues for:
1. **READY** techniques without a detection (label: `coverage-gap`, `ready-to-author`)
2. **BLOCKED** techniques without a data source gap issue (label: `data-source-gap`)

```python
def create_gap_issues(gaps: list[dict], repo: str = "lsmithg12/ai-detection-engineering"):
    """Create GitHub issues for untracked gaps using GitHub MCP tools."""
    for gap in gaps:
        if gap["actionability"] == "READY":
            # Check if issue already exists for this technique
            existing = mcp__github__search_issues(
                q=f"repo:{repo} is:issue [Gap] {gap['technique_id']} in:title"
            )
            if not existing:
                mcp__github__create_issue(
                    owner="lsmithg12", repo="ai-detection-engineering",
                    title=f"[Gap] No detection for {gap['technique_name']} ({gap['technique_id']})",
                    body=f"## Coverage Gap\n\n"
                         f"Fawkes command: `{gap.get('fawkes_command', 'N/A')}`\n\n"
                         f"Required data sources: {', '.join(s['source'] for s in gap['required_sources'])}\n"
                         f"All sources are **available** — this detection can be authored now.\n\n"
                         f"Priority: based on Fawkes capability overlap and data availability.",
                    labels=["coverage-gap", "ready-to-author"]
                )
        elif gap["actionability"] == "BLOCKED":
            for source in gap["required_sources"]:
                if source["status"] == "gap":
                    mcp__github__create_issue(
                        owner="lsmithg12", repo="ai-detection-engineering",
                        title=f"[Data Gap] {source['source']} needed for {gap['technique_id']}",
                        body=f"## Data Source Gap\n\n"
                             f"Source: `{source['source']}`\n"
                             f"Blocks: {gap['technique_id']} ({gap['technique_name']})\n"
                             f"Fawkes command: `{gap.get('fawkes_command', 'N/A')}`",
                        labels=["data-source-gap"]
                    )
```

---

## Validation Criteria

- [ ] Data quality scores generated for all registered sources (Task 5.1)
- [ ] `cli.py data-quality` shows per-source health with composite score
- [ ] Linux simulation generates valid auditd-format events (Task 5.2)
- [ ] Cloud simulation generates valid CloudTrail JSON events (Task 5.2)
- [ ] Network simulation generates valid Zeek TSV logs (Task 5.2)
- [ ] At least 1 detection authored for a non-Windows platform (Task 5.2)
- [ ] Schema definitions exist for Sysmon, CloudTrail, Zeek (Task 5.3)
- [ ] `cli.py schema-diff` identifies field changes between versions (Task 5.3)
- [ ] Detection impact analysis flags rules affected by schema changes (Task 5.3)
- [ ] Raw event converters work for Linux auditd, CloudTrail, Zeek formats (Task 5.4)
- [ ] End-to-end validation: raw -> Cribl -> ES -> Lucene -> F1 for 1+ non-Windows event (Task 5.4)
- [ ] Per-source Cribl pipelines replace monolithic `cim_normalize` (Task 5.5)
- [ ] Route table dispatches by sourcetype to correct pipeline (Task 5.5)
- [ ] `cli.py data-gaps` shows technique -> source -> status mapping (Task 5.6)
- [ ] GitHub issues auto-created for READY and BLOCKED gaps (Task 5.6)

---

## Commit Strategy

Logical grouping by deliverable:

1. `feat(data-quality): add data quality monitoring engine with health scoring`
   - `autonomous/orchestration/data_quality.py`, `autonomous/orchestration/source_expectations.yml`
   - CLI extension for `data-quality` subcommand
2. `feat(simulator): add multi-platform event generators (Linux, cloud, network, macOS)`
   - `simulator/generators/` directory with all platform modules
   - `simulator/scenarios/linux/`, `simulator/scenarios/cloud/`, etc.
   - Updated `simulator/simulator.py` dynamic loading
3. `feat(schema): add versioned schema definitions and diff tool`
   - `data-sources/schemas/` directory with JSON schema files
   - CLI extension for `schema-diff` subcommand
   - Detection impact analysis function
4. `feat(raw-events): extend raw event converter for Linux, CloudTrail, Zeek formats`
   - Updated `simulator/raw_events.py` with 3 new converter functions
   - Extended `ecs_to_raw()` dispatcher
5. `feat(cribl): split monolithic pipeline into per-source pipelines with dynamic routing`
   - 5 Cribl pipeline definitions
   - Updated route table
   - Pipeline testing framework
6. `feat(gaps): add automated data source gap analysis with GitHub issue creation`
   - `autonomous/orchestration/gap_analyzer.py`
   - CLI extension for `data-gaps` subcommand

**Branch strategy**: `infra/phase5-data-engineering` for the full phase, or split into
per-task branches if working in parallel sessions:
- `infra/phase5-data-quality` (Task 5.1)
- `infra/phase5-multi-platform-sim` (Tasks 5.2 + 5.4)
- `infra/phase5-schema-mgmt` (Task 5.3)
- `infra/phase5-cribl-pipelines` (Task 5.5)
- `infra/phase5-gap-detection` (Task 5.6)
