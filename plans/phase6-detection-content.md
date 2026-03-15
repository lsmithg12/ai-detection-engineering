# Phase 6: Detection Content at Scale

**Status**: NOT STARTED
**Priority**: HIGH
**Estimated effort**: 16-20 hours (multi-session)
**Dependencies**: Phase 4 (agent refactoring, validation agent) should be complete. Phase 5 (multi-platform data) recommended for cross-platform content.
**Branch**: `infra/phase6-detection-content` (or per-task branches)

---

## Context

At 29 individual Sigma rules, the lab has proven the detection authoring pipeline works. Now
it needs to scale from a rule collection to a production detection content factory. Real-world
detection programs need:

- **Content packs**: Grouped detections for easy deployment and lifecycle management
- **Multi-rule-type support**: EQL sequences for kill chains, threshold rules for volume anomalies
- **Evasion resilience**: Systematic testing against adversary tradecraft variants
- **Continuous validation**: Rules degrade silently when data changes — catch it automatically
- **Performance profiling**: Expensive rules consume SIEM compute budget — measure and optimize

### What Previous Phases Built (Leverage Points)

| Phase | Asset | Phase 6 Leverage |
|-------|-------|-----------------|
| Phase 2 | `validation.py` — `validate_against_elasticsearch()` | Continuous re-validation reuses same function |
| Phase 2 | ES ingestion + Lucene query pattern | EQL validation uses `_eql/search` endpoint instead |
| Phase 3 | Cribl streaming path | Evasion test events flow through full pipeline |
| Phase 4 | Detection Author Agent (refactored) | Agent generates EQL + threshold rules, not just Sigma |
| Phase 4 | Scenario Engineer Agent (new) | Agent generates evasion variants automatically |
| Phase 4 | Validation Agent (new) | Agent runs continuous + evasion validation |
| Phase 5 | Multi-platform generators | Cross-platform content (Linux, cloud, network) |
| Phase 5 | Schema management | CI validates rules against registered schemas |

---

## Task 6.1: Content Pack Framework (3h)

Group related detections into deployable packs with shared lifecycle management. Instead
of deploying 29 individual rules, deploy "Process Injection Pack v1.2.0" containing 5 rules
that work together.

### Deliverables

- `detections/packs/` — New directory for pack manifests
- Pack manifest schema (`pack.yml`) with metadata, dependency declarations, test requirements
- Pack-level test suites (all rules in pack validated together against shared scenario)
- Pack versioning (semver per pack, changelog per version)
- CLI: `python orchestration/cli.py pack list | validate | deploy <pack-name>`

### Pack Manifest Schema

```yaml
# detections/packs/process-injection/pack.yml
name: Process Injection Detection Pack
version: "1.0.0"
description: |
  Comprehensive process injection detection spanning CreateRemoteThread,
  APC injection, threadless injection, and behavioral indicators. Designed
  to detect Fawkes C2 injection capabilities with resilience against
  common evasion techniques.
author: blue-team-agent
created: "2026-03-15"
modified: "2026-03-15"
status: validated  # draft | validated | deployed | deprecated

# Threat mapping
threat_actors:
  - fawkes
  - cobalt-strike
  - generic-rat
mitre_tactics:
  - privilege_escalation
  - defense_evasion
mitre_techniques:
  - T1055.001  # CreateRemoteThread
  - T1055.004  # APC Injection
  - T1055.012  # Threadless Injection

# Platform requirements
platforms:
  - windows
minimum_sysmon_version: "15.0"

# Data requirements — what log sources must be available
data_requirements:
  - source: sysmon_eid_8
    description: CreateRemoteThread events
    required: true
  - source: sysmon_eid_10
    description: Process access events (GrantedAccess)
    required: true
  - source: sysmon_eid_7
    description: Image load events (DLL injection indicator)
    required: false  # Enhances detection but not strictly required

# Rules included in this pack
rules:
  - path: detections/privilege_escalation/t1055_001.yml
    technique: T1055.001
    type: sigma  # sigma | eql | threshold
    required: true  # Must deploy — core detection
  - path: detections/privilege_escalation/t1055_004_apc.yml
    technique: T1055.004
    type: sigma
    required: true
  - path: detections/privilege_escalation/t1055_012_threadless.yml
    technique: T1055.012
    type: eql
    required: false  # Optional — requires EQL support

# Quality gates
quality:
  min_f1: 0.90
  min_evasion_resilience: 0.60
  max_fp_rate: 0.05

# Test suite
test_suite:
  scenarios:
    - tests/integration/injection_kill_chain.json
  evasion_variants:
    - tests/evasion/t1055_001_syscall_direct.json
    - tests/evasion/t1055_001_ppid_spoof.json
    - tests/evasion/t1055_004_early_bird.json

# Changelog
changelog:
  - version: "1.0.0"
    date: "2026-03-15"
    changes:
      - "Initial pack release"
      - "3 rules: CRT, APC injection, threadless"
```

### Pack Directory Structure

```
detections/packs/
  process-injection/
    pack.yml                # Pack manifest
    CHANGELOG.md            # Version history
  persistence/
    pack.yml
    CHANGELOG.md
  defense-evasion/
    pack.yml
    CHANGELOG.md
  execution/
    pack.yml
    CHANGELOG.md
  credential-access/
    pack.yml
    CHANGELOG.md
  discovery/
    pack.yml
    CHANGELOG.md
  initial-access/
    pack.yml
    CHANGELOG.md
  impact/
    pack.yml
    CHANGELOG.md
  c2/
    pack.yml
    CHANGELOG.md
```

### Migration Plan: Existing 29 Rules into Packs

Map existing rules to content packs by technique family. Rules remain in their
current file locations (`detections/<tactic>/*.yml`) — packs reference them by path.

| Pack Name | Techniques | Rule Count | Status |
|-----------|-----------|------------|--------|
| `process-injection` | T1055.001, T1055.004* | 1 (+1 new) | validated |
| `persistence` | T1053.005, T1543.003, T1547.001 | 3 | monitoring (2), validated (1) |
| `defense-evasion` | T1027, T1070.001, T1078.004, T1562.001, T1562.004, T1562.006 (x2) | 7 | monitoring (3), validated (4) |
| `execution` | T1059.001, T1059.003, T1082, T1105, T1133, T1190, T1204.002, T1486, T1490, T1569.002 | 10 | mixed |
| `credential-access` | T1003.001, T1134.001 | 2 | monitoring (1), needs_rework (1) |
| `discovery` | T1046, T1083 | 2 | validated |
| `initial-access` | T1219, T1566.004 | 2 | monitoring |
| `c2` | T1071.001 | 1 | monitoring |
| `impact` | T1486, T1490 | (shared with execution) | validated+ |

*T1055.004 to be authored in Task 6.7

### CLI Implementation

```python
# In cli.py — new pack subcommands

def cmd_pack_list(args):
    """List all content packs and their status."""
    packs_dir = Path("detections/packs")
    for pack_dir in sorted(packs_dir.iterdir()):
        if not pack_dir.is_dir():
            continue
        manifest_path = pack_dir / "pack.yml"
        if manifest_path.exists():
            manifest = yaml.safe_load(manifest_path.read_text())
            rule_count = len(manifest.get("rules", []))
            techniques = manifest.get("mitre_techniques", [])
            status = manifest.get("status", "unknown")
            print(f"  {manifest['name']} v{manifest['version']}")
            print(f"    Status: {status} | Rules: {rule_count} | Techniques: {', '.join(techniques)}")


def cmd_pack_validate(args):
    """Validate all rules in a pack, run pack-level test suite."""
    manifest = _load_pack_manifest(args.pack_name)

    # 1. Validate each rule individually
    for rule_ref in manifest["rules"]:
        rule_path = Path(rule_ref["path"])
        technique = rule_ref["technique"]
        # Run Sigma check + local/ES validation
        result = validate_rule(rule_path, technique)
        print(f"  {technique}: F1={result['f1']:.2f} ({result['validation_method']})")

    # 2. Run pack-level test suite (kill chain scenarios)
    for scenario_path in manifest.get("test_suite", {}).get("scenarios", []):
        result = validate_scenario(scenario_path, manifest["rules"])
        print(f"  Kill chain test: {result['status']}")

    # 3. Check quality gates
    quality = manifest.get("quality", {})
    min_f1 = quality.get("min_f1", 0.90)
    # Compare aggregate F1 against threshold
    ...


def cmd_pack_deploy(args):
    """Deploy all required rules in a pack to active SIEMs."""
    manifest = _load_pack_manifest(args.pack_name)
    for rule_ref in manifest["rules"]:
        if rule_ref.get("required", True):
            deploy_rule(Path(rule_ref["path"]))
    print(f"  Deployed {manifest['name']} v{manifest['version']}")
```

Usage:
```bash
python orchestration/cli.py pack list
python orchestration/cli.py pack validate process-injection
python orchestration/cli.py pack deploy process-injection
```

---

## Task 6.2: EQL Rule Support (4h)

Add Elasticsearch EQL (Event Query Language) for multi-event correlation detections. EQL
enables sequence-based detection: "Process A did X, then Process B did Y within 60 seconds
on the same host." Single-event Sigma rules cannot express this.

### Deliverables

- `templates/eql-template.yml` — EQL rule template with sequence/join syntax
- `autonomous/orchestration/validation_eql.py` — EQL validation against ES (~200 lines)
- Phase 4 Detection Author Agent updated to generate EQL rules
- Transpilation: EQL -> Elastic Detection Engine JSON (native support)
- Splunk equivalent: SPL correlation searches (no direct EQL, but same logic)

### EQL Rule Template

```yaml
# templates/eql-template.yml
# EQL Sequence Detection Rule Template
title: <Title>
id: <uuid>
status: experimental
description: |
  <Description of the multi-event behavior being detected>
references:
  - https://attack.mitre.org/techniques/<TXXXX>/
author: blue-team-agent
date: <YYYY/MM/DD>
modified: <YYYY/MM/DD>
tags:
  - attack.<tactic>
  - attack.<technique_id>
logsource:
  product: windows
  service: sysmon
# EQL-specific fields (not standard Sigma — custom extension)
detection_type: eql
eql_query: |
  sequence by host.name with maxspan=<duration>
    [<event_category> where <condition_1>]
    [<event_category> where <condition_2>]
    [<event_category> where <condition_3>]
eql_tiebreaker: "@timestamp"
# Threshold for sequence (optional)
eql_min_sequences: 1
# Equivalent SPL correlation for Splunk deployment
spl_correlation: |
  index=sysmon (<condition_1>) OR (<condition_2>) OR (<condition_3>)
  | transaction host maxspan=<duration>s
  | where eventcount >= <N>
  | where <has_all_required_events>
falsepositives:
  - <description>
level: high
```

### Priority EQL Detections

#### EQL-1: Discovery Burst Detection

Detects rapid-fire reconnaissance commands typical of post-exploitation enumeration.
Fawkes commands: `ps`, `whoami`, `net-enum`, `net-shares`, `net-stat`, `arp`, `ifconfig`.

```yaml
title: Rapid Reconnaissance Command Burst
id: 8a3c1f2e-4b5d-6e7f-8a9b-0c1d2e3f4a5b
detection_type: eql
eql_query: |
  sequence by host.name with maxspan=60s
    [process where event.code == "1" and process.name in
      ("whoami.exe", "net.exe", "ipconfig.exe", "systeminfo.exe",
       "tasklist.exe", "nltest.exe", "netstat.exe", "arp.exe",
       "nslookup.exe", "net1.exe")]
    [process where event.code == "1" and process.name in
      ("whoami.exe", "net.exe", "ipconfig.exe", "systeminfo.exe",
       "tasklist.exe", "nltest.exe", "netstat.exe", "arp.exe",
       "nslookup.exe", "net1.exe")]
    [process where event.code == "1" and process.name in
      ("whoami.exe", "net.exe", "ipconfig.exe", "systeminfo.exe",
       "tasklist.exe", "nltest.exe", "netstat.exe", "arp.exe",
       "nslookup.exe", "net1.exe")]
eql_tiebreaker: "@timestamp"
spl_correlation: |
  index=sysmon EventCode=1
    (Image="*\\whoami.exe" OR Image="*\\net.exe" OR Image="*\\ipconfig.exe"
     OR Image="*\\systeminfo.exe" OR Image="*\\tasklist.exe"
     OR Image="*\\nltest.exe" OR Image="*\\netstat.exe" OR Image="*\\arp.exe")
  | bucket _time span=60s
  | stats dc(Image) as distinct_tools count by host, _time, User
  | where distinct_tools >= 3
level: high
tags:
  - attack.discovery
  - attack.t1087.002
falsepositives:
  - System administrators troubleshooting
  - Monitoring scripts running multiple network checks
  - IT inventory/audit scripts
```

**Scenario requirements** (`simulator/scenarios/t1087_002_discovery_burst.json`):
- Attack: 5 recon commands within 30 seconds from same host, same user
- Benign: 1-2 recon commands spaced minutes apart (sysadmin usage)

#### EQL-2: Process Injection Chain

Detects the sequence: open process handle -> create remote thread, indicating process injection.

```yaml
title: Process Injection Sequence — Access Then Remote Thread
id: 9b4d2a3f-5c6e-7f8a-9b0c-1d2e3f4a5b6c
detection_type: eql
eql_query: |
  sequence by host.name with maxspan=10s
    [process where event.code == "10" and
      winlog.event_data.GrantedAccess in ("0x1F0FFF", "0x1F3FFF", "0x001F0FFF") and
      not process.executable : ("*\\MsMpEng.exe", "*\\csrss.exe", "*\\svchost.exe")]
    [process where event.code == "8" and
      not process.executable : ("*\\MsMpEng.exe", "*\\csrss.exe")]
eql_tiebreaker: "@timestamp"
level: critical
tags:
  - attack.privilege_escalation
  - attack.t1055.001
  - attack.t1055.004
```

#### EQL-3: Persistence After Suspicious Execution

Detects: PowerShell with bypass flags -> registry Run key modification within 5 minutes.

```yaml
title: PowerShell Execution Followed by Registry Persistence
id: 0c5e3b4a-6d7f-8a9b-0c1d-2e3f4a5b6c7d
detection_type: eql
eql_query: |
  sequence by host.name with maxspan=300s
    [process where event.code == "1" and
      process.name : ("powershell.exe", "pwsh.exe") and
      process.command_line : ("*-ExecutionPolicy*Bypass*", "*-ep*bypass*",
                              "*-enc*", "*-EncodedCommand*", "*-e *")]
    [registry where event.code == "13" and
      registry.path : ("*\\CurrentVersion\\Run\\*",
                        "*\\CurrentVersion\\RunOnce\\*")]
eql_tiebreaker: "@timestamp"
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.persistence
  - attack.t1547.001
```

### EQL Validation Module

```python
# autonomous/orchestration/validation_eql.py

"""
EQL Validation Module — Validates EQL sequence rules against Elasticsearch.

Uses the ES EQL search API instead of the standard _search API.
Reuses the ephemeral index pattern from validation.py.
"""

import json
import time
from pathlib import Path
from uuid import uuid4

from orchestration.validation import (
    _es_request, _ensure_index_template, _ensure_ilm_policy,
    _bulk_ingest_events, _cleanup_index
)


def validate_eql_against_elasticsearch(
    eql_query: str,
    events: list[dict],
    expected_sequences: int = 1,
    index_prefix: str = "sim-validation",
    timeout_seconds: int = 30,
    cleanup: bool = True,
    ingestion_method: str = "direct"
) -> dict | None:
    """
    Validate an EQL sequence query against ingested events in Elasticsearch.

    Flow:
    1. Create ephemeral index (sim-validation-{uuid})
    2. Bulk ingest all scenario events (attack + benign)
    3. Run EQL query via POST /{index}/_eql/search
    4. Count matched sequences
    5. Compare against expected_sequences for TP/FP scoring
    6. Cleanup index

    Returns:
        {
            "validation_method": "elasticsearch_eql",
            "eql_query": "...",
            "sequences_found": 1,
            "expected_sequences": 1,
            "tp": 1, "fp": 0, "fn": 0, "tn": 1,
            "f1": 1.0,
            "events_ingested": 12,
            "index_used": "sim-validation-abc123"
        }
    Returns None if ES is unreachable.
    """
    infra = _load_infra_config()
    es_url = infra["elasticsearch"]["url"]

    # Create ephemeral index
    index_name = f"{index_prefix}-{uuid4().hex[:8]}"
    _ensure_index_template(es_url)
    _ensure_ilm_policy(es_url)

    try:
        # Ingest events
        _bulk_ingest_events(es_url, index_name, events)

        # Wait for indexing
        _es_request(f"{es_url}/{index_name}/_refresh", method="POST")
        time.sleep(1)

        # Run EQL query
        eql_body = {
            "query": eql_query,
            "tiebreaker_field": "@timestamp",
            "size": 100
        }
        status, response = _es_request(
            f"{es_url}/{index_name}/_eql/search",
            method="POST",
            data=eql_body
        )

        if status != 200:
            return {"error": f"EQL query failed: {response}", "validation_method": "elasticsearch_eql"}

        # Parse EQL results
        hits = response.get("hits", {})
        sequences = hits.get("sequences", [])
        events_matched = hits.get("events", [])

        sequences_found = len(sequences) if sequences else (1 if events_matched else 0)

        # Score: did we find the expected number of sequences?
        # For attack events: expect sequences_found >= expected_sequences
        # For benign-only: expect sequences_found == 0
        attack_events = [e for e in events if e.get("_simulation", {}).get("type") == "attack"]
        benign_events = [e for e in events if e.get("_simulation", {}).get("type") == "benign"]

        if attack_events and sequences_found >= expected_sequences:
            tp = 1
            fn = 0
        elif attack_events:
            tp = 0
            fn = 1
        else:
            tp = 0
            fn = 0

        # FP: sequences matching only benign events
        fp = max(0, sequences_found - expected_sequences) if attack_events else sequences_found
        tn = 1 if (benign_events and fp == 0) else 0

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            "validation_method": "elasticsearch_eql",
            "eql_query": eql_query[:200] + "..." if len(eql_query) > 200 else eql_query,
            "sequences_found": sequences_found,
            "expected_sequences": expected_sequences,
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "events_ingested": len(events),
            "index_used": index_name
        }

    finally:
        if cleanup:
            _cleanup_index(es_url, index_name)
```

### Elastic Detection Engine EQL Format

EQL rules compile to Elastic Detection Engine JSON natively — no Sigma transpilation needed:

```json
{
  "name": "Rapid Reconnaissance Command Burst",
  "description": "Detects 3+ reconnaissance commands within 60 seconds on a single host",
  "risk_score": 73,
  "severity": "high",
  "type": "eql",
  "language": "eql",
  "query": "sequence by host.name with maxspan=60s ...",
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {"id": "TA0007", "name": "Discovery"},
      "technique": [{"id": "T1087", "name": "Account Discovery"}]
    }
  ],
  "from": "now-6m",
  "interval": "5m",
  "enabled": true,
  "tags": ["Process Injection Detection Pack", "Fawkes"]
}
```

### Splunk Equivalent for EQL Detections

Since Splunk has no native EQL, translate to SPL correlation searches:

```spl
# Discovery burst — SPL equivalent
index=sysmon EventCode=1
  (Image="*\\whoami.exe" OR Image="*\\net.exe" OR Image="*\\ipconfig.exe"
   OR Image="*\\systeminfo.exe" OR Image="*\\tasklist.exe" OR Image="*\\arp.exe")
| bucket _time span=60s
| stats dc(Image) as distinct_tools values(Image) as tools count by host, _time, User
| where distinct_tools >= 3
```

Store compiled SPL in `detections/<tactic>/compiled/<technique>.spl` alongside the EQL JSON.

---

## Task 6.3: Threshold Rule Support (3h)

Add aggregation-based threshold rules for detecting volume-based anomalies. Threshold rules
answer: "Did event X happen more than N times in window T?" — critical for brute force,
ransomware, and discovery burst detection.

### Deliverables

- `templates/threshold-template.yml` — Threshold rule template
- `autonomous/orchestration/validation_threshold.py` — Threshold validation against ES (~200 lines)
- Detection Author Agent updated to generate threshold rules
- ES implementation: `threshold` rule type in Detection Engine
- Splunk implementation: `| stats count by ... | where count > N`

### Threshold Rule Template

```yaml
# templates/threshold-template.yml
title: <Title>
id: <uuid>
status: experimental
description: |
  <Description of the volume-based behavior>
references:
  - https://attack.mitre.org/techniques/<TXXXX>/
author: blue-team-agent
date: <YYYY/MM/DD>
modified: <YYYY/MM/DD>
tags:
  - attack.<tactic>
  - attack.<technique_id>
logsource:
  product: windows
  service: <service>
# Threshold-specific fields
detection_type: threshold
detection:
  selection:
    <field>: <value>
  condition: selection
threshold:
  field: <group_by_field>      # e.g., "source.ip", "host.name", "process.name"
  value: <min_count>           # e.g., 5
  window: <time_window>        # e.g., "10m", "60s", "5m"
  cardinality_field: null      # Optional: count distinct values instead of events
  cardinality_value: null      # Minimum distinct count
falsepositives:
  - <description>
level: <severity>
```

### Priority Threshold Detections

#### Threshold-1: Brute Force Login Attempts

```yaml
title: Brute Force Login — Failed Logon Threshold
id: 1d6f4b5c-7e8a-9b0c-1d2e-3f4a5b6c7d8e
detection_type: threshold
logsource:
  product: windows
  service: security
detection:
  selection:
    event.code: "4625"
  condition: selection
threshold:
  field: source.ip
  value: 5
  window: "10m"
spl_query: |
  index=wineventlog EventCode=4625
  | bucket _time span=10m
  | stats count by src_ip, _time
  | where count > 5
elastic_threshold: |
  {
    "type": "threshold",
    "query": "event.code: \"4625\"",
    "threshold": {
      "field": ["source.ip"],
      "value": 5
    },
    "from": "now-10m"
  }
falsepositives:
  - Service accounts with expired passwords
  - Vulnerability scanners probing authentication
  - SSO systems with retry logic
level: medium
tags:
  - attack.credential_access
  - attack.t1110.001
```

#### Threshold-2: Discovery Command Burst (Simple)

A threshold alternative to the EQL discovery burst — catches the same behavior with simpler
logic, useful when EQL is not available.

```yaml
title: Discovery Burst — Recon Command Threshold
id: 2e7a5c6d-8f9b-0c1d-2e3f-4a5b6c7d8e9f
detection_type: threshold
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    event.code: "1"
    process.name:
      - whoami.exe
      - net.exe
      - net1.exe
      - ipconfig.exe
      - systeminfo.exe
      - tasklist.exe
      - nltest.exe
      - netstat.exe
      - arp.exe
  condition: selection
threshold:
  field: host.name
  value: 3
  window: "60s"
  cardinality_field: process.name
  cardinality_value: 3   # At least 3 DISTINCT recon tools
level: high
tags:
  - attack.discovery
  - attack.t1087.002
```

#### Threshold-3: File Encryption Burst (Ransomware)

```yaml
title: Rapid File Modification — Ransomware Indicator
id: 3f8b6d7e-9a0c-1d2e-3f4a-5b6c7d8e9f0a
detection_type: threshold
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    event.code: "11"  # FileCreate (includes modify)
  filter_system:
    process.name:
      - MsMpEng.exe
      - TiWorker.exe
      - svchost.exe
  condition: selection and not filter_system
threshold:
  field: process.name
  value: 10
  window: "30s"
level: critical
tags:
  - attack.impact
  - attack.t1486
```

#### Threshold-4: Mass Service Stop

```yaml
title: Mass Service Stop — Pre-Ransomware Indicator
id: 4a9c7e8f-0b1d-2e3f-4a5b-6c7d8e9f0a1b
detection_type: threshold
logsource:
  product: windows
  service: system
detection:
  selection:
    event.code: "7036"
    winlog.event_data.param2: "stopped"
  filter_normal:
    winlog.event_data.param1:
      - Windows Update
      - Background Intelligent Transfer Service
  condition: selection and not filter_normal
threshold:
  field: host.name
  value: 3
  window: "5m"
level: high
tags:
  - attack.impact
  - attack.t1489
```

### Threshold Validation Module

```python
# autonomous/orchestration/validation_threshold.py

"""
Threshold Validation Module — Validates aggregation-based rules against Elasticsearch.

Uses ES aggregation queries to count events in time windows, then checks if
the count exceeds the threshold for the grouping field.
"""

def validate_threshold_against_elasticsearch(
    base_query: str,
    threshold_field: str,
    threshold_value: int,
    window: str,
    events: list[dict],
    cardinality_field: str = None,
    cardinality_value: int = None,
    index_prefix: str = "sim-validation",
    cleanup: bool = True
) -> dict | None:
    """
    Validate a threshold rule against ingested events.

    Flow:
    1. Create ephemeral index, ingest events
    2. Run aggregation query:
       - Group by threshold_field
       - Count events (or distinct cardinality_field values) per group
    3. Check if any group exceeds threshold_value
    4. Score against _simulation.type tags

    Returns:
        {
            "validation_method": "elasticsearch_threshold",
            "groups_exceeding_threshold": [{"key": "WORKSTATION-01", "count": 7}],
            "threshold_field": "host.name",
            "threshold_value": 5,
            "tp": 1, "fp": 0, "fn": 0, "tn": 1,
            "f1": 1.0
        }
    """
    # ... (same ephemeral index pattern as validation.py)

    # Aggregation query
    agg_query = {
        "size": 0,
        "query": {"query_string": {"query": base_query}},
        "aggs": {
            "by_field": {
                "terms": {"field": threshold_field, "size": 100},
                "aggs": {}
            }
        }
    }

    if cardinality_field:
        agg_query["aggs"]["by_field"]["aggs"]["distinct"] = {
            "cardinality": {"field": cardinality_field}
        }

    # POST /{index}/_search
    status, response = _es_request(f"{es_url}/{index_name}/_search", method="POST", data=agg_query)

    buckets = response.get("aggregations", {}).get("by_field", {}).get("buckets", [])
    exceeding = []
    for bucket in buckets:
        count = bucket.get("doc_count", 0)
        if cardinality_field:
            count = bucket.get("distinct", {}).get("value", 0)
            check_value = cardinality_value or threshold_value
        else:
            check_value = threshold_value

        if count >= check_value:
            exceeding.append({"key": bucket["key"], "count": count})

    # Score: exceeding groups from attack events = TP, from benign = FP
    # ...
```

### Elastic Detection Engine Threshold Format

```json
{
  "name": "Brute Force Login - Failed Logon Threshold",
  "type": "threshold",
  "query": "event.code: \"4625\"",
  "threshold": {
    "field": ["source.ip"],
    "value": 5,
    "cardinality": []
  },
  "from": "now-10m",
  "interval": "5m",
  "severity": "medium",
  "risk_score": 47,
  "enabled": true
}
```

---

## Task 6.4: Evasion Resilience Testing (3h)

Test deployed detections against evasion variants. Real adversaries do not run
`powershell.exe -ExecutionPolicy Bypass` — they use obfuscation, LOLBins, API-direct calls,
and parent process spoofing. Evasion testing reveals how brittle our detections are.

### Deliverables

- `tests/evasion/` — New directory with evasion variant test cases
- Evasion catalog: per-technique evasion variants with expected detection outcomes
- Scenario Engineer Agent generates evasion variants automatically (Phase 4 integration)
- Validation Agent tests original rule against evasion variants
- GitHub Issues auto-created for detections that fail evasion tests

### Evasion Catalog

```
tests/evasion/
  t1059_001/                           # PowerShell detections
    caret_insertion.json               # po^wer^shell
    string_concat.json                 # $a="pow";$b="ershell";& "$a$b"
    env_variable.json                  # %comspec% /c powershell
    renamed_binary.json                # copy powershell.exe svc.exe; svc.exe -ep bypass
    encoded_command.json               # -e <base64> without -EncodedCommand flag
  t1055_001/                           # CreateRemoteThread
    syscall_direct.json                # NtCreateThreadEx via direct syscall (no EID 8)
    ppid_spoof.json                    # Spoofed parent PID
    dll_sideload.json                  # DLL side-loading instead of thread injection
  t1547_001/                           # Registry Run Key
    powershell_set_itemproperty.json   # Set-ItemProperty instead of reg.exe
    wmi_registry.json                  # WMI StdRegProv for registry write
    vbs_registry.json                  # VBScript RegWrite method
  t1071_001/                           # C2 over HTTPS
    domain_fronting.json               # CDN-fronted HTTPS with mismatched Host header
    malleable_profile.json             # Custom HTTP profile mimicking legitimate traffic
    dns_over_https.json                # DoH for C2 resolution
  t1053_005/                           # Scheduled Task
    com_object.json                    # Schedule.Service COM instead of schtasks.exe
    at_command.json                    # at.exe legacy scheduler
    powershell_scheduledtask.json      # Register-ScheduledTask cmdlet
```

### Evasion Variant JSON Format

```json
{
  "technique_id": "T1059.001",
  "evasion_type": "caret_insertion",
  "description": "Uses caret character insertion to break process name string matching",
  "difficulty": "low",
  "expected_detection": false,
  "attack_events": [
    {
      "@timestamp": "2026-03-15T10:00:00Z",
      "event": {"code": "1", "category": "process", "type": "start"},
      "process": {
        "name": "cmd.exe",
        "executable": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "cmd.exe /c p^ow^er^sh^ell -ep bypass -f C:\\temp\\payload.ps1",
        "pid": 5678,
        "parent": {"name": "explorer.exe", "pid": 1234}
      },
      "host": {"name": "WORKSTATION-01"},
      "user": {"name": "jsmith"},
      "_simulation": {"type": "attack", "technique": "T1059.001", "evasion": "caret_insertion"}
    }
  ],
  "why_evades": "Caret characters break simple substring matching on 'powershell' in command_line. The OS strips carets at execution time, but log records preserve them.",
  "remediation": "Use regex matching or normalize command_line by stripping carets before comparison. Or detect the parent chain: cmd.exe spawning child with bypass flags."
}
```

### Evasion Scoring

```python
def calculate_evasion_resilience(technique_id: str) -> dict:
    """Test a detection against all its evasion variants.

    Returns:
        {
            "technique_id": "T1059.001",
            "total_variants": 5,
            "detected": 2,
            "evaded": 3,
            "evasion_resilience": 0.40,
            "results": [
                {"variant": "caret_insertion", "detected": false, "difficulty": "low"},
                {"variant": "string_concat", "detected": false, "difficulty": "low"},
                {"variant": "env_variable", "detected": true, "difficulty": "medium"},
                {"variant": "renamed_binary", "detected": false, "difficulty": "medium"},
                {"variant": "encoded_command", "detected": true, "difficulty": "low"}
            ],
            "verdict": "FRAGILE"  # RESILIENT >= 0.80, MODERATE >= 0.60, FRAGILE < 0.60
        }
    """
    evasion_dir = Path(f"tests/evasion/{technique_id.lower().replace('.', '_')}")
    if not evasion_dir.exists():
        return {"technique_id": technique_id, "error": "No evasion variants found"}

    # Load the original detection rule
    rule = _find_rule_for_technique(technique_id)
    compiled_query = _load_compiled_lucene(technique_id)

    results = []
    for variant_file in sorted(evasion_dir.glob("*.json")):
        variant = json.loads(variant_file.read_text())
        attack_events = variant["attack_events"]
        benign_events = []  # Evasion tests don't need TN — just test if attack is caught

        # Validate against ES (or local fallback)
        validation = validate_against_elasticsearch(
            lucene_query=compiled_query,
            attack_events=attack_events,
            benign_events=benign_events
        )

        detected = validation and validation.get("tp", 0) > 0
        results.append({
            "variant": variant_file.stem,
            "evasion_type": variant.get("evasion_type", "unknown"),
            "detected": detected,
            "difficulty": variant.get("difficulty", "unknown"),
            "expected_detection": variant.get("expected_detection", False)
        })

    detected_count = sum(1 for r in results if r["detected"])
    total = len(results)
    resilience = detected_count / total if total > 0 else 0.0

    if resilience >= 0.80:
        verdict = "RESILIENT"
    elif resilience >= 0.60:
        verdict = "MODERATE"
    else:
        verdict = "FRAGILE"

    return {
        "technique_id": technique_id,
        "total_variants": total,
        "detected": detected_count,
        "evaded": total - detected_count,
        "evasion_resilience": round(resilience, 2),
        "results": results,
        "verdict": verdict
    }
```

**Targets:**
- Each high-priority detection (MONITORING state) should have >= 3 evasion variants
- Target resilience score >= 0.60 (catches at least 60% of evasion variants)
- Detections scoring FRAGILE (< 0.60) get automatic GitHub issue:
  `[Evasion] T1059.001 PowerShell Bypass — 40% resilience (3/5 variants evade)`

### Integration with Scenario Engineer Agent (Phase 4)

The Phase 4 Scenario Engineer Agent generates evasion variants automatically. Its prompt
includes the evasion catalog structure and guidance:

```
For each technique, generate 3-5 evasion variants:
1. LOW difficulty: Simple obfuscation (carets, string concat, encoding changes)
2. MEDIUM difficulty: Tool substitution (LOLBins, PowerShell cmdlets, WMI)
3. HIGH difficulty: API-direct (syscalls, NTAPI), process hollowing, masquerading

Each variant includes:
- Modified attack events with evasion applied
- "why_evades" explanation for the detection author
- "remediation" suggestion for improving the detection
- "expected_detection" flag (some evasions SHOULD be caught — marks false negatives)
```

---

## Task 6.5: Continuous Validation (2h)

Re-validate deployed rules periodically. Rules degrade silently when:
- Data source schema changes (vendor update)
- Field mappings drift (ES template change)
- Benign activity patterns shift (new software deployed)
- Rule was tuned in a way that introduced blind spots

### Deliverables

- `autonomous/orchestration/continuous_validation.py` — Scheduled re-validation engine (~150 lines)
- Weekly re-validation of all MONITORING rules against latest scenarios
- Regression detection: F1 dropped > 0.10 from previous validation -> flag
- SIEM mismatch detection: local passes but ES fails -> field mapping issue
- GitHub Actions workflow: `.github/workflows/continuous-validation.yml`

### Continuous Validation Engine

```python
# autonomous/orchestration/continuous_validation.py

"""
Continuous Validation — Re-validates deployed detections on a schedule.

Catches rule degradation before it causes missed detections in production.
Compares current F1 against historical baseline and flags regressions.
"""

def run_continuous_validation(
    rules_filter: str = "MONITORING",
    regression_threshold: float = 0.10,
    create_issues: bool = True
) -> dict:
    """
    Re-validate all rules in a given state.

    Args:
        rules_filter: Detection state to validate ("MONITORING", "VALIDATED", "ALL")
        regression_threshold: F1 drop that triggers a regression alert
        create_issues: Whether to auto-create GitHub issues for regressions

    Returns:
        {
            "timestamp": "2026-03-15T12:00:00Z",
            "rules_tested": 11,
            "passed": 9,
            "regressed": 1,
            "siem_mismatch": 1,
            "details": [...]
        }
    """
    sm = StateManager()
    rules = sm.get_by_state(rules_filter)

    results = {"timestamp": _now_iso(), "rules_tested": 0, "passed": 0,
               "regressed": 0, "siem_mismatch": 0, "details": []}

    for technique_id in rules:
        results["rules_tested"] += 1

        # Load scenario + compiled query
        scenario = _load_scenario(technique_id)
        compiled = _load_compiled_lucene(technique_id)
        if not scenario or not compiled:
            results["details"].append({"technique": technique_id, "status": "SKIP", "reason": "missing scenario or compiled query"})
            continue

        # Load previous result for comparison
        prev_result = _load_previous_result(technique_id)
        prev_f1 = prev_result.get("f1", 1.0) if prev_result else 1.0

        # Validate against ES
        es_result = validate_against_elasticsearch(
            lucene_query=compiled,
            attack_events=scenario.get("attack", []),
            benign_events=scenario.get("benign", [])
        )

        # Validate locally (for mismatch detection)
        local_result = validate_detection(compiled, scenario)

        if es_result:
            current_f1 = es_result.get("f1", 0.0)
            f1_delta = prev_f1 - current_f1

            # Check for regression
            if f1_delta > regression_threshold:
                results["regressed"] += 1
                detail = {
                    "technique": technique_id,
                    "status": "REGRESSION",
                    "previous_f1": prev_f1,
                    "current_f1": current_f1,
                    "delta": round(f1_delta, 4)
                }
                if create_issues:
                    _create_regression_issue(technique_id, prev_f1, current_f1)
            else:
                results["passed"] += 1
                detail = {"technique": technique_id, "status": "PASS", "f1": current_f1}

            # Check for SIEM mismatch
            if local_result and local_result.get("f1", 0) >= 0.90 and current_f1 < 0.75:
                results["siem_mismatch"] += 1
                detail["siem_mismatch"] = True
                detail["local_f1"] = local_result["f1"]
                detail["es_f1"] = current_f1
                # This usually means a field mapping issue
                if create_issues:
                    _create_mismatch_issue(technique_id, local_result["f1"], current_f1)

        else:
            # ES unreachable — use local result only
            detail = {"technique": technique_id, "status": "ES_OFFLINE", "local_f1": local_result.get("f1") if local_result else None}
            results["passed"] += 1

        results["details"].append(detail)

        # Store updated result
        _save_validation_result(technique_id, es_result or local_result)

    # Store history for trending
    _append_validation_history(results)
    return results
```

### GitHub Actions Workflow

```yaml
# .github/workflows/continuous-validation.yml
name: Continuous Detection Validation
on:
  schedule:
    - cron: '0 6 * * 1'  # Every Monday at 06:00 UTC
  workflow_dispatch:       # Manual trigger

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
        with:
          python-version: '3.12'
      - name: Install dependencies
        run: pip install pyyaml requests
      - name: Run continuous validation (local mode — no ES in CI)
        run: |
          cd autonomous
          python3 -c "
          from orchestration.continuous_validation import run_continuous_validation
          results = run_continuous_validation(
              rules_filter='ALL',
              create_issues=False  # Don't create issues from CI — just report
          )
          print(f'Tested: {results[\"rules_tested\"]}')
          print(f'Passed: {results[\"passed\"]}')
          print(f'Regressed: {results[\"regressed\"]}')
          print(f'SIEM mismatch: {results[\"siem_mismatch\"]}')
          if results['regressed'] > 0:
              print('::error::Detection regressions found!')
              for d in results['details']:
                  if d.get('status') == 'REGRESSION':
                      print(f'  {d[\"technique\"]}: F1 {d[\"previous_f1\"]:.2f} -> {d[\"current_f1\"]:.2f}')
              exit(1)
          "
```

### Validation History Storage

```
monitoring/validation-history/
  2026-03-15.json    # Weekly validation results
  2026-03-22.json
  ...
```

Each file contains the full `run_continuous_validation()` output. Quality Agent reads
this history for trend analysis and regression detection.

---

## Task 6.6: Detection Performance Profiling (2h)

Measure rule performance (query cost) at simulated scale. In production, expensive rules
consume SIEM compute budget and can delay alert generation. Profiling identifies rules that
need optimization before they become problems.

### Deliverables

- `autonomous/orchestration/performance.py` — Query performance profiler (~200 lines)
- For each rule: measure search time against 10K, 100K, 1M simulated events
- Performance budget: queries must complete in < 5 seconds at 1M events
- Flag expensive rules for optimization (query rewrite, field pre-filtering)
- Store results in `tests/results/<technique>_performance.json`

### Performance Profiler

```python
# autonomous/orchestration/performance.py

"""
Detection Performance Profiler — Measures query execution time at scale.

Generates synthetic event volumes and benchmarks each detection query
against Elasticsearch to identify expensive rules before production deployment.
"""

SCALE_TIERS = {
    "small": 10_000,
    "medium": 100_000,
    "large": 1_000_000
}

PERFORMANCE_BUDGET_MS = {
    "small": 500,     # 10K events: < 500ms
    "medium": 2000,   # 100K events: < 2s
    "large": 5000     # 1M events: < 5s
}


def profile_detection(
    technique_id: str,
    compiled_query: str,
    scale: str = "medium",
    iterations: int = 3
) -> dict:
    """
    Profile a detection query's performance at the given scale.

    Args:
        technique_id: MITRE technique ID
        compiled_query: Compiled Lucene query string
        scale: "small" (10K), "medium" (100K), or "large" (1M)
        iterations: Number of times to run query (for averaging)

    Returns:
        {
            "technique_id": "T1059.001",
            "scale": "medium",
            "events_count": 100000,
            "query_times_ms": [145, 132, 138],
            "avg_ms": 138.3,
            "p95_ms": 145,
            "budget_ms": 2000,
            "within_budget": true,
            "es_profile": { ... }  # ES _search profile output for optimization hints
        }
    """
    event_count = SCALE_TIERS[scale]
    budget = PERFORMANCE_BUDGET_MS[scale]

    # Generate synthetic events at scale
    # Mix: 99% benign baseline, 1% attack events matching the technique
    events = _generate_scale_events(technique_id, event_count)

    # Create temporary index, bulk ingest
    index_name = f"sim-perf-{uuid4().hex[:8]}"
    _bulk_ingest_events(es_url, index_name, events, batch_size=5000)
    _es_request(f"{es_url}/{index_name}/_refresh", method="POST")

    try:
        # Run query multiple times, measure timing
        times = []
        for _ in range(iterations):
            query_body = {
                "query": {"query_string": {"query": compiled_query}},
                "size": 0,  # Don't fetch docs — just measure query time
                "profile": True  # Get ES query profiling data
            }
            start = time.monotonic()
            status, response = _es_request(
                f"{es_url}/{index_name}/_search",
                method="POST", data=query_body
            )
            elapsed_ms = (time.monotonic() - start) * 1000
            times.append(elapsed_ms)

        avg_ms = sum(times) / len(times)
        p95_ms = sorted(times)[int(len(times) * 0.95)] if len(times) >= 2 else max(times)

        # Extract ES profile for optimization hints
        profile_data = response.get("profile", {}) if response else {}

        return {
            "technique_id": technique_id,
            "scale": scale,
            "events_count": event_count,
            "query": compiled_query[:200],
            "query_times_ms": [round(t, 1) for t in times],
            "avg_ms": round(avg_ms, 1),
            "p95_ms": round(p95_ms, 1),
            "budget_ms": budget,
            "within_budget": p95_ms <= budget,
            "es_profile_summary": _summarize_profile(profile_data),
            "optimization_hints": _generate_hints(compiled_query, avg_ms, budget, profile_data)
        }

    finally:
        _cleanup_index(es_url, index_name)


def _generate_hints(query: str, avg_ms: float, budget: float, profile: dict) -> list[str]:
    """Generate optimization suggestions for expensive queries."""
    hints = []
    if avg_ms > budget:
        if "*" in query and query.count("*") > 2:
            hints.append("Multiple wildcards detected — consider using keyword field with exact match")
        if "OR" in query.upper() and query.upper().count("OR") > 5:
            hints.append("Many OR clauses — consider using terms query with array instead")
        if "regex" in query.lower() or "/.*/" in query:
            hints.append("Regex in query — very expensive at scale. Use wildcard or keyword match")
        if not hints:
            hints.append("Query is expensive — review ES profile for specific bottleneck")
    return hints
```

### Performance Result Format

```json
{
  "technique_id": "T1059.001",
  "profiled_date": "2026-03-15",
  "results": {
    "small": {
      "events_count": 10000,
      "avg_ms": 23.4,
      "p95_ms": 28.1,
      "within_budget": true
    },
    "medium": {
      "events_count": 100000,
      "avg_ms": 145.2,
      "p95_ms": 162.8,
      "within_budget": true
    },
    "large": {
      "events_count": 1000000,
      "avg_ms": 1834.5,
      "p95_ms": 2103.2,
      "within_budget": true
    }
  },
  "optimization_hints": [],
  "verdict": "PASS"
}
```

### CLI Extension

```bash
python orchestration/cli.py perf T1059.001 --scale medium    # Profile one rule
python orchestration/cli.py perf --all --scale small          # Profile all rules (fast)
python orchestration/cli.py perf --report                     # Show performance summary
```

---

## Task 6.7: Coverage Expansion Sprint (4h)

Use the new multi-rule-type capabilities (EQL, threshold) and multi-platform simulation
(Phase 5) to close high-priority coverage gaps. This task produces actual detection content,
not infrastructure.

### Deliverables — New Detections

| # | Technique | Name | Rule Type | Platform | Fawkes Cmd | File |
|---|-----------|------|-----------|----------|------------|------|
| 1 | T1055.004 | APC Injection | Sigma | Windows | `apc-injection` | `detections/privilege_escalation/t1055_004.yml` |
| 2 | T1087.002 | Discovery Burst | EQL + Threshold | Windows | `ps`, `whoami`, etc. | `detections/discovery/t1087_002.yml` |
| 3 | T1090.001 | SOCKS5 Proxy | Threshold | Windows | `socks5` | `detections/command_and_control/t1090_001.yml` |
| 4 | T1489 | Service Stop (Pre-Ransomware) | Threshold | Windows | — | `detections/impact/t1489.yml` |
| 5 | T1486 v2 | Ransomware Encryption (Threshold) | Threshold | Windows | — | `detections/impact/t1486_threshold.yml` |
| 6 | T1053.003 | Crontab Persistence | Sigma | Linux | `crontab` | `detections/persistence/t1053_003.yml` |

### Detection 1: T1055.004 — APC Injection

**Fawkes command**: `apc-injection`

Detects APC (Asynchronous Procedure Call) injection by monitoring for process access with
full access rights followed by suspicious thread activity. Distinct from CreateRemoteThread
(T1055.001) because APC injection uses `QueueUserAPC` instead of `CreateRemoteThread`.

```yaml
title: Suspicious APC Injection Indicators
id: 5b0d8e9f-1a2b-3c4d-5e6f-7a8b9c0d1e2f
status: experimental
description: |
  Detects potential APC injection by monitoring for process access events with
  full process access rights (0x1F0FFF) to a target process, followed by thread
  creation. APC injection queues a user-mode APC to a thread in the target process,
  which executes shellcode when the thread enters an alertable wait state.
  Fawkes C2 command: apc-injection.
references:
  - https://attack.mitre.org/techniques/T1055/004/
  - https://github.com/galoryber/fawkes
author: blue-team-agent
date: 2026/03/15
tags:
  - attack.privilege_escalation
  - attack.defense_evasion
  - attack.t1055.004
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    event.code: "10"
    winlog.event_data.GrantedAccess:
      - "0x1F0FFF"
      - "0x1F3FFF"
      - "0x001F0FFF"
  filter_system:
    process.executable|endswith:
      - "\\MsMpEng.exe"
      - "\\csrss.exe"
      - "\\lsass.exe"
      - "\\services.exe"
      - "\\svchost.exe"
      - "\\WmiPrvSE.exe"
      - "\\taskhostw.exe"
  filter_av:
    process.executable|contains:
      - "\\Microsoft\\Windows Defender\\"
      - "\\CrowdStrike\\"
      - "\\Carbon Black\\"
  condition: selection and not filter_system and not filter_av
falsepositives:
  - Debuggers (WinDbg, Visual Studio)
  - Some AV products during scanning
  - .NET runtime in rare cases
level: high
```

### Detection 2: T1087.002 — Discovery Burst (EQL)

See EQL-1 in Task 6.2. This detection uses the EQL sequence rule for precise correlation,
plus a threshold rule fallback for Splunk or non-EQL environments.

**Full workflow:**
1. Author EQL rule (Task 6.2 — `detections/discovery/t1087_002_eql.yml`)
2. Author threshold fallback (Task 6.3 — `detections/discovery/t1087_002_threshold.yml`)
3. Generate scenario: `simulator/scenarios/t1087_002_discovery_burst.json`
   - Attack: whoami -> net user -> systeminfo -> ipconfig -> netstat in 30s
   - Benign: Single whoami by sysadmin, 5 minutes later single ipconfig
4. Validate both rules
5. Include both in `discovery` content pack

### Detection 3: T1090.001 — SOCKS5 Proxy Detection (Threshold)

```yaml
title: SOCKS5 Proxy — High Internal Fan-Out
id: 6c1e9f0a-2b3c-4d5e-6f7a-8b9c0d1e2f3a
detection_type: threshold
description: |
  Detects a single process making connections to many distinct internal IP addresses,
  indicating proxy or tunnel usage. Fawkes SOCKS5 command establishes a local proxy
  that tunnels traffic to internal network segments.
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    event.code: "3"
    destination.ip|startswith:
      - "10."
      - "172.16."
      - "172.17."
      - "172.18."
      - "172.19."
      - "172.20."
      - "172.21."
      - "172.22."
      - "172.23."
      - "172.24."
      - "172.25."
      - "172.26."
      - "172.27."
      - "172.28."
      - "172.29."
      - "172.30."
      - "172.31."
      - "192.168."
  filter_browsers:
    process.name:
      - chrome.exe
      - firefox.exe
      - msedge.exe
      - iexplore.exe
  filter_system:
    process.name:
      - svchost.exe
      - lsass.exe
      - System
  condition: selection and not filter_browsers and not filter_system
threshold:
  field: process.name
  value: 10
  window: "5m"
  cardinality_field: destination.ip
  cardinality_value: 10
level: high
tags:
  - attack.command_and_control
  - attack.t1090.001
```

### Detection 4: T1489 — Service Stop for Ransomware

See Threshold-4 in Task 6.3. Author Sigma rule, generate scenario, validate, add to
`impact` content pack.

### Detection 5: T1486 v2 — Ransomware Encryption (Threshold)

See Threshold-3 in Task 6.3. This complements the existing T1486 Sigma rule (which detects
ransomware via process name/command line) by adding a behavioral threshold detection for
mass file modification regardless of the ransomware binary name.

### Detection 6: T1053.003 — Crontab Persistence (Linux)

First cross-platform detection. Requires Phase 5 Linux auditd simulator.

```yaml
title: Crontab Persistence — Suspicious Cron Job Creation
id: 7d2f0a1b-3c4d-5e6f-7a8b-9c0d1e2f3a4b
status: experimental
description: |
  Detects crontab modifications that may indicate persistence via cron job.
  Fawkes C2 command: crontab. Adversaries add entries to crontab to execute
  malicious payloads at scheduled intervals.
references:
  - https://attack.mitre.org/techniques/T1053/003/
author: blue-team-agent
date: 2026/03/15
tags:
  - attack.persistence
  - attack.t1053.003
logsource:
  product: linux
  service: auditd
detection:
  selection_crontab:
    process.name: "crontab"
    process.args|contains:
      - "-e"
      - "-l"
  selection_direct_write:
    event.category: "file"
    file.path|contains:
      - "/var/spool/cron"
      - "/etc/cron.d/"
      - "/etc/crontab"
  filter_package_manager:
    process.parent.name:
      - apt
      - apt-get
      - dpkg
      - yum
      - rpm
      - dnf
  condition: (selection_crontab or selection_direct_write) and not filter_package_manager
falsepositives:
  - System administrators editing crontab for maintenance
  - Configuration management tools (Ansible, Puppet, Chef)
  - Package installation/update processes
level: medium
```

### Expected Coverage Improvement

| Metric | Before Phase 6 | After Phase 6 |
|--------|---------------|--------------|
| Total Sigma rules | 29 | 35+ |
| EQL rules | 0 | 3 |
| Threshold rules | 0 | 4 |
| Fawkes coverage | 62% | 75%+ |
| Non-Fawkes detections | 5 | 8+ |
| Cross-platform detections | 0 | 1+ |
| Content packs | 0 | 9 |

### Workflow for Each New Detection

Follow the standard detection lifecycle (CLAUDE.md workflow):

1. **INTEL**: Identify technique from Fawkes capability list + `coverage/attack-matrix.md` gaps
2. **DISCOVER**: Verify data source availability via `cli.py data-gaps`
3. **AUTHOR**: Write Sigma/EQL/threshold rule using appropriate template
4. **VALIDATE**: Run `validate_against_elasticsearch()` or EQL/threshold validator
5. **TEST**: Generate TP/TN test cases, run evasion variants (Task 6.4)
6. **COMPILE**: Transpile to Lucene + SPL (Sigma rules) or generate Elastic JSON (EQL/threshold)
7. **PACK**: Add rule to appropriate content pack manifest
8. **PR**: Create feature branch, push, create PR

---

## Validation Criteria

- [ ] Content pack framework working with `cli.py pack list | validate | deploy` (Task 6.1)
- [ ] Existing 29 rules organized into 9 content packs with manifests (Task 6.1)
- [ ] EQL template created and documented (Task 6.2)
- [ ] `validation_eql.py` validates EQL sequences against ES (Task 6.2)
- [ ] At least 2 EQL correlation rules authored and validated (F1 >= 0.90) (Task 6.2)
- [ ] Compiled Elastic Detection Engine JSON for all EQL rules (Task 6.2)
- [ ] Threshold template created and documented (Task 6.3)
- [ ] `validation_threshold.py` validates threshold rules against ES (Task 6.3)
- [ ] At least 3 threshold rules authored and validated (F1 >= 0.90) (Task 6.3)
- [ ] Evasion test suite with 3+ variants per high-priority technique (Task 6.4)
- [ ] Evasion resilience score calculated for all MONITORING detections (Task 6.4)
- [ ] Continuous validation runs weekly in CI (Task 6.5)
- [ ] Regression detection catches F1 drops > 0.10 (Task 6.5)
- [ ] Performance profiling completes for all rules at "medium" scale (Task 6.6)
- [ ] All rules within performance budget at medium scale (Task 6.6)
- [ ] 6 new detections authored (3 Sigma, 2 EQL, 4 threshold) (Task 6.7)
- [ ] T1053.003 crontab detection validates on Linux platform (Task 6.7)
- [ ] Coverage at 75%+ Fawkes techniques (Task 6.7)

---

## Commit Strategy

Per-deliverable commits, grouped logically:

1. `feat(packs): add content pack framework with manifest schema and CLI`
   - `detections/packs/` directory with 9 pack manifests
   - CLI extensions: `pack list`, `pack validate`, `pack deploy`
2. `feat(eql): add EQL rule template and ES validation module`
   - `templates/eql-template.yml`
   - `autonomous/orchestration/validation_eql.py`
3. `feat(detection): add EQL correlation rules (discovery burst, injection chain, persistence chain)`
   - 3 EQL rules in `detections/` with compiled Elastic JSON
   - Scenario files in `simulator/scenarios/`
4. `feat(threshold): add threshold rule template and ES validation module`
   - `templates/threshold-template.yml`
   - `autonomous/orchestration/validation_threshold.py`
5. `feat(detection): add threshold rules (brute force, discovery burst, ransomware, service stop)`
   - 4 threshold rules with compiled outputs
6. `feat(evasion): add evasion resilience testing framework`
   - `tests/evasion/` directory with variants for top 5 techniques
   - Evasion scoring engine
7. `feat(validation): add continuous validation engine and CI workflow`
   - `autonomous/orchestration/continuous_validation.py`
   - `.github/workflows/continuous-validation.yml`
8. `feat(perf): add detection query performance profiler`
   - `autonomous/orchestration/performance.py`
   - Performance result files
9. `feat(detection): add APC injection, SOCKS5 proxy, crontab persistence detections`
   - New Sigma rules for T1055.004, T1090.001, T1053.003
   - Scenario files, TP/TN test cases
10. `docs(coverage): update ATT&CK matrix with new detections — 75%+ Fawkes coverage`
    - Updated `coverage/attack-matrix.md`
    - Updated `STATUS.md`, `ROADMAP.md`

**Branch strategy**: `infra/phase6-detection-content` for the full phase, or split:
- `infra/phase6-content-packs` (Task 6.1)
- `infra/phase6-eql-support` (Tasks 6.2 + EQL detections from 6.7)
- `infra/phase6-threshold-support` (Tasks 6.3 + threshold detections from 6.7)
- `infra/phase6-evasion-testing` (Task 6.4)
- `infra/phase6-continuous-validation` (Task 6.5)
- `infra/phase6-performance` (Task 6.6)
- `detection/batch-coverage-expansion` (remaining Task 6.7 detections)
