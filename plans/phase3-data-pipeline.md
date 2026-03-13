# Phase 3: Data Pipeline — Raw Logs through Cribl

**Priority**: HIGH
**Estimated effort**: 8-12 hours (multi-session)
**Dependencies**: Phase 2 (SIEM validation), Docker + Cribl running
**Branch**: `infra/phase3-data-pipeline`

---

## Context

Current flow skips the normalization layer where most real-world detection failures occur:

```
Current:  Red-team → pre-normalized ECS JSON → direct to SIEM
Problem:  Fields are always correct because they're hand-crafted
Reality:  Raw logs → parsing → normalization → SIEM (failures at every step)
```

This phase implements the full pipeline: raw vendor events → Cribl normalization → SIEM.

## Architecture

```
Red-Team Agent
  ↓ generates raw vendor-format events
  ↓ (Windows Event XML, raw syslog, HEC JSON with _raw field)
simulator/raw/<source_type>/<technique_id>.json
  ↓
Cribl Stream (cim_normalize pipeline)
  ↓ regex_extract: parse fields from _raw
  ↓ eval: map to ECS field names
  ↓ drop: filter noise events
  ↓
Elasticsearch (sim-validation index)
  ↓
Blue-Team Agent
  ↓ runs Lucene query → measures TP/FP
  ↓
Detection validated end-to-end
```

## Tasks

### Task 3.1: Define Raw Event Formats

Create reference formats for each data source the lab uses.

**Steps**:
1. Create `simulator/raw/README.md` documenting supported raw formats
2. Create example raw events for the 3 most common sources:

**Sysmon EID 1 (Process Create)** — raw HEC format:
```json
{
  "event": "EventID: 1\nUtcTime: 2026-03-13 10:00:00.123\nProcessGuid: {12345}\nProcessId: 4321\nImage: C:\\Users\\victim\\AppData\\Local\\Temp\\malware.exe\nCommandLine: malware.exe --inject --pid 1234\nParentImage: C:\\Windows\\explorer.exe\nParentProcessId: 1000\nUser: CORP\\jsmith\nLogonId: 0x12345\nHashes: SHA256=abc123...",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "host": "WS-FINANCE-01",
  "source": "WinEventLog:Microsoft-Windows-Sysmon/Operational",
  "time": 1710316800
}
```

**Windows Security 4688 (Process Create)** — raw HEC format:
```json
{
  "event": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4688</EventID><Computer>WS-FINANCE-01</Computer><TimeCreated SystemTime='2026-03-13T10:00:00.123Z'/></System><EventData><Data Name='NewProcessName'>C:\\Users\\victim\\malware.exe</Data><Data Name='CommandLine'>malware.exe --payload</Data><Data Name='ParentProcessName'>C:\\Windows\\explorer.exe</Data><Data Name='SubjectUserName'>jsmith</Data></EventData></Event>",
  "sourcetype": "WinEventLog:Security",
  "host": "WS-FINANCE-01",
  "time": 1710316800
}
```

**Sysmon EID 3 (Network Connection)** — raw HEC format:
```json
{
  "event": "EventID: 3\nUtcTime: 2026-03-13 10:01:00.000\nImage: C:\\Users\\victim\\AppData\\Local\\Temp\\malware.exe\nDestinationIp: 185.220.101.42\nDestinationPort: 443\nSourceIp: 10.0.1.50\nSourcePort: 54321\nProtocol: tcp",
  "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
  "host": "WS-FINANCE-01",
  "time": 1710316860
}
```

### Task 3.2: Add Raw Event Generator to Red-Team Agent

Modify `red_team_agent.py` to generate raw events alongside ECS events.

**Steps**:
1. Add `generate_raw_events()` function that converts ECS events to raw vendor format
2. For each scenario, generate both:
   - `simulator/scenarios/<technique_id>.json` (current ECS format — for local validation fallback)
   - `simulator/raw/sysmon/<technique_id>.json` (raw HEC format — for Cribl pipeline)
3. Include `_raw` field with the unstructured log text
4. Include HEC metadata: `sourcetype`, `host`, `source`, `time`

**Conversion logic** (ECS → raw Sysmon):
```python
def ecs_to_raw_sysmon(ecs_event: dict) -> dict:
    """Convert an ECS-formatted event to raw Sysmon HEC format."""
    eid = ecs_event.get("event", {}).get("code", "1")

    # Build raw Sysmon text
    raw_lines = [f"EventID: {eid}"]
    if "process" in ecs_event:
        raw_lines.append(f"Image: {ecs_event['process'].get('executable', '')}")
        raw_lines.append(f"CommandLine: {ecs_event['process'].get('command_line', '')}")
        if "parent" in ecs_event["process"]:
            raw_lines.append(f"ParentImage: {ecs_event['process']['parent'].get('executable', '')}")
    # ... map remaining fields

    return {
        "event": "\n".join(raw_lines),
        "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "host": ecs_event.get("host", {}).get("name", "WORKSTATION-01"),
        "time": int(datetime.now().timestamp()),
        "_simulation": ecs_event.get("_simulation", {})
    }
```

### Task 3.3: Build Cribl Normalization Pipeline

Use the existing Cribl MCP tools to build/verify the `cim_normalize` pipeline.

**Steps**:
1. Check Cribl health: `cribl_health()`
2. Get current pipeline: `cribl_get_pipeline('cim_normalize')`
3. Sample raw events: `cribl_get_input_samples('lab_hec_in', count=10)`
4. Add parsing functions for each Sysmon EID:

**Function 1: Extract EventID**
```javascript
cribl_add_pipeline_function('cim_normalize', {
  type: 'regex_extract',
  filter: 'true',
  conf: { field: '_raw', regex: 'EventID[=:]\\s*(?<event_code>\\d+)' },
  description: 'Extract Sysmon EventID from raw event'
})
```

**Function 2: Extract Process Fields (EID 1)**
```javascript
cribl_add_pipeline_function('cim_normalize', {
  type: 'regex_extract',
  filter: "event_code == '1'",
  conf: { field: '_raw', regex: 'Image:\\s*(?<process_executable>.+?)\\n' },
  description: 'Extract process image path from Sysmon EID 1'
})
```

**Function 3: Map to ECS**
```javascript
cribl_add_pipeline_function('cim_normalize', {
  type: 'eval',
  filter: 'true',
  conf: { add: [
    { name: 'process.executable', value: 'process_executable' },
    { name: 'process.command_line', value: 'command_line' },
    { name: 'process.name', value: "process_executable ? process_executable.split('\\\\').pop() : undefined" },
    { name: 'event.code', value: 'event_code' },
    { name: 'process.parent.executable', value: 'parent_image' }
  ]},
  description: 'Map extracted fields to ECS dotted notation'
})
```

**Function 4: CIM Aliases (Splunk)**
```javascript
cribl_add_pipeline_function('cim_normalize', {
  type: 'eval',
  filter: 'true',
  conf: { add: [
    { name: 'src_ip', value: "__e['source.ip']" },
    { name: 'dest_ip', value: "__e['destination.ip']" },
    { name: 'user', value: "__e['user.name']" },
    { name: 'CommandLine', value: "__e['process.command_line']" },
    { name: 'EventCode', value: "__e['event.code']" }
  ]},
  description: 'CIM field aliases for Splunk compatibility'
})
```

5. Preview pipeline with raw samples: `cribl_preview_pipeline('cim_normalize', raw_samples)`
6. Verify all required ECS fields are present in output
7. Check metrics: `cribl_get_metrics()`

### Task 3.4: Integrate Cribl into Validation Flow

Modify the validation flow to route raw events through Cribl before querying.

**Steps**:
1. In `validate_against_elasticsearch()`, add option to route via Cribl:
   ```python
   if use_cribl:
       # Send raw events to Cribl HEC input
       for event in raw_events:
           requests.post(f"{CRIBL_HEC_URL}/services/collector/event",
               headers={"Authorization": f"Splunk {HEC_TOKEN}"},
               json=event)
       # Wait for Cribl to process and forward to ES
       time.sleep(2)
       # Query ES for normalized events
   ```
2. Compare results: raw→Cribl→ES vs direct ECS→ES
3. If fields are missing after Cribl normalization, use MCP tools to fix the pipeline

### Task 3.5: Data Source Gap Tracking (Structured YAML)

Replace free-text `gaps/data-source-gaps.md` with structured YAML files.

**Steps**:
1. Create `gaps/data-sources/` directory
2. For each identified gap, create a YAML file:

```yaml
# gaps/data-sources/sysmon_eid_19.yml
source_type: sysmon
event_id: 19
event_name: WmiEventFilter
status: gap  # gap | in_progress | onboarded
priority: high
affected_techniques:
  - T1047  # WMI Execution
  - T1546.003  # WMI Event Subscription
simulator_support: false
cribl_pipeline: null
ecs_fields_expected:
  - wmi.filter.name
  - wmi.filter.query
  - user.name
  - event.code
resolution_notes: |
  Need to add WMI event generator to simulator.
  Raw format: Windows Event XML with EventID 19-21.
  Requires Sysmon config to enable WMI logging.
created_date: 2026-03-13
```

3. Create files for all 9 identified gaps (GAP-001 through GAP-009)
4. Add `check_data_sources()` to `cli.py` that scans these files and reports status

### Task 3.6: Intel Agent — Tag Data Source Requirements

Modify `intel_agent.py` to include `data_source_requirements` in detection requests.

**Steps**:
1. When creating a detection request, look up required data sources from the Fawkes TTP mapping
2. Add to the request YAML:
   ```yaml
   data_source_requirements:
     - source: sysmon
       event_ids: [1]
       fields_needed: [process.executable, process.command_line]
     - source: sysmon
       event_ids: [8]
       fields_needed: [source.process.executable, target.process.executable]
   ```
3. Cross-reference against `gaps/data-sources/*.yml` to check availability
4. If a required source has `status: gap`, note it on the request:
   ```yaml
   data_source_gaps: ["sysmon_eid_19"]
   ```

---

## Verification Checklist

- [ ] Raw event formats documented for Sysmon EID 1, 3, 7, 8, 10, 13
- [ ] Red-team agent generates raw HEC events alongside ECS events
- [ ] Cribl `cim_normalize` pipeline parses raw Sysmon → ECS fields
- [ ] `cribl_preview_pipeline` shows correct field extraction
- [ ] Events flow: raw → Cribl HEC → pipeline → Elasticsearch
- [ ] Blue-team validation works against Cribl-normalized data
- [ ] Data source gap files exist in `gaps/data-sources/` for all 9 gaps
- [ ] Intel agent tags requests with `data_source_requirements`
- [ ] Pipeline change log created: `tuning/changelog/cribl-pipeline-<date>.md`

---

## Commit Strategy

1. `feat(simulator): add raw vendor event format support`
2. `feat(cribl): build cim_normalize pipeline for Sysmon events`
3. `feat(validation): route raw events through Cribl for end-to-end testing`
4. `feat(gaps): structured data source gap tracking (YAML)`
5. `feat(intel): tag detection requests with data source requirements`
