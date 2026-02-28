# Data Source Gaps

**Last updated**: 2026-02-23
**Purpose**: Track missing telemetry that blocks detection development

---

## Gap Summary

| Gap ID | Missing Source | Affected Techniques | Severity | Resolution |
|---|---|---|---|---|
| GAP-001 | Sysmon EID 11 (File Create) | T1547.001 startup folder, file drops | High | Add EID 11 to simulator |
| GAP-002 | Windows EID 7045 (Service Install) | T1543.003 service persistence | High | Add System log collection to simulator |
| GAP-003 | Sysmon EID 19/20/21 (WMI events) | T1047 WMI execution | High | Add WMI event logging to simulator |
| GAP-004 | Sysmon EID 22 (DNS Query) | T1071.001 domain fronting, T1071.004 | High | Add DNS logging to simulator |
| GAP-005 | Sysmon EID 17/18 (Named Pipe) | T1134, C2 lateral movement via pipes | Medium | Add pipe events to simulator |
| GAP-006 | Sysmon EID 2 (File time change) | T1070.006 timestomping | Medium | Add EID 2 to simulator |
| GAP-007 | Network flow / proxy logs | T1090.004 domain fronting, T1071 | High | Add Zeek/Suricata container to lab |
| GAP-008 | ETW process telemetry | T1056.001 keylogging, T1620 .NET in-mem | High | Requires Elastic Endpoint agent (not Sysmon) |
| GAP-009 | Sysmon EID 25 (Process tampering) | T1055 injection evasion detection | Medium | Add EID 25 to simulator |
| GAP-010 | Docker not installed | ALL — SIEM cannot start | Critical | Install Docker Desktop |

---

## Detailed Gap Analysis

### GAP-001: Missing Sysmon EID 11 — File Create Events

**Severity**: High
**Affected techniques**:
- T1547.001 (Startup Folder persistence) — requires seeing file creation in `shell:startup`
- T1105 (Ingress Tool Transfer) — detecting downloaded payloads
- File drop activity by Fawkes `upload`, `cp`, `mv` commands

**Current workaround**: None effective. Can partially detect via registry (if binary path confirmed) but startup folder writes are invisible.

**Resolution**:
Add to `simulator.py` `attack_persistence_startup_folder()` function that generates:
```json
{
  "event": {"category": "file", "type": "creation", "code": "11"},
  "file": {
    "name": "update_svc.exe",
    "path": "C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update_svc.exe"
  },
  "process": {"name": "cmd.exe"}
}
```

**GitHub Issue**: `[Gap] Missing Sysmon EID 11 file creation — blocks startup folder persistence detection (T1547.001)`

---

### GAP-002: Missing Windows EID 7045 — Service Install Events

**Severity**: High
**Affected techniques**:
- T1543.003 (Windows Service persistence / execution) — Fawkes `service` command

**Current workaround**: Detect `sc.exe create` command line via Sysmon EID 1 (lower fidelity).

**Resolution**:
Add Windows System event log collection to simulation. Generate events with:
```json
{
  "event": {"category": "driver", "type": "start", "code": "7045"},
  "winlog": {
    "event_data": {
      "ServiceName": "WindowsUpdate",
      "ImagePath": "C:\\ProgramData\\update_svc.exe",
      "ServiceType": "User Mode Service",
      "StartType": "Auto Start"
    }
  }
}
```

**GitHub Issue**: `[Gap] Missing Windows EID 7045 — blocks Windows Service persistence detection (T1543.003)`

---

### GAP-003: Missing Sysmon EID 19/20/21 — WMI Events

**Severity**: High
**Affected techniques**:
- T1047 (WMI Execution) — Fawkes `wmi` command for local and remote execution
- T1546.003 (WMI Event Subscription persistence)

**Current workaround**: None effective. WMI execution via Sysmon EID 1 only catches wmiprvse.exe spawning children, which is indirect.

**Resolution**:
Enable Sysmon WMI event logging in lab configuration and add simulator events:
- EID 19: WmiEventFilter activity
- EID 20: WmiEventConsumer activity
- EID 21: WmiEventConsumerToFilter activity

**GitHub Issue**: `[Gap] Missing Sysmon WMI events (EID 19-21) — blocks T1047 and T1546.003 detection`

---

### GAP-004: Missing Sysmon EID 22 — DNS Query Events

**Severity**: High
**Affected techniques**:
- T1071.001 (C2 via HTTPS with domain fronting) — DNS query for CDN domains hiding C2 traffic
- T1071.004 (DNS C2) — direct DNS-based C2 channels
- T1568 (Dynamic Resolution) — DGA domains

**Current workaround**: Detect IP-based beaconing (EID 3) but miss domain fronting entirely.

**Resolution**:
Add DNS query events to simulator:
```json
{
  "event": {"category": "network", "type": "protocol", "code": "22"},
  "dns": {"question": {"name": "cdn.legit-cdn.com", "type": "A"}},
  "process": {"name": "update_helper.exe"}
}
```
Also consider adding a local DNS sinkhole or Pi-hole for DNS visibility.

**GitHub Issue**: `[Gap] Missing Sysmon EID 22 DNS events — blocks domain fronting detection (T1071.001)`

---

### GAP-005: Missing Sysmon EID 17/18 — Named Pipe Events

**Severity**: Medium
**Affected techniques**:
- T1134 (Token theft via named pipe impersonation)
- Lateral movement via SMB named pipes (Impacket-style)
- BOF execution can create named pipes

**Current workaround**: Partial — process access events may reveal pipe-related patterns.

**Resolution**: Add named pipe creation/connection events to Sysmon config and simulator.

---

### GAP-006: Missing Sysmon EID 2 — File Timestamp Change

**Severity**: Medium
**Affected techniques**:
- T1070.006 (Timestomping) — Fawkes `timestomp` command

**Resolution**: Add EID 2 events to simulator with `file.created` and `file.modified` timestamp manipulation indicators.

---

### GAP-007: Missing Network Flow / Proxy Logs

**Severity**: High
**Affected techniques**:
- T1090.004 (Domain Fronting) — need to see HTTP Host header vs. SNI mismatch
- T1071.001 beaconing patterns beyond raw IP
- SOCKS5 proxy traffic from Fawkes `socks5` command

**Resolution**:
Add Zeek or Suricata container to `docker-compose.yml`. Zeek generates rich network metadata including:
- HTTP host headers
- TLS SNI
- Connection duration and bytes
- DNS answers

**GitHub Issue**: `[Gap] No network flow logs — blocks domain fronting and advanced C2 detection (T1090.004)`

---

### GAP-008: Missing ETW Process Telemetry

**Severity**: High
**Affected techniques**:
- T1056.001 (Keylogging) — `SetWindowsHookEx` API call not visible in Sysmon
- T1620 (Reflective Code Loading) — in-memory .NET without Sysmon EID 7 in some variants
- T1027.009 (Embedded Payloads) — binary padding techniques

**Resolution**:
Elastic Endpoint agent (instead of Sysmon) provides ETW-based telemetry including API-level events. This is a significant infrastructure upgrade but enables detection of:
- API call sequences (OpenProcess → VirtualAllocEx → WriteProcessMemory)
- .NET runtime events
- Keyboard hook installation

**GitHub Issue**: `[Gap] No ETW telemetry — blocks keylogging and in-memory .NET detection (T1056.001, T1620)`

---

### GAP-009: Missing Sysmon EID 25 — Process Tampering

**Severity**: Medium
**Affected techniques**:
- T1055 (Process Injection variants) — process herpaderping, ghosting
- Detecting injection evasion techniques

**Resolution**: Enable Sysmon EID 25 in lab Sysmon config.

---

### GAP-010: Docker Not Installed (Critical — Lab Blocker)

**Severity**: Critical
**Impact**: ALL detections blocked — cannot start SIEM, log simulator, or Elastic MCP

**Resolution**:
1. Install Docker Desktop for Windows: https://www.docker.com/products/docker-desktop/
2. Enable WSL 2 backend (required for Windows)
3. Run: `make setup` (choose Elastic stack)
4. Verify: `curl http://localhost:9200/_cluster/health`

**After Docker is installed**, the following will become available:
- Elasticsearch at `http://localhost:9200`
- Kibana at `http://localhost:5601`
- Log simulator generating ~5 EPS of baseline + attack events
- Elastic MCP tools for programmatic SIEM access

---

## Resolution Priority

| Priority | Gap | Effort | Impact |
|---|---|---|---|
| P0 (Blocker) | GAP-010: Install Docker | Low (download + install) | Unblocks everything |
| P1 (High) | GAP-004: DNS events (EID 22) | Low (simulator change) | Enables domain fronting detection |
| P1 (High) | GAP-001: File events (EID 11) | Low (simulator change) | Enables startup folder detection |
| P1 (High) | GAP-002: EID 7045 service events | Low (simulator change) | Enables service persistence detection |
| P1 (High) | GAP-003: WMI events (EID 19-21) | Low (simulator change) | Enables WMI detection |
| P2 (Medium) | GAP-007: Network flow logs | Medium (add Zeek container) | Enables advanced C2 detection |
| P2 (Medium) | GAP-005/006/009: EID 17/18/2/25 | Low (simulator change) | Closes misc gaps |
| P3 (Low) | GAP-008: ETW telemetry | High (agent swap) | Advanced injection detection |
