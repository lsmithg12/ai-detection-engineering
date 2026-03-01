# TODO: Log Onboarding — Scattered Spider Data Gaps

**Created**: 2026-03-01
**Source**: Scattered Spider intel analysis (https://research.splunk.com/stories/scattered_spider/)
**Status**: All items BACKLOGGED — to be addressed in a future session

---

## Why These Logs Matter

Scattered Spider's 26 Splunk detections rely on data sources we don't yet collect.
Without these, **9 detections are fully blocked** and several others have only partial coverage.
Onboarding these log sources unlocks detections for both Scattered Spider AND Fawkes C2.

---

## BACKLOGGED Items

### 1. [BACKLOG] PowerShell Script Block Logging (EID 4104) — CRITICAL

**Impact**: Unlocks 5 Scattered Spider detections (Mimikatz PS, encoded commands, Exchange cmdlets, PS hunting, PS scheduled tasks)
**What's needed**:
- Enable PowerShell Module + Script Block logging in Group Policy (or via registry)
- Collect `Microsoft-Windows-PowerShell/Operational` log
- Simulator: add EID 4104 events with `ScriptBlockText` field for attack scenarios
- Fields needed: `event.code: "4104"`, `powershell.file.script_block_text`, `powershell.file.script_block_id`

**How to onboard**:
1. Add 4104 event generation to `simulator/simulator.py`
2. Include in both baseline (benign PS scripts) and attack (encoded commands, Mimikatz) scenarios
3. Map fields to ECS: `powershell.file.script_block_text` or `winlog.event_data.ScriptBlockText`
4. Update `sim-logs` index template with new field mappings
5. Test: `curl -u elastic:changeme http://localhost:9200/sim-attack/_search -d '{"query":{"term":{"event.code":"4104"}}}'`

**Detections unlocked**:
- Detect Mimikatz With PowerShell Script Block (T1003 + T1059.001)
- PowerShell 4104 Hunting (T1059.001)
- Malicious PowerShell Process - Encoded Command (T1027) — enhanced version
- Exchange PowerShell Module Usage (T1059.001)
- Windows MSExchange Management Mailbox Cmdlet Usage (T1059.001)

---

### 2. [BACKLOG] Sysmon EID 11 — File Create — HIGH

**Impact**: Unlocks 3 Scattered Spider detections (RAT file drops, tool staging, ingress transfer)
**What's needed**:
- Simulator: add EID 11 events for file creation on disk
- Fields needed: `event.code: "11"`, `file.path`, `file.name`, `file.directory`, `process.name`, `process.executable`

**How to onboard**:
1. Add file create event generation to `simulator/simulator.py`
2. Baseline: normal file operations (Office saves, temp files, Windows Update)
3. Attack: RMM tool binary drops (TeamViewer.exe, AnyDesk.exe in %TEMP%), Fawkes `upload` command artifacts
4. Update ECS mappings in `sim-logs` template
5. Also unlocks: T1547.001 Startup Folder persistence (Fawkes `persist -method startup-folder`)

**Detections unlocked**:
- Detect Remote Access Software Usage (File) (T1219)
- Detect Remote Access Software Usage (FileInfo) (T1219)
- Fawkes startup folder persistence (T1547.001)

---

### 3. [BACKLOG] Sysmon EID 22 — DNS Query — HIGH

**Impact**: Unlocks DNS-based RMM/RAT detection — most reliable remote access indicator
**What's needed**:
- Simulator: add EID 22 events with DNS query details
- Fields needed: `event.code: "22"`, `dns.question.name`, `process.name`, `process.executable`

**How to onboard**:
1. Add DNS query event generation to `simulator/simulator.py`
2. Baseline: normal DNS (microsoft.com, windows.com, office365.com, cdn domains)
3. Attack: RMM tool DNS (*.teamviewer.com, *.anydesk.com, *.ngrok.io, *.screenconnect.com)
4. Also useful for: C2 domain fronting detection (T1090.004), DNS tunneling

**Detections unlocked**:
- Detect Remote Access Software Usage DNS (T1219)
- Enhanced C2 beaconing detection (T1071.001)

---

### 4. [BACKLOG] Sysmon EID 17/18 — Named Pipe Create/Connect — MEDIUM

**Impact**: Unlocks named pipe-based RMM and lateral movement detection
**What's needed**:
- Simulator: add EID 17 (pipe created) and EID 18 (pipe connected) events
- Fields needed: `event.code: "17"/"18"`, `file.name` (pipe name), `process.name`, `process.executable`

**How to onboard**:
1. Add pipe events to `simulator/simulator.py`
2. Baseline: standard Windows pipes (`\lsass`, `\wkssvc`, `\srvsvc`)
3. Attack: RMM tool pipes, Cobalt Strike default pipes, Fawkes C2 pipes
4. Also useful for: Cobalt Strike detection, PsExec lateral movement

**Detections unlocked**:
- Windows RMM Named Pipe (T1559 + T1021.002 + T1055)

---

### 5. [BACKLOG] Windows System EID 7045 — Service Install — MEDIUM

**Impact**: Full coverage for service creation persistence (currently partial via sc.exe process detection)
**What's needed**:
- Simulator: add EID 7045 events from Windows System log
- Fields needed: `event.code: "7045"`, `winlog.event_data.ServiceName`, `winlog.event_data.ImagePath`, `winlog.event_data.ServiceType`, `winlog.event_data.StartType`

**How to onboard**:
1. Add service install event generation to `simulator/simulator.py`
2. Baseline: legitimate service installs (Windows Update, software installers)
3. Attack: Fawkes `service -action create` with binary in temp dir, Scattered Spider sc.exe abuse
4. Agent type: `winlogbeat` (System event log, not Sysmon)

**Detections unlocked**:
- Sc exe Manipulating Windows Services (T1543.003) — full coverage
- Fawkes service persistence (T1543.003) — enhanced

---

### 6. [BACKLOG] Sysmon EID 23 — File Delete — LOW

**Impact**: Anti-forensics tracking (cipher.exe, sdelete.exe file deletion events)
**What's needed**:
- Simulator: add EID 23 events for file deletion
- Fields needed: `event.code: "23"`, `file.path`, `file.name`, `process.name`, `process.executable`

**How to onboard**:
1. Add file delete events to `simulator/simulator.py`
2. Baseline: normal temp file cleanup, browser cache clearing
3. Attack: cipher /w: wiping, sdelete secure deletion
4. Lower priority because process-based detection (EID 1) already covers cipher/sdelete execution

**Detections unlocked**:
- Clear Unallocated Sector Using Cipher App (T1070.004) — enhanced
- Sdelete Application Execution (T1070.004 + T1485) — enhanced

---

### 7. [BACKLOG] Sysmon EID 19/20/21 — WMI Events — LOW (for Scattered Spider)

**Impact**: WMI event subscription persistence detection
**What's needed**:
- Simulator: add EID 19 (WmiEventFilter), 20 (WmiEventConsumer), 21 (WmiEventConsumerToFilter)
- Fields needed: WMI-specific winlog fields

**How to onboard**:
1. Add WMI event subscription events to `simulator/simulator.py`
2. Lower priority for Scattered Spider (they use WMI for execution, not persistence)
3. Higher priority for Fawkes `wmi` command detection

**Detections unlocked**:
- Script Execution via WMI (T1047) — enhanced
- Fawkes WMI execution (T1047) — full coverage

---

## Summary: Onboarding Priority Matrix

| Priority | Log Source | EID | Detections Unlocked | Effort | Fawkes Overlap |
|---|---|---|---|---|---|
| 1 - CRITICAL | PowerShell Script Block | 4104 | 5 | Medium | Indirect |
| 2 - HIGH | File Create | 11 | 3 + Fawkes startup | Medium | Yes |
| 3 - HIGH | DNS Query | 22 | 2 + C2 enhanced | Medium | Yes (C2) |
| 4 - MEDIUM | Named Pipe | 17/18 | 1 + lateral movement | Medium | No |
| 5 - MEDIUM | Service Install | 7045 | 2 | Low | Yes |
| 6 - LOW | File Delete | 23 | 2 (enhanced only) | Low | No |
| 7 - LOW | WMI Events | 19/20/21 | 2 | High | Yes |

**Estimated effort**: All changes are to `simulator/simulator.py` + `sim-logs` index template.
Items 1-3 should be tackled first — they unlock the most detections with moderate effort.

---

## Quick Start (Next Session)

```bash
# 1. Start the lab
./setup.sh --both

# 2. Edit simulator to add new event types
# File: simulator/simulator.py
# Add new generator functions for EID 4104, 11, 22, 17/18, 7045

# 3. Update index template
# File: simulator/simulator.py (sim-logs template section)
# Add field mappings for new event types

# 4. Verify new events are flowing
curl -u elastic:changeme http://localhost:9200/sim-baseline/_search \
  -d '{"query":{"term":{"event.code":"4104"}},"size":1}'

# 5. Build detections against new data sources
```
