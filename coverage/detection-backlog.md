# Detection Backlog — Prioritized Top 10

**Created**: 2026-02-23
**Last updated**: 2026-03-01
**Scoring method**: Intel overlap (3pts) + Data source availability (3pts) + Impact (3pts) + Coverage urgency (1pt)
**SIEM status**: Elasticsearch 8.17.0 ONLINE | Splunk 9.3.9 ONLINE — lab profile `--both`
**Intel sources**: Fawkes C2 (primary), Scattered Spider / UNC3944 (2026-03-01)

---

## Scoring Rubric

| Dimension | 3 pts | 2 pts | 1 pt | 0 pts |
|---|---|---|---|---|
| **Intel overlap** | Multiple intel sources | Single intel source (Fawkes OR external) | Adjacent technique | Not in any intel |
| **Data available** | Fully simulated | Partially simulated | Requires config change | Not available |
| **Impact** | Credential/injection/C2 | Persistence/execution | Discovery | Collection |
| **Coverage urgency** | 0 detections in tactic | Few detections | Some coverage | Well covered |

---

## Backlog

### Rank 1 — T1055.001: CreateRemoteThread Process Injection

**Score**: 10/10
**Fawkes command**: `vanilla-injection`
**MITRE**: Privilege Escalation / Defense Evasion → T1055.001
**ATT&CK description**: Adversary injects code into another process using VirtualAllocEx + WriteProcessMemory + CreateRemoteThread

**Why top priority**:
- Core Fawkes injection technique; used to execute shellcode in a remote process
- Both required event types are simulated (Sysmon EID 8 + EID 10)
- Zero process injection detections exist — entire tactic undetected
- Highest-impact technique: persistence + evasion + execution in one

**Detection hypothesis**:
A process that is not a known debugger or security tool opens another process with full access rights (`GrantedAccess: 0x1F3FFF`) AND creates a remote thread with a start address in an unbacked memory region.

**Required data**:
- Sysmon EID 10 (Process Access): `winlog.event_data.GrantedAccess`, `winlog.event_data.TargetImage`
- Sysmon EID 8 (CreateRemoteThread): `winlog.event_data.TargetImage`, `winlog.event_data.StartAddress`

**Key detection logic (KQL preview)**:
```
event.code: "8" AND
NOT winlog.event_data.SourceImage: ("C:\\Windows\\System32\\*")
```

**Target rule file**: `detections/privilege_escalation/t1055_001_create_remote_thread.yml`
**GitHub Issue**: `[Gap] No detection for Process Injection: CreateRemoteThread (T1055.001)`

---

### ~~Rank 2 — T1059.001: Suspicious PowerShell Execution~~ ✅ DEPLOYED

**Score**: 9/10
**Fawkes command**: `powershell`
**Status**: DEPLOYED — `t1059_001_powershell_bypass.yml` (catches bypass flags; Scattered Spider encoded command variant needs separate T1027 rule)
**MITRE**: Execution → T1059.001
**ATT&CK description**: Adversary uses PowerShell to execute commands, often with bypass flags to circumvent policy

**Why rank 2**:
- Fawkes `powershell` command sends encoded/bypass-flagged commands
- Simulated with Sysmon EID 1 (ProcessCreate with powershell.exe)
- PowerShell used in multiple Fawkes techniques (download, execution, privilege esc)
- High TP rate expected on `-EncodedCommand`, `-ExecutionPolicy Bypass`, `-NoProfile -w hidden`

**Detection hypothesis**:
PowerShell.exe spawned with `EncodedCommand`, `ExecutionPolicy Bypass`, or `WindowStyle Hidden` combined with network connection or file creation behavior.

**Required data**:
- Sysmon EID 1: `process.name: "powershell.exe"`, `process.command_line`
- Pattern match on: `-EncodedCommand`, `-ExecutionPolicy Bypass`, `-w hidden`, `IEX`, `DownloadString`

**Key detection logic (KQL preview)**:
```
event.code: "1" AND process.name: "powershell.exe" AND (
  process.command_line: *EncodedCommand* OR
  process.command_line: *ExecutionPolicy Bypass* OR
  process.command_line: (*IEX* AND *DownloadString*)
)
```

**Target rule file**: `detections/execution/t1059_001_suspicious_powershell.yml`
**GitHub Issue**: `[Gap] No detection for PowerShell Execution with Bypass Flags (T1059.001)`

---

### ~~Rank 3 — T1547.001: Registry Run Key Persistence~~ ✅ DEPLOYED

**Score**: 9/10
**Fawkes command**: `persist -method registry`
**Status**: DEPLOYED — also covers Scattered Spider RMM tool persistence via Run keys
**MITRE**: Persistence → T1547.001
**ATT&CK description**: Adversary writes to Run/RunOnce registry keys to achieve persistence across reboots

**Why rank 3**:
- Most common Fawkes persistence method; used in majority of campaigns
- Simulated with Sysmon EID 13 — registry.path matches Run key patterns
- Fawkes writes to: `HKCU\...\CurrentVersion\Run\*`, `HKLM\...\CurrentVersion\Run\*`
- Binary paths point to temp directories (`AppData\Local\Temp`, `ProgramData`) — strong signal

**Detection hypothesis**:
A registry value is written to a Run or RunOnce key, where the binary path points to a non-standard location (user temp dirs, ProgramData, no digital signature).

**Required data**:
- Sysmon EID 13: `registry.path`, `registry.value`, `process.name`, `process.command_line`

**Key detection logic (KQL preview)**:
```
event.code: "13" AND
registry.path: (*\\CurrentVersion\\Run* OR *\\CurrentVersion\\RunOnce*) AND
registry.value: (*AppData\\Local\\Temp* OR *ProgramData* OR *AppData\\Roaming*)
```

**Target rule file**: `detections/persistence/t1547_001_registry_run_key.yml`
**GitHub Issue**: `[Gap] No detection for Registry Run Key Persistence (T1547.001)`

---

### ~~Rank 4 — T1134.001: Token Impersonation via LSASS Access~~ ✅ DEPLOYED

**Score**: 9/10
**Fawkes command**: `steal-token`
**Status**: DEPLOYED — covers LSASS access for token theft
**MITRE**: Credential Access / Privilege Escalation → T1134.001
**ATT&CK description**: Adversary duplicates a token from a privileged process to impersonate a higher-privilege user

**Why rank 4**:
- `steal-token` opens LSASS with PROCESS_DUP_HANDLE (`0x0040`) access rights
- Simulated with Sysmon EID 10; specific GrantedAccess value is a strong indicator
- Token theft enables lateral movement and privilege escalation
- LSASS access is a classic high-fidelity detection anchor

**Detection hypothesis**:
An unsigned process opens LSASS.exe with `GrantedAccess: 0x0040` (PROCESS_DUP_HANDLE), which is the specific right needed to duplicate a token but a suspicious access pattern.

**Required data**:
- Sysmon EID 10: `winlog.event_data.TargetImage: "lsass.exe"`, `winlog.event_data.GrantedAccess`

**Key detection logic (KQL preview)**:
```
event.code: "10" AND
winlog.event_data.TargetImage: *lsass.exe AND
winlog.event_data.GrantedAccess: ("0x0040" OR "0x1F3FFF" OR "0x1010")
```

**Target rule file**: `detections/credential_access/t1134_001_lsass_access_token_theft.yml`
**GitHub Issue**: `[Gap] No detection for LSASS Access for Token Theft (T1134.001)`

---

### Rank 5 — T1071.001: C2 Beaconing via HTTP/HTTPS

**Score**: 8/10
**Fawkes command**: `sleep` / Mythic callback loop
**MITRE**: Command and Control → T1071.001
**ATT&CK description**: Adversary communicates with C2 over standard web protocols to blend with normal traffic

**Why rank 5**:
- Fawkes C2 uses regular HTTP/HTTPS callbacks with jitter to mimic normal traffic
- Simulated: periodic connections from unusual process (`update_helper.exe`) to known C2 IP
- Detection focuses on process → unusual external IP on port 443, high-frequency pattern
- Domain fronting variant requires DNS logs (data gap), but direct IP detection available now

**Detection hypothesis**:
An unsigned process with no legitimate network footprint makes repeated outbound connections to a non-CDN external IP over HTTPS. Correlate with process path in temp directories.

**Required data**:
- Sysmon EID 3: `process.name`, `destination.ip`, `destination.port`, `network.direction`

**Key detection logic (KQL preview)**:
```
event.code: "3" AND
network.direction: "outbound" AND
destination.port: 443 AND
process.executable: (*\\AppData\\Local\\Temp* OR *\\ProgramData*)
```

**Target rule file**: `detections/command_and_control/t1071_001_c2_beaconing_unusual_process.yml`
**GitHub Issue**: `[Gap] No detection for C2 HTTP Beaconing from Unusual Process (T1071.001)`

---

### Rank 6 — T1053.005: Scheduled Task Persistence

**Score**: 8/10
**Fawkes command**: `schtask -action create`
**MITRE**: Persistence / Execution → T1053.005
**ATT&CK description**: Adversary creates a scheduled task to execute malicious code at a set time or trigger

**Why rank 6**:
- Fawkes creates tasks with suspicious trigger (`ONLOGON`) and paths to temp executables
- Simulated with Sysmon EID 1 (`schtasks.exe /Create /TN ... /SC ONLOGON`)
- Task name disguised under `Microsoft\Windows\Maintenance\` — blend-in technique
- High-confidence signal when combined with binary path in temp dirs

**Detection hypothesis**:
`schtasks.exe` is called with `/Create` and the task binary path points to user temp directories or ProgramData, OR trigger is ONLOGON/ONSTART with a binary outside System32.

**Required data**:
- Sysmon EID 1: `process.name: "schtasks.exe"`, `process.command_line`

**Key detection logic (KQL preview)**:
```
event.code: "1" AND process.name: "schtasks.exe" AND
process.command_line: */Create* AND (
  process.command_line: (*AppData\\Local\\Temp* OR *ProgramData*) OR
  process.command_line: (*ONLOGON* OR *ONSTART*)
)
```

**Target rule file**: `detections/persistence/t1053_005_scheduled_task_persistence.yml`
**GitHub Issue**: `[Gap] No detection for Scheduled Task Persistence (T1053.005)`

---

### Rank 7 — T1562.001: AMSI Bypass via CLR Load in Unsigned Process

**Score**: 7/10
**Fawkes command**: `start-clr`, `autopatch`
**MITRE**: Defense Evasion → T1562.001
**ATT&CK description**: Adversary disables AMSI by patching amsi.dll in memory, enabling execution of malicious .NET code

**Why rank 7**:
- Fawkes `start-clr` loads CLR + patches AMSI/ETW before executing inline .NET
- Simulated with Sysmon EID 7 — `clr.dll` and `amsi.dll` loaded by unsigned process
- CLR loading in a process that has no legitimate .NET footprint is anomalous
- AMSI bypass detection covers a defense evasion capability that undermines other detections

**Detection hypothesis**:
`amsi.dll` or `clr.dll` is loaded by a process whose executable path is in a user temp directory (not a legitimate .NET application), indicating runtime .NET loading for AMSI bypass.

**Required data**:
- Sysmon EID 7: `file.name`, `process.executable`

**Key detection logic (KQL preview)**:
```
event.code: "7" AND
file.name: ("amsi.dll" OR "clr.dll") AND
process.executable: (*\\AppData\\Local\\Temp* OR *\\ProgramData*)
```

**Target rule file**: `detections/defense_evasion/t1562_001_amsi_bypass_clr_load.yml`
**GitHub Issue**: `[Gap] No detection for AMSI Bypass via CLR Load (T1562.001)`

---

### Rank 8 — T1087.002: Rapid Discovery Command Burst

**Score**: 7/10
**Fawkes commands**: `net-enum`, `ps`, `whoami`, `arp`, `ifconfig`, `net-stat`
**MITRE**: Discovery → T1087.001 / T1087.002 / T1057 / T1016 / T1033
**ATT&CK description**: Adversary runs multiple discovery commands in rapid succession after initial access

**Why rank 8**:
- Fawkes discovery burst: 7 recon commands (whoami, net user, tasklist, arp, ipconfig, netstat) in < 60 seconds
- All simulated with Sysmon EID 1; each command has a common parent (cmd.exe)
- Low individual signal, high signal when correlated by parent PID and time window
- Pattern detection (sequence/burst) is more effective than single-command detection

**Detection hypothesis**:
Five or more discovery commands (whoami, net.exe, tasklist, arp, ipconfig, netstat) are spawned by the same parent process within a 60-second window.

**Required data**:
- Sysmon EID 1: `process.name`, `process.parent.name`, `process.parent.pid`, `@timestamp`
- Requires: aggregation over time window (EQL sequence or threshold rule)

**Key detection logic (EQL preview)**:
```
sequence by process.parent.pid with maxspan=60s
  [process where process.name in ("whoami.exe", "net.exe", "tasklist.exe", "arp.exe")]
  [process where process.name in ("whoami.exe", "net.exe", "tasklist.exe", "ipconfig.exe", "netstat.exe")]
  [process where process.name in ("whoami.exe", "net.exe", "tasklist.exe", "arp.exe", "ipconfig.exe")]
```

**Target rule file**: `detections/discovery/t1087_002_discovery_command_burst.yml`
**GitHub Issue**: `[Gap] No detection for Rapid Discovery Command Burst (T1087.002)`

---

### Rank 9 — T1055.004: APC Injection

**Score**: 6/10
**Fawkes command**: `apc-injection`
**MITRE**: Privilege Escalation / Defense Evasion → T1055.004
**ATT&CK description**: Adversary queues an APC into an alertable thread to execute code in the context of another process

**Why rank 9**:
- Second Fawkes injection technique; harder to detect than vanilla injection
- No dedicated APC event in Sysmon; detection relies on process access pattern similar to EID 10
- Key signal: process access with `SetThreadContext` or thread-related access masks
- Partial data available — EID 10 present but APC-specific fields not exposed

**Detection hypothesis**:
A process with an anomalous executable path accesses another process requesting thread-related access rights (`0x001F` = THREAD_ALL_ACCESS bits), followed by execution in the target process.

**Required data**:
- Sysmon EID 10: `winlog.event_data.GrantedAccess` (thread rights mask), `winlog.event_data.TargetImage`
- Note: APC uses SetThreadContext which may appear as thread access; direct EID 8 may not fire for APC

**Target rule file**: `detections/privilege_escalation/t1055_004_apc_injection.yml`
**GitHub Issue**: `[Gap] No detection for APC Injection (T1055.004)`

---

### Rank 10 — T1543.003: Windows Service Creation

**Score**: 5/10
**Fawkes command**: `service -action create`
**MITRE**: Persistence / Privilege Escalation → T1543.003
**ATT&CK description**: Adversary creates or modifies a Windows service to execute malicious code

**Why rank 10**:
- Fawkes can register a service with a malicious binary path
- **Data gap**: Windows Service Install event (EID 7045) not in current simulation
- Can partially detect via Sysmon EID 1 watching for `sc.exe create` or `services.exe` spawning unexpected children
- Lower score because data gap limits TP rate; needs simulation enhancement

**Detection hypothesis** (workaround):
`sc.exe` is called with `create` and the binary path points to a non-System32 executable, OR `services.exe` spawns an unexpected child process from a temp directory.

**Required data** (primary — not available):
- Windows EID 7045: New Service Installed (System event log, via winlogbeat)

**Required data** (workaround — available):
- Sysmon EID 1: `process.name: "sc.exe"`, `process.command_line: *create*`

**Data gap note**: Add `windows` event log collection (System log, EID 7045) to the simulator. See `gaps/data-source-gaps.md`.

**Target rule file**: `detections/persistence/t1543_003_windows_service_creation.yml`
**GitHub Issue**: `[Gap] No detection for Windows Service Creation (T1543.003) — data gap for EID 7045`

---

## Backlog Summary Table

### Tier 1 — Data Available, Build Now

| Rank | Technique | Intel Source(s) | Score | Data | Rule File |
|---|---|---|---|---|---|
| 1 | T1055.001 CreateRemoteThread | Fawkes, Scattered Spider | 10/10 | Available | `privilege_escalation/t1055_001_create_remote_thread.yml` |
| 2 | T1053.005 Scheduled Task | Fawkes, Scattered Spider | 9/10 | Available | `persistence/t1053_005_scheduled_task_persistence.yml` |
| 3 | T1071.001 C2 Beaconing | Fawkes | 8/10 | Available | `command_and_control/t1071_001_c2_beaconing_unusual_process.yml` |
| 4 | T1562.001 AMSI Bypass CLR | Fawkes | 7/10 | Available | `defense_evasion/t1562_001_amsi_bypass_clr_load.yml` |
| 5 | T1087.002 Discovery Burst | Fawkes, Scattered Spider | 7/10 | Available | `discovery/t1087_002_discovery_command_burst.yml` |
| 6 | T1070.001 Event Log Clearing | Scattered Spider | 7/10 | Available | `defense_evasion/t1070_001_event_log_clearing.yml` |
| 7 | T1197 BITS Jobs Download | Scattered Spider | 6/10 | Available | `defense_evasion/t1197_bitsadmin_download.yml` |
| 8 | T1070.004 Anti-Forensics (cipher/sdelete) | Scattered Spider | 6/10 | Available | `defense_evasion/t1070_004_file_deletion_tools.yml` |
| 9 | T1219 Remote Access Software (process) | Scattered Spider | 6/10 | Available | `command_and_control/t1219_remote_access_software_process.yml` |
| 10 | T1047 WMI Execution (process) | Fawkes, Scattered Spider | 6/10 | Available | `execution/t1047_wmi_execution_process.yml` |
| 11 | T1543.003 Windows Service (sc.exe) | Fawkes, Scattered Spider | 5/10 | Available | `persistence/t1543_003_windows_service_creation.yml` |
| 12 | T1027 Encoded PowerShell | Scattered Spider | 5/10 | Available | `defense_evasion/t1027_encoded_powershell.yml` |
| 13 | T1003 Mimikatz Process Execution | Scattered Spider | 5/10 | Available | `credential_access/t1003_mimikatz_process.yml` |

### Tier 2 — Partial Data / Needs Log Onboarding

| Rank | Technique | Intel Source(s) | Score | Data | Blocker |
|---|---|---|---|---|---|
| 14 | T1055.004 APC Injection | Fawkes | 6/10 | Partial | EID 8 not APC-labelled |
| 15 | T1219 Remote Access (DNS) | Scattered Spider | 6/10 | Blocked | Needs EID 22 |
| 16 | T1219 Remote Access (file) | Scattered Spider | 5/10 | Blocked | Needs EID 11 |
| 17 | T1059.001 PowerShell Script Block | Scattered Spider | 5/10 | Blocked | Needs EID 4104 |
| 18 | T1559 RMM Named Pipes | Scattered Spider | 4/10 | Blocked | Needs EID 17/18 |
| 19 | T1543.003 Service Install (full) | Fawkes, Scattered Spider | 4/10 | Blocked | Needs EID 7045 |
| 20 | T1047 WMI Persistence | Fawkes, Scattered Spider | 4/10 | Blocked | Needs EID 19/20/21 |

> See `TODO-log-onboarding.md` for onboarding plan to unblock Tier 2 detections.

---

## Next Action

### Deployed (3 detections)
- ~~T1059.001~~ PowerShell Bypass — deployed to both SIEMs
- ~~T1547.001~~ Registry Run Keys — deployed to both SIEMs
- ~~T1134.001~~ LSASS Token Theft — deployed to both SIEMs

### Build Next (Tier 1 — data available)
1. **T1055.001** CreateRemoteThread — highest signal, Fawkes + Scattered Spider overlap
2. **T1053.005** Scheduled Task — Fawkes + Scattered Spider overlap
3. **T1071.001** C2 Beaconing — Fawkes priority
4. **T1562.001** AMSI Bypass — Fawkes priority
5. **T1070.001** Event Log Clearing — Scattered Spider priority, very low FP
6. **T1197** BITS Jobs — Scattered Spider, low FP
7. **T1219** Remote Access Software (process) — Scattered Spider, 7 detections in one
8. **T1027** Encoded PowerShell — extends our T1059.001 coverage for Scattered Spider variant

### Onboard Logs First (Tier 2)
See `TODO-log-onboarding.md` for detailed log onboarding plan.
Priority order: EID 4104 → EID 11 → EID 22 → EID 17/18 → EID 7045

### Intel Sources
| Source | Date Added | Techniques Extracted | Report |
|---|---|---|---|
| Fawkes C2 Agent | 2026-02-23 | 21 | `threat-intel/fawkes/fawkes-ttp-mapping.md` |
| Scattered Spider (UNC3944) | 2026-03-01 | 20 | `threat-intel/analysis/2026-03-01-scattered-spider.md` |
