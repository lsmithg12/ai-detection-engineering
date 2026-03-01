# Threat Intel Analysis: Scattered Spider

**Source**: https://research.splunk.com/stories/scattered_spider/
**Extraction Date**: 2026-03-01
**Analyst**: Blue Team Detection Agent

---

## 1. Threat Actor Profile

| Field | Detail |
|---|---|
| **Name** | Scattered Spider |
| **Aliases** | UNC3944, Octo Tempest, Storm-0875 |
| **Motivation** | Financial — data theft, ransomware (DragonForce), extortion |
| **Targets** | Large enterprises, IT helpdesks, Snowflake databases, VMware ESXi |
| **Primary TTP** | Social engineering (vishing IT helpdesks to steal MFA tokens) |
| **Tools** | Mimikatz, TeamViewer, AnyDesk, Ngrok, BITSAdmin, sdelete, cipher, WMI, PowerShell |
| **Notable** | Monitors victim Slack/Teams to evade detection in real-time |

---

## 2. Techniques Extracted (Mapped to MITRE ATT&CK)

| Technique ID | Name | Description from Report | Confidence | Splunk Detections |
|---|---|---|---|---|
| T1003 | OS Credential Dumping | Mimikatz binary execution + PowerShell script block dumping | High | 3 |
| T1036.005 | Match Legitimate Name/Location | Attacker tools masquerading on endpoint | Medium | 1 |
| T1197 | BITS Jobs | BITSAdmin used to download tools | High | 1 |
| T1105 | Ingress Tool Transfer | Tool download via BITS and other methods | High | 1 |
| T1070.004 | File Deletion | cipher.exe and sdelete used to wipe unallocated sectors | High | 2 |
| T1070.001 | Clear Windows Event Logs | wevtutil used to clear event logs | High | 1 |
| T1059.001 | PowerShell | Encoded commands, Exchange cmdlets, scheduled tasks via PS | High | 5 |
| T1219 | Remote Access Software | TeamViewer, AnyDesk, Ngrok — process/file/registry/DNS/network | High | 7 |
| T1592 | Gather Victim Host Info | WMI class reconnaissance | Medium | 1 |
| T1543.003 | Windows Service | sc.exe to create/modify services | High | 1 |
| T1053.005 | Scheduled Task | schtasks from public directories + PowerShell-based | High | 3 |
| T1047 | WMI | Script execution via WMI | High | 1 |
| T1485 | Data Destruction | sdelete for data destruction | Medium | 1 |
| T1012 | Query Registry | Browser password store access via registry | Medium | 1 |
| T1555.005 | Password Managers | Discovery of password manager artifacts | Medium | 1 |
| T1559 | Inter-Process Communication | RMM named pipe detection | Medium | 1 |
| T1021.002 | SMB/Windows Admin Shares | RMM tool lateral movement | Medium | 1 |
| T1055 | Process Injection | RMM named pipe injection context | Medium | 1 |
| T1027 | Obfuscated Files/Commands | Encoded PowerShell commands | High | 1 |
| T1595 | Active Scanning | Network reconnaissance | Low | 1 |

---

## 3. Indicators of Compromise (IOCs)

> IOCs are ephemeral. The Splunk research page focuses on behavioral detections (TTPs) rather than static IOCs. Key behavioral indicators:

- **Process names**: `mimikatz.exe`, `bitsadmin.exe`, `cipher.exe`, `sdelete.exe`, `wevtutil.exe`, `sc.exe`, `schtasks.exe`, `wmic.exe`, `wmiprvse.exe`
- **Remote access tools**: `TeamViewer.exe`, `AnyConnect.exe`, `ngrok.exe`, `AnyDesk.exe`, `ScreenConnect*.exe`
- **PowerShell patterns**: `-EncodedCommand`, `-enc`, `Get-Mailbox`, `New-ManagementRoleAssignment`
- **Registry paths**: HKCU/HKLM Run keys (for RAT persistence)
- **Named pipes**: `\\.\pipe\` patterns associated with RMM tools
- **DNS domains**: `*.teamviewer.com`, `*.anydesk.com`, `*.ngrok.io`

---

## 4. Artifacts Generated (Expected Log Sources)

| Artifact | Sysmon EID | Windows EID | Scattered Spider Activity |
|---|---|---|---|
| Process Create | 1 | 4688 | Mimikatz, bitsadmin, cipher, sdelete, sc.exe, schtasks, wmic, RMM tools |
| Network Connect | 3 | — | C2, RMM tool callbacks, Ngrok tunnels |
| Image Load | 7 | — | Mimikatz DLLs, CLR loads |
| Process Access | 10 | — | LSASS credential dumping |
| File Create | 11 | — | RMM tool drops, tool staging |
| Registry Set | 13 | — | RMM persistence, Run key writes |
| Pipe Create/Connect | 17/18 | — | RMM named pipes |
| DNS Query | 22 | — | RMM tool DNS lookups |
| File Delete | 23 | — | Anti-forensics (cipher, sdelete) |
| Service Install | — | 7045 | sc.exe service creation |
| PowerShell Script Block | — | 4104 | Encoded commands, Exchange abuse |

---

## 5. Cross-Reference: Our Environment

### A. Detections We Can Build Now

These use data sources we already have (EID 1, 3, 7, 8, 10, 13, 4624):

| Technique | Data Source | Detection Approach | Est. FP Risk | Fawkes Overlap | Priority |
|---|---|---|---|---|---|
| **T1053.005** Scheduled Task | EID 1 | `schtasks.exe /create` from unusual parent or public dir | Medium | `schtask` | 1 (High) |
| **T1055.001** Process Injection | EID 8 + 10 | CreateRemoteThread to remote process | Low | `vanilla-injection` | 2 (High) |
| **T1070.001** Event Log Clearing | EID 1 | `wevtutil cl` or `wevtutil clear-log` | Low | — | 3 (High) |
| **T1197** BITS Jobs | EID 1 | `bitsadmin /transfer` download pattern | Low | — | 4 (Medium) |
| **T1070.004** File Deletion (process) | EID 1 | `cipher /w:` or `sdelete` execution | Low | — | 5 (Medium) |
| **T1543.003** Windows Service | EID 1 | `sc.exe create` or `sc.exe config` | Medium | `service` | 6 (Medium) |
| **T1047** WMI (process-based) | EID 1 | `wmic process call create` or wmiprvse child | Medium | `wmi` | 7 (Medium) |
| **T1219** Remote Access (process) | EID 1 | TeamViewer/AnyDesk/Ngrok/ScreenConnect process names | Low | — | 8 (Medium) |
| **T1219** Remote Access (registry) | EID 13 | RMM tool registry persistence writes | Low | — | 9 (Low) |
| **T1219** Remote Access (network) | EID 3 | Connections to known RMM tool ports/IPs | Medium | — | 10 (Low) |
| **T1027** Encoded PowerShell | EID 1 | `-EncodedCommand` or `-enc` flag in command line | Low | — | 11 (Low) |
| **T1003** Mimikatz (process) | EID 1 | `mimikatz.exe` or known mimikatz command patterns | Low | — | 12 (Low) |

### B. Detections Blocked by Data Gaps

| Technique | Missing Data Source | What's Needed | Gap Severity |
|---|---|---|---|
| **T1219** Remote Access (DNS) | Sysmon EID 22 (DNS Query) | DNS queries to `*.teamviewer.com`, `*.anydesk.com`, `*.ngrok.io` | **High** — DNS is the most reliable RMM indicator |
| **T1219** Remote Access (file) | Sysmon EID 11 (FileCreate) | RMM tool binary drops, installer artifacts | **High** — file-based anomaly detection |
| **T1559** Named Pipes (RMM) | Sysmon EID 17/18 (PipeCreate/Connect) | Named pipe patterns for RMM tools | **Medium** — lateral movement indicator |
| **T1070.004** File Deletion (full) | Sysmon EID 23 (FileDelete) | Track actual file deletions by cipher/sdelete | **Medium** — process detection covers most cases |
| **T1059.001** PowerShell Script Block | PowerShell EID 4104 | Full script block logging for obfuscated commands | **High** — critical for encoded command deobfuscation |
| **T1543.003** Service Install (full) | Windows System EID 7045 | Service installation events | **Medium** — sc.exe process detection is partial coverage |
| **T1047** WMI (full) | Sysmon EID 19/20/21 | WMI event subscription persistence | **High** — process-based detection is partial |
| **T1105** Tool Transfer (file) | Sysmon EID 11 (FileCreate) | File write events for staged tools | **Medium** |
| **T1595** Active Scanning | Network flow/firewall logs | Cisco NVM, Palo Alto — out of scope for this lab | **Low** — not achievable in current lab |

### C. Already Covered

| Technique | Our Detection | Covers Scattered Spider Variant? |
|---|---|---|
| **T1059.001** PowerShell Bypass | `t1059_001_powershell_bypass.yml` | **Partial** — catches `-exec bypass` but not `-EncodedCommand` or Exchange cmdlets. A dedicated encoded command detection would improve coverage. |
| **T1547.001** Registry Run Keys | `t1547_001_registry_run_key.yml` | **Yes** — would catch RMM tool persistence via Run keys |
| **T1134.001** Token Theft | `t1134_001_lsass_token_theft.yml` | **Partial** — covers LSASS access but Scattered Spider primarily uses Mimikatz (T1003), not steal-token |

---

## 6. Fawkes C2 Overlap

Techniques shared between Scattered Spider and Fawkes (highest priority — we can simulate AND detect):

| Technique | Scattered Spider Usage | Fawkes Command | Simulator Data |
|---|---|---|---|
| T1059.001 | Encoded PowerShell, Exchange abuse | `powershell` | Yes (EID 1) |
| T1053.005 | Scheduled tasks from public dirs | `schtask -action create` | Yes (EID 1) |
| T1543.003 | sc.exe service manipulation | `service -action create` | Partial (EID 1) |
| T1047 | WMI script execution | `wmi` | Partial (EID 1) |
| T1055 | Process injection (RMM context) | `vanilla-injection` | Yes (EID 8+10) |

---

## 7. Prioritized Detection Plan

### Top 3 Recommendations

**1. T1053.005 — Scheduled Task Creation (Priority: HIGH)**
- Already backlogged, Fawkes overlap, Scattered Spider uses it heavily
- Detection logic: `event.code:"1" AND process.name:"schtasks.exe" AND process.command_line:(*\/create* OR *-create*)`
- Filter: exclude `process.parent.name:"msiexec.exe"` or system installers
- FP Risk: Medium (legitimate software uses schtasks)

**2. T1055.001 — Process Injection via CreateRemoteThread (Priority: HIGH)**
- Already backlogged, Fawkes primary injection method
- Detection logic: `event.code:"8" AND NOT process.name:("csrss.exe" OR "lsass.exe")`
- Cross-correlate with EID 10 for process access
- FP Risk: Low (CreateRemoteThread to foreign process is rare in baseline)

**3. T1070.001 — Event Log Clearing (Priority: HIGH)**
- New from Scattered Spider intel, not in our backlog yet
- Detection logic: `event.code:"1" AND process.name:"wevtutil.exe" AND process.command_line:(*cl* OR *clear-log*)`
- FP Risk: Very Low (wevtutil clear is almost never benign)

---

## 8. Summary

- **26 Splunk detections** mapped from Scattered Spider story
- **20 unique MITRE techniques** extracted
- **12 detections buildable now** with current data sources
- **9 detections blocked** by missing log sources (EID 11, 17/18, 22, 23, 4104, 7045, 19-21)
- **3 techniques already partially covered** by existing rules
- **5 techniques overlap with Fawkes** C2 capabilities (highest priority)
- **Key gap**: No PowerShell Script Block Logging (EID 4104) — critical for Scattered Spider's encoded command and Exchange abuse TTPs
