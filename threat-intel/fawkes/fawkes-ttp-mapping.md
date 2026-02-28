# Fawkes C2 Agent — MITRE ATT&CK TTP Mapping

**Source**: https://github.com/galoryber/fawkes
**Agent type**: Golang-based Mythic C2 agent
**Total commands**: 59
**Last reviewed**: 2026-02-23

---

## Overview

Fawkes is a Golang-based C2 agent designed to work with the Mythic C2 framework.
It implements 59 commands spanning the full ATT&CK kill chain from discovery through
credential access, persistence, lateral movement, and exfiltration. This document maps
each Fawkes command to its corresponding ATT&CK technique(s) and the artifacts it leaves
in endpoint telemetry.

---

## Command → ATT&CK Mapping

### Execution (TA0002)

| Fawkes Command | ATT&CK Technique | Sub-technique | Description | Simulator | Priority |
|---|---|---|---|---|---|
| `run` | T1059 | T1059.003 | Execute arbitrary command via cmd.exe | Yes (EID 1) | High |
| `powershell` | T1059 | T1059.001 | Execute PowerShell with bypass flags | Yes (EID 1) | Critical |
| `inline-assembly` | T1620 | — | Load and execute .NET assembly in-memory | No | High |
| `inline-execute` | T1059 | T1059.003 | Execute BOF/COFF in current process memory | No | High |
| `wmi` | T1047 | — | Remote/local WMI execution | No | High |
| `spawn` | T1059 | T1059.003 | Spawn a new agent process | No | Medium |
| `shell` | T1059 | T1059.003 | Interactive shell session | No | Medium |

### Process Injection (TA0004 / TA0005)

| Fawkes Command | ATT&CK Technique | Sub-technique | Description | Simulator | Priority |
|---|---|---|---|---|---|
| `vanilla-injection` | T1055 | T1055.001 | VirtualAllocEx → WriteProcessMemory → CreateRemoteThread | Yes (EID 8+10) | Critical |
| `apc-injection` | T1055 | T1055.004 | QueueUserAPC into alertable thread | Partial (EID 10) | Critical |
| `threadless-inject` | T1055 | T1055.012 | DLL function pointer overwrite (no new thread) | No | High |
| `poolparty-injection` | T1055 | T1055.015 | 8 variants abusing Windows thread pool internals | No | High |
| `opus-injection` | T1055 | T1055.013 | Ctrl-C handler chain / KernelCallbackTable hijack | No | High |

### Persistence (TA0003)

| Fawkes Command | ATT&CK Technique | Sub-technique | Description | Simulator | Priority |
|---|---|---|---|---|---|
| `persist -method registry` | T1547 | T1547.001 | HKCU/HKLM Run key write | Yes (EID 13) | Critical |
| `persist -method startup-folder` | T1547 | T1547.001 | Drop file in shell:startup directory | No | High |
| `schtask -action create` | T1053 | T1053.005 | Create scheduled task via schtasks.exe | Yes (EID 1) | High |
| `service -action create` | T1543 | T1543.003 | Register new Windows service | No | High |
| `crontab -action add` | T1053 | T1053.003 | Add crontab entry (Linux) | No | Medium |
| `launchagent` | T1543 | T1543.001 | macOS LaunchAgent plist creation | No | Low |

### Credential Access (TA0006)

| Fawkes Command | ATT&CK Technique | Sub-technique | Description | Simulator | Priority |
|---|---|---|---|---|---|
| `keylog` | T1056 | T1056.001 | Low-level keyboard hook via SetWindowsHookEx | No | High |
| `steal-token` | T1134 | T1134.001 | Duplicate token from target process (LSASS/privileged proc) | Yes (EID 10) | Critical |
| `make-token` | T1134 | T1134.003 | Create new token with provided credentials (LogonUser) | No | High |
| `keychain` | T1555 | T1555.001 | macOS keychain credential access | No | Low |
| `ssh-keys` | T1552 | T1552.004 | Read private SSH keys from disk | No | Medium |

### Defense Evasion (TA0005)

| Fawkes Command | ATT&CK Technique | Sub-technique | Description | Simulator | Priority |
|---|---|---|---|---|---|
| `autopatch` | T1562 | T1562.001 | Patch AMSI.dll in memory to disable AV scanning | No | Critical |
| `start-clr` | T1562 | T1562.001 | Load CLR + patch AMSI/ETW before executing .NET | Yes (EID 7) | Critical |
| `timestomp` | T1070 | T1070.006 | Modify file timestamps to hide activity | No | Medium |
| `binary-inflate` | T1027 | T1027.001 | Pad binary to exceed AV scan size limit | No | Medium |
| `sleep` | T1497 | T1497.003 | Jitter-based sleep to evade beacon detection | Partial (EID 3) | High |

### Discovery (TA0007)

| Fawkes Command | ATT&CK Technique | Sub-technique | Description | Simulator | Priority |
|---|---|---|---|---|---|
| `ps` | T1057 | — | List running processes (tasklist) | Yes (EID 1) | Medium |
| `whoami` | T1033 | — | Current user and privileges | Yes (EID 1) | Medium |
| `net-enum` | T1087 | T1087.001/002 | Enumerate local/domain users and groups | Yes (EID 1) | Medium |
| `net-shares` | T1135 | — | Enumerate network shares | No | Medium |
| `net-stat` | T1049 | — | Active network connections (netstat) | Yes (EID 1) | Low |
| `arp` | T1016 | T1016.001 | ARP table (host discovery) | Yes (EID 1) | Low |
| `ifconfig` | T1016 | — | Network interface configuration | Yes (EID 1) | Low |
| `drives` | T1082 | — | Enumerate local drives | No | Low |
| `av-detect` | T1518 | T1518.001 | Detect installed AV/EDR products | No | Medium |
| `env` | T1082 | — | Dump environment variables | No | Low |

### Lateral Movement (TA0008)

| Fawkes Command | ATT&CK Technique | Sub-technique | Description | Simulator | Priority |
|---|---|---|---|---|---|
| `socks5` | T1090 | T1090.001 | Start SOCKS5 proxy listener on agent | No | High |
| `wmi` (remote) | T1021 | T1021.006 | Remote WMI execution for lateral movement | No | High |

### Collection (TA0009)

| Fawkes Command | ATT&CK Technique | Sub-technique | Description | Simulator | Priority |
|---|---|---|---|---|---|
| `clipboard` | T1115 | — | Capture clipboard contents | No | Medium |
| `screenshot` | T1113 | — | Capture screen | No | Medium |
| `download` | T1560 | T1560.002 | Download files from target | No | Medium |

### Command and Control (TA0011)

| Fawkes Command | ATT&CK Technique | Sub-technique | Description | Simulator | Priority |
|---|---|---|---|---|---|
| `sleep` / beacon | T1071 | T1071.001 | HTTP/HTTPS C2 with jittered callback | Yes (EID 3) | High |
| Domain fronting | T1090 | T1090.004 | Route C2 traffic through CDN | No | High |
| TLS cert pinning | T1573 | T1573.002 | Encrypted C2 with pinned certificate | No | Medium |

---

## Artifact Type Matrix

| Artifact Type | Generating Commands | Sysmon EID | ECS Event Code |
|---|---|---|---|
| Process Create | run, powershell, spawn, wmi, schtask, service, net-enum, net-shares | 1 | `event.code: "1"` |
| Process Access | vanilla-injection, apc-injection, steal-token, make-token | 10 | `event.code: "10"` |
| Create Remote Thread | vanilla-injection | 8 | `event.code: "8"` |
| Image Load | start-clr, autopatch, threadless-inject | 7 | `event.code: "7"` |
| Registry Write | reg-write, persist (registry) | 12, 13 | `event.code: "13"` |
| File Write | upload, cp, mv | 11 | `event.code: "11"` |
| File Create | mkdir | 11 | `event.code: "11"` |
| File Delete | rm | 23 | `event.code: "23"` |
| File Modify (timestamp) | timestomp | 2 | `event.code: "2"` |
| Network Connection | sleep/beacon, socks5 | 3 | `event.code: "3"` |
| Logon | make-token | — | `event.code: "4624"` |
| Token Steal | steal-token | 10 | `event.code: "10"` (LSASS access) |

---

## Detection Priority by Technique

| Priority | Technique | Fawkes Command(s) | Data Available |
|---|---|---|---|
| 1 | T1055.001 Create Remote Thread | vanilla-injection | Yes — EID 8 + EID 10 |
| 2 | T1059.001 PowerShell | powershell | Yes — EID 1 |
| 3 | T1547.001 Registry Run Keys | persist -method registry | Yes — EID 13 |
| 4 | T1134.001 Token Impersonation | steal-token | Yes — EID 10 |
| 5 | T1071.001 C2 HTTP Beaconing | sleep / beacon | Yes — EID 3 |
| 6 | T1053.005 Scheduled Task | schtask | Yes — EID 1 |
| 7 | T1562.001 AMSI/ETW Disable | start-clr, autopatch | Yes — EID 7 |
| 8 | T1087.002 Domain Enumeration | net-enum, whoami | Yes — EID 1 |
| 9 | T1055.004 APC Injection | apc-injection | Partial — EID 10 |
| 10 | T1543.003 Windows Service | service | Partial — EID 1 (svchost) |

---

## Coverage Status

| Status | Count | Percentage |
|---|---|---|
| Detected (rule deployed) | 0 | 0% |
| Backlogged (data available) | 8 | ~37% |
| Backlogged (partial data) | 2 | ~9% |
| No data source | 11 | ~51% |
| **Total Techniques** | **21** | — |

*Note: Count covers primary techniques only; sub-techniques may overlap.*

---

## References

- Fawkes GitHub: https://github.com/galoryber/fawkes
- Mythic C2 Framework: https://github.com/its-a-feature/Mythic
- MITRE ATT&CK: https://attack.mitre.org/
- Elastic Common Schema (ECS): https://www.elastic.co/guide/en/ecs/current/
