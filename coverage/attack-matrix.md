# MITRE ATT&CK Coverage Matrix — Fawkes C2 Detections

**Last updated**: _not yet started_
**Detections deployed**: 0
**Techniques covered**: 0 / 21 (0%)

Legend: ✅ Deployed | 🔨 In progress | 📋 Backlogged | ⚠️ Data gap | ❌ No coverage

---

## Tactic Coverage Summary

| Tactic | Techniques | Covered | In Progress | Backlogged | Gap |
|---|---|---|---|---|---|
| Execution (TA0002) | 7 | 0 | 0 | 2 | 5 |
| Persistence (TA0003) | 6 | 0 | 0 | 2 | 4 |
| Privilege Escalation (TA0004) | 5 | 0 | 0 | 2 | 3 |
| Defense Evasion (TA0005) | 7 | 0 | 0 | 2 | 5 |
| Credential Access (TA0006) | 5 | 0 | 0 | 1 | 4 |
| Discovery (TA0007) | 10 | 0 | 0 | 1 | 9 |
| Lateral Movement (TA0008) | 2 | 0 | 0 | 0 | 2 |
| Collection (TA0009) | 3 | 0 | 0 | 0 | 3 |
| Command and Control (TA0011) | 3 | 0 | 0 | 1 | 2 |
| **Total** | **48** | **0** | **0** | **10** | **37** |

---

## Execution (TA0002)

| Technique | Sub | Name | Fawkes Cmd | Status | Rule File |
|---|---|---|---|---|---|
| T1059 | .001 | PowerShell | `powershell` | 📋 Backlogged | — |
| T1059 | .003 | Windows Command Shell | `run`, `shell` | ❌ No coverage | — |
| T1047 | — | Windows Management Instrumentation | `wmi` | ⚠️ Data gap (no Sysmon EID 19-21) | — |
| T1620 | — | Reflective Code Loading | `inline-assembly` | ⚠️ Data gap | — |
| T1059 | .003 | BOF Execution | `inline-execute` | ⚠️ Data gap | — |

---

## Persistence (TA0003)

| Technique | Sub | Name | Fawkes Cmd | Status | Rule File |
|---|---|---|---|---|---|
| T1547 | .001 | Registry Run Keys | `persist -method registry` | 📋 Backlogged | — |
| T1547 | .001 | Startup Folder | `persist -method startup-folder` | ⚠️ Data gap (no Sysmon EID 11) | — |
| T1053 | .005 | Scheduled Task | `schtask -action create` | 📋 Backlogged | — |
| T1543 | .003 | Windows Service | `service -action create` | ⚠️ Data gap (no EID 7045) | — |
| T1053 | .003 | Cron Job | `crontab -action add` | ❌ No coverage | — |
| T1543 | .001 | Launch Agent | `launchagent` | ❌ No coverage (macOS) | — |

---

## Privilege Escalation (TA0004)

| Technique | Sub | Name | Fawkes Cmd | Status | Rule File |
|---|---|---|---|---|---|
| T1055 | .001 | Process Injection: CreateRemoteThread | `vanilla-injection` | 📋 Backlogged | — |
| T1055 | .004 | Process Injection: APC | `apc-injection` | 📋 Backlogged | — |
| T1055 | .012 | Process Injection: Threadless | `threadless-inject` | ⚠️ Data gap | — |
| T1055 | .015 | Process Injection: PoolParty | `poolparty-injection` | ⚠️ Data gap | — |
| T1134 | .001 | Token Impersonation | `steal-token` | 📋 Backlogged | — |

---

## Defense Evasion (TA0005)

| Technique | Sub | Name | Fawkes Cmd | Status | Rule File |
|---|---|---|---|---|---|
| T1055 | .001 | Process Injection | `vanilla-injection` | 📋 Backlogged | — |
| T1562 | .001 | Disable/Modify Tools (AMSI) | `autopatch`, `start-clr` | 📋 Backlogged | — |
| T1070 | .006 | Timestomp | `timestomp` | ⚠️ Data gap (no EID 2) | — |
| T1027 | .001 | Binary Padding | `binary-inflate` | ⚠️ Data gap | — |
| T1090 | .004 | Domain Fronting | built-in C2 | ⚠️ Data gap (need network proxy logs) | — |
| T1497 | .003 | Time-based Evasion | `sleep` | ❌ No coverage | — |

---

## Credential Access (TA0006)

| Technique | Sub | Name | Fawkes Cmd | Status | Rule File |
|---|---|---|---|---|---|
| T1134 | .001 | Token Impersonation | `steal-token` | 📋 Backlogged | — |
| T1134 | .003 | Make/Impersonate Token | `make-token` | ❌ No coverage | — |
| T1056 | .001 | Keylogging | `keylog` | ⚠️ Data gap (ETW/hook events) | — |
| T1555 | .001 | macOS Keychain | `keychain` | ❌ No coverage (macOS) | — |
| T1552 | .004 | Private Keys | `ssh-keys` | ❌ No coverage | — |

---

## Discovery (TA0007)

| Technique | Sub | Name | Fawkes Cmd | Status | Rule File |
|---|---|---|---|---|---|
| T1057 | — | Process Discovery | `ps` | 📋 Backlogged (discovery burst) | — |
| T1033 | — | System Owner/User Discovery | `whoami` | 📋 Backlogged (discovery burst) | — |
| T1087 | .001/.002 | Account Discovery | `net-enum` | 📋 Backlogged (discovery burst) | — |
| T1049 | — | System Network Connections | `net-stat` | ❌ No coverage | — |
| T1016 | — | System Network Config | `arp`, `ifconfig` | ❌ No coverage | — |
| T1135 | — | Network Share Discovery | `net-shares` | ❌ No coverage | — |
| T1082 | — | System Information Discovery | `drives`, `env` | ❌ No coverage | — |
| T1518 | .001 | Security Software Discovery | `av-detect` | ❌ No coverage | — |

---

## Lateral Movement (TA0008)

| Technique | Sub | Name | Fawkes Cmd | Status | Rule File |
|---|---|---|---|---|---|
| T1090 | .001 | SOCKS5 Proxy | `socks5` | ⚠️ Data gap (need network flow data) | — |
| T1021 | .006 | Remote WMI | `wmi` (remote) | ⚠️ Data gap | — |

---

## Collection (TA0009)

| Technique | Sub | Name | Fawkes Cmd | Status | Rule File |
|---|---|---|---|---|---|
| T1115 | — | Clipboard Data | `clipboard` | ⚠️ Data gap | — |
| T1113 | — | Screen Capture | `screenshot` | ⚠️ Data gap | — |
| T1560 | .002 | Archive via Library | `download` | ❌ No coverage | — |

---

## Command and Control (TA0011)

| Technique | Sub | Name | Fawkes Cmd | Status | Rule File |
|---|---|---|---|---|---|
| T1071 | .001 | HTTP/HTTPS C2 | beacon / `sleep` | 📋 Backlogged | — |
| T1090 | .004 | Domain Fronting | built-in | ⚠️ Data gap | — |
| T1573 | .002 | Asymmetric Cryptography | TLS pinning | ⚠️ Data gap | — |

---

## Coverage Over Time

| Date | Deployed | Techniques | % Coverage |
|---|---|---|---|
| — | 0 | 0/21 | 0% |

*This table updates with each detection deployment.*
