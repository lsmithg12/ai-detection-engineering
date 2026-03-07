# MITRE ATT&CK Coverage Matrix — Fawkes C2 Detections

**Last updated**: 2026-03-07
**Detections deployed**: 8 (+ 1 in monitoring, + 1 validated awaiting deploy)
**Techniques covered**: 9 / 21 (43%)
**Intel sources**: Fawkes C2 (21 techniques), Scattered Spider/UNC3944 (20 techniques)
**Pipeline**: 6 deployed by Patronus, 3 manually deployed, T1055.001 validated (F1=1.0)

Legend: ✅ Deployed | 🔄 Monitoring | 🔨 In progress | 📋 Backlogged | ⚠️ Data gap | ❌ No coverage
Intel tags: [F] = Fawkes, [SS] = Scattered Spider, [F+SS] = both sources

---

## Tactic Coverage Summary

| Tactic | Techniques | Covered | In Progress | Backlogged | Gap |
|---|---|---|---|---|---|
| Initial Access (TA0001) | 2 | 2 | 0 | 0 | 0 |
| Execution (TA0002) | 5 | 1 | 0 | 1 | 3 |
| Persistence (TA0003) | 6 | 2 | 0 | 1 | 3 |
| Privilege Escalation (TA0004) | 5 | 2 | 0 | 1 | 2 |
| Defense Evasion (TA0005) | 11 | 2 | 0 | 4 | 5 |
| Credential Access (TA0006) | 6 | 1 | 0 | 1 | 4 |
| Discovery (TA0007) | 8 | 0 | 0 | 3 | 5 |
| Lateral Movement (TA0008) | 2 | 0 | 0 | 0 | 2 |
| Collection (TA0009) | 3 | 0 | 0 | 0 | 3 |
| Command and Control (TA0011) | 4 | 1 | 0 | 1 | 2 |
| **Total** | **52** | **11** | **0** | **12** | **29** |

---

## Initial Access (TA0001)

| Technique | Sub | Name | Fawkes Cmd | Status | Rule File |
|---|---|---|---|---|---|
| T1566 | .004 | Spearphishing Voice (Vishing) | — | ✅ Deployed | [t1566_004.yml](../detections/initial_access/t1566_004.yml) | [SS] |
| T1078 | .004 | Cloud Account Abuse | — | ✅ Deployed | [t1078_004.yml](../detections/defense_evasion/t1078_004.yml) | [SS] |

---

## Execution (TA0002)

| Technique | Sub | Name | Fawkes Cmd | Status | Rule File |
|---|---|---|---|---|---|
| T1059 | .001 | PowerShell | `powershell` | 🔄 Monitoring | [t1059_001_powershell_bypass.yml](../detections/execution/t1059_001_powershell_bypass.yml) | [F+SS] |
| T1059 | .003 | Windows Command Shell | `run`, `shell` | ❌ No coverage | — | [F] |
| T1047 | — | Windows Management Instrumentation | `wmi` | 📋 Backlogged (process-based via EID 1) | — | [F+SS] |
| T1620 | — | Reflective Code Loading | `inline-assembly` | ⚠️ Data gap | — |
| T1059 | .003 | BOF Execution | `inline-execute` | ⚠️ Data gap | — |

---

## Persistence (TA0003)

| Technique | Sub | Name | Fawkes Cmd | Status | Rule File |
|---|---|---|---|---|---|
| T1547 | .001 | Registry Run Keys | `persist -method registry` | ✅ Deployed | [t1547_001_registry_run_key.yml](../detections/persistence/t1547_001_registry_run_key.yml) | [F+SS] |
| T1547 | .001 | Startup Folder | `persist -method startup-folder` | 📋 Backlogged (EID 11 now available) | — |
| T1053 | .005 | Scheduled Task | `schtask -action create` | ✅ Deployed | [t1053_005.yml](../detections/persistence/t1053_005.yml) | [F+SS] |
| T1543 | .003 | Windows Service | `service -action create` | 📋 Backlogged (EID 7045 now available) | — | [F+SS] |
| T1053 | .003 | Cron Job | `crontab -action add` | ❌ No coverage | — |
| T1543 | .001 | Launch Agent | `launchagent` | ❌ No coverage (macOS) | — |

---

## Privilege Escalation (TA0004)

| Technique | Sub | Name | Fawkes Cmd | Status | Rule File |
|---|---|---|---|---|---|
| T1055 | .001 | Process Injection: CreateRemoteThread | `vanilla-injection` | ✅ Validated (F1=1.0) | [t1055_001.yml](../detections/privilege_escalation/t1055_001.yml) | [F+SS] |
| T1055 | .004 | Process Injection: APC | `apc-injection` | 📋 Backlogged | — |
| T1055 | .012 | Process Injection: Threadless | `threadless-inject` | ⚠️ Data gap | — |
| T1055 | .015 | Process Injection: PoolParty | `poolparty-injection` | ⚠️ Data gap | — |
| T1134 | .001 | Token Impersonation | `steal-token` | ✅ Deployed | [t1134_001_lsass_token_theft.yml](../detections/credential_access/t1134_001_lsass_token_theft.yml) | [F] |

---

## Defense Evasion (TA0005)

| Technique | Sub | Name | Fawkes Cmd | Status | Rule File |
|---|---|---|---|---|---|
| T1055 | .001 | Process Injection | `vanilla-injection` | ✅ Validated | — (see Priv Esc) |
| T1562 | .001 | Disable/Modify Tools (AMSI) | `autopatch`, `start-clr` | 📋 Backlogged | — | [F] |
| T1070 | .001 | Clear Windows Event Logs | — | ✅ Deployed | [t1070_001.yml](../detections/defense_evasion/t1070_001.yml) | [SS] |
| T1078 | .004 | Cloud Account Abuse | — | ✅ Deployed | [t1078_004.yml](../detections/defense_evasion/t1078_004.yml) | [SS] |
| T1070 | .004 | File Deletion | — | 📋 Backlogged (cipher/sdelete via EID 1) | — | [SS] |
| T1070 | .006 | Timestomp | `timestomp` | ⚠️ Data gap (no EID 2) | — | [F] |
| T1027 | — | Encoded PowerShell | — | 📋 Backlogged (EID 1) | — | [SS] |
| T1027 | .001 | Binary Padding | `binary-inflate` | ⚠️ Data gap | — | [F] |
| T1197 | — | BITS Jobs | — | 📋 Backlogged (bitsadmin via EID 1) | — | [SS] |
| T1090 | .004 | Domain Fronting | built-in C2 | ⚠️ Data gap (need network proxy logs) | — | [F] |
| T1497 | .003 | Time-based Evasion | `sleep` | ❌ No coverage | — | [F] |

---

## Credential Access (TA0006)

| Technique | Sub | Name | Fawkes Cmd | Status | Rule File |
|---|---|---|---|---|---|
| T1134 | .001 | Token Impersonation | `steal-token` | ✅ Deployed | [t1134_001_lsass_token_theft.yml](../detections/credential_access/t1134_001_lsass_token_theft.yml) | [F] |
| T1003 | — | OS Credential Dumping (Mimikatz) | — | 📋 Backlogged (process via EID 1) | — | [SS] |
| T1134 | .003 | Make/Impersonate Token | `make-token` | ❌ No coverage | — | [F] |
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
| T1071 | .001 | HTTP/HTTPS C2 | beacon / `sleep` | 📋 Backlogged | — | [F] |
| T1219 | — | Remote Access Software | — | ✅ Deployed | [t1219.yml](../detections/initial_access/t1219.yml) | [SS] |
| T1090 | .004 | Domain Fronting | built-in | ⚠️ Data gap | — | [F] |
| T1573 | .002 | Asymmetric Cryptography | TLS pinning | ⚠️ Data gap | — | [F] |

---

## Coverage Over Time

| Date | Deployed | Techniques | % Coverage |
|---|---|---|---|
| 2026-03-01 | 2 | 2/21 | 10% |
| 2026-03-01 | 3 | 3/21 | 14% |
| 2026-03-06 | 8 | 8/21 | 38% |
| 2026-03-07 | 8 (+1 monitoring) | 8/21 | 38% |
| 2026-03-07 | 8 (+1 monitoring, +1 validated) | 9/21 | 43% |

*This table updates with each detection deployment.*
