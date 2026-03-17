# MITRE ATT&CK Coverage Matrix — Fawkes C2 Detections

**Last updated**: 2026-03-17
**Total detections**: 37 rules (30 Sigma + 3 EQL + 4 threshold)
**Deployed to SIEM**: 11 (MONITORING state)
**Validated (deploy-ready)**: 12 (F1 >= 0.75)
**Needs rework**: 4 (F1 < 0.75)
**Authored (pending validation)**: 10 (2 pre-Phase6 + 8 new Phase 6 rules)
**Fawkes technique coverage**: 14 / 21 core techniques (67%)
**Tactics covered**: 9 (Impact tactic added in Phase 6)

Legend: ✅ Monitoring | ✓ Validated | 🔨 Authored | ❌ No coverage | ⚠️ Data gap
Quality: 🟢 auto_deploy (F1>=0.90) | 🟡 validated (F1>=0.75) | 🔴 needs_rework (F1<0.75)

---

## Tactic Coverage Summary

| Tactic | Detections | Monitoring | Validated | Authored | Needs Rework |
|---|---|---|---|---|---|
| Initial Access (TA0001) | 2 | 2 | 0 | 0 | 0 |
| Execution (TA0002) | 12 | 2 | 6 | 1 | 3 |
| Persistence (TA0003) | 3 | 2 | 1 | 0 | 0 |
| Privilege Escalation (TA0004) | 3 | 0 | 1 | 2 | 0 |
| Defense Evasion (TA0005) | 7 | 3 | 3 | 1 | 0 |
| Credential Access (TA0006) | 3 | 1 | 0 | 1 | 1 |
| Discovery (TA0007) | 4 | 0 | 1 | 3 | 0 |
| Impact (TA0040) | 2 | 0 | 0 | 2 | 0 |
| Command & Control (TA0011) | 1 | 1 | 0 | 0 | 0 |
| **Total** | **37** | **11** | **12** | **10** | **4** |
<!-- Note: 11 MONITORING confirmed via quality report 2026-03-13; 8 new AUTHORED rules added Phase 6 (2026-03-17) -->

---

## All Detections — Current State

| Technique | Title | Status | F1 | Tier | Rule File |
|---|---|---|---|---|---|
| T1003.001 | LSASS Credential Dump | 🔨 AUTHORED | 0.00 | 🔴 needs_rework | [t1003_001.yml](../detections/credential_access/t1003_001.yml) |
| T1021.001 | Remote Desktop Protocol | 🔨 AUTHORED | 0.50 | 🔴 needs_rework | [t1021_001.yml](../detections/execution/t1021_001.yml) |
| T1027 | Obfuscated Files or Information | ✓ VALIDATED | 1.00 | 🟢 auto_deploy | [t1027.yml](../detections/defense_evasion/t1027.yml) |
| T1046 | Network Service Discovery | ✓ VALIDATED | 1.00 | 🟢 auto_deploy | [t1046.yml](../detections/discovery/t1046.yml) |
| T1053.005 | Scheduled Task Persistence | ✅ MONITORING | 1.00 | 🟢 auto_deploy | [t1053_005.yml](../detections/persistence/t1053_005.yml) |
| T1055.001 | CreateRemoteThread Injection | ✓ VALIDATED | 1.00 | 🟢 auto_deploy | [t1055_001.yml](../detections/privilege_escalation/t1055_001.yml) |
| T1055.004 | APC Injection (QueueUserAPC) | 🔨 AUTHORED | — | pending | [t1055_004_apc_injection.yml](../detections/privilege_escalation/t1055_004_apc_injection.yml) |
| T1055 | Process Injection Sequence (EQL) | 🔨 AUTHORED | — | pending | [t1055_sequence_eql.yml](../detections/privilege_escalation/t1055_sequence_eql.yml) |
| T1059.001 | PowerShell Bypass Flags | ✅ MONITORING | 0.95 | 🟢 auto_deploy | [t1059_001_powershell_bypass.yml](../detections/execution/t1059_001_powershell_bypass.yml) |
| T1059.001+T1547.001 | Persistence After Exec (EQL) | 🔨 AUTHORED | — | pending | [t1059_001_t1547_001_persistence_after_exec_eql.yml](../detections/execution/t1059_001_t1547_001_persistence_after_exec_eql.yml) |
| T1059.003 | Windows Command Shell | ✓ VALIDATED | 0.75 | 🟡 validated | [t1059_003.yml](../detections/execution/t1059_003.yml) |
| T1070.001 | Event Log Clearing | ✅ MONITORING | 1.00 | 🟢 auto_deploy | [t1070_001.yml](../detections/defense_evasion/t1070_001.yml) |
| T1071.001 | C2 Beaconing HTTP/HTTPS | ✅ MONITORING | 1.00 | 🟢 auto_deploy | [t1071_001.yml](../detections/command_and_control/t1071_001.yml) |
| T1078.004 | Cloud Account Abuse | ✅ MONITORING | 1.00 | 🟢 auto_deploy | [t1078_004.yml](../detections/defense_evasion/t1078_004.yml) |
| T1082 | System Info Discovery | ✓ VALIDATED | 0.75 | 🟡 validated | [t1082.yml](../detections/execution/t1082.yml) |
| T1083 | File/Directory Discovery | ✓ VALIDATED | 1.00 | 🟢 auto_deploy | [t1083.yml](../detections/discovery/t1083.yml) |
| T1087.002 | Account Discovery Burst (EQL) | 🔨 AUTHORED | — | pending | [t1087_002_discovery_burst_eql.yml](../detections/discovery/t1087_002_discovery_burst_eql.yml) |
| T1087.002 | Account Discovery Threshold | 🔨 AUTHORED | — | pending | [t1087_002_discovery_threshold.yml](../detections/discovery/t1087_002_discovery_threshold.yml) |
| T1105 | Ingress Tool Transfer | 🔨 AUTHORED | 0.50 | 🔴 needs_rework | [t1105.yml](../detections/execution/t1105.yml) |
| T1110.001 | Brute Force Login Threshold | 🔨 AUTHORED | — | pending | [t1110_001_brute_force_threshold.yml](../detections/credential_access/t1110_001_brute_force_threshold.yml) |
| T1133 | External Remote Services | ✓ VALIDATED | 0.86 | 🟡 validated | [t1133.yml](../detections/execution/t1133.yml) |
| T1134.001 | LSASS Token Theft | ✅ MONITORING | 1.00 | 🟢 auto_deploy | [t1134_001_lsass_token_theft.yml](../detections/credential_access/t1134_001_lsass_token_theft.yml) |
| T1190 | Exploit Public-Facing App | ✓ VALIDATED | 0.75 | 🟡 validated | [t1190.yml](../detections/execution/t1190.yml) |
| T1204.002 | Malicious File Execution | ✓ VALIDATED | 0.75 | 🟡 validated | [t1204_002.yml](../detections/execution/t1204_002.yml) |
| T1219 | Remote Access Software | ✅ MONITORING | 1.00 | 🟢 auto_deploy | [t1219.yml](../detections/initial_access/t1219.yml) |
| T1486 | Data Encrypted for Impact | ✅ MONITORING | 1.00 | 🟢 auto_deploy | [t1486.yml](../detections/execution/t1486.yml) |
| T1486 | File Encryption Burst (threshold) | 🔨 AUTHORED | — | pending | [t1486_file_encryption_threshold.yml](../detections/impact/t1486_file_encryption_threshold.yml) |
| T1489 | Mass Service Stop (threshold) | 🔨 AUTHORED | — | pending | [t1489_mass_service_stop_threshold.yml](../detections/impact/t1489_mass_service_stop_threshold.yml) |
| T1490 | Inhibit System Recovery | ✓ VALIDATED | 1.00 | 🟢 auto_deploy | [t1490.yml](../detections/execution/t1490.yml) |
| T1543.003 | Windows Service Persistence | ✓ VALIDATED | 0.86 | 🟡 validated | [t1543_003.yml](../detections/persistence/t1543_003.yml) |
| T1547.001 | Registry Run Key Persistence | ✅ MONITORING | 1.00 | 🟢 auto_deploy | [t1547_001_registry_run_key.yml](../detections/persistence/t1547_001_registry_run_key.yml) |
| T1562.001 | AMSI Bypass CLR Load | ✅ MONITORING | 1.00 | 🟢 auto_deploy | [t1562_001.yml](../detections/defense_evasion/t1562_001.yml) |
| T1562.004 | Firewall Disable | ✓ VALIDATED | 0.86 | 🟡 validated | [t1562_004.yml](../detections/defense_evasion/t1562_004.yml) |
| T1562.006 | Indicator Blocking (auditpol) | ✓ VALIDATED | 1.00 | 🟢 auto_deploy | [t1562_006.yml](../detections/defense_evasion/t1562_006.yml) |
| T1562.006 | Indicator Blocking (registry) | ✓ VALIDATED | 1.00 | 🟢 auto_deploy | [t1562_006_registry.yml](../detections/defense_evasion/t1562_006_registry.yml) |
| T1566.004 | Spearphishing Voice | ✅ MONITORING | 1.00 | 🟢 auto_deploy | [t1566_004.yml](../detections/initial_access/t1566_004.yml) |
| T1569.002 | Service Execution | ✓ VALIDATED | 1.00 | 🟢 auto_deploy | [t1569_002.yml](../detections/execution/t1569_002.yml) |

---

## Detections Fixed in Phase 1 (2026-03-13)

| Technique | Issue | Fix | Before | After |
|---|---|---|---|---|
| T1569.002 | Corrupted rule (rate-limit error stored as YAML) | Full rewrite from scenario | F1=N/A | F1=1.0 |
| T1562.006 | Only covered 1/3 attack vectors (auditpol only) | Split into process + registry rules | F1=0.0 | F1=1.0 (both) |
| T1562.001 | Hard-coded process name, wrong MITRE tag | Path-based patterns, tag fix | F1=1.0* | F1=1.0 |
| T1046 | Backslash bug caused 0 matches | Re-validated + TP split | F1=0.0 | F1=1.0 |

*T1562.001 had F1=1.0 because scenario used same hard-coded process name. Now detection is robust.

---

## Remaining Gaps — Fawkes C2 Capabilities Not Yet Detected

| Technique | Name | Fawkes Command | Blocker |
|---|---|---|---|
| T1055.004 | APC Injection | `apc-injection` | ⚠️ AUTHORED (Phase 6) — awaiting validation |
| T1055.012 | Threadless Injection | `threadless-inject` | Data gap — need ETW |
| T1055.015 | PoolParty Injection | `poolparty-injection` | Data gap — need ETW |
| T1056.001 | Keylogging | `keylog` | Data gap — need hook events |
| T1115 | Clipboard Data | `clipboard` | Data gap |
| T1113 | Screen Capture | `screenshot` | Data gap |
| T1090.001 | SOCKS5 Proxy | `socks5` | Data gap — need network flow |
| T1070.006 | Timestomping | `timestomp` | Data gap — no EID 2 |

## Phase 6 Additions (2026-03-17)

New rule types added in Phase 6 (all AUTHORED, pending validation):

| Rule | Type | Technique(s) | Detects |
|---|---|---|---|
| t1055_004_apc_injection.yml | Sigma | T1055.004 | QueueUserAPC via Sysmon EID 8 |
| t1055_sequence_eql.yml | EQL | T1055 | EID 10 (handle open) → EID 8 (thread create) in 10s |
| t1059_001_t1547_001_persistence_after_exec_eql.yml | EQL | T1059.001+T1547.001 | PowerShell bypass → registry Run key in 5min |
| t1087_002_discovery_burst_eql.yml | EQL | T1087.002 | 3+ recon tools in 60s sequence |
| t1087_002_discovery_threshold.yml | Threshold | T1087.002 | Aggregation fallback for discovery burst |
| t1110_001_brute_force_threshold.yml | Threshold | T1110.001 | 5+ EID 4625 failures from same source.ip in 10min |
| t1486_file_encryption_threshold.yml | Threshold | T1486 | High-volume file writes (ransomware burst) |
| t1489_mass_service_stop_threshold.yml | Threshold | T1489 | 5+ service stops in 60s (pre-ransomware) |

Content packs created: 8 tactic-based packs + 1 process-injection pack (all in `detections/packs/`)

---

## Coverage Over Time

| Date | Deployed | Validated | Total Rules | Fawkes % | Notes |
|---|---|---|---|---|---|
| 2026-03-01 | 2 | 0 | 2 | 10% | Initial rules |
| 2026-03-06 | 8 | 1 | 9 | 38% | Batch authoring |
| 2026-03-07 | 8 | 1 | 9 | 43% | — |
| 2026-03-08 | 9 | 12 | 28 | 43% | Bulk validation |
| 2026-03-13 | 9 | 16 | 29 | 62% | Phase 1 (PR #52) |
| 2026-03-15 | 11 | 12 | 29 | 62% | Phases 2-4 (PR #54, #58, #62) |
| 2026-03-17 | 11 | 12 | 37 | 67% | Phase 6 (PR #65) — +8 rules, +Impact tactic |
