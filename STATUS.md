# Patronus Pipeline Status

## Pipeline State

- **Status**: Active
- **Total detection rules**: 37 (30 Sigma + 3 EQL + 4 threshold; 8 new from Phase 6)
- **Detections monitoring (SIEM)**: 11
- **Detections validated (deploy-ready)**: 12 (F1 >= 0.75)
- **Detections authored (pending validation)**: 10 (2 pre-Phase6 + 8 new Phase 6 rules)
- **Detections needs rework**: 4 (F1 < 0.75: T1003.001, T1021.001, T1105, borderline)
- **Fawkes coverage**: 14/21 core techniques (67%) — T1055.004 APC injection added
- **Tactics covered**: 9 (Impact tactic added in Phase 6)
- **Validation method**: Elasticsearch-based + EQL/threshold variants (local JSON fallback for CI)
- **Phases complete**: 1, 2, 3, 4, 5, 6 (Phase 7 next)

## Agent Summary

| Agent | Role | Trigger |
|-------|------|---------|
| Intel | Ingests threat reports, creates detection requests | Daily / manual |
| Red Team | Generates attack + benign scenarios per technique | On intel merge |
| Blue Team | Authors Sigma rules, validates against ES, transpiles, deploys | On intel/red-team merge |
| Quality | Health scoring, daily reports, cross-agent journals | Daily |
| Security | PR gate: secrets, code security, rule checks | Every PR to main |

## Deployed Detections (MONITORING)

| Technique | Name | SIEMs | Health |
|-----------|------|-------|--------|
| T1053.005 | Scheduled Task | Elastic + Splunk | 0.915 |
| T1059.001 | PowerShell Bypass | Elastic + Splunk | 0.907 |
| T1070.001 | Event Log Clearing | Elastic + Splunk | 0.915 |
| T1071.001 | C2 Beaconing | Elastic + Splunk | 0.915 |
| T1078.004 | Cloud Account Abuse | Elastic + Splunk | 0.915 |
| T1134.001 | LSASS Token Theft | Elastic + Splunk | 0.915 |
| T1219 | Remote Access Software | Elastic + Splunk | 0.915 |
| T1486 | Data Encrypted for Impact | Elastic + Splunk | 0.915 |
| T1547.001 | Registry Run Keys | Elastic + Splunk | 0.915 |
| T1562.001 | AMSI Bypass CLR | Elastic + Splunk | 0.915 |
| T1566.004 | Spearphishing Voice | Elastic + Splunk | 0.915 |

## Validated (Deploy-Ready, F1 >= 0.75)

| Technique | Name | F1 | Tier |
|-----------|------|----|------|
| T1027 | Obfuscated Files | 1.00 | auto_deploy |
| T1046 | Network Service Discovery | 1.00 | auto_deploy |
| T1055.001 | CreateRemoteThread | 1.00 | auto_deploy |
| T1083 | File/Directory Discovery | 1.00 | auto_deploy |
| T1490 | Inhibit System Recovery | 1.00 | auto_deploy |
| T1562.006 | Indicator Blocking (auditpol) | 1.00 | auto_deploy |
| T1562.006 | Indicator Blocking (registry) | 1.00 | auto_deploy |
| T1569.002 | Service Execution | 1.00 | auto_deploy |
| T1059.003 | Windows Command Shell | 0.75 | validated |
| T1082 | System Info Discovery | 0.75 | validated |
| T1133 | External Remote Services | 0.86 | validated |
| T1190 | Exploit Public-Facing App | 0.75 | validated |
| T1204.002 | Malicious File Execution | 0.75 | validated |
| T1543.003 | Windows Service | 0.86 | validated |
| T1562.004 | Firewall Disable | 0.86 | validated |

## Simulator Log Sources

| EID | Type | Baseline Events | Attack Events | Added |
|-----|------|-----------------|---------------|-------|
| 1 | Process Create | Yes | Yes | v1 |
| 3 | Network Connect | Yes | Yes | v1 |
| 7 | Image Load | Yes | Yes | v1 |
| 8 | CreateRemoteThread | Yes | Yes | v1 |
| 10 | Process Access | Yes | Yes | v1 |
| 13 | Registry Event | Yes | Yes | v1 |
| 4624 | Windows Logon | Yes | No | v1 |
| 4104 | PowerShell ScriptBlock | Yes | Yes | PR #17 |
| 11 | File Create | Yes | Yes | PR #17 |
| 22 | DNS Query | Yes | Yes | PR #17 |
| 17/18 | Named Pipe | Yes | Yes | PR #17 |
| 7045 | Service Install | Yes | Yes | PR #17 |

## Improvement Phases

Phases 4-8 were redesigned on 2026-03-15 around real-world scaling concerns.
See `plans/architecture-scalable-detection-platform.md` for the architectural vision.

| Phase | Status | Key Deliverable |
|-------|--------|-----------------|
| Phase 1 | COMPLETED (PR #52, 2026-03-13) | Fixed stuck detections, compiled all outputs |
| Phase 2 | COMPLETED (PR #54, 2026-03-14) | Elasticsearch-based SIEM validation |
| Phase 3 | COMPLETED (PR #58, 2026-03-14) | Raw → Cribl → ES streaming validation + data source gap tracking |
| Phase 4 | COMPLETED (PR #62, 2026-03-15) | 10 specialized agents, threat model registry, coordinator, log source registry |
| Phase 5 | COMPLETED (PR #63, 2026-03-15) | Multi-platform simulation, data quality engine, schema versioning, per-source Cribl |
| Phase 6 | COMPLETED (PR #65, 2026-03-17) | Content packs, EQL/threshold rules, evasion testing, perf profiling, continuous validation CI |
| Phase 7 | NOT STARTED | Operational excellence: feedback loops, regression testing, SLAs, dashboards |
| Phase 8 | NOT STARTED | Advanced capabilities: Agent SDK, live C2, behavioral analytics, marketplace |

## Token Budget

- **Daily cap**: 500,000 tokens
- **Warning threshold**: 80%
- **Budget log**: `autonomous/budget-log.jsonl`

## Recent Changes

- **PR #65** (2026-03-17): Phase 6 — Content packs (9), EQL rules (3), threshold rules (4), T1055.004 Sigma, evasion tests (5), continuous-validation CI, performance profiler, EQL/threshold/evasion Python modules
- **PR #63** (2026-03-15): Phase 5 — Data quality engine, multi-platform simulators (Linux/cloud/network/macOS), schema versioning, per-source Cribl pipelines, automated gap analysis
- **PR #62** (2026-03-15): Phase 4 — 10 specialized agents, threat model registry (Fawkes + LockBit + Scattered Spider), coordinator, log source registry
- **PR #60** (2026-03-15): Architecture redesign — Phases 4-8 rebuilt for enterprise scale
- **PR #58** (2026-03-14): Phase 3 — Raw event converter, Cribl streaming validation, data source gap tracking
- **PR #54** (2026-03-14): Phase 2 — Elasticsearch-based SIEM validation with local fallback
- **PR #52** (2026-03-13): Phase 1 — Fixed stuck detections, compiled Lucene/SPL for all 29 rules

---
*Updated 2026-03-17. See `autonomous/orchestration/config.yml` for agent configuration.*

