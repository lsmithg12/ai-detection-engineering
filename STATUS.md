# Patronus Pipeline Status

## Pipeline State

- **Status**: Active
- **Detections authored**: 29 (28 techniques + 1 companion registry rule)
- **Detections monitoring (SIEM)**: 11
- **Detections validated (deploy-ready)**: 12 (F1 >= 0.75)
- **Detections needs rework**: 4 (F1 < 0.75)
- **Detections authored (pending validation)**: 2
- **Fawkes coverage**: 13/21 core techniques (62%)
- **Validation method**: Elasticsearch-based (local JSON fallback for CI)

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
| Phase 3 | COMPLETED (2026-03-14) | Raw → Cribl → ES streaming validation + data source gap tracking |
| Phase 4 | IN PROGRESS | Scalable architecture: 10 agents, threat model registry, log source registry |
| Phase 5 | NOT STARTED | Data engineering: multi-platform simulation, data quality, schema evolution |
| Phase 6 | NOT STARTED | Detection content: content packs, EQL, threshold rules, evasion testing |
| Phase 7 | NOT STARTED | Operational excellence: feedback loops, regression testing, SLAs, dashboards |
| Phase 8 | NOT STARTED | Advanced capabilities: Agent SDK, live C2, behavioral analytics, marketplace |

## Token Budget

- **Daily cap**: 500,000 tokens
- **Warning threshold**: 80%
- **Budget log**: `autonomous/budget-log.jsonl`

## Recent Changes

- **PR #59**: Phase 3 — Raw event converter, Cribl streaming validation, data source gap tracking
- **Architecture redesign**: Phases 4-8 rebuilt for enterprise scale (threat model registry, 10 agents, multi-platform)
- **PR #54**: Phase 2 — Elasticsearch-based SIEM validation with local fallback
- **PR #53**: Quality agent run — 11 detections healthy
- **PR #52**: Phase 1 — Fixed stuck detections, compiled Lucene/SPL for all 29 rules
- **PR #50**: Quality agent run — 11 detections healthy
- **PR #49**: Intel agent run — processed 4 reports
- **PR #47**: Pipeline run — backslash normalization fix + blue-team authored 4 detections

---
*Updated 2026-03-15. See `autonomous/orchestration/config.yml` for agent configuration.*

