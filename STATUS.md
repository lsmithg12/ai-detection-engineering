# Patronus Pipeline Status

## Pipeline State

- **Status**: Active
- **Detections tracked**: 9
- **Detections deployed**: 8
- **Detections in monitoring**: 1 (T1059.001)
- **Detections validated**: 1 (T1055.001 — F1=1.0, awaiting SIEM deploy)
- **Coverage**: 9/21 techniques (43%)

## Agent Summary

| Agent | Role | Trigger |
|-------|------|---------|
| Intel | Ingests threat reports, creates detection requests | Daily / manual |
| Red Team | Generates attack + benign scenarios per technique | On intel merge |
| Blue Team | Authors Sigma rules, validates, transpiles, deploys | On intel/red-team merge |
| Quality | Health scoring, daily reports, cross-agent journals | Daily |
| Security | PR gate: secrets, code security, rule checks | Every PR to main |

## Deployed Detections

| Technique | Name | State | SIEMs |
|-----------|------|-------|-------|
| T1059.001 | PowerShell Bypass | MONITORING | Elastic + Splunk |
| T1547.001 | Registry Run Keys | DEPLOYED | Elastic + Splunk |
| T1134.001 | LSASS Token Theft | DEPLOYED | Elastic + Splunk |
| T1053.005 | Scheduled Task | DEPLOYED | Elastic + Splunk |
| T1070.001 | Event Log Clearing | DEPLOYED | Elastic + Splunk |
| T1078.004 | Cloud Account Abuse | DEPLOYED | Elastic + Splunk |
| T1219 | Remote Access Software | DEPLOYED | Elastic + Splunk |
| T1566.004 | Spearphishing Voice | DEPLOYED | Elastic + Splunk |
| T1055.001 | CreateRemoteThread | VALIDATED (F1=1.0) | — (awaiting deploy) |

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

## Token Budget

- **Daily cap**: 500,000 tokens
- **Warning threshold**: 80%
- **Budget log**: `autonomous/budget-log.jsonl`

## Recent Changes

- **PR #18**: `setup.sh` auto-rebuilds simulator on lab restart + synced index template
- **PR #17**: 5 new log sources (EID 4104, 11, 22, 17/18, 7045) + CI workflow fixes
- **PR #16**: T1055.001 rework — F1 improved from 0.667 to 1.0
- **PR #15**: Repo consolidation — deduplicated detections, extracted SIEM module

---
*Updated 2026-03-07. See `autonomous/orchestration/config.yml` for agent configuration.*
