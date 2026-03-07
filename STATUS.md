# Patronus Pipeline Status

## Pipeline State

- **Status**: Active
- **Detections tracked**: 9
- **Detections deployed**: 8
- **Detections in monitoring**: 1 (T1059.001)
- **Detections in progress**: 1 (T1055.001 — F1=0.667, needs rework)
- **Coverage**: 8/21 techniques (38%)

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
| T1055.001 | CreateRemoteThread | AUTHORED | — (needs rework) |

## Token Budget

- **Daily cap**: 500,000 tokens
- **Warning threshold**: 80%
- **Budget log**: `autonomous/budget-log.jsonl`

---
*Updated 2026-03-07. See `autonomous/orchestration/config.yml` for agent configuration.*
