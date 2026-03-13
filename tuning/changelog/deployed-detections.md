# Tuning Changelog — Deployed Detections (MONITORING State)

Last updated: 2026-03-13

## T1059.001 — PowerShell Execution with Bypass Flags
- **2026-03-06**: Initial deployment to Elastic + Splunk (PR #18)
- **2026-03-08**: Quality review — F1=0.95, 11/11 healthy. No tuning needed.
- **2026-03-10**: Pipeline v1 re-validation — stable, no changes.
- **2026-03-12**: Quality review — healthy, no changes.

## T1547.001 — Registry Run Key Persistence
- **2026-03-06**: Initial deployment to Elastic + Splunk (PR #18)
- **2026-03-08**: Quality review — F1=1.0, healthy.
- **2026-03-12**: Quality review — healthy, no changes.

## T1134.001 — LSASS Process Access for Token Theft
- **2026-03-06**: Initial deployment to Elastic + Splunk (PR #18)
- **2026-03-08**: Quality review — F1=1.0, healthy.
- **2026-03-12**: Quality review — healthy, no changes.

## T1053.005 — Scheduled Task Creation for Persistence
- **2026-03-06**: Initial deployment to Elastic + Splunk (PR #18)
- **2026-03-08**: Quality review — F1=1.0, healthy.
- **2026-03-12**: Quality review — healthy, no changes.

## T1070.001 — Clear Windows Event Logs
- **2026-03-06**: Initial deployment to Elastic + Splunk (PR #18)
- **2026-03-08**: Quality review — F1=1.0, healthy.
- **2026-03-12**: Quality review — healthy, no changes.

## T1078.004 — Cloud Account Abuse
- **2026-03-06**: Initial deployment to Elastic + Splunk (PR #18)
- **2026-03-08**: Quality review — F1=1.0, healthy.
- **2026-03-12**: Quality review — healthy, no changes.

## T1219 — Remote Access Software
- **2026-03-06**: Initial deployment to Elastic + Splunk (PR #18)
- **2026-03-08**: Quality review — F1=1.0, healthy.
- **2026-03-12**: Quality review — healthy, no changes.

## T1566.004 — Spearphishing Voice (Vishing)
- **2026-03-06**: Initial deployment to Elastic + Splunk (PR #18)
- **2026-03-08**: Quality review — F1=1.0, healthy.
- **2026-03-12**: Quality review — healthy, no changes.

## T1071.001 — C2 Beaconing via HTTP/HTTPS
- **2026-03-07**: Red-team scenario generated (PR #20)
- **2026-03-08**: Blue-team authored + deployed to Elastic + Splunk
- **2026-03-08**: Quality review — F1=1.0, auto_deploy tier.
- **2026-03-12**: Quality review — healthy, no changes.

## T1562.001 — AMSI Bypass via CLR Load
- **2026-03-07**: Initial deployment to Elastic + Splunk
- **2026-03-13**: **Phase 1 fix** — rewrote rule: removed hard-coded `process.name: update_helper.exe`, replaced with path-based `process.executable|contains` patterns for AppData/Temp/ProgramData. Fixed MITRE tag from `attack.execution` to `attack.defense_evasion`. Added broader filter list (pwsh, dotnet, csc, vbc). F1 unchanged at 1.0 but now resilient to process renaming.
