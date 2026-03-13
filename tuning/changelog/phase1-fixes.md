# Tuning Changelog — Phase 1 Detection Quality Fixes (2026-03-13)

## T1569.002 — Service Execution via sc.exe
- **Before**: Rule file corrupted — contained API rate-limit error text instead of YAML
- **Root cause**: BUG 8 — Claude returned error response, `yaml.safe_load` parsed as string, stored as rule
- **Fix**: Full rewrite from scratch using scenario data
  - Selection: `sc.exe` with `create`/`start` args + suspicious binary path (ProgramData/AppData/Temp)
  - Filter: exclude parent processes from Program Files/System32
  - Result: F1=1.0 (1 TP, 0 FP, 0 FN, 2 TN)
- **TP split**: Reduced from 3 events to 1 (only `sc.exe create` matches; `sc.exe start` and service spawn are separate detection opportunities)

## T1562.006 — Indicator Blocking
- **Before**: Single rule covering only auditpol.exe disable (1/3 attack vectors). F1=0.0 due to 2 FN from registry events.
- **Root cause**: Rule used `process_creation` logsource, couldn't match registry events (EID 13)
- **Fix**: Split into 2 rules per "multi-EID: separate Sigma rules per event type" lesson
  1. `t1562_006.yml` — auditpol.exe disable detection (process_creation)
  2. `t1562_006_registry.yml` — NEW — SysmonDrv tampering + ETW autologger disable (registry_set)
  - Result: Both F1=1.0. Combined coverage: 3/3 attack vectors.
- **TP split**: Original 3-event TP → 1 event for auditpol rule + 2 events for registry rule
- **New TN**: Created from benign scenario (services.exe setting MaxSize)

## T1562.001 — AMSI Bypass via CLR Load
- **Before**: Hard-coded `process.name: update_helper.exe` — trivially evaded by renaming. Filter referenced only 2 processes.
- **Root cause**: Blue-team agent copied process name from scenario instead of generalizing
- **Fix**: Rewrote detection logic
  - Selection split: `selection_dll` (EID 7 + amsi.dll/clr.dll) AND `selection_suspicious_path` (AppData/Temp/ProgramData/Public/Downloads)
  - Expanded filter: 8 legitimate .NET hosts (powershell, pwsh, dotnet, devenv, msbuild, csc, vbc, MSBuild)
  - Fixed MITRE tag: `attack.execution` → `attack.defense_evasion`
  - Added Fawkes reference and `detection.fawkes` tag
  - Result: F1=1.0 (maintained, but now resilient to evasion)

## T1046 — Network Service Discovery
- **Before**: Rule logic was correct but F1=0.0 during automated validation
- **Root cause**: BUG 7 — backslash normalization mismatch between YAML and JSON (fixed in PR #47). Also, 3-event TP (1 process + 2 network) inflated FN count since rule only matches process_creation.
- **Fix**: No rule changes needed — re-validated after bug fix + TP event split
  - TP split: 3 events → 1 (process_creation only; network events moved to integration/)
  - Result: F1=1.0 (1 TP, 0 FP, 0 FN, 2 TN)
