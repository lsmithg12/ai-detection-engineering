# Changelog — Execution Detection Pack

## [1.0.0] — 2026-03-15

### Added
- Initial pack release
- PowerShell Bypass Flags (T1059.001) — monitoring, F1=0.95
- Windows Command Shell (T1059.003) — validated, F1=0.75
- System Info Discovery (T1082) — validated, F1=0.75
- Ingress Tool Transfer (T1105) — authored, F1=0.50 (needs rework)
- External Remote Services (T1133) — validated, F1=0.86
- Exploit Public-Facing App (T1190) — validated, F1=0.75
- Malicious File Execution (T1204.002) — validated, F1=0.75
- Data Encrypted for Impact (T1486) — monitoring, F1=1.00
- Inhibit System Recovery (T1490) — validated, F1=1.00
- Service Execution (T1569.002) — validated, F1=1.00
- Phase 6 content pack framework introduction

### Quality Gates
- min_f1: 0.75
- max_fp_rate: 0.15
