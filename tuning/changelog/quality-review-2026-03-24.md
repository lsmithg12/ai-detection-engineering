# Quality Review — 2026-03-24

## Duplicate Pair: T1543.003 vs T1569.002

**Files:**
- `detections/persistence/t1543_003.yml` — Service Creation with Suspicious Binary Path
- `detections/execution/t1569_002.yml` — sc.exe Service with Suspicious Binary Path

**Overlap:** Both rules detect `sc.exe create` with a binary path in a writable directory
(ProgramData, Temp, AppData, etc.). Both share the same core logic pattern and will
co-fire on every Fawkes `service` command, producing duplicate alerts.

**Differences:**
- T1543.003 additionally detects `sc.exe config` and `sc.exe start` from writable paths
- T1543.003 includes `%APPDATA%`, `%TEMP%`, `%USERPROFILE%` environment variable patterns
- T1569.002 has a slightly tighter filter_legitimate block

**Decision:** Keep both deployed. T1543.003 maps to persistence (creating the service),
T1569.002 maps to execution (starting the service). They serve different MITRE tactic
attribution even though the trigger events overlap. Analysts should expect co-firing
and may want to suppress T1569.002 when T1543.003 fires on the same event.

**Action needed:** Add `related` fields cross-referencing each other in a future PR.

---

## Overlapping LSASS Access Codes: T1003.001 vs T1134.001

**Files:**
- `detections/credential_access/t1003_001.yml` — LSASS Credential Dumping
- `detections/credential_access/t1134_001_lsass_token_theft.yml` — LSASS Token Theft

**Overlap:** All 6 GrantedAccess codes in T1134.001 also appear in T1003.001:
`0x0040`, `0x1FFFFF`, `0x1010`, `0x1410`, `0x1438`, `0x143a`

**Impact:** Every token theft access to LSASS fires both rules.

**Recommended separation:**
- T1134.001 (token theft): focus on `0x0040` (PROCESS_DUP_HANDLE) — the token-specific code
- T1003.001 (credential dump): keep memory-read codes (`0x1F0FFF`, `0x1F1FFF`, `0x100000`)
- Shared codes (`0x1010`, `0x1410`, `0x1438`, `0x143a`): leave in both but document expected co-fire

**Action needed:** Refine GrantedAccess split in a future tuning PR.

---

## Severity Recalibration (this PR)

| Rule | Before | After | Rationale |
|------|--------|-------|-----------|
| T1190 (webserver shell) | high | critical | High-fidelity initial access indicator |
| T1486 (ransomware ext) | high | critical | Matches threshold companion; first encrypt signal |
| T1082 (systeminfo) | high | medium | Single discovery command, common in admin workflows |
| T1046 (port scan) | high | medium | Leading indicator, not high-severity standalone |

---

## ECS Field Name Corrections (this PR)

4 rules converted from Sysmon XML to ECS field names:
- T1059.003, T1082, T1190, T1204.002

All used `Image`, `CommandLine`, `ParentImage`, `User` instead of
`process.executable`, `process.command_line`, `process.parent.executable`, `user.name`.

---

## Missing logsource.category Added (this PR)

3 rules had `product: windows` but no `category`:
- T1003.001: added `category: process_access`
- T1021.001: added `category: process_creation`
- T1027.001: added `category: process_creation`
