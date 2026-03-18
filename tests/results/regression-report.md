## Detection Regression Test Results

| Rule | Previous F1 | Current F1 | Delta | Status |
|------|------------|------------|-------|--------|
| T1027 | 0.75 | 0.75 | +0.00 | [ PASS ] PASS |
| T1059.001 | 0.95 | 0.95 | +0.00 | [ PASS ] PASS |
| T1053.005 | 0.50 | 0.50 | +0.00 | [ PASS ] PASS |

**Overall: PASS** — all rules within acceptable thresholds

<details><summary>Details</summary>

- **T1027** (Obfuscated PowerShell Execution With Encoded Command and Suspicious Indicators): [ PASS ] First local run; baseline established at F1=0.75
- **T1059.001** (T1059.001): [ PASS ] Local validation skipped — no test data or keywords; using baseline
- **T1053.005** (Scheduled Task Creation for Persistence [T1053.005]): [ PASS ] F1 stable or improved (0.50 → 0.50)

</details>
