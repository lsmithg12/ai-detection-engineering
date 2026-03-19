# Detection Pipeline Status

> Auto-generated from state machine on 2026-03-19 11:18 UTC
> Run `cd autonomous && python3 orchestration/cli.py export-status` to regenerate

## Summary

| Metric | Count |
|--------|-------|
| Total rules | 36 |
| Sigma | 29 |
| EQL | 3 |
| Threshold | 4 |
| MONITORING | 11 |
| DEPLOYED | 0 |
| VALIDATED | 14 |
| AUTHORED | 11 |
| Needs rework | 3 |

## By State

### MONITORING (11)

- T1053.005: Scheduled Task Creation for Persistence (F1=1.0)
- T1059.001: PowerShell Execution with Bypass Flags (F1=0.95)
- T1070.001: Clear Windows Event Logs (F1=1.0)
- T1071.001: C2 Beaconing via HTTP/HTTPS from Unusual Process (F1=1.0)
- T1078.004: Cloud Account Abuse (F1=1.0)
- T1134.001: LSASS Process Access for Token Theft (F1=1.0)
- T1219: Remote Access Software (F1=1.0)
- T1486: Data Encrypted for Impact (F1=1.0)
- T1547.001: Registry Run Key Persistence (F1=1.0)
- T1562.001: AMSI Bypass via CLR Load in Unsigned Process (F1=1.0)
- T1566.004: Spearphishing Voice (Vishing) (F1=1.0)

### VALIDATED (14)

- T1027: Obfuscated Files or Information (F1=1.0)
- T1046: Network Service Discovery (F1=1.0)
- T1055.001: Process Injection via CreateRemoteThread (F1=0.667)
- T1059.003: Command and Scripting Interpreter: Windows Command Shell (F1=0.75)
- T1082: System Information Discovery (F1=0.75)
- T1083: File and Directory Discovery (F1=1.0)
- T1133: External Remote Services (F1=0.857)
- T1190: Exploit Public-Facing Application (F1=0.75)
- T1204.002: User Execution: Malicious File (F1=0.75)
- T1490: Inhibit System Recovery (F1=1.0)
- T1543.003: Create or Modify System Process: Windows Service (F1=0.857)
- T1562.004: Impair Defenses: Disable or Modify System Firewall (F1=0.857)
- T1562.006: Impair Defenses: Indicator Blocking (F1=1.0)
- T1569.002: System Services: Service Execution (F1=1.0)

### AUTHORED (11)

- T1003.001: OS Credential Dumping: LSASS Memory
- T1021.001: Remote Services: Remote Desktop Protocol (F1=0.5)
- T1055.004: APC Injection â€” Suspicious QueueUserAPC Pattern
- T1055_EQL: Process Injection Sequence â€” Handle Open Then Remote Thread Creation (EQL)
- T1059.001_T1547.001_EQL: PowerShell Execution Followed by Registry Persistence (EQL)
- T1087.002_EQL: Rapid Reconnaissance Command Burst (EQL)
- T1087.002_THRESHOLD: Discovery Command Burst â€” Recon Tool Threshold
- T1105: Ingress Tool Transfer (F1=0.5)
- T1110.001: Brute Force Login â€” Failed Logon Threshold
- T1486_THRESHOLD: Rapid File Modification Burst â€” Ransomware Indicator (Threshold)
- T1489: Mass Service Stop â€” Pre-Ransomware Indicator

