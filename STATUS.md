# Detection Pipeline Status

> Auto-generated from state machine on 2026-03-22 16:27 UTC
> Run `cd autonomous && python3 orchestration/cli.py export-status` to regenerate

## Summary

| Metric | Count |
|--------|-------|
| Total rules | 71 |
| Sigma | 64 |
| EQL | 3 |
| Threshold | 4 |
| MONITORING | 16 |
| DEPLOYED | 0 |
| VALIDATED | 17 |
| AUTHORED | 8 |
| Needs rework | 1 |

## By State

### MONITORING (16)

- T1027: Obfuscated Files or Information (F1=1.0)
- T1046: Network Service Discovery (F1=1.0)
- T1053.005: Scheduled Task Creation for Persistence (F1=1.0)
- T1059.001: PowerShell Execution with Bypass Flags (F1=0.95)
- T1070.001: Clear Windows Event Logs (F1=1.0)
- T1071.001: C2 Beaconing via HTTP/HTTPS from Unusual Process (F1=1.0)
- T1078.004: Cloud Account Abuse (F1=1.0)
- T1083: File and Directory Discovery (F1=1.0)
- T1134.001: LSASS Process Access for Token Theft (F1=1.0)
- T1219: Remote Access Software (F1=1.0)
- T1486: Data Encrypted for Impact (F1=1.0)
- T1490: Inhibit System Recovery (F1=1.0)
- T1547.001: Registry Run Key Persistence (F1=1.0)
- T1562.001: AMSI Bypass via CLR Load in Unsigned Process (F1=1.0)
- T1562.006: Impair Defenses: Indicator Blocking (F1=1.0)
- T1566.004: Spearphishing Voice (Vishing) (F1=1.0)

### VALIDATED (17)

- T1003.001: OS Credential Dumping: LSASS Memory (F1=0.8)
- T1016: Detection for T1016 — Network interface configuration (F1=1.0)
- T1016.001: Detection for T1016.001 — ARP table (host discovery) (F1=0.8)
- T1021.001: Remote Services: Remote Desktop Protocol (F1=0.857)
- T1021.006: Detection for T1021.006 — Remote WMI execution for lateral movement (F1=1.0)
- T1027.001: Detection for T1027.001 — Pad binary to exceed AV scan size limit (F1=1.0)
- T1033: Detection for T1033 — Current user and privileges (F1=0.857)
- T1055.001: Process Injection via CreateRemoteThread (F1=0.667)
- T1059.003: Command and Scripting Interpreter: Windows Command Shell (F1=0.75)
- T1082: System Information Discovery (F1=0.75)
- T1105: Ingress Tool Transfer (F1=1.0)
- T1133: External Remote Services (F1=0.857)
- T1190: Exploit Public-Facing Application (F1=0.75)
- T1204.002: User Execution: Malicious File (F1=0.75)
- T1543.003: Create or Modify System Process: Windows Service (F1=0.857)
- T1562.004: Impair Defenses: Disable or Modify System Firewall (F1=0.857)
- T1569.002: System Services: Service Execution (F1=1.0)

### AUTHORED (8)

- T1055.004: APC Injection - Suspicious QueueUserAPC Pattern
- T1055_EQL: Process Injection Sequence - Handle Open Then Remote Thread Creation (EQL)
- T1059.001_T1547.001_EQL: PowerShell Execution Followed by Registry Persistence (EQL)
- T1087.002_EQL: Rapid Reconnaissance Command Burst (EQL)
- T1087.002_THRESHOLD: Discovery Command Burst - Recon Tool Threshold
- T1110.001: Brute Force Login - Failed Logon Threshold
- T1486_THRESHOLD: Rapid File Modification Burst - Ransomware Indicator (Threshold)
- T1489: Mass Service Stop - Pre-Ransomware Indicator

### REQUESTED (30)

- T1021.002: Remote Services: SMB/Windows Admin Shares
- T1036.003: Masquerading: Rename System Utilities
- T1047: Detection for T1047 — Remote/local WMI execution
- T1049: Detection for T1049 — Active network connections (netstat)
- T1053.003: Detection for T1053.003 — Add crontab entry (Linux)
- T1055.012: Detection for T1055.012 — DLL function pointer overwrite (no new thread)
- T1055.013: Detection for T1055.013 — Ctrl-C handler chain / KernelCallbackTable hijack
- T1055.015: Detection for T1055.015 — 8 variants abusing Windows thread pool internals
- T1056.001: Detection for T1056.001 — Low-level keyboard hook via SetWindowsHookEx
- T1057: Detection for T1057 — List running processes (tasklist)
- T1068: Exploitation for Privilege Escalation
- T1069.002: Permission Groups Discovery: Domain Groups
- T1070.006: Detection for T1070.006 — Modify file timestamps to hide activity
- T1078.002: Valid Accounts: Domain Accounts
- T1087.001: Detection for T1087.001 — Enumerate local/domain users and groups
- T1087.002: Detection for T1087.002 — Enumerate local/domain users and groups
- T1090.001: Detection for T1090.001 — Start SOCKS5 proxy listener on agent
- T1090.004: Detection for T1090.004 — Route C2 traffic through CDN
- T1113: Detection for T1113 — Capture screen
- T1115: Detection for T1115 — Capture clipboard contents
- T1134.003: Detection for T1134.003 — Create new token with provided credentials (LogonUser)
- T1135: Detection for T1135 — Enumerate network shares
- T1497.003: Detection for T1497.003 — Jitter-based sleep to evade beacon detection
- T1518.001: Detection for T1518.001 — Detect installed AV/EDR products
- T1543.001: Detection for T1543.001 — macOS LaunchAgent plist creation
- T1552.004: Detection for T1552.004 — Read private SSH keys from disk
- T1555.001: Detection for T1555.001 — macOS keychain credential access
- T1560.002: Detection for T1560.002 — Download files from target
- T1573.002: Detection for T1573.002 — Encrypted C2 with pinned certificate
- T1620: Detection for T1620 — Load and execute .NET assembly in-memory

