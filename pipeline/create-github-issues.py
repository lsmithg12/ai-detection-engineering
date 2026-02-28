#!/usr/bin/env python3
"""Create GitHub Issues for all 10 Fawkes coverage gaps."""
import urllib.request
import urllib.error
import json
import sys
import os

PAT = os.environ.get("GITHUB_PAT") or (sys.argv[1] if len(sys.argv) > 1 else "")
if not PAT:
    print("ERROR: Set GITHUB_PAT env var or pass token as argument.")
    sys.exit(1)

REPO = os.environ.get("GITHUB_REPO", "")
if not REPO:
    print("ERROR: Set GITHUB_REPO env var (e.g., 'myuser/ai-detection-engineering').")
    sys.exit(1)
BASE = f"https://api.github.com/repos/{REPO}"
HEADERS = {
    "Authorization": f"Bearer {PAT}",
    "Accept": "application/vnd.github+json",
    "Content-Type": "application/json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "blue-team-agent/1.0",
}


def api(method, path, data=None):
    url = BASE + path
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode()), e.code


# ── Labels ────────────────────────────────────────────────────────────────────
LABELS = [
    ("coverage-gap",         "e11d48", "Missing detection for a technique"),
    ("detection",            "0ea5e9", "PR adds or modifies a detection rule"),
    ("data-source-gap",      "f97316", "Missing log source for detection"),
    ("high-priority",        "dc2626", "Critical technique prioritized"),
    ("privilege-escalation", "7c3aed", "MITRE TA0004"),
    ("execution",            "16a34a", "MITRE TA0002"),
    ("persistence",          "ca8a04", "MITRE TA0003"),
    ("credential-access",    "db2777", "MITRE TA0006"),
    ("command-and-control",  "0891b2", "MITRE TA0011"),
    ("defense-evasion",      "4f46e5", "MITRE TA0005"),
    ("discovery",            "059669", "MITRE TA0007"),
]

print("[*] Testing auth...")
resp, status = api("GET", "")
if status != 200:
    print(f"ERROR: HTTP {status} — {resp.get('message', '')}")
    sys.exit(1)
print("[+] Auth OK")

print("[*] Creating labels...")
for name, color, desc in LABELS:
    resp, status = api("POST", "/labels", {"name": name, "color": color, "description": desc})
    if status == 201:
        print(f"  [+] {name}")
    elif status == 422:
        print(f"  [=] exists: {name}")
    else:
        print(f"  [!] {name}: HTTP {status}")

# ── Issues ────────────────────────────────────────────────────────────────────
ISSUES = [
    {
        "title": "[Gap] No detection for Process Injection: CreateRemoteThread (T1055.001)",
        "labels": ["coverage-gap", "high-priority", "privilege-escalation"],
        "body": (
            "## Coverage Gap: T1055.001 — CreateRemoteThread Process Injection\n\n"
            "**Priority**: Rank 1 / Score 10/10  \n"
            "**Fawkes command**: `vanilla-injection`  \n"
            "**Tactic**: Privilege Escalation / Defense Evasion (TA0004/TA0005)\n\n"
            "### Detection Hypothesis\n"
            "A process that is not a known debugger opens another process with full access rights "
            "(`GrantedAccess: 0x1F3FFF`) AND creates a remote thread in an unbacked memory region.\n\n"
            "### Required Data Sources\n"
            "- Sysmon EID 8 (CreateRemoteThread) — **available in sim-attack**\n"
            "- Sysmon EID 10 (Process Access) — **available in sim-attack**\n\n"
            "### Key KQL\n"
            "```\n"
            'event.code: "8" AND\n'
            'NOT winlog.event_data.SourceImage: ("C:\\\\Windows\\\\System32\\\\*")\n'
            "```\n\n"
            "### Rule File\n"
            "`detections/privilege_escalation/t1055_001_create_remote_thread.yml`"
        ),
    },
    {
        "title": "[Gap] No detection for PowerShell Execution with Bypass Flags (T1059.001)",
        "labels": ["coverage-gap", "high-priority", "execution"],
        "body": (
            "## Coverage Gap: T1059.001 — Suspicious PowerShell Execution\n\n"
            "**Priority**: Rank 2 / Score 9/10  \n"
            "**Fawkes command**: `powershell`  \n"
            "**Tactic**: Execution (TA0002)\n\n"
            "### Detection Hypothesis\n"
            "PowerShell.exe spawned with `-EncodedCommand`, `-ExecutionPolicy Bypass`, or `-WindowStyle Hidden`.\n\n"
            "### Required Data Sources\n"
            "- Sysmon EID 1: `process.name`, `process.command_line` — **available**\n\n"
            "### Key KQL\n"
            "```\n"
            'event.code: "1" AND process.name: "powershell.exe" AND (\n'
            "  process.command_line: *EncodedCommand* OR\n"
            "  process.command_line: *ExecutionPolicy Bypass* OR\n"
            "  process.command_line: (*IEX* AND *DownloadString*)\n"
            ")\n"
            "```\n\n"
            "### Rule File\n"
            "`detections/execution/t1059_001_suspicious_powershell.yml`"
        ),
    },
    {
        "title": "[Gap] No detection for Registry Run Key Persistence (T1547.001)",
        "labels": ["coverage-gap", "high-priority", "persistence"],
        "body": (
            "## Coverage Gap: T1547.001 — Registry Run Key Persistence\n\n"
            "**Priority**: Rank 3 / Score 9/10  \n"
            "**Fawkes command**: `persist -method registry`  \n"
            "**Tactic**: Persistence (TA0003)\n\n"
            "### Detection Hypothesis\n"
            "Registry value written to Run/RunOnce key where the binary path points to temp directories.\n\n"
            "### Required Data Sources\n"
            "- Sysmon EID 13: `registry.path`, `registry.value` — **available**\n\n"
            "### Key KQL\n"
            "```\n"
            'event.code: "13" AND\n'
            "registry.path: (*\\\\CurrentVersion\\\\Run* OR *\\\\CurrentVersion\\\\RunOnce*) AND\n"
            "registry.value: (*AppData\\\\Local\\\\Temp* OR *ProgramData* OR *AppData\\\\Roaming*)\n"
            "```\n\n"
            "### Rule File\n"
            "`detections/persistence/t1547_001_registry_run_key.yml`"
        ),
    },
    {
        "title": "[Gap] No detection for LSASS Access for Token Theft (T1134.001)",
        "labels": ["coverage-gap", "high-priority", "credential-access"],
        "body": (
            "## Coverage Gap: T1134.001 — Token Impersonation via LSASS Access\n\n"
            "**Priority**: Rank 4 / Score 9/10  \n"
            "**Fawkes command**: `steal-token`  \n"
            "**Tactic**: Credential Access / Privilege Escalation (TA0006/TA0004)\n\n"
            "### Detection Hypothesis\n"
            "Unsigned process opens LSASS with `GrantedAccess: 0x0040` (PROCESS_DUP_HANDLE) "
            "— the specific right to duplicate a token.\n\n"
            "### Required Data Sources\n"
            "- Sysmon EID 10: `winlog.event_data.TargetImage`, `winlog.event_data.GrantedAccess` — **available**\n\n"
            "### Key KQL\n"
            "```\n"
            'event.code: "10" AND\n'
            "winlog.event_data.TargetImage: *lsass.exe AND\n"
            'winlog.event_data.GrantedAccess: ("0x0040" OR "0x1F3FFF" OR "0x1010")\n'
            "```\n\n"
            "### Rule File\n"
            "`detections/credential_access/t1134_001_lsass_access_token_theft.yml`"
        ),
    },
    {
        "title": "[Gap] No detection for C2 HTTP Beaconing from Unusual Process (T1071.001)",
        "labels": ["coverage-gap", "command-and-control"],
        "body": (
            "## Coverage Gap: T1071.001 — C2 Beaconing via HTTP/HTTPS\n\n"
            "**Priority**: Rank 5 / Score 8/10  \n"
            "**Fawkes command**: `sleep` / Mythic callback loop  \n"
            "**Tactic**: Command and Control (TA0011)\n\n"
            "### Detection Hypothesis\n"
            "Process with executable in temp directory makes repeated outbound HTTPS connections to non-CDN IP.\n\n"
            "### Required Data Sources\n"
            "- Sysmon EID 3: `process.executable`, `destination.ip`, `destination.port` — **available**\n\n"
            "### Key KQL\n"
            "```\n"
            'event.code: "3" AND\n'
            'network.direction: "outbound" AND\n'
            "destination.port: 443 AND\n"
            "process.executable: (*\\\\AppData\\\\Local\\\\Temp* OR *\\\\ProgramData*)\n"
            "```\n\n"
            "### Rule File\n"
            "`detections/command_and_control/t1071_001_c2_beaconing_unusual_process.yml`"
        ),
    },
    {
        "title": "[Gap] No detection for Scheduled Task Persistence (T1053.005)",
        "labels": ["coverage-gap", "persistence"],
        "body": (
            "## Coverage Gap: T1053.005 — Scheduled Task Creation\n\n"
            "**Priority**: Rank 6 / Score 8/10  \n"
            "**Fawkes command**: `schtask -action create`  \n"
            "**Tactic**: Persistence / Execution (TA0003/TA0002)\n\n"
            "### Detection Hypothesis\n"
            "`schtasks.exe` called with `/Create` where binary path is in temp dirs or trigger is ONLOGON/ONSTART.\n\n"
            "### Confirmed TP (from sim-attack)\n"
            "```\n"
            'schtasks.exe /Create /TN "\\Microsoft\\Windows\\Maintenance\\SystemUpdate"\n'
            '  /TR "C:\\Users\\agarcia\\AppData\\Local\\Temp\\update.exe" /SC ONLOGON /RL HIGHEST\n'
            "```\n\n"
            "### Required Data Sources\n"
            "- Sysmon EID 1: `process.name: schtasks.exe`, `process.command_line` — **available**\n\n"
            "### Key KQL\n"
            "```\n"
            'event.code: "1" AND process.name: "schtasks.exe" AND\n'
            "process.command_line: */Create* AND (\n"
            "  process.command_line: (*AppData\\\\Local\\\\Temp* OR *ProgramData*) OR\n"
            "  process.command_line: (*ONLOGON* OR *ONSTART*)\n"
            ")\n"
            "```\n\n"
            "### Rule File\n"
            "`detections/persistence/t1053_005_scheduled_task_persistence.yml`"
        ),
    },
    {
        "title": "[Gap] No detection for AMSI Bypass via CLR Load in Unsigned Process (T1562.001)",
        "labels": ["coverage-gap", "defense-evasion"],
        "body": (
            "## Coverage Gap: T1562.001 — AMSI/ETW Bypass via CLR Load\n\n"
            "**Priority**: Rank 7 / Score 7/10  \n"
            "**Fawkes commands**: `start-clr`, `autopatch`  \n"
            "**Tactic**: Defense Evasion (TA0005)\n\n"
            "### Detection Hypothesis\n"
            "`amsi.dll` or `clr.dll` loaded by a process whose executable is in a user temp directory.\n\n"
            "### Required Data Sources\n"
            "- Sysmon EID 7: `file.name`, `process.executable` — **available**\n\n"
            "### Key KQL\n"
            "```\n"
            'event.code: "7" AND\n'
            'file.name: ("amsi.dll" OR "clr.dll") AND\n'
            "process.executable: (*\\\\AppData\\\\Local\\\\Temp* OR *\\\\ProgramData*)\n"
            "```\n\n"
            "### Rule File\n"
            "`detections/defense_evasion/t1562_001_amsi_bypass_clr_load.yml`"
        ),
    },
    {
        "title": "[Gap] No detection for Rapid Discovery Command Burst (T1087.002 / T1057 / T1033 / T1016)",
        "labels": ["coverage-gap", "discovery"],
        "body": (
            "## Coverage Gap: Discovery Command Burst\n\n"
            "**Priority**: Rank 8 / Score 7/10  \n"
            "**Fawkes commands**: `net-enum`, `ps`, `whoami`, `arp`, `ifconfig`, `net-stat`  \n"
            "**Tactic**: Discovery (TA0007)\n\n"
            "### Detection Hypothesis\n"
            "5+ discovery commands (whoami, net, tasklist, arp, ipconfig, netstat) spawned by same parent within 60s.\n\n"
            "### Required Data Sources\n"
            "- Sysmon EID 1: `process.name`, `process.parent.pid`, `@timestamp` — **available**\n"
            "- Requires EQL sequence rule in Elastic Security\n\n"
            "### Key EQL\n"
            "```\n"
            "sequence by process.parent.pid with maxspan=60s\n"
            '  [process where process.name in ("whoami.exe","net.exe","tasklist.exe","arp.exe")]\n'
            '  [process where process.name in ("whoami.exe","net.exe","ipconfig.exe","netstat.exe")]\n'
            '  [process where process.name in ("whoami.exe","net.exe","arp.exe","ipconfig.exe")]\n'
            "```\n\n"
            "### Rule File\n"
            "`detections/discovery/t1087_002_discovery_command_burst.yml`"
        ),
    },
    {
        "title": "[Gap] No detection for APC Injection (T1055.004)",
        "labels": ["coverage-gap", "privilege-escalation"],
        "body": (
            "## Coverage Gap: T1055.004 — APC Injection\n\n"
            "**Priority**: Rank 9 / Score 6/10  \n"
            "**Fawkes command**: `apc-injection`  \n"
            "**Tactic**: Privilege Escalation / Defense Evasion (TA0004/TA0005)\n\n"
            "### Detection Hypothesis\n"
            "Process with anomalous executable path accesses another process with thread-related access rights. "
            "No EID 8 fires for APC (uses SetThreadContext, not CreateRemoteThread).\n\n"
            "### Data Availability\n"
            "**Partial** — EID 10 present but APC-specific access mask differentiation is limited without additional context.\n\n"
            "### Required Data Sources\n"
            "- Sysmon EID 10: `winlog.event_data.GrantedAccess` — partially available\n\n"
            "### Rule File\n"
            "`detections/privilege_escalation/t1055_004_apc_injection.yml`"
        ),
    },
    {
        "title": "[Gap] No detection for Windows Service Creation (T1543.003) — EID 7045 data gap",
        "labels": ["coverage-gap", "data-source-gap", "persistence"],
        "body": (
            "## Coverage Gap: T1543.003 — Windows Service Creation\n\n"
            "**Priority**: Rank 10 / Score 5/10  \n"
            "**Fawkes command**: `service -action create`  \n"
            "**Tactic**: Persistence / Privilege Escalation (TA0003/TA0004)\n\n"
            "### Primary Data Gap\n"
            "Windows System Event Log **EID 7045** (New Service Installed) is not currently collected by the simulator. "
            "This is the highest-fidelity signal for service creation. See `gaps/data-source-gaps.md`.\n\n"
            "### Workaround Detection (available now)\n"
            "```\n"
            'event.code: "1" AND process.name: "sc.exe" AND\n'
            "process.command_line: (*create* AND NOT process.command_line: *query*)\n"
            "```\n\n"
            "### Simulator Enhancement Needed\n"
            "Add Windows System Event Log EID 7045 collection to `simulator/simulator.py`.\n\n"
            "### Rule File\n"
            "`detections/persistence/t1543_003_windows_service_creation.yml`"
        ),
    },
]

print("\n[*] Creating issues...")
created = []
for issue in ISSUES:
    resp, status = api("POST", "/issues", {
        "title": issue["title"],
        "body": issue["body"],
        "labels": issue["labels"],
    })
    if status == 201:
        num = resp["number"]
        url = resp["html_url"]
        created.append((num, url, issue["title"]))
        print(f"  [+] #{num}: {issue['title'][:65]}...")
    else:
        print(f"  [!] FAILED ({status}): {resp.get('message', '')} — {issue['title'][:50]}")

print(f"\n[+] Created {len(created)}/10 issues")
print(f"[+] https://github.com/{REPO}/issues")
for num, url, title in created:
    print(f"    #{num}: {url}")
