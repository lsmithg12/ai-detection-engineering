#!/usr/bin/env bash
# =============================================================================
# Create GitHub Issues for all 10 coverage gaps
# Usage: ./pipeline/create-github-issues.sh [PAT]
# PAT is read from env var GITHUB_PAT or passed as $1
# =============================================================================

set -euo pipefail

PAT="${1:-${GITHUB_PAT:-}}"
REPO="${GITHUB_REPO:-}"
if [[ -z "$REPO" ]]; then
  echo "ERROR: Set GITHUB_REPO env var (e.g., 'myuser/ai-detection-engineering')."
  exit 1
fi
BASE="https://api.github.com/repos/$REPO"
AUTH_HEADER="Authorization: Bearer $PAT"

if [[ -z "$PAT" ]]; then
  echo "ERROR: GitHub PAT required. Pass as argument or set GITHUB_PAT env var."
  exit 1
fi

# ─── Test auth ─────────────────────────────────────────────────────────────────
echo "[*] Testing GitHub API access..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "$AUTH_HEADER" "$BASE")
if [[ "$STATUS" != "200" ]]; then
  echo "ERROR: API returned $STATUS. Check PAT permissions (needs Metadata+Issues+PRs) and repo access."
  exit 1
fi
echo "[+] Auth OK — repo accessible"

# ─── Create labels ─────────────────────────────────────────────────────────────
echo "[*] Creating labels..."
create_label() {
  local name="$1" color="$2" desc="$3"
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "$AUTH_HEADER" -H "Content-Type: application/json" \
    "$BASE/labels" \
    -d "{\"name\":\"$name\",\"color\":\"$color\",\"description\":\"$desc\"}")
  if [[ "$status" == "201" ]]; then
    echo "  [+] Created: $name"
  elif [[ "$status" == "422" ]]; then
    echo "  [=] Exists:  $name"
  else
    echo "  [!] Warning: $name returned $status"
  fi
}

create_label "coverage-gap"         "e11d48" "Missing detection for a technique"
create_label "detection"            "0ea5e9" "PR adds or modifies a detection rule"
create_label "data-source-gap"      "f97316" "Missing log source for detection"
create_label "high-priority"        "dc2626" "Critical technique — prioritized"
create_label "privilege-escalation" "7c3aed" "MITRE TA0004"
create_label "execution"            "16a34a" "MITRE TA0002"
create_label "persistence"          "ca8a04" "MITRE TA0003"
create_label "credential-access"    "db2777" "MITRE TA0006"
create_label "command-and-control"  "0891b2" "MITRE TA0011"
create_label "defense-evasion"      "4f46e5" "MITRE TA0005"
create_label "discovery"            "059669" "MITRE TA0007"

# ─── Create issues ─────────────────────────────────────────────────────────────
echo ""
echo "[*] Creating coverage gap issues..."

create_issue() {
  local title="$1" body="$2" labels="$3"
  local resp
  resp=$(curl -s -X POST \
    -H "$AUTH_HEADER" -H "Content-Type: application/json" \
    "$BASE/issues" \
    -d "{\"title\":\"$title\",\"body\":\"$body\",\"labels\":$labels}")
  local num
  num=$(echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('number', d.get('message','?')))" 2>/dev/null)
  echo "  [+] #$num: $title"
}

# Issue 1: T1055.001
create_issue \
  "[Gap] No detection for Process Injection: CreateRemoteThread (T1055.001)" \
  "## Coverage Gap: T1055.001 — CreateRemoteThread Process Injection\n\n**Priority**: Rank 1 / Score 10/10\n**Fawkes command**: \`vanilla-injection\`\n**Tactic**: Privilege Escalation / Defense Evasion (TA0004/TA0005)\n\n### Detection Hypothesis\nA process that is not a known debugger/security tool opens another process with full access rights (\`GrantedAccess: 0x1F3FFF\`) AND creates a remote thread.\n\n### Required Data Sources\n- Sysmon EID 8 (CreateRemoteThread): available in \`sim-attack\`\n- Sysmon EID 10 (Process Access): available in \`sim-attack\`\n\n### Key KQL Logic\n\`\`\`\nevent.code: \"8\" AND NOT winlog.event_data.SourceImage: (\"C:\\\\Windows\\\\System32\\\\*\")\n\`\`\`\n\n### Rule File\n\`detections/privilege_escalation/t1055_001_create_remote_thread.yml\`\n\n*Closes this issue when merged.*" \
  '["coverage-gap","high-priority","privilege-escalation"]'

# Issue 2: T1059.001
create_issue \
  "[Gap] No detection for PowerShell Execution with Bypass Flags (T1059.001)" \
  "## Coverage Gap: T1059.001 — Suspicious PowerShell Execution\n\n**Priority**: Rank 2 / Score 9/10\n**Fawkes command**: \`powershell\`\n**Tactic**: Execution (TA0002)\n\n### Detection Hypothesis\nPowerShell spawned with \`-EncodedCommand\`, \`-ExecutionPolicy Bypass\`, or \`-WindowStyle Hidden\`.\n\n### Required Data Sources\n- Sysmon EID 1: \`process.name: powershell.exe\`, \`process.command_line\` — available\n\n### Key KQL Logic\n\`\`\`\nevent.code: \"1\" AND process.name: \"powershell.exe\" AND process.command_line: (*EncodedCommand* OR *ExecutionPolicy Bypass* OR *IEX*)\n\`\`\`\n\n### Rule File\n\`detections/execution/t1059_001_suspicious_powershell.yml\`" \
  '["coverage-gap","high-priority","execution"]'

# Issue 3: T1547.001
create_issue \
  "[Gap] No detection for Registry Run Key Persistence (T1547.001)" \
  "## Coverage Gap: T1547.001 — Registry Run Key Persistence\n\n**Priority**: Rank 3 / Score 9/10\n**Fawkes command**: \`persist -method registry\`\n**Tactic**: Persistence (TA0003)\n\n### Detection Hypothesis\nRegistry value written to Run/RunOnce key where binary path is in temp directories.\n\n### Required Data Sources\n- Sysmon EID 13: \`registry.path\`, \`registry.value\` — available\n\n### Key KQL Logic\n\`\`\`\nevent.code: \"13\" AND registry.path: (*\\\\CurrentVersion\\\\Run*) AND registry.value: (*AppData\\\\Local\\\\Temp* OR *ProgramData*)\n\`\`\`\n\n### Rule File\n\`detections/persistence/t1547_001_registry_run_key.yml\`" \
  '["coverage-gap","high-priority","persistence"]'

# Issue 4: T1134.001
create_issue \
  "[Gap] No detection for LSASS Access for Token Theft (T1134.001)" \
  "## Coverage Gap: T1134.001 — Token Impersonation via LSASS Access\n\n**Priority**: Rank 4 / Score 9/10\n**Fawkes command**: \`steal-token\`\n**Tactic**: Credential Access / Privilege Escalation\n\n### Detection Hypothesis\nUnsigned process opens LSASS with \`GrantedAccess: 0x0040\` (PROCESS_DUP_HANDLE).\n\n### Required Data Sources\n- Sysmon EID 10: \`winlog.event_data.TargetImage\`, \`winlog.event_data.GrantedAccess\` — available\n\n### Key KQL Logic\n\`\`\`\nevent.code: \"10\" AND winlog.event_data.TargetImage: *lsass.exe AND winlog.event_data.GrantedAccess: (\"0x0040\" OR \"0x1F3FFF\")\n\`\`\`\n\n### Rule File\n\`detections/credential_access/t1134_001_lsass_access_token_theft.yml\`" \
  '["coverage-gap","high-priority","credential-access"]'

# Issue 5: T1071.001
create_issue \
  "[Gap] No detection for C2 HTTP Beaconing from Unusual Process (T1071.001)" \
  "## Coverage Gap: T1071.001 — C2 Beaconing via HTTP/HTTPS\n\n**Priority**: Rank 5 / Score 8/10\n**Fawkes command**: \`sleep\` / Mythic callback loop\n**Tactic**: Command and Control (TA0011)\n\n### Detection Hypothesis\nProcess with executable path in temp directory makes repeated outbound HTTPS connections.\n\n### Required Data Sources\n- Sysmon EID 3: \`process.executable\`, \`destination.ip\`, \`destination.port\` — available\n\n### Key KQL Logic\n\`\`\`\nevent.code: \"3\" AND network.direction: \"outbound\" AND destination.port: 443 AND process.executable: (*\\\\AppData\\\\Local\\\\Temp* OR *\\\\ProgramData*)\n\`\`\`\n\n### Rule File\n\`detections/command_and_control/t1071_001_c2_beaconing_unusual_process.yml\`" \
  '["coverage-gap","command-and-control"]'

# Issue 6: T1053.005
create_issue \
  "[Gap] No detection for Scheduled Task Persistence (T1053.005)" \
  "## Coverage Gap: T1053.005 — Scheduled Task Creation\n\n**Priority**: Rank 6 / Score 8/10\n**Fawkes command**: \`schtask -action create\`\n**Tactic**: Persistence / Execution\n\n### Detection Hypothesis\nschtasks.exe called with /Create where binary path is in temp dirs or trigger is ONLOGON/ONSTART.\n\n### Required Data Sources\n- Sysmon EID 1: \`process.name: schtasks.exe\`, \`process.command_line\` — available\n\n### Key KQL Logic\n\`\`\`\nevent.code: \"1\" AND process.name: \"schtasks.exe\" AND process.command_line: */Create* AND process.command_line: (*AppData\\\\Local\\\\Temp* OR *ONLOGON*)\n\`\`\`\n\n### Rule File\n\`detections/persistence/t1053_005_scheduled_task_persistence.yml\`" \
  '["coverage-gap","persistence"]'

# Issue 7: T1562.001
create_issue \
  "[Gap] No detection for AMSI Bypass via CLR Load in Unsigned Process (T1562.001)" \
  "## Coverage Gap: T1562.001 — AMSI/ETW Bypass\n\n**Priority**: Rank 7 / Score 7/10\n**Fawkes command**: \`start-clr\`, \`autopatch\`\n**Tactic**: Defense Evasion (TA0005)\n\n### Detection Hypothesis\namsi.dll or clr.dll loaded by a process whose executable is in a user temp directory.\n\n### Required Data Sources\n- Sysmon EID 7: \`file.name\`, \`process.executable\` — available\n\n### Key KQL Logic\n\`\`\`\nevent.code: \"7\" AND file.name: (\"amsi.dll\" OR \"clr.dll\") AND process.executable: (*\\\\AppData\\\\Local\\\\Temp* OR *\\\\ProgramData*)\n\`\`\`\n\n### Rule File\n\`detections/defense_evasion/t1562_001_amsi_bypass_clr_load.yml\`" \
  '["coverage-gap","defense-evasion"]'

# Issue 8: T1087.002
create_issue \
  "[Gap] No detection for Rapid Discovery Command Burst (T1087.002 / T1057 / T1033 / T1016)" \
  "## Coverage Gap: Discovery Command Burst\n\n**Priority**: Rank 8 / Score 7/10\n**Fawkes commands**: \`net-enum\`, \`ps\`, \`whoami\`, \`arp\`, \`ifconfig\`, \`net-stat\`\n**Tactic**: Discovery (TA0007)\n\n### Detection Hypothesis\n5+ discovery commands (whoami, net, tasklist, arp, ipconfig, netstat) spawned by same parent within 60 seconds.\n\n### Required Data Sources\n- Sysmon EID 1: \`process.name\`, \`process.parent.pid\` — available. Requires EQL sequence.\n\n### Rule Type\nEQL sequence rule (not KQL) — requires Elastic Security.\n\n### Rule File\n\`detections/discovery/t1087_002_discovery_command_burst.yml\`" \
  '["coverage-gap","discovery"]'

# Issue 9: T1055.004
create_issue \
  "[Gap] No detection for APC Injection (T1055.004)" \
  "## Coverage Gap: T1055.004 — APC Injection\n\n**Priority**: Rank 9 / Score 6/10\n**Fawkes command**: \`apc-injection\`\n**Tactic**: Privilege Escalation / Defense Evasion\n\n### Detection Hypothesis\nProcess accesses another with thread-related access rights (no EID 8 for APC; relies on EID 10 access mask).\n\n### Data Availability\nPartial — EID 10 present but APC-specific access mask differentiation is limited.\n\n### Required Data Sources\n- Sysmon EID 10: \`winlog.event_data.GrantedAccess\` — partially available\n\n### Rule File\n\`detections/privilege_escalation/t1055_004_apc_injection.yml\`" \
  '["coverage-gap","privilege-escalation"]'

# Issue 10: T1543.003
create_issue \
  "[Gap] No detection for Windows Service Creation (T1543.003) — data gap for EID 7045" \
  "## Coverage Gap: T1543.003 — Windows Service Creation\n\n**Priority**: Rank 10 / Score 5/10\n**Fawkes command**: \`service -action create\`\n**Tactic**: Persistence / Privilege Escalation\n\n### Data Gap\nWindows System Event Log EID 7045 (New Service Installed) not currently collected by simulator.\nWorkaround: detect via EID 1 watching for \`sc.exe create\`.\n\n### Required Data Sources (primary — missing)\n- Windows EID 7045 — NOT in simulation. See gaps/data-source-gaps.md.\n\n### Required Data Sources (workaround — available)\n- Sysmon EID 1: \`process.name: sc.exe\`, \`process.command_line: *create*\`\n\n### Rule File\n\`detections/persistence/t1543_003_windows_service_creation.yml\`" \
  '["coverage-gap","data-source-gap","persistence"]'

echo ""
echo "[+] Done. Check https://github.com/$REPO/issues"
