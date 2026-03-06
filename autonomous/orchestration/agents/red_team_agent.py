"""
Red Team / Scenario Agent — Generates synthetic attack and benign
log scenarios for detection validation.

Takes detection requests in REQUESTED state and generates:
  - attack_sequence: ECS-compatible events that SHOULD trigger the detection
  - benign_similar: Similar-looking events that should NOT trigger

Output: JSON scenario files in simulator/scenarios/<technique_id>.json

Called by agent_runner.py. Implements run(state_manager) interface.
"""

import datetime
import json
import random
from pathlib import Path
from uuid import uuid4

from orchestration.state import StateManager
from orchestration import learnings

AUTONOMOUS_DIR = Path(__file__).resolve().parent.parent.parent
REPO_ROOT = AUTONOMOUS_DIR.parent
SCENARIOS_DIR = REPO_ROOT / "simulator" / "scenarios"
FAWKES_TTP_PATH = REPO_ROOT / "threat-intel" / "fawkes" / "fawkes-ttp-mapping.md"

AGENT_NAME = "red-team"
MAX_SCENARIOS = 5


def _random_pid() -> int:
    return random.randint(100, 65000)


# ─── Simulated Environment (matches simulator.py) ──────────────────
HOSTNAMES = [
    "WS-FINANCE-01", "WS-FINANCE-02", "WS-HR-01", "WS-DEV-01",
    "WS-DEV-02", "WS-EXEC-01", "SRV-DC-01", "SRV-FILE-01",
]

USERS = [
    ("jsmith", "CORP"), ("mjones", "CORP"), ("agarcia", "CORP"),
    ("bwilson", "CORP"), ("clee", "CORP"), ("dkim", "CORP"),
]

MALICIOUS_PROCS = [
    "update_helper.exe", "sync_agent.exe", "svc_updater.exe",
    "runtime_host.exe", "task_scheduler.exe",
]

TEMP_PATHS = [
    "C:\\Users\\{user}\\AppData\\Local\\Temp",
    "C:\\ProgramData\\WindowsUpdate",
    "C:\\Users\\{user}\\AppData\\Roaming\\Microsoft",
]


# ─── Scenario Generators ───────────────────────────────────────────
# Each generator returns (attack_events, benign_events, metadata)

def scenario_t1055_001():
    """T1055.001 — CreateRemoteThread Process Injection (Fawkes: vanilla-injection)"""
    host = random.choice(HOSTNAMES)
    user, domain = random.choice(USERS)
    src_proc = random.choice(MALICIOUS_PROCS)
    target_proc = random.choice(["explorer.exe", "svchost.exe", "RuntimeBroker.exe"])
    temp = random.choice(TEMP_PATHS).format(user=user)

    attack_events = [
        {
            "@timestamp": "{{now}}",
            "event": {"category": "process", "type": "access", "action": "Process accessed (rule: ProcessAccess)", "code": "10"},
            "process": {"name": src_proc, "executable": f"{temp}\\{src_proc}", "pid": _random_pid()},
            "winlog": {"event_data": {
                "TargetImage": f"C:\\Windows\\System32\\{target_proc}",
                "GrantedAccess": "0x1F3FFF",
                "SourceProcessGUID": str(uuid4()),
            }},
            "user": {"name": user, "domain": domain},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {
                "type": "attack", "technique": "T1055.001",
                "sequence_order": 1, "sequence_total": 2,
                "description": "Source process opens target with PROCESS_ALL_ACCESS"
            },
        },
        {
            "@timestamp": "{{now}}",
            "event": {"category": "process", "type": "change", "action": "CreateRemoteThread detected (rule: CreateRemoteThread)", "code": "8"},
            "process": {"name": src_proc, "executable": f"{temp}\\{src_proc}", "pid": _random_pid()},
            "winlog": {"event_data": {
                "TargetImage": f"C:\\Windows\\System32\\{target_proc}",
                "StartAddress": hex(random.randint(0x7FF600000000, 0x7FF6FFFFFFFF)),
                "StartModule": "",
                "StartFunction": "",
            }},
            "user": {"name": user, "domain": domain},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {
                "type": "attack", "technique": "T1055.001",
                "sequence_order": 2, "sequence_total": 2,
                "description": "CreateRemoteThread into target process"
            },
        },
    ]

    benign_events = [
        {
            "@timestamp": "{{now}}",
            "event": {"category": "process", "type": "access", "action": "Process accessed (rule: ProcessAccess)", "code": "10"},
            "process": {"name": "MsMpEng.exe", "executable": "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe", "pid": _random_pid()},
            "winlog": {"event_data": {
                "TargetImage": "C:\\Windows\\System32\\svchost.exe",
                "GrantedAccess": "0x1410",
            }},
            "user": {"name": "SYSTEM", "domain": "NT AUTHORITY"},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {"type": "benign_similar", "technique": "T1055.001",
                            "description": "Windows Defender scanning — legitimate process access"},
        },
        {
            "@timestamp": "{{now}}",
            "event": {"category": "process", "type": "change", "action": "CreateRemoteThread detected (rule: CreateRemoteThread)", "code": "8"},
            "process": {"name": "csrss.exe", "executable": "C:\\Windows\\System32\\csrss.exe", "pid": _random_pid()},
            "winlog": {"event_data": {
                "TargetImage": "C:\\Windows\\System32\\svchost.exe",
                "StartAddress": hex(random.randint(0x7FF600000000, 0x7FF6FFFFFFFF)),
                "StartModule": "C:\\Windows\\System32\\ntdll.dll",
                "StartFunction": "RtlUserThreadStart",
            }},
            "user": {"name": "SYSTEM", "domain": "NT AUTHORITY"},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {"type": "benign_similar", "technique": "T1055.001",
                            "description": "csrss.exe creating thread in svchost — normal OS behavior"},
        },
    ]

    return attack_events, benign_events, {
        "key_fields": ["process.name", "process.executable", "event.code", "winlog.event_data.TargetImage", "winlog.event_data.GrantedAccess"],
        "notes": "Detection should flag CreateRemoteThread from non-system processes in temp/user paths into system processes. Exclude known AV and OS internals.",
        "log_sources_used": ["sysmon_8", "sysmon_10"],
        "platforms": ["windows"],
    }


def scenario_t1053_005():
    """T1053.005 — Scheduled Task Creation (Fawkes: schtask)"""
    host = random.choice(HOSTNAMES)
    user, domain = random.choice(USERS)
    mal_exe = f"C:\\Users\\{user}\\AppData\\Local\\Temp\\update.exe"

    attack_events = [
        {
            "@timestamp": "{{now}}",
            "event": {"category": "process", "type": "start", "action": "Process Create (rule: ProcessCreate)", "code": "1"},
            "process": {
                "pid": _random_pid(), "name": "schtasks.exe",
                "executable": "C:\\Windows\\System32\\schtasks.exe",
                "command_line": f'schtasks.exe /Create /TN "\\Microsoft\\Windows\\Maintenance\\SystemUpdate" /TR "{mal_exe}" /SC ONLOGON /RL HIGHEST',
                "parent": {"pid": _random_pid(), "name": "cmd.exe", "executable": "C:\\Windows\\System32\\cmd.exe"},
            },
            "user": {"name": user, "domain": domain},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {
                "type": "attack", "technique": "T1053.005",
                "sequence_order": 1, "sequence_total": 1,
                "description": "Scheduled task created for persistence with HIGHEST privileges"
            },
        },
    ]

    benign_events = [
        {
            "@timestamp": "{{now}}",
            "event": {"category": "process", "type": "start", "action": "Process Create (rule: ProcessCreate)", "code": "1"},
            "process": {
                "pid": _random_pid(), "name": "schtasks.exe",
                "executable": "C:\\Windows\\System32\\schtasks.exe",
                "command_line": 'schtasks.exe /Create /TN "\\Microsoft\\Windows\\Defrag\\ScheduledDefrag" /TR "C:\\Windows\\System32\\defrag.exe -c" /SC WEEKLY /D SUN',
                "parent": {"pid": _random_pid(), "name": "mmc.exe", "executable": "C:\\Windows\\System32\\mmc.exe"},
            },
            "user": {"name": "SYSTEM", "domain": "NT AUTHORITY"},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {"type": "benign_similar", "technique": "T1053.005",
                            "description": "Windows defrag scheduled task — legitimate system maintenance"},
        },
        {
            "@timestamp": "{{now}}",
            "event": {"category": "process", "type": "start", "action": "Process Create (rule: ProcessCreate)", "code": "1"},
            "process": {
                "pid": _random_pid(), "name": "schtasks.exe",
                "executable": "C:\\Windows\\System32\\schtasks.exe",
                "command_line": 'schtasks.exe /Create /TN "GoogleUpdateTaskMachineUA" /TR "C:\\Program Files\\Google\\Update\\GoogleUpdate.exe /ua /installsource scheduler" /SC HOURLY',
                "parent": {"pid": _random_pid(), "name": "GoogleUpdate.exe", "executable": "C:\\Program Files\\Google\\Update\\GoogleUpdate.exe"},
            },
            "user": {"name": "SYSTEM", "domain": "NT AUTHORITY"},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {"type": "benign_similar", "technique": "T1053.005",
                            "description": "Google Chrome update scheduled task — legitimate software update"},
        },
    ]

    return attack_events, benign_events, {
        "key_fields": ["process.name", "process.command_line", "process.parent.name", "user.name"],
        "notes": "Detection should flag schtasks /Create with executables in user-writable paths (AppData, Temp, ProgramData). Exclude known system/vendor tasks.",
        "log_sources_used": ["sysmon_1"],
        "platforms": ["windows"],
    }


def scenario_t1070_001():
    """T1070.001 — Clear Windows Event Logs"""
    host = random.choice(HOSTNAMES)
    user, domain = random.choice(USERS)

    attack_events = [
        {
            "@timestamp": "{{now}}",
            "event": {"category": "process", "type": "start", "action": "Process Create (rule: ProcessCreate)", "code": "1"},
            "process": {
                "pid": _random_pid(), "name": "wevtutil.exe",
                "executable": "C:\\Windows\\System32\\wevtutil.exe",
                "command_line": "wevtutil.exe cl Security",
                "parent": {"pid": _random_pid(), "name": "cmd.exe", "executable": "C:\\Windows\\System32\\cmd.exe"},
            },
            "user": {"name": user, "domain": domain},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {
                "type": "attack", "technique": "T1070.001",
                "sequence_order": 1, "sequence_total": 2,
                "description": "Clear Security event log via wevtutil"
            },
        },
        {
            "@timestamp": "{{now}}",
            "event": {"category": "process", "type": "start", "action": "Process Create (rule: ProcessCreate)", "code": "1"},
            "process": {
                "pid": _random_pid(), "name": "powershell.exe",
                "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": 'powershell.exe -Command "Clear-EventLog -LogName Security"',
                "parent": {"pid": _random_pid(), "name": "cmd.exe", "executable": "C:\\Windows\\System32\\cmd.exe"},
            },
            "user": {"name": user, "domain": domain},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {
                "type": "attack", "technique": "T1070.001",
                "sequence_order": 2, "sequence_total": 2,
                "description": "Clear Security event log via PowerShell Clear-EventLog"
            },
        },
    ]

    benign_events = [
        {
            "@timestamp": "{{now}}",
            "event": {"category": "process", "type": "start", "action": "Process Create (rule: ProcessCreate)", "code": "1"},
            "process": {
                "pid": _random_pid(), "name": "wevtutil.exe",
                "executable": "C:\\Windows\\System32\\wevtutil.exe",
                "command_line": "wevtutil.exe qe Application /c:10 /rd:true /f:text",
                "parent": {"pid": _random_pid(), "name": "powershell.exe", "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
            },
            "user": {"name": "admin", "domain": "CORP"},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {"type": "benign_similar", "technique": "T1070.001",
                            "description": "wevtutil querying events — legitimate admin activity, not clearing"},
        },
    ]

    return attack_events, benign_events, {
        "key_fields": ["process.name", "process.command_line"],
        "notes": "Detection should flag wevtutil cl and Clear-EventLog targeting Security/System logs. Exclude wevtutil qe (query, not clear).",
        "log_sources_used": ["sysmon_1"],
        "platforms": ["windows"],
    }


def scenario_t1219():
    """T1219 — Remote Access Software (Scattered Spider: RMM tools)"""
    host = random.choice(HOSTNAMES)
    user, domain = random.choice(USERS)

    rmm_tools = [
        ("AnyDesk.exe", "C:\\Users\\{user}\\Downloads\\AnyDesk.exe"),
        ("splashtop.exe", "C:\\Users\\{user}\\AppData\\Local\\Temp\\splashtop.exe"),
        ("TeamViewer.exe", "C:\\Users\\{user}\\Downloads\\TeamViewer_Setup.exe"),
    ]

    attack_events = []
    for proc_name, proc_path in rmm_tools[:2]:
        attack_events.append({
            "@timestamp": "{{now}}",
            "event": {"category": "process", "type": "start", "action": "Process Create (rule: ProcessCreate)", "code": "1"},
            "process": {
                "pid": _random_pid(), "name": proc_name,
                "executable": proc_path.format(user=user),
                "command_line": proc_path.format(user=user),
                "parent": {"pid": _random_pid(), "name": "explorer.exe", "executable": "C:\\Windows\\explorer.exe"},
            },
            "user": {"name": user, "domain": domain},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {
                "type": "attack", "technique": "T1219",
                "sequence_order": rmm_tools.index((proc_name, proc_path)) + 1,
                "sequence_total": 2,
                "description": f"Unauthorized RMM tool {proc_name} launched from user directory"
            },
        })

    benign_events = [
        {
            "@timestamp": "{{now}}",
            "event": {"category": "process", "type": "start", "action": "Process Create (rule: ProcessCreate)", "code": "1"},
            "process": {
                "pid": _random_pid(), "name": "TeamViewer.exe",
                "executable": "C:\\Program Files\\TeamViewer\\TeamViewer.exe",
                "command_line": "C:\\Program Files\\TeamViewer\\TeamViewer.exe",
                "parent": {"pid": _random_pid(), "name": "services.exe", "executable": "C:\\Windows\\System32\\services.exe"},
            },
            "user": {"name": "SYSTEM", "domain": "NT AUTHORITY"},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {"type": "benign_similar", "technique": "T1219",
                            "description": "TeamViewer installed in Program Files, running as service — legitimate IT support tool"},
        },
    ]

    return attack_events, benign_events, {
        "key_fields": ["process.name", "process.executable", "process.parent.name"],
        "notes": "Detection should flag RMM tools (AnyDesk, Splashtop, TeamViewer, ScreenConnect) running from non-standard paths (Downloads, Temp, AppData). Exclude approved installations in Program Files.",
        "log_sources_used": ["sysmon_1"],
        "platforms": ["windows"],
    }


def scenario_t1566_004():
    """T1566.004 — Spearphishing Voice (Vishing) — identity-based, no endpoint telemetry"""
    # This technique leaves no Sysmon artifacts — it's social engineering.
    # We generate the downstream artifacts: MFA reset followed by login from new device.
    host = random.choice(HOSTNAMES)
    user, domain = random.choice(USERS)

    attack_events = [
        {
            "@timestamp": "{{now}}",
            "event": {"category": "authentication", "type": "start", "action": "logged-in", "code": "4624", "outcome": "success"},
            "winlog": {"logon": {"type": "RemoteInteractive", "id": hex(random.randint(0x10000, 0xFFFFF))}},
            "source": {"ip": "203.0.113.42"},
            "user": {"name": user, "domain": domain},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "winlogbeat"},
            "_simulation": {
                "type": "attack", "technique": "T1566.004",
                "sequence_order": 1, "sequence_total": 1,
                "description": "Remote login from external IP immediately after MFA reset (vishing follow-up)"
            },
        },
    ]

    benign_events = [
        {
            "@timestamp": "{{now}}",
            "event": {"category": "authentication", "type": "start", "action": "logged-in", "code": "4624", "outcome": "success"},
            "winlog": {"logon": {"type": "Interactive", "id": hex(random.randint(0x10000, 0xFFFFF))}},
            "source": {"ip": "10.10.1.50"},
            "user": {"name": user, "domain": domain},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "winlogbeat"},
            "_simulation": {"type": "benign_similar", "technique": "T1566.004",
                            "description": "Normal interactive logon from internal IP"},
        },
    ]

    return attack_events, benign_events, {
        "key_fields": ["source.ip", "winlog.logon.type", "event.code"],
        "notes": "Limited endpoint telemetry for vishing. Detection relies on correlation: MFA reset + immediate external login. Sysmon alone insufficient — needs identity provider logs.",
        "log_sources_used": ["windows_security_4624"],
        "platforms": ["windows"],
    }


def scenario_t1078_004():
    """T1078.004 — Cloud Account Abuse — minimal endpoint artifacts"""
    host = random.choice(HOSTNAMES)
    user, domain = random.choice(USERS)

    attack_events = [
        {
            "@timestamp": "{{now}}",
            "event": {"category": "authentication", "type": "start", "action": "logged-in", "code": "4624", "outcome": "success"},
            "winlog": {"logon": {"type": "NewCredentials", "id": hex(random.randint(0x10000, 0xFFFFF))}},
            "source": {"ip": "198.51.100.23"},
            "user": {"name": user, "domain": domain},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "winlogbeat"},
            "_simulation": {
                "type": "attack", "technique": "T1078.004",
                "sequence_order": 1, "sequence_total": 1,
                "description": "NewCredentials logon from external IP — possible cloud credential abuse"
            },
        },
    ]

    benign_events = [
        {
            "@timestamp": "{{now}}",
            "event": {"category": "authentication", "type": "start", "action": "logged-in", "code": "4624", "outcome": "success"},
            "winlog": {"logon": {"type": "NewCredentials", "id": hex(random.randint(0x10000, 0xFFFFF))}},
            "source": {"ip": "10.10.2.100"},
            "user": {"name": "svc_backup", "domain": "CORP"},
            "host": {"name": "SRV-FILE-01", "os": {"platform": "windows"}},
            "agent": {"type": "winlogbeat"},
            "_simulation": {"type": "benign_similar", "technique": "T1078.004",
                            "description": "Service account NewCredentials logon from internal IP — normal backup operation"},
        },
    ]

    return attack_events, benign_events, {
        "key_fields": ["source.ip", "winlog.logon.type", "user.name"],
        "notes": "Cloud account abuse is best detected via cloud provider logs (Azure AD, AWS CloudTrail). Endpoint telemetry limited to logon events. Correlate with impossible travel / new device signals.",
        "log_sources_used": ["windows_security_4624"],
        "platforms": ["windows"],
    }


# ─── Scenario Registry ─────────────────────────────────────────────
SCENARIO_GENERATORS = {
    "T1055.001": scenario_t1055_001,
    "T1053.005": scenario_t1053_005,
    "T1070.001": scenario_t1070_001,
    "T1219": scenario_t1219,
    "T1566.004": scenario_t1566_004,
    "T1078.004": scenario_t1078_004,
}


def build_scenario(technique_id: str, request: dict) -> dict | None:
    """
    Generate a scenario JSON file for the given technique.
    Returns the scenario dict or None if no generator exists.
    """
    generator = SCENARIO_GENERATORS.get(technique_id)
    if not generator:
        print(f"    [red-team] No scenario generator for {technique_id}")
        return None

    attack_events, benign_events, metadata = generator()

    scenario = {
        "technique_id": technique_id,
        "technique_name": request.get("title", ""),
        "description": f"Simulates {request.get('title', technique_id)} attack sequence",
        "mitre_tactic": request.get("mitre_tactic", "unknown"),
        "events": {
            "attack_sequence": attack_events,
            "benign_similar": benign_events,
        },
        "expected_detection": {
            "should_alert_on": "attack_sequence",
            "should_not_alert_on": "benign_similar",
            "key_fields": metadata.get("key_fields", []),
            "notes": metadata.get("notes", ""),
        },
        "log_sources_used": metadata.get("log_sources_used", []),
        "platforms": metadata.get("platforms", ["windows"]),
    }

    return scenario


def save_scenario(scenario: dict) -> Path:
    """Write scenario JSON to simulator/scenarios/."""
    SCENARIOS_DIR.mkdir(parents=True, exist_ok=True)
    tid = scenario["technique_id"].lower().replace(".", "_")
    path = SCENARIOS_DIR / f"{tid}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(scenario, f, indent=2, ensure_ascii=False)
    return path


def run(state_manager: StateManager) -> dict:
    """
    Main entry point for the red team agent.

    1. Load learnings briefing
    2. Query state machine for REQUESTED detections
    3. Generate scenarios for up to MAX_SCENARIOS techniques
    4. Save scenario files
    5. Transition requests to SCENARIO_BUILT
    """
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    print(f"  [red-team] Starting red team agent run {run_id}")

    # 1. Load briefing
    briefing = learnings.get_briefing(AGENT_NAME)
    print(f"  [red-team] {briefing}")

    schema_lessons = learnings.get_relevant_lessons(AGENT_NAME, "schema")
    if schema_lessons:
        print(f"  [red-team] {len(schema_lessons)} schema lessons loaded")

    # 2. Get REQUESTED detections
    requested = state_manager.query_by_state("REQUESTED")
    if not requested:
        print("  [red-team] No REQUESTED detections. Nothing to do.")
        return {"summary": "No REQUESTED detections", "scenarios_built": 0}

    # Sort by priority: critical > high > medium > low
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    requested.sort(key=lambda r: priority_order.get(r.get("priority", "medium"), 2))

    print(f"  [red-team] Found {len(requested)} REQUESTED detections, "
          f"processing up to {MAX_SCENARIOS}")

    # 3. Generate scenarios
    scenarios_built = []
    scenarios_skipped = []
    total_attack = 0
    total_benign = 0

    for request in requested[:MAX_SCENARIOS]:
        tid = request["technique_id"]
        print(f"\n  [red-team] Generating scenario for {tid} — {request.get('title', '')}")

        scenario = build_scenario(tid, request)
        if not scenario:
            scenarios_skipped.append(tid)
            learnings.record(
                AGENT_NAME, run_id, "improvement", "general",
                f"No generator for {tid}",
                f"Need to implement scenario generator for {request.get('title', tid)}",
                technique_id=tid,
            )
            continue

        # Save scenario file
        path = save_scenario(scenario)
        n_attack = len(scenario["events"]["attack_sequence"])
        n_benign = len(scenario["events"]["benign_similar"])
        total_attack += n_attack
        total_benign += n_benign

        print(f"    [red-team] Saved: {path.name} "
              f"({n_attack} attack, {n_benign} benign events)")

        # Update detection request with scenario path
        rel_path = str(path.relative_to(REPO_ROOT))
        state_manager.update(
            tid, agent=AGENT_NAME,
            scenario_file=rel_path,
        )

        # Transition REQUESTED → SCENARIO_BUILT
        try:
            state_manager.transition(
                tid, "SCENARIO_BUILT", agent=AGENT_NAME,
                details=f"Scenario generated: {n_attack} attack, {n_benign} benign events",
            )
            scenarios_built.append(tid)
            print(f"    [red-team] Transitioned {tid} -> SCENARIO_BUILT")
        except ValueError as e:
            print(f"    [red-team] Transition failed for {tid}: {e}")

    # 4. Summary
    summary = (
        f"Built {len(scenarios_built)} scenarios "
        f"({total_attack} attack, {total_benign} benign events), "
        f"skipped {len(scenarios_skipped)}"
    )
    print(f"\n  [red-team] {summary}")

    return {
        "summary": summary,
        "scenarios_built": len(scenarios_built),
        "scenarios_list": scenarios_built,
        "scenarios_skipped": scenarios_skipped,
        "total_attack_events": total_attack,
        "total_benign_events": total_benign,
    }
