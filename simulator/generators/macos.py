"""
simulator/generators/macos.py — macOS platform event generator.

Generates ECS-formatted process/file events for macOS attack techniques
mapped to Fawkes C2 capabilities and MITRE ATT&CK.
"""
from __future__ import annotations

import random

from simulator.generators import (
    PlatformGenerator,
    _now_iso,
    _random_pid,
    _random_uid,
)

_MACOS_HOSTNAMES = ["MAC-DEV-01", "MAC-EXEC-01", "MAC-HR-01", "MAC-ENG-01"]
_MACOS_USERS = ["alice", "bob", "charlie", "admin"]


def _generate_macos_process_create(
    cmd: str,
    args: list,
    user: str,
    hostname: str,
    technique_id: str,
    executable: str = "",
) -> dict:
    if not executable:
        executable = f"/usr/bin/{cmd}"
    return {
        "@timestamp": _now_iso(),
        "event": {
            "category": "process",
            "type": "start",
            "kind": "event",
            "module": "endpoint",
            "dataset": "endpoint.events.process",
        },
        "agent": {"type": "elastic_endpoint"},
        "host": {
            "name": hostname,
            "os": {"family": "macos", "platform": "macosx", "version": "14.2.1"},
        },
        "process": {
            "name": cmd,
            "executable": executable,
            "args": args,
            "command_line": f"{cmd} {' '.join(str(a) for a in args)}",
            "pid": _random_pid(),
            "parent": {"name": "zsh", "pid": _random_pid()},
        },
        "user": {
            "name": user,
            "id": "0" if user == "root" else str(_random_uid()),
        },
        "_simulation": {
            "type": "attack",
            "technique": technique_id,
            "platform": "macos",
        },
    }


class MacOSGenerator(PlatformGenerator):
    """Generates macOS ECS events for attack simulation and baselines."""

    platform = "macos"
    event_types = ["process_create", "file_create", "auth"]

    def generate_attack(self, technique_id: str, **kwargs) -> list[dict]:
        hostname = kwargs.get("hostname", random.choice(_MACOS_HOSTNAMES))
        user = kwargs.get("user", random.choice(_MACOS_USERS))

        if technique_id == "T1543.004":
            return self._t1543_004(hostname, user)
        elif technique_id == "T1555.001":
            return self._t1555_001(hostname, user)
        else:
            return []

    def generate_benign(self, event_type: str = "process_create", count: int = 5) -> list[dict]:
        benign_cmds = [
            ("zsh", ["--login"], "/bin/zsh"),
            ("python3", ["/usr/local/bin/pip", "install", "requests"], "/usr/bin/python3"),
            ("brew", ["update"], "/usr/local/bin/brew"),
            ("git", ["pull", "origin", "main"], "/usr/bin/git"),
            ("curl", ["-s", "https://api.github.com"], "/usr/bin/curl"),
            ("launchctl", ["list"], "/bin/launchctl"),
            ("security", ["list-keychains"], "/usr/bin/security"),
            ("defaults", ["read", "com.apple.finder"], "/usr/bin/defaults"),
        ]
        events = []
        for _ in range(count):
            cmd, args, exe = random.choice(benign_cmds)
            hostname = random.choice(_MACOS_HOSTNAMES)
            user = random.choice(_MACOS_USERS)
            ev = _generate_macos_process_create(cmd, args, user, hostname, "baseline", exe)
            ev["_simulation"] = {
                "type": "baseline",
                "platform": "macos",
                "expected_match": False,
            }
            events.append(ev)
        return events

    # ── Technique implementations ──────────────────────────────────────

    def _t1543_004(self, hostname: str, user: str) -> list[dict]:
        """T1543.004 — Create or Modify System Process: Launch Agent."""
        plist_path = f"/Users/{user}/Library/LaunchAgents/com.apple.systemevent.plist"
        # plutil modifying the plist
        proc_ev = _generate_macos_process_create(
            cmd="plutil",
            args=["-convert", "xml1", plist_path],
            user=user,
            hostname=hostname,
            technique_id="T1543.004",
            executable="/usr/bin/plutil",
        )
        proc_ev["_simulation"]["expected_match"] = True
        proc_ev["_simulation"]["description"] = (
            "plutil modifying LaunchAgent plist — persistence via macOS LaunchAgent"
        )

        # File write event for the plist creation
        file_ev = {
            "@timestamp": _now_iso(),
            "event": {
                "category": "file",
                "type": "creation",
                "kind": "event",
                "module": "endpoint",
                "dataset": "endpoint.events.file",
                "action": "creation",
            },
            "agent": {"type": "elastic_endpoint"},
            "host": {
                "name": hostname,
                "os": {"family": "macos", "platform": "macosx", "version": "14.2.1"},
            },
            "file": {
                "path": plist_path,
                "name": "com.apple.systemevent.plist",
                "directory": f"/Users/{user}/Library/LaunchAgents",
                "extension": "plist",
            },
            "process": {
                "name": "plutil",
                "executable": "/usr/bin/plutil",
                "pid": _random_pid(),
            },
            "user": {"name": user, "id": str(_random_uid())},
            "_simulation": {
                "type": "attack",
                "technique": "T1543.004",
                "platform": "macos",
                "expected_match": True,
                "description": (
                    "LaunchAgent plist created at user's LaunchAgents directory — "
                    "runs payload on user login"
                ),
            },
        }
        return [proc_ev, file_ev]

    def _t1555_001(self, hostname: str, user: str) -> list[dict]:
        """T1555.001 — Credentials from Password Stores: Keychain."""
        ev = _generate_macos_process_create(
            cmd="security",
            args=["dump-keychain", "-d", "/Users/" + user + "/Library/Keychains/login.keychain-db"],
            user=user,
            hostname=hostname,
            technique_id="T1555.001",
            executable="/usr/bin/security",
        )
        ev["_simulation"]["expected_match"] = True
        ev["_simulation"]["description"] = (
            "security dump-keychain -d — dumps macOS keychain credentials in plaintext"
        )
        return [ev]
