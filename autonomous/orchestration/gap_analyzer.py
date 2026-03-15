#!/usr/bin/env python3
"""
Gap Analysis Engine — Phase 5, Task 5.6

Cross-references Fawkes C2 technique coverage against:
  1. Existing Sigma rules in detections/
  2. Data source availability from gaps/data-sources/*.yml

Classifies each technique as:
  READY   — detection can be authored now (all data sources available)
  PARTIAL — some required sources are available; limited detection is possible
  BLOCKED — critical data sources are missing; onboard first

Usage:
    from orchestration.gap_analyzer import GapAnalyzer
    analyzer = GapAnalyzer(repo_root)
    gaps = analyzer.analyze_data_gaps()
"""

from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None


# ---------------------------------------------------------------------------
# Fawkes technique catalogue
# ---------------------------------------------------------------------------

FAWKES_TECHNIQUES: dict = {
    "T1055.001": {
        "name": "Process Injection: CreateRemoteThread",
        "fawkes_command": "vanilla-injection",
        "platform": "windows",
    },
    "T1055.004": {
        "name": "Process Injection: APC Injection",
        "fawkes_command": "apc-injection",
        "platform": "windows",
    },
    "T1055.012": {
        "name": "Process Hollowing",
        "fawkes_command": "poolparty-injection",
        "platform": "windows",
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "fawkes_command": "schtask",
        "platform": "windows",
    },
    "T1053.003": {
        "name": "Cron Job",
        "fawkes_command": "crontab",
        "platform": "linux",
    },
    "T1059.001": {
        "name": "PowerShell",
        "fawkes_command": "powershell",
        "platform": "windows",
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "fawkes_command": "run",
        "platform": "windows",
    },
    "T1059.004": {
        "name": "Unix Shell",
        "fawkes_command": "run",
        "platform": "linux",
    },
    "T1056.001": {
        "name": "Keylogging",
        "fawkes_command": "keylog",
        "platform": "windows",
    },
    "T1070.001": {
        "name": "Event Log Clearing",
        "fawkes_command": "wevtutil",
        "platform": "windows",
    },
    "T1071.001": {
        "name": "C2 Application Layer Protocol",
        "fawkes_command": "http-c2",
        "platform": "all",
    },
    "T1078.004": {
        "name": "Cloud Accounts",
        "fawkes_command": "cloud-creds",
        "platform": "cloud",
    },
    "T1082": {
        "name": "System Information Discovery",
        "fawkes_command": "whoami/env",
        "platform": "windows",
    },
    "T1098": {
        "name": "Account Manipulation (SSH Keys)",
        "fawkes_command": "ssh-keys",
        "platform": "linux",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "fawkes_command": "download",
        "platform": "all",
    },
    "T1115": {
        "name": "Clipboard Data",
        "fawkes_command": "clipboard",
        "platform": "windows",
    },
    "T1134.001": {
        "name": "Token Impersonation",
        "fawkes_command": "steal-token",
        "platform": "windows",
    },
    "T1136.001": {
        "name": "Create Local Account",
        "fawkes_command": "useradd",
        "platform": "linux",
    },
    "T1543.003": {
        "name": "Windows Service",
        "fawkes_command": "service",
        "platform": "windows",
    },
    "T1543.004": {
        "name": "Launch Agent",
        "fawkes_command": "launchagent",
        "platform": "macos",
    },
    "T1547.001": {
        "name": "Registry Run Keys",
        "fawkes_command": "persist",
        "platform": "windows",
    },
}


# ---------------------------------------------------------------------------
# Technique -> required data sources
# ---------------------------------------------------------------------------

TECHNIQUE_DATA_SOURCES: dict = {
    "T1055.001": ["sysmon_eid_8", "sysmon_eid_10"],
    "T1055.004": ["sysmon_eid_8", "sysmon_eid_10"],
    "T1055.012": ["sysmon_eid_8"],
    "T1053.005": ["sysmon_eid_1"],
    "T1053.003": ["linux_auditd"],
    "T1059.001": ["sysmon_eid_1"],
    "T1059.003": ["sysmon_eid_1"],
    "T1059.004": ["linux_auditd"],
    "T1056.001": ["etw_telemetry"],
    "T1070.001": ["sysmon_eid_1"],
    "T1071.001": ["sysmon_eid_3", "zeek_conn"],
    "T1078.004": ["aws_cloudtrail"],
    "T1082":     ["sysmon_eid_1"],
    "T1098":     ["linux_auditd"],
    "T1105":     ["sysmon_eid_1", "sysmon_eid_11"],
    "T1115":     ["etw_telemetry"],
    "T1134.001": ["sysmon_eid_10"],
    "T1136.001": ["linux_auditd"],
    "T1543.003": ["sysmon_eid_1"],
    "T1543.004": ["linux_auditd"],   # macOS unified log — treat as linux_auditd for now
    "T1547.001": ["sysmon_eid_13"],
}


# ---------------------------------------------------------------------------
# Known-available sources
# (sources present in source_expectations.yml are considered "available"
#  unless overridden by a gap file with status == "gap")
# ---------------------------------------------------------------------------

SOURCES_IN_EXPECTATIONS = {
    "sysmon_eid_1",
    "sysmon_eid_3",
    "sysmon_eid_8",
    "sysmon_eid_10",
    "sysmon_eid_11",
    "sysmon_eid_13",
    "windows_security_4624",
    "linux_auditd",
    "aws_cloudtrail",
    "zeek_conn",
}


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class GapAnalyzer:
    """
    Analyzes detection coverage gaps for Fawkes C2 techniques.

    Parameters
    ----------
    repo_root : Path to the repository root (contains detections/ and gaps/)
    """

    def __init__(self, repo_root: Path):
        self.repo_root = Path(repo_root)
        self.detections_dir = self.repo_root / "detections"
        self.gaps_dir       = self.repo_root / "gaps" / "data-sources"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_data_gaps(self) -> list:
        """
        For each Fawkes technique:
          1. Skip if detection already exists (has_detection → True)
          2. Check each required source against gap files / expectations
          3. Classify actionability: READY | PARTIAL | BLOCKED

        Returns
        -------
        List of gap dicts sorted by actionability (READY first) then technique ID.
        """
        results = []

        for technique_id, meta in FAWKES_TECHNIQUES.items():
            if self._has_detection(technique_id):
                continue  # already covered — skip

            required_sources = TECHNIQUE_DATA_SOURCES.get(technique_id, [])
            source_statuses  = []

            for source_id in required_sources:
                gap_file = self._find_gap_file(source_id)
                if gap_file:
                    # Gap file says something explicit about this source
                    gap_status = gap_file.get("status", "gap")
                    if gap_status == "gap":
                        status = "MISSING"
                    elif gap_status == "partially_available":
                        status = "PARTIAL"
                    else:  # onboarded
                        status = "AVAILABLE"
                else:
                    # No gap file — check if it's in the expectations config
                    if source_id in SOURCES_IN_EXPECTATIONS:
                        status = "AVAILABLE"
                    else:
                        status = "MISSING"

                source_statuses.append({"source": source_id, "status": status})

            actionability = self._classify_actionability(source_statuses)
            recommendation = self._generate_recommendation(technique_id, source_statuses)

            results.append({
                "technique_id":    technique_id,
                "technique_name":  meta["name"],
                "fawkes_command":  meta["fawkes_command"],
                "platform":        meta["platform"],
                "required_sources": source_statuses,
                "actionability":   actionability,
                "recommendation":  recommendation,
            })

        # Sort: READY → PARTIAL → BLOCKED, then by technique ID
        order = {"READY": 0, "PARTIAL": 1, "BLOCKED": 2}
        results.sort(key=lambda r: (order.get(r["actionability"], 9), r["technique_id"]))

        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _has_detection(self, technique_id: str) -> bool:
        """
        Return True if any Sigma rule exists for technique_id.

        Checks:
          1. Filename contains the technique id (case-insensitive, dots/hyphens flexible)
          2. Rule content contains the technique id in the tags section
        """
        if not self.detections_dir.exists():
            return False

        tid_variants = [
            technique_id.lower(),
            technique_id.lower().replace(".", "-"),
            technique_id.lower().replace(".", "_"),
        ]

        for rule_file in self.detections_dir.rglob("*.yml"):
            if "compiled" in rule_file.parts:
                continue

            # Quick filename check
            fname = rule_file.stem.lower()
            for variant in tid_variants:
                if variant in fname:
                    return True

            # Content check — search for the technique ID in the file
            try:
                content = rule_file.read_text(encoding="utf-8", errors="ignore")
                for variant in tid_variants:
                    if variant in content.lower():
                        return True
            except OSError:
                continue

        return False

    def _find_gap_file(self, source_id: str) -> Optional[dict]:
        """
        Read gaps/data-sources/<source_id>.yml if it exists.

        Returns the parsed YAML dict or None if the file is absent.
        """
        if not self.gaps_dir.exists():
            return None

        gap_path = self.gaps_dir / f"{source_id}.yml"
        if not gap_path.exists():
            return None

        if yaml is None:
            # PyYAML not available — treat as absent
            return None

        try:
            with open(gap_path, encoding="utf-8") as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return None

    def _classify_actionability(self, source_statuses: list) -> str:
        """
        READY   — all required sources are AVAILABLE
        PARTIAL — at least one is AVAILABLE but one or more are MISSING
        BLOCKED — all required sources are MISSING (or none required)
        """
        if not source_statuses:
            # No data source requirement — can author with generic telemetry
            return "READY"

        statuses = {s["status"] for s in source_statuses}

        if "MISSING" not in statuses:
            return "READY"
        if "AVAILABLE" in statuses or "PARTIAL" in statuses:
            return "PARTIAL"
        return "BLOCKED"

    def _generate_recommendation(self, technique_id: str, source_statuses: list) -> str:
        """
        Generate a human-readable recommendation based on source availability.
        """
        missing  = [s["source"] for s in source_statuses if s["status"] == "MISSING"]
        partial  = [s["source"] for s in source_statuses if s["status"] == "PARTIAL"]
        available = [s["source"] for s in source_statuses if s["status"] == "AVAILABLE"]

        if not source_statuses:
            return f"Author detection for {technique_id} — no specific data source required."

        if not missing and not partial:
            return (
                f"All required sources available ({', '.join(available)}). "
                f"Author {technique_id} detection now."
            )

        if missing and not available and not partial:
            sources_str = ", ".join(missing)
            return (
                f"Onboard missing sources first: {sources_str}. "
                f"Check gaps/data-sources/ for onboarding instructions."
            )

        parts = []
        if available:
            parts.append(f"available: {', '.join(available)}")
        if partial:
            parts.append(f"partial: {', '.join(partial)}")
        if missing:
            parts.append(f"missing: {', '.join(missing)}")

        return (
            f"Partial coverage possible ({'; '.join(parts)}). "
            f"Author limited detection now, expand after onboarding missing sources."
        )
