"""
Detection Lifecycle State Manager

Reads/writes detection request YAML files in detection-requests/.
Manages state transitions, artifact validation, and audit trails.
"""

import os
import glob
import datetime
from pathlib import Path
from typing import Optional

import yaml

# Resolve paths relative to the autonomous/ directory
AUTONOMOUS_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = AUTONOMOUS_DIR.parent
REQUESTS_DIR = AUTONOMOUS_DIR / "detection-requests"
SCHEMA_PATH = AUTONOMOUS_DIR / "orchestration" / "schema.yml"


def _load_schema():
    with open(SCHEMA_PATH) as f:
        return yaml.safe_load(f)


def _load_request(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def _save_request(path: Path, data: dict):
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, width=120)


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _technique_to_filename(technique_id: str) -> str:
    """T1055.001 -> t1055_001.yml"""
    return technique_id.lower().replace(".", "_") + ".yml"


class StateManager:
    def __init__(self):
        self.schema = _load_schema()
        self.valid_transitions = self.schema["valid_transitions"]
        self.states = self.schema["states"]
        REQUESTS_DIR.mkdir(parents=True, exist_ok=True)

    def _request_path(self, technique_id: str) -> Path:
        return REQUESTS_DIR / _technique_to_filename(technique_id)

    def list_all(self) -> list[dict]:
        """Return all detection requests."""
        results = []
        for f in sorted(REQUESTS_DIR.glob("*.yml")):
            if f.name.startswith("_"):
                continue
            data = _load_request(f)
            if data:
                data["_file"] = str(f)
                results.append(data)
        return results

    def query_by_state(self, state: str) -> list[dict]:
        """Return all detection requests in a given state."""
        return [r for r in self.list_all() if r.get("status") == state]

    def query_pending(self, agent: str) -> list[dict]:
        """Return detections that need work from a specific agent."""
        agent_states = {
            "intel": ["REQUESTED"],
            "red-team": ["REQUESTED"],
            "blue-team": ["SCENARIO_BUILT", "AUTHORED"],
            "quality": ["DEPLOYED", "MONITORING"],
            "security": [],
        }
        target_states = agent_states.get(agent, [])
        results = []
        for r in self.list_all():
            if r.get("status") in target_states:
                results.append(r)
        return results

    def get(self, technique_id: str) -> Optional[dict]:
        """Get a single detection request by technique ID."""
        path = self._request_path(technique_id)
        if path.exists():
            return _load_request(path)
        return None

    def create(self, technique_id: str, title: str = "",
               priority: str = "medium", intel_report: str = "",
               requested_by: str = "intel_agent") -> dict:
        """Create a new detection request in REQUESTED state."""
        path = self._request_path(technique_id)
        if path.exists():
            raise ValueError(f"Detection request already exists: {technique_id}")

        data = {
            "technique_id": technique_id,
            "title": title or f"Detection for {technique_id}",
            "status": "REQUESTED",
            "priority": priority,
            "requested_by": requested_by,
            "requested_date": _now_iso(),
            "intel_report": intel_report,
            "scenario_file": "",
            "sigma_rule": "",
            "deployed_date": "",
            "last_quality_review": "",
            "quality_score": 0.0,
            "fp_rate": 0.0,
            "tp_rate": 0.0,
            "alert_volume_24h": 0,
            "cost_estimate": "low",
            "auto_deploy_eligible": False,
            "changelog": [
                {
                    "date": _now_iso(),
                    "agent": requested_by,
                    "action": "created",
                    "details": f"Detection request created from intel: {intel_report}",
                }
            ],
        }
        _save_request(path, data)
        return data

    def transition(self, technique_id: str, target_state: str,
                   agent: str, details: str = "", **updates) -> dict:
        """Transition a detection request to a new state."""
        path = self._request_path(technique_id)
        if not path.exists():
            raise ValueError(f"Detection request not found: {technique_id}")

        data = _load_request(path)
        current_state = data.get("status")

        # Validate transition
        allowed = self.valid_transitions.get(current_state, [])
        if target_state not in allowed:
            raise ValueError(
                f"Invalid transition: {current_state} -> {target_state}. "
                f"Allowed: {allowed}"
            )

        # Check required exit artifacts for current state
        state_def = self.states.get(current_state, {})
        exit_artifacts = state_def.get("exit_artifacts", [])
        artifact_paths = self.schema.get("artifact_paths", {})
        missing = []
        for artifact in exit_artifacts:
            tmpl = artifact_paths.get(artifact, "")
            if tmpl:
                resolved = tmpl.format(
                    technique_id=technique_id,
                    technique_id_underscored=technique_id.lower().replace(".", "_"),
                    tactic=data.get("mitre_tactic", "unknown"),
                )
                full_path = REPO_ROOT / resolved
                if not full_path.exists():
                    # detection_request_yaml and deployment_record are the request itself
                    if artifact in ("detection_request_yaml", "deployment_record"):
                        continue
                    missing.append(f"{artifact} ({resolved})")

        if missing:
            raise ValueError(
                f"Missing artifacts for transition {current_state} -> {target_state}: "
                + ", ".join(missing)
            )

        # Apply transition
        data["status"] = target_state
        for key, val in updates.items():
            data[key] = val

        # Audit trail
        data.setdefault("changelog", [])
        data["changelog"].append({
            "date": _now_iso(),
            "agent": agent,
            "action": f"transition:{current_state}->{target_state}",
            "details": details or f"Transitioned by {agent}",
        })

        _save_request(path, data)
        return data

    def update(self, technique_id: str, agent: str, **updates) -> dict:
        """Update fields on a detection request without changing state."""
        path = self._request_path(technique_id)
        if not path.exists():
            raise ValueError(f"Detection request not found: {technique_id}")

        data = _load_request(path)
        for key, val in updates.items():
            data[key] = val

        data.setdefault("changelog", [])
        data["changelog"].append({
            "date": _now_iso(),
            "agent": agent,
            "action": "update",
            "details": f"Updated fields: {', '.join(updates.keys())}",
        })

        _save_request(path, data)
        return data

    def status_summary(self) -> dict[str, list[str]]:
        """Return a dict of state -> list of technique_ids."""
        summary = {}
        for r in self.list_all():
            state = r.get("status", "UNKNOWN")
            tid = r.get("technique_id", "???")
            summary.setdefault(state, []).append(tid)
        return summary
