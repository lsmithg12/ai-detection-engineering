"""
Coverage Analyst Agent — Auto-generates coverage analysis from detection state,
threat models, and the log source registry.

Produces three artifacts:
  1. coverage/attack-matrix.md   — multi-threat coverage matrix
  2. coverage/gap-report.md      — prioritized detection backlog
  3. coverage/navigator.json     — ATT&CK Navigator layer (v4.5+)

Called by agent_runner.py. Implements run(state_manager) interface.
"""

import datetime
import json
import re
from pathlib import Path
from typing import Optional

import yaml

from orchestration.state import StateManager
from orchestration import learnings

AUTONOMOUS_DIR = Path(__file__).resolve().parent.parent.parent
REPO_ROOT = AUTONOMOUS_DIR.parent
MODELS_DIR = REPO_ROOT / "threat-intel" / "models"
SOURCES_DIR = REPO_ROOT / "data-sources" / "registry"
DETECTIONS_DIR = REPO_ROOT / "detections"
RESULTS_DIR = REPO_ROOT / "tests" / "results"
COVERAGE_DIR = REPO_ROOT / "coverage"

AGENT_NAME = "coverage"

# ATT&CK Navigator layer metadata
NAVIGATOR_VERSION = "4.5"
NAVIGATOR_DOMAIN = "enterprise-attack"
NAVIGATOR_DESCRIPTION = "Auto-generated detection coverage layer"

# Status -> color mapping for Navigator
STATUS_COLORS = {
    "MONITORING": "#00ff00",    # green
    "DEPLOYED": "#90ee90",      # light green
    "VALIDATED": "#ffff00",     # yellow
    "AUTHORED": "#ffa500",      # orange
    "SCENARIO_BUILT": "#ff8c00",  # dark orange
    "REQUESTED": "#ff6347",     # red-orange
}

# Complexity -> numeric value (for priority scoring)
COMPLEXITY_MAP = {
    "low": 0.25,
    "medium": 0.50,
    "high": 0.75,
    "expert": 1.00,
}

# MITRE technique ID to tactic name (for display)
# Augmented at runtime from detection requests
TACTIC_NAMES = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Data Loaders
# ---------------------------------------------------------------------------

def load_threat_models() -> list[dict]:
    """Load all threat model YAML files from threat-intel/models/ (skip schema.yml).

    Returns a list of parsed threat model dicts. Each has at minimum:
      name, type, platform, priority, techniques (dict keyed by technique ID)
    """
    if not MODELS_DIR.exists():
        print(f"  [{AGENT_NAME}] Warning: threat models dir not found: {MODELS_DIR}")
        return []

    models = []
    for path in sorted(MODELS_DIR.glob("*.yml")):
        if path.name == "schema.yml":
            continue
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if data and isinstance(data, dict) and "techniques" in data:
                data["_file"] = str(path.relative_to(REPO_ROOT))
                models.append(data)
            else:
                print(f"  [{AGENT_NAME}] Skipping {path.name}: no techniques field")
        except Exception as e:
            print(f"  [{AGENT_NAME}] Error loading {path.name}: {e}")
    return models


def load_source_registry() -> dict[str, dict]:
    """Load all log source YAML files from data-sources/registry/ (skip schema.yml).

    Returns a dict of {source_id: source_data}.
    """
    if not SOURCES_DIR.exists():
        print(f"  [{AGENT_NAME}] Warning: source registry dir not found: {SOURCES_DIR}")
        return {}

    sources = {}
    for path in sorted(SOURCES_DIR.glob("*.yml")):
        if path.name == "schema.yml":
            continue
        try:
            with open(path, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if data and isinstance(data, dict):
                sid = data.get("source_id", path.stem)
                data["_file"] = str(path.relative_to(REPO_ROOT))
                sources[sid] = data
        except Exception as e:
            print(f"  [{AGENT_NAME}] Error loading {path.name}: {e}")
    return sources


def load_detection_state(state_manager: StateManager) -> dict[str, dict]:
    """Load all detection requests keyed by technique_id.

    Includes status, F1 scores, and other metadata from the state manager.
    """
    detections = {}
    for req in state_manager.list_all():
        tid = req.get("technique_id", "")
        if tid:
            detections[tid] = req
    return detections


def load_validation_results() -> dict[str, dict]:
    """Load F1 scores and metrics from tests/results/*.json.

    Returns {technique_id: result_data} with the newest result per technique.
    """
    results = {}
    if not RESULTS_DIR.exists():
        return results

    for path in sorted(RESULTS_DIR.glob("*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            tid = data.get("technique_id", "")
            if tid:
                # If we already have a result for this technique, keep the newer one
                existing = results.get(tid)
                if existing:
                    existing_date = existing.get("date", existing.get("validated_at", ""))
                    new_date = data.get("date", data.get("validated_at", ""))
                    if new_date > existing_date:
                        results[tid] = data
                else:
                    results[tid] = data
        except Exception as e:
            print(f"  [{AGENT_NAME}] Error loading {path.name}: {e}")
    return results


def load_sigma_rules() -> dict[str, Path]:
    """Scan detections/ for Sigma rule files, return {technique_id: path}.

    Technique ID is extracted from filename (e.g., t1055_001.yml -> T1055.001).
    """
    rules = {}
    if not DETECTIONS_DIR.exists():
        return rules

    for path in DETECTIONS_DIR.rglob("*.yml"):
        # Skip compiled/ directories and non-rule files
        if "compiled" in str(path):
            continue
        # Extract technique ID from filename
        stem = path.stem
        # Handle patterns like t1055_001, t1562_006_registry, t1059_001_powershell_bypass
        match = re.match(r"^(t\d{4}(?:_\d{3})?)", stem)
        if match:
            tid_raw = match.group(1)
            # Convert t1055_001 -> T1055.001
            tid = tid_raw.upper().replace("_", ".", 1)
            # Only replace the first underscore after T#### with a dot
            # Handle t1055_001 (one sub) correctly
            parts = tid_raw.upper().split("_")
            if len(parts) >= 2 and parts[0].startswith("T") and parts[1].isdigit():
                tid = f"{parts[0]}.{parts[1]}"
            else:
                tid = parts[0]
            rules[tid] = path
    return rules


# ---------------------------------------------------------------------------
# Priority Scoring
# ---------------------------------------------------------------------------

def calculate_gap_priority(
    technique_id: str,
    models: list[dict],
    detections: dict[str, dict],
    sources: dict[str, dict],
) -> float:
    """Calculate priority score for a technique gap.

    Score formula:
        score = (
            threat_relevance * 3    # How many threat models reference this (0-1, capped at 4)
            + data_available * 2    # Do we have the required log sources? (0 or 1)
            + no_detection * 2      # Is there currently no detection? (0 or 1)
            + technique_severity * 1  # 1 - avg detection_complexity (inverted)
        ) / 8.0

    Returns a float in [0.0, 1.0].
    """
    # --- threat_relevance: count how many models reference this technique ---
    model_count = 0
    complexities = []
    required_sources = set()

    for model in models:
        techniques = model.get("techniques", {})
        if technique_id in techniques:
            model_count += 1
            tech_data = techniques[technique_id]
            complexity_str = tech_data.get("detection_complexity", "medium")
            complexities.append(COMPLEXITY_MAP.get(complexity_str, 0.5))
            # Collect required data sources
            for ds in tech_data.get("data_sources", []):
                # Format: "source_id:event_type" e.g. "sysmon:eid_8"
                source_id = ds.split(":")[0] if ":" in ds else ds
                required_sources.add(source_id)

    # Cap at 4 models for normalization
    threat_relevance = min(model_count / 4.0, 1.0) if models else 0.0

    # --- data_available: are the required log sources active? ---
    if required_sources:
        available_count = 0
        for src_id in required_sources:
            source = sources.get(src_id, {})
            if source.get("status") == "active":
                available_count += 1
        data_available = 1.0 if available_count == len(required_sources) else 0.0
    else:
        # No specific source requirements known -- assume not available
        data_available = 0.0

    # --- no_detection: is there currently no detection for this technique? ---
    detection = detections.get(technique_id)
    if detection is None:
        no_detection = 1.0
    else:
        status = detection.get("status", "")
        # Consider it "covered" if it has progressed past REQUESTED
        no_detection = 1.0 if status == "REQUESTED" else 0.0

    # --- technique_severity: inverted complexity (simpler = higher priority) ---
    if complexities:
        avg_complexity = sum(complexities) / len(complexities)
    else:
        avg_complexity = 0.5  # default medium
    technique_severity = 1.0 - avg_complexity

    # Weighted sum
    score = (
        threat_relevance * 3
        + data_available * 2
        + no_detection * 2
        + technique_severity * 1
    ) / 8.0

    return round(score, 3)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_f1_score(
    technique_id: str,
    detections: dict[str, dict],
    validation_results: dict[str, dict],
) -> Optional[float]:
    """Get the best available F1 score for a technique.

    Checks validation results first, then detection request quality_score.
    """
    # Prefer validation result file (more authoritative)
    vr = validation_results.get(technique_id)
    if vr:
        metrics = vr.get("metrics", vr.get("results", {}))
        f1 = metrics.get("f1_score")
        if f1 is not None:
            return f1

    # Fall back to detection request quality_score
    det = detections.get(technique_id)
    if det:
        qs = det.get("quality_score", 0.0)
        if qs > 0:
            return qs

    return None


def _get_technique_status(
    technique_id: str,
    detections: dict[str, dict],
) -> str:
    """Get the lifecycle status of a technique detection."""
    det = detections.get(technique_id)
    if det:
        return det.get("status", "UNKNOWN")
    return "NO_DETECTION"


def _get_status_emoji(status: str) -> str:
    """Map status to display emoji for markdown."""
    return {
        "MONITORING": "✅",
        "DEPLOYED": "✅",
        "VALIDATED": "✓",
        "AUTHORED": "🔨",
        "SCENARIO_BUILT": "🔧",
        "REQUESTED": "📋",
        "NO_DETECTION": "❌",
    }.get(status, "❓")


def _get_quality_emoji(f1: Optional[float]) -> str:
    """Map F1 score to quality indicator."""
    if f1 is None:
        return "—"
    if f1 >= 0.90:
        return "🟢"
    if f1 >= 0.75:
        return "🟡"
    return "🔴"


def _collect_all_techniques(models: list[dict]) -> dict[str, dict]:
    """Collect all unique techniques across all threat models.

    Returns {technique_id: {description, models: [model_names], ...}}.
    """
    all_techs = {}
    for model in models:
        model_name = model.get("name", "Unknown")
        for tid, tech_data in model.get("techniques", {}).items():
            if tid not in all_techs:
                all_techs[tid] = {
                    "description": tech_data.get("description", ""),
                    "models": [],
                    "data_sources": set(),
                    "complexities": [],
                    "artifacts": set(),
                    "commands": [],
                }
            all_techs[tid]["models"].append(model_name)
            for ds in tech_data.get("data_sources", []):
                all_techs[tid]["data_sources"].add(ds)
            complexity = tech_data.get("detection_complexity", "medium")
            all_techs[tid]["complexities"].append(complexity)
            for artifact in tech_data.get("artifacts", []):
                all_techs[tid]["artifacts"].add(artifact)
            for cmd in tech_data.get("commands", []):
                all_techs[tid]["commands"].append(cmd)
    return all_techs


def _check_source_availability(
    required_sources: set[str],
    source_registry: dict[str, dict],
) -> tuple[bool, list[str]]:
    """Check if all required sources are active. Returns (all_available, missing_list)."""
    missing = []
    for ds_ref in required_sources:
        source_id = ds_ref.split(":")[0] if ":" in ds_ref else ds_ref
        source = source_registry.get(source_id)
        if source is None:
            missing.append(ds_ref)
        elif source.get("status") != "active":
            missing.append(f"{ds_ref} ({source.get('status', 'unknown')})")
    return len(missing) == 0, missing


# ---------------------------------------------------------------------------
# Output Generators
# ---------------------------------------------------------------------------

def generate_attack_matrix(
    detections: dict[str, dict],
    models: list[dict],
    validation_results: dict[str, dict],
    source_registry: dict[str, dict],
) -> str:
    """Generate the coverage/attack-matrix.md markdown content.

    Includes:
    - Summary statistics table
    - Per-threat-model coverage table
    - Full multi-dimensional matrix (technique x threat actor)
    - All detections current state table
    - Remaining gaps table
    """
    all_techniques = _collect_all_techniques(models)
    total_techniques = len(all_techniques)
    sigma_rules = load_sigma_rules()

    # Count by status
    status_counts = {}
    detected_techniques = set()
    for tid in all_techniques:
        status = _get_technique_status(tid, detections)
        status_counts[status] = status_counts.get(status, 0) + 1
        if status not in ("NO_DETECTION", "REQUESTED"):
            detected_techniques.add(tid)

    # Count detections that are also in threat models
    total_detections = len([d for d in detections.values()
                           if d.get("status") not in (None, "")])

    monitoring_count = len([d for d in detections.values()
                           if d.get("status") == "MONITORING"])
    validated_count = len([d for d in detections.values()
                          if d.get("status") == "VALIDATED"])
    authored_count = len([d for d in detections.values()
                         if d.get("status") == "AUTHORED"])

    # Build the markdown
    lines = [
        "# AUTO-GENERATED by coverage_agent.py -- DO NOT EDIT MANUALLY",
        f"# Generated: {_now_iso()}",
        "",
        "# MITRE ATT&CK Coverage Matrix — Multi-Threat Analysis",
        "",
        f"**Last updated**: {_today()}",
        f"**Total detections**: {total_detections} Sigma rules",
        f"**Deployed to SIEM**: {monitoring_count} (MONITORING state)",
        f"**Validated (deploy-ready)**: {validated_count} (F1 >= 0.75)",
        f"**Authored (pending validation)**: {authored_count}",
        f"**Threat models loaded**: {len(models)}",
        f"**Unique techniques across models**: {total_techniques}",
        f"**Techniques with detections**: {len(detected_techniques)} / {total_techniques}"
        f" ({round(100 * len(detected_techniques) / total_techniques) if total_techniques else 0}%)",
        f"**Active log sources**: {len([s for s in source_registry.values() if s.get('status') == 'active'])} / {len(source_registry)}",
        "",
        "Legend: ✅ Monitoring | ✓ Validated | 🔨 Authored | 📋 Requested"
        " | ❌ No coverage | 🟢 F1>=0.90 | 🟡 F1>=0.75 | 🔴 F1<0.75",
        "",
        "---",
        "",
    ]

    # --- Coverage by Threat Model ---
    lines.append("## Coverage by Threat Model")
    lines.append("")
    lines.append("| Threat Model | Type | Priority | Techniques | Detected | Coverage % |")
    lines.append("|---|---|---|---|---|---|")

    for model in sorted(models, key=lambda m: m.get("name", "")):
        model_name = model.get("name", "Unknown")
        model_type = model.get("type", "unknown")
        model_priority = model.get("priority", "medium")
        model_techs = model.get("techniques", {})
        total = len(model_techs)
        detected = sum(
            1 for tid in model_techs
            if _get_technique_status(tid, detections) not in ("NO_DETECTION", "REQUESTED")
        )
        pct = round(100 * detected / total) if total else 0
        lines.append(
            f"| {model_name} | {model_type} | {model_priority} "
            f"| {total} | {detected} | {pct}% |"
        )

    lines.extend(["", "---", ""])

    # --- Multi-Dimensional Matrix (technique x threat model) ---
    lines.append("## Technique x Threat Model Matrix")
    lines.append("")

    model_names = [m.get("name", "?") for m in models]
    # Abbreviate model names for column headers
    model_abbrevs = []
    for name in model_names:
        # Take first word or abbreviation
        words = name.split()
        abbrev = words[0][:12] if words else "?"
        model_abbrevs.append(abbrev)

    header = "| Technique | Description | Status | F1 | " + " | ".join(model_abbrevs) + " |"
    separator = "|---|---|---|---|" + "|".join(["---"] * len(model_abbrevs)) + "|"
    lines.append(header)
    lines.append(separator)

    for tid in sorted(all_techniques.keys()):
        tech_info = all_techniques[tid]
        description = tech_info["description"][:40]
        status = _get_technique_status(tid, detections)
        f1 = _get_f1_score(tid, detections, validation_results)
        status_emoji = _get_status_emoji(status)
        f1_display = f"{f1:.2f}" if f1 is not None else "—"

        # Per-model presence markers
        model_marks = []
        for model in models:
            if tid in model.get("techniques", {}):
                model_marks.append("●")
            else:
                model_marks.append("·")

        row = (
            f"| {tid} | {description} | {status_emoji} {status} | {f1_display} | "
            + " | ".join(model_marks) + " |"
        )
        lines.append(row)

    lines.extend(["", "---", ""])

    # --- All Detections Current State ---
    lines.append("## All Detections — Current State")
    lines.append("")
    lines.append("| Technique | Title | Status | F1 | Tier | Threat Models |")
    lines.append("|---|---|---|---|---|---|")

    for tid in sorted(detections.keys()):
        det = detections[tid]
        title = det.get("title", f"Detection for {tid}")[:40]
        status = det.get("status", "UNKNOWN")
        f1 = _get_f1_score(tid, detections, validation_results)
        status_emoji = _get_status_emoji(status)
        quality = _get_quality_emoji(f1)
        f1_display = f"{f1:.2f}" if f1 is not None else "—"

        # Which models reference this technique?
        in_models = [
            m.get("name", "?")[:10]
            for m in models
            if tid in m.get("techniques", {})
        ]
        models_display = ", ".join(in_models) if in_models else "—"

        lines.append(
            f"| {tid} | {title} | {status_emoji} {status} "
            f"| {f1_display} | {quality} | {models_display} |"
        )

    lines.extend(["", "---", ""])

    # --- Remaining Gaps ---
    lines.append("## Remaining Gaps — Techniques Without Detections")
    lines.append("")
    lines.append("| Technique | Description | Threat Models | Data Sources | Blocker |")
    lines.append("|---|---|---|---|---|")

    for tid in sorted(all_techniques.keys()):
        status = _get_technique_status(tid, detections)
        if status not in ("NO_DETECTION", "REQUESTED"):
            continue

        tech_info = all_techniques[tid]
        desc = tech_info["description"][:45]
        model_list = ", ".join(tech_info["models"])
        sources = ", ".join(sorted(tech_info["data_sources"]))[:50]

        # Determine blocker
        all_available, missing = _check_source_availability(
            tech_info["data_sources"], source_registry
        )
        if missing:
            blocker = f"Data gap: {', '.join(missing)[:40]}"
        elif status == "REQUESTED":
            blocker = "Pending scenario build"
        else:
            blocker = "No detection request"

        lines.append(f"| {tid} | {desc} | {model_list} | {sources} | {blocker} |")

    lines.extend([
        "",
        "---",
        "",
        f"*Generated by coverage_agent.py on {_now_iso()}*",
        "",
    ])

    return "\n".join(lines)


def generate_gap_report(
    detections: dict[str, dict],
    models: list[dict],
    source_registry: dict[str, dict],
    validation_results: dict[str, dict],
) -> str:
    """Generate coverage/gap-report.md with prioritized detection gaps.

    Includes:
    - Top prioritized gaps (sorted by score)
    - Blocked gaps (missing data sources)
    - Low-quality detections needing rework
    - Recommendations
    """
    all_techniques = _collect_all_techniques(models)

    # Calculate priority for every technique in the models
    gaps = []
    blocked = []
    rework_needed = []

    for tid, tech_info in all_techniques.items():
        status = _get_technique_status(tid, detections)
        priority = calculate_gap_priority(tid, models, detections, source_registry)

        all_available, missing = _check_source_availability(
            tech_info["data_sources"], source_registry
        )

        f1 = _get_f1_score(tid, detections, validation_results)

        entry = {
            "technique_id": tid,
            "description": tech_info["description"],
            "models": tech_info["models"],
            "status": status,
            "priority_score": priority,
            "data_available": all_available,
            "missing_sources": missing,
            "f1": f1,
            "commands": tech_info["commands"],
        }

        if status in ("NO_DETECTION", "REQUESTED"):
            if not all_available:
                blocked.append(entry)
            else:
                gaps.append(entry)
        elif f1 is not None and f1 < 0.75:
            rework_needed.append(entry)

    # Sort by priority score descending
    gaps.sort(key=lambda g: g["priority_score"], reverse=True)
    blocked.sort(key=lambda g: g["priority_score"], reverse=True)
    rework_needed.sort(key=lambda g: g.get("f1", 0))

    lines = [
        "# AUTO-GENERATED by coverage_agent.py -- DO NOT EDIT MANUALLY",
        f"# Generated: {_now_iso()}",
        "",
        "# Detection Gap Report — Prioritized Backlog",
        "",
        f"**Generated**: {_today()}",
        f"**Total gaps (actionable)**: {len(gaps)}",
        f"**Blocked by data sources**: {len(blocked)}",
        f"**Needs rework (F1 < 0.75)**: {len(rework_needed)}",
        "",
        "---",
        "",
    ]

    # --- Top Prioritized Gaps ---
    lines.append("## Top Prioritized Gaps (Data Available)")
    lines.append("")
    if gaps:
        lines.append("| Priority | Technique | Description | Threat Models | Score | Commands |")
        lines.append("|---|---|---|---|---|---|")
        for i, g in enumerate(gaps, 1):
            models_str = ", ".join(g["models"])
            commands_str = ", ".join(g["commands"])[:30] if g["commands"] else "—"
            lines.append(
                f"| {i} | {g['technique_id']} | {g['description'][:40]} "
                f"| {models_str} | {g['priority_score']:.3f} | {commands_str} |"
            )
    else:
        lines.append("No actionable gaps with available data sources.")
    lines.extend(["", "---", ""])

    # --- Blocked Gaps ---
    lines.append("## Blocked Gaps (Missing Data Sources)")
    lines.append("")
    if blocked:
        lines.append("| Technique | Description | Missing Sources | Threat Models | Score |")
        lines.append("|---|---|---|---|---|")
        for g in blocked:
            models_str = ", ".join(g["models"])
            missing_str = ", ".join(g["missing_sources"])[:50]
            lines.append(
                f"| {g['technique_id']} | {g['description'][:40]} "
                f"| {missing_str} | {models_str} | {g['priority_score']:.3f} |"
            )
    else:
        lines.append("No blocked gaps.")
    lines.extend(["", "---", ""])

    # --- Rework Needed ---
    lines.append("## Detections Needing Rework (F1 < 0.75)")
    lines.append("")
    if rework_needed:
        lines.append("| Technique | Description | Current F1 | Status | Threat Models |")
        lines.append("|---|---|---|---|---|")
        for g in rework_needed:
            f1_str = f"{g['f1']:.2f}" if g["f1"] is not None else "—"
            models_str = ", ".join(g["models"])
            lines.append(
                f"| {g['technique_id']} | {g['description'][:40]} "
                f"| {f1_str} | {g['status']} | {models_str} |"
            )
    else:
        lines.append("All active detections meet minimum quality threshold.")
    lines.extend(["", "---", ""])

    # --- Recommendations ---
    lines.append("## Recommendations")
    lines.append("")

    if gaps:
        top = gaps[0]
        lines.append(
            f"1. **Highest priority gap**: {top['technique_id']} — "
            f"{top['description']} (score: {top['priority_score']:.3f}, "
            f"referenced by {len(top['models'])} threat model(s))"
        )
    if blocked:
        # Group blocked by missing source
        source_blocks = {}
        for g in blocked:
            for src in g["missing_sources"]:
                src_id = src.split(" ")[0].split(":")[0]
                source_blocks.setdefault(src_id, []).append(g["technique_id"])
        for src_id, tids in sorted(source_blocks.items(),
                                    key=lambda x: len(x[1]), reverse=True):
            lines.append(
                f"2. **Onboard data source `{src_id}`** — would unblock "
                f"{len(tids)} technique(s): {', '.join(tids[:5])}"
            )
    if rework_needed:
        for g in rework_needed[:3]:
            lines.append(
                f"3. **Rework {g['technique_id']}** — current F1={g['f1']:.2f}, "
                f"needs rule logic improvement"
            )

    if not gaps and not blocked and not rework_needed:
        lines.append("Full coverage achieved across all loaded threat models. "
                      "Consider adding new threat models to expand scope.")

    lines.extend([
        "",
        "---",
        "",
        f"*Generated by coverage_agent.py on {_now_iso()}*",
        "",
    ])

    return "\n".join(lines)


def generate_navigator_layer(
    detections: dict[str, dict],
    models: list[dict],
    validation_results: dict[str, dict],
) -> dict:
    """Generate ATT&CK Navigator v4.5+ JSON layer.

    Colors by status:
      MONITORING = green (#00ff00)
      DEPLOYED = light green (#90ee90)
      VALIDATED = yellow (#ffff00)
      AUTHORED = orange (#ffa500)
      REQUESTED = red-orange (#ff6347)

    Score = F1 * 100 (0-100 scale).
    """
    all_techniques = _collect_all_techniques(models)

    # Merge techniques from detections that may not be in models
    for tid in detections:
        if tid not in all_techniques:
            det = detections[tid]
            all_techniques[tid] = {
                "description": det.get("title", ""),
                "models": [],
                "data_sources": set(),
                "complexities": [],
                "artifacts": set(),
                "commands": [],
            }

    techniques = []
    for tid in sorted(all_techniques.keys()):
        status = _get_technique_status(tid, detections)
        f1 = _get_f1_score(tid, detections, validation_results)

        color = STATUS_COLORS.get(status, "")
        score = int(f1 * 100) if f1 is not None else 0

        # Build comment with model references
        tech_info = all_techniques[tid]
        comment_parts = []
        if tech_info["models"]:
            comment_parts.append(f"Threat models: {', '.join(tech_info['models'])}")
        if f1 is not None:
            comment_parts.append(f"F1: {f1:.2f}")
        comment_parts.append(f"Status: {status}")
        if tech_info.get("commands"):
            comment_parts.append(f"Commands: {', '.join(tech_info['commands'])}")
        comment = "; ".join(comment_parts)

        # Convert technique ID to ATT&CK format for Navigator
        # T1055.001 -> tactic ID is optional, Navigator uses technique ID
        tech_entry = {
            "techniqueID": tid,
            "score": score,
            "comment": comment,
            "enabled": True,
            "showSubtechniques": False,
        }

        if color:
            tech_entry["color"] = color

        # Metadata for detailed view
        if status != "NO_DETECTION":
            tech_entry["metadata"] = [
                {"name": "status", "value": status},
            ]
            if f1 is not None:
                tech_entry["metadata"].append({"name": "f1_score", "value": str(f1)})
            det = detections.get(tid)
            if det:
                if det.get("sigma_rule"):
                    tech_entry["metadata"].append(
                        {"name": "sigma_rule", "value": det["sigma_rule"]}
                    )
                if det.get("priority"):
                    tech_entry["metadata"].append(
                        {"name": "priority", "value": det["priority"]}
                    )

        techniques.append(tech_entry)

    # Build the Navigator layer
    layer = {
        "name": "Detection Coverage — Auto-Generated",
        "versions": {
            "attack": "14",
            "navigator": NAVIGATOR_VERSION,
            "layer": "4.5",
        },
        "domain": NAVIGATOR_DOMAIN,
        "description": (
            f"Auto-generated detection coverage layer. "
            f"{len(detections)} detections across {len(models)} threat models. "
            f"Generated: {_now_iso()}"
        ),
        "filters": {
            "platforms": ["Windows", "Linux", "macOS", "Azure AD",
                          "Office 365", "Google Workspace", "IaaS",
                          "Network", "Containers"],
        },
        "sorting": 3,  # Sort by score descending
        "layout": {
            "layout": "side",
            "aggregateFunction": "max",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ff6347", "#ffa500", "#ffff00", "#90ee90", "#00ff00"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Monitoring (deployed + healthy)", "color": "#00ff00"},
            {"label": "Deployed", "color": "#90ee90"},
            {"label": "Validated (F1 >= 0.75)", "color": "#ffff00"},
            {"label": "Authored (pending validation)", "color": "#ffa500"},
            {"label": "Requested (no rule yet)", "color": "#ff6347"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
        "metadata": [
            {"name": "generated_by", "value": "coverage_agent.py"},
            {"name": "generated_at", "value": _now_iso()},
            {"name": "threat_models", "value": ", ".join(
                m.get("name", "?") for m in models
            )},
            {"name": "total_detections", "value": str(len(detections))},
        ],
    }

    return layer


# ---------------------------------------------------------------------------
# GitHub Issue Creation for Coverage Gaps (ISSUE-019)
# ---------------------------------------------------------------------------

def _get_github_token() -> str:
    """Retrieve GitHub token from env or .mcp.json."""
    import os
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        return token
    mcp_path = REPO_ROOT / ".mcp.json"
    if mcp_path.exists():
        try:
            with open(mcp_path) as f:
                mcp = json.load(f)
            token = (mcp.get("mcpServers", {})
                     .get("github", {})
                     .get("env", {})
                     .get("GITHUB_PERSONAL_ACCESS_TOKEN", ""))
        except Exception:
            pass
    return token


def _list_open_gap_issues(token: str) -> set[str]:
    """List technique IDs that already have open coverage-gap issues."""
    import urllib.request
    import urllib.error

    url = ("https://api.github.com/repos/lsmithg12/ai-detection-engineering/issues"
           "?labels=coverage-gap&state=open&per_page=100")
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            issues = json.loads(resp.read())
        # Extract technique IDs from titles like "[Gap] No detection for ... (T1234.001)"
        existing = set()
        for issue in issues:
            title = issue.get("title", "")
            match = re.search(r'\(T\d{4}(?:\.\d{3})?\)', title)
            if match:
                existing.add(match.group(0).strip("()"))
        return existing
    except Exception:
        return set()


def _create_gap_issue(
    technique_id: str,
    description: str,
    priority_score: float,
    models: list[str],
    required_sources: list[str],
    token: str,
) -> str | None:
    """Create a GitHub Issue for a coverage gap. Returns issue URL or None."""
    import urllib.request
    import urllib.error

    body = f"""## Coverage Gap: {technique_id}

**Priority score**: {priority_score:.3f}
**Threat models**: {', '.join(models)}
**Required data sources**: {', '.join(required_sources) if required_sources else 'Unknown'}

### Description
{description}

### Action Required
1. Create attack/benign scenarios for this technique
2. Author a Sigma detection rule
3. Validate against sim data (target F1 >= 0.90)

---
*Auto-generated by coverage_agent.py*
"""
    payload = json.dumps({
        "title": f"[Gap] No detection for {description[:50]} ({technique_id})",
        "body": body,
        "labels": ["coverage-gap", "needs-review"],
    }).encode()

    req = urllib.request.Request(
        "https://api.github.com/repos/lsmithg12/ai-detection-engineering/issues",
        data=payload, method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            return data.get("html_url", "")
    except Exception as e:
        print(f"  [{AGENT_NAME}] Failed to create issue for {technique_id}: {e}")
        return None


def create_gap_issues(
    gaps: list[dict],
    max_issues: int = 5,
) -> list[str]:
    """Create GitHub Issues for top actionable gaps. Returns list of created URLs."""
    token = _get_github_token()
    if not token:
        print(f"  [{AGENT_NAME}] No GitHub token — skipping issue creation")
        return []

    existing = _list_open_gap_issues(token)
    print(f"  [{AGENT_NAME}] Found {len(existing)} existing open coverage-gap issues")

    created = []
    for gap in gaps[:max_issues]:
        tid = gap.get("technique_id", "")
        if tid in existing:
            continue  # Already has an open issue

        url = _create_gap_issue(
            technique_id=tid,
            description=gap.get("description", ""),
            priority_score=gap.get("priority_score", 0),
            models=gap.get("models", []),
            required_sources=list(gap.get("data_sources", set())),
            token=token,
        )
        if url:
            created.append(url)
            print(f"  [{AGENT_NAME}] Created issue: {url}")

    return created


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def run(state_manager: StateManager) -> dict:
    """Main entry point for the coverage analyst agent.

    1. Load briefing and learnings
    2. Load threat models, source registry, detection state, validation results
    3. Generate attack matrix markdown
    4. Generate gap report markdown
    5. Generate Navigator JSON layer
    6. Write all outputs to coverage/
    7. Return summary statistics
    """
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    print(f"  [{AGENT_NAME}] Starting coverage analyst run {run_id}")

    # 0. Re-read state from disk (ISSUE-015 — pick up changes from prior agents)
    state_manager.reload()

    # 1. Load briefing
    briefing = learnings.get_briefing(AGENT_NAME)
    print(f"  [{AGENT_NAME}] {briefing}")

    coverage_lessons = learnings.get_relevant_lessons(AGENT_NAME, "general")
    if coverage_lessons:
        print(f"  [{AGENT_NAME}] {len(coverage_lessons)} lessons loaded")

    # 2. Load all data sources
    print(f"  [{AGENT_NAME}] Loading threat models...")
    models = load_threat_models()
    print(f"  [{AGENT_NAME}] Loaded {len(models)} threat models: "
          + ", ".join(m.get("name", "?") for m in models))

    print(f"  [{AGENT_NAME}] Loading source registry...")
    source_registry = load_source_registry()
    active_sources = [sid for sid, s in source_registry.items()
                      if s.get("status") == "active"]
    planned_sources = [sid for sid, s in source_registry.items()
                       if s.get("status") == "planned"]
    print(f"  [{AGENT_NAME}] Loaded {len(source_registry)} sources "
          f"({len(active_sources)} active, {len(planned_sources)} planned)")

    print(f"  [{AGENT_NAME}] Loading detection state...")
    detections = load_detection_state(state_manager)
    print(f"  [{AGENT_NAME}] Loaded {len(detections)} detection requests")

    print(f"  [{AGENT_NAME}] Loading validation results...")
    validation_results = load_validation_results()
    print(f"  [{AGENT_NAME}] Loaded {len(validation_results)} validation results")

    # Collect summary stats before generating outputs
    all_techniques = _collect_all_techniques(models)
    total_model_techniques = len(all_techniques)
    detected = sum(
        1 for tid in all_techniques
        if _get_technique_status(tid, detections) not in ("NO_DETECTION", "REQUESTED")
    )
    coverage_pct = round(100 * detected / total_model_techniques) if total_model_techniques else 0

    # Count gaps
    actionable_gaps = 0
    blocked_gaps = 0
    for tid, tech_info in all_techniques.items():
        status = _get_technique_status(tid, detections)
        if status not in ("NO_DETECTION", "REQUESTED"):
            continue
        all_available, _ = _check_source_availability(
            tech_info["data_sources"], source_registry
        )
        if all_available:
            actionable_gaps += 1
        else:
            blocked_gaps += 1

    # 3. Generate attack matrix
    print(f"  [{AGENT_NAME}] Generating attack matrix...")
    matrix_md = generate_attack_matrix(
        detections, models, validation_results, source_registry
    )

    # 4. Generate gap report
    print(f"  [{AGENT_NAME}] Generating gap report...")
    gap_md = generate_gap_report(
        detections, models, source_registry, validation_results
    )

    # 4b. Create GitHub Issues for top actionable gaps (ISSUE-019)
    gap_entries = []
    for tid, tech_info in all_techniques.items():
        status = _get_technique_status(tid, detections)
        if status not in ("NO_DETECTION", "REQUESTED"):
            continue
        all_available, _ = _check_source_availability(
            tech_info["data_sources"], source_registry
        )
        if all_available:
            priority = calculate_gap_priority(tid, models, detections, source_registry)
            gap_entries.append({
                "technique_id": tid,
                "description": tech_info["description"],
                "priority_score": priority,
                "models": tech_info["models"],
                "data_sources": tech_info["data_sources"],
            })
    gap_entries.sort(key=lambda g: g["priority_score"], reverse=True)

    created_issues = create_gap_issues(gap_entries, max_issues=5)
    if created_issues:
        print(f"  [{AGENT_NAME}] Created {len(created_issues)} new coverage-gap issues")

    # 5. Generate Navigator layer
    print(f"  [{AGENT_NAME}] Generating ATT&CK Navigator layer...")
    navigator = generate_navigator_layer(detections, models, validation_results)

    # 6. Write outputs
    COVERAGE_DIR.mkdir(parents=True, exist_ok=True)

    matrix_path = COVERAGE_DIR / "attack-matrix.md"
    matrix_path.write_text(matrix_md, encoding="utf-8")
    print(f"  [{AGENT_NAME}] Wrote {matrix_path.relative_to(REPO_ROOT)}")

    gap_path = COVERAGE_DIR / "gap-report.md"
    gap_path.write_text(gap_md, encoding="utf-8")
    print(f"  [{AGENT_NAME}] Wrote {gap_path.relative_to(REPO_ROOT)}")

    navigator_path = COVERAGE_DIR / "navigator.json"
    navigator_path.write_text(
        json.dumps(navigator, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"  [{AGENT_NAME}] Wrote {navigator_path.relative_to(REPO_ROOT)}")

    # 7. Summary
    summary = (
        f"Coverage: {detected}/{total_model_techniques} techniques "
        f"({coverage_pct}%) across {len(models)} threat models. "
        f"Gaps: {actionable_gaps} actionable, {blocked_gaps} blocked. "
        f"Outputs: attack-matrix.md, gap-report.md, navigator.json"
    )
    print(f"\n  [{AGENT_NAME}] {summary}")

    return {
        "summary": summary,
        "threat_models_loaded": len(models),
        "source_registry_loaded": len(source_registry),
        "active_sources": len(active_sources),
        "total_detections": len(detections),
        "total_model_techniques": total_model_techniques,
        "techniques_detected": detected,
        "coverage_pct": coverage_pct,
        "actionable_gaps": actionable_gaps,
        "blocked_gaps": blocked_gaps,
        "validation_results_loaded": len(validation_results),
        "outputs": {
            "attack_matrix": str(matrix_path.relative_to(REPO_ROOT)),
            "gap_report": str(gap_path.relative_to(REPO_ROOT)),
            "navigator": str(navigator_path.relative_to(REPO_ROOT)),
        },
    }
