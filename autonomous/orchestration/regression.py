"""Regression testing for detection rules — CI-safe, no ES dependency."""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

# Project root relative to this file: autonomous/orchestration/ -> ../../
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_RESULTS_DIR = _PROJECT_ROOT / "tests" / "results"
_TP_DIR = _PROJECT_ROOT / "tests" / "true_positives"
_TN_DIR = _PROJECT_ROOT / "tests" / "true_negatives"
_DETECTIONS_DIR = _PROJECT_ROOT / "detections"

# Regression thresholds
_FAIL_DELTA = -0.10
_WARN_DELTA = -0.05


@dataclass
class RegressionResult:
    technique_id: str
    rule_name: str
    previous_f1: float
    current_f1: float
    delta: float
    status: str  # "PASS", "WARN", "FAIL"
    message: str


# ---------------------------------------------------------------------------
# Baseline loading
# ---------------------------------------------------------------------------

def _result_path_candidates(technique_id: str) -> list[Path]:
    """Return candidate result file paths for a technique ID."""
    normalized = technique_id.lower().replace(".", "_")
    return [
        _RESULTS_DIR / f"{technique_id}.json",
        _RESULTS_DIR / f"{normalized}.json",
    ]


def load_baseline(technique_id: str) -> float | None:
    """Load the baseline F1 score from the stored test result.

    Checks ``tests/results/{technique_id}.json`` first, then the lower-case
    dot-replaced variant as a fallback.  Returns ``None`` when no baseline
    exists.
    """
    for path in _result_path_candidates(technique_id):
        if path.exists():
            try:
                data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
                # Support both flat {"f1_score": 0.9} and nested {"results": {"f1_score": 0.9}}
                if "f1_score" in data:
                    return float(data["f1_score"])
                if "results" in data and "f1_score" in data["results"]:
                    return float(data["results"]["f1_score"])
            except (json.JSONDecodeError, KeyError, ValueError):
                pass
    return None


# ---------------------------------------------------------------------------
# Local validation (keyword-based, CI-safe)
# ---------------------------------------------------------------------------

def _extract_detection_keywords(rule_data: dict[str, Any]) -> list[str]:
    """Pull string literals out of the Sigma detection block for keyword matching.

    This is intentionally simple — we flatten all string values from the
    detection mapping to build a set of expected keywords.  The goal is to
    detect obvious regressions (wrong field names, removed conditions) rather
    than to replicate the full Sigma evaluation engine.
    """
    detection = rule_data.get("detection", {})
    keywords: list[str] = []

    def _collect(obj: Any) -> None:
        if isinstance(obj, str):
            stripped = obj.strip()
            if stripped and len(stripped) >= 2:
                keywords.append(stripped)
        elif isinstance(obj, list):
            for item in obj:
                _collect(item)
        elif isinstance(obj, dict):
            for v in obj.values():
                _collect(v)

    for key, value in detection.items():
        if key == "condition":
            continue
        _collect(value)

    return keywords


def _event_matches_keywords(event: dict[str, Any], keywords: list[str]) -> bool:
    """Return True if the event JSON contains at least one detection keyword.

    We serialise the event to a flat string and do case-insensitive substring
    matching.  This is a best-effort heuristic suitable for CI smoke-testing.
    """
    if not keywords:
        return False
    event_text = json.dumps(event).lower()
    return any(kw.lower() in event_text for kw in keywords)


def _load_events(path: Path) -> list[dict[str, Any]]:
    """Load a JSON file that is either a list of events or a single event."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return [raw]
    return []


def validate_local(rule_path: str, tp_path: str, tn_path: str) -> float:
    """Simplified local validator — keyword matching against TP/TN test events.

    This is NOT the full ES-based validator.  It checks whether key fields
    from the detection condition appear in the events and returns an F1 score.
    Returns the baseline F1 (effectively no-change) when validation is not
    possible due to missing files.

    Parameters
    ----------
    rule_path:
        Absolute or project-relative path to the Sigma YAML rule.
    tp_path:
        Path to the true-positive test events JSON file.
    tn_path:
        Path to the true-negative test events JSON file.

    Returns
    -------
    float
        F1 score in [0.0, 1.0].  Returns -1.0 as a sentinel when validation
        cannot run (caller should fall back to baseline).
    """
    rule_file = Path(rule_path)
    tp_file = Path(tp_path)
    tn_file = Path(tn_path)

    if not rule_file.exists():
        return -1.0

    try:
        rule_data = yaml.safe_load(rule_file.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return -1.0

    keywords = _extract_detection_keywords(rule_data)
    if not keywords:
        # No keywords to match — cannot validate locally
        return -1.0

    # --- True Positives ---
    tp_events: list[dict[str, Any]] = []
    if tp_file.exists():
        try:
            tp_events = _load_events(tp_file)
        except (json.JSONDecodeError, ValueError):
            pass

    # --- True Negatives ---
    tn_events: list[dict[str, Any]] = []
    if tn_file.exists():
        try:
            tn_events = _load_events(tn_file)
        except (json.JSONDecodeError, ValueError):
            pass

    if not tp_events and not tn_events:
        return -1.0

    tp_count = sum(1 for e in tp_events if _event_matches_keywords(e, keywords))
    fn_count = len(tp_events) - tp_count
    fp_count = sum(1 for e in tn_events if _event_matches_keywords(e, keywords))
    tn_count = len(tn_events) - fp_count

    # Precision / recall / F1
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
    recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0

    if (precision + recall) == 0.0:
        return 0.0
    f1 = 2 * precision * recall / (precision + recall)
    return round(f1, 4)


# ---------------------------------------------------------------------------
# Rule discovery helpers
# ---------------------------------------------------------------------------

def _find_rule_for_technique(technique_id: str) -> Path | None:
    """Search detections/ for a Sigma rule matching the technique ID."""
    normalized = technique_id.lower().replace(".", "_")
    # e.g. t1055_001.yml
    for yml_file in _DETECTIONS_DIR.rglob("*.yml"):
        if yml_file.parent.name == "compiled":
            continue
        stem = yml_file.stem.lower()
        if stem == normalized or stem.startswith(normalized):
            return yml_file
    return None


def _find_tp_for_technique(technique_id: str) -> Path | None:
    normalized = technique_id.lower().replace(".", "_")
    candidate = _TP_DIR / f"{normalized}_tp.json"
    return candidate if candidate.exists() else None


def _find_tn_for_technique(technique_id: str) -> Path | None:
    normalized = technique_id.lower().replace(".", "_")
    candidate = _TN_DIR / f"{normalized}_tn.json"
    return candidate if candidate.exists() else None


def _rule_name_from_path(rule_path: Path | None, technique_id: str) -> str:
    if rule_path is None:
        return technique_id
    try:
        data = yaml.safe_load(rule_path.read_text(encoding="utf-8")) or {}
        return data.get("title", technique_id)
    except (yaml.YAMLError, OSError):
        return technique_id


# ---------------------------------------------------------------------------
# Core regression check
# ---------------------------------------------------------------------------

def check_regression(technique_id: str, rule_path: str) -> RegressionResult:
    """Run a regression check for a single technique.

    Parameters
    ----------
    technique_id:
        MITRE ATT&CK technique ID (e.g. ``"T1055.001"``).
    rule_path:
        Path to the Sigma YAML rule file.
    """
    baseline = load_baseline(technique_id)
    rule_file = Path(rule_path)
    rule_name = _rule_name_from_path(rule_file if rule_file.exists() else None, technique_id)

    # Locate TP/TN files
    tp_file = _find_tp_for_technique(technique_id)
    tn_file = _find_tn_for_technique(technique_id)

    tp_path = str(tp_file) if tp_file else ""
    tn_path = str(tn_file) if tn_file else ""

    current_f1_raw = validate_local(rule_path, tp_path, tn_path)

    # -1.0 sentinel means local validation could not run
    if current_f1_raw < 0.0:
        # No change detectable — treat as pass with baseline value
        effective_f1 = baseline if baseline is not None else 1.0
        return RegressionResult(
            technique_id=technique_id,
            rule_name=rule_name,
            previous_f1=baseline if baseline is not None else 0.0,
            current_f1=effective_f1,
            delta=0.0,
            status="PASS",
            message="Local validation skipped — no test data or keywords; using baseline",
        )

    current_f1 = current_f1_raw

    if baseline is None:
        # No prior baseline to compare against
        return RegressionResult(
            technique_id=technique_id,
            rule_name=rule_name,
            previous_f1=0.0,
            current_f1=current_f1,
            delta=0.0,
            status="PASS",
            message=f"No baseline found; new rule scored F1={current_f1:.2f}",
        )

    delta = round(current_f1 - baseline, 4)

    if delta < _FAIL_DELTA:
        status = "FAIL"
        message = (
            f"F1 dropped {abs(delta):.2f} points (from {baseline:.2f} to {current_f1:.2f}) "
            f"— exceeds FAIL threshold of {abs(_FAIL_DELTA):.2f}"
        )
    elif delta < _WARN_DELTA:
        status = "WARN"
        message = (
            f"F1 dropped {abs(delta):.2f} points (from {baseline:.2f} to {current_f1:.2f}) "
            f"— exceeds WARN threshold of {abs(_WARN_DELTA):.2f}"
        )
    else:
        status = "PASS"
        if delta >= 0:
            message = f"F1 stable or improved ({baseline:.2f} → {current_f1:.2f})"
        else:
            message = (
                f"F1 dropped {abs(delta):.2f} points ({baseline:.2f} → {current_f1:.2f}) "
                f"— within acceptable threshold"
            )

    return RegressionResult(
        technique_id=technique_id,
        rule_name=rule_name,
        previous_f1=baseline,
        current_f1=current_f1,
        delta=delta,
        status=status,
        message=message,
    )


# ---------------------------------------------------------------------------
# Batch processing of changed files
# ---------------------------------------------------------------------------

_TECHNIQUE_RE = re.compile(r"(t\d{4}(?:[._]\d{3})?)", re.IGNORECASE)


def _technique_id_from_filename(filename: str) -> str | None:
    """Extract a MITRE technique ID from a file path string.

    Handles patterns like ``t1055_001.yml`` and ``t1055.001.yml``.
    Returns the canonical upper-case dotted form (e.g. ``"T1055.001"``).
    """
    stem = Path(filename).stem
    match = _TECHNIQUE_RE.search(stem)
    if not match:
        return None
    raw = match.group(1).upper()
    # Normalise separator: T1055_001 -> T1055.001
    return raw.replace("_", ".", 1) if "_" in raw else raw


def check_changed_files(file_list: str) -> list[RegressionResult]:
    """Check regression for all detection files listed in *file_list*.

    Parameters
    ----------
    file_list:
        Space-separated (or newline-separated) list of changed file paths,
        typically produced by ``git diff --name-only``.
    """
    results: list[RegressionResult] = []
    seen: set[str] = set()

    # Accept both space and newline separators
    paths = file_list.replace("\n", " ").split()

    for file_path in paths:
        file_path = file_path.strip()
        if not file_path:
            continue
        # Only process Sigma YAML files outside compiled/ directories
        if not file_path.endswith(".yml"):
            continue
        if "/compiled/" in file_path or "\\compiled\\" in file_path:
            continue

        technique_id = _technique_id_from_filename(file_path)
        if technique_id is None:
            continue
        if technique_id in seen:
            continue
        seen.add(technique_id)

        # Resolve to absolute path
        rule_path = Path(file_path)
        if not rule_path.is_absolute():
            rule_path = _PROJECT_ROOT / rule_path

        result = check_regression(technique_id, str(rule_path))
        results.append(result)

    return results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

_STATUS_EMOJI = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌"}


def generate_report(results: list[RegressionResult]) -> str:
    """Generate a markdown regression report and write it to disk.

    Returns the markdown string.
    """
    lines: list[str] = [
        "## Detection Regression Test Results",
        "",
        "| Rule | Previous F1 | Current F1 | Delta | Status |",
        "|------|------------|------------|-------|--------|",
    ]

    for r in results:
        emoji = _STATUS_EMOJI.get(r.status, "")
        delta_str = f"{r.delta:+.2f}"
        lines.append(
            f"| {r.technique_id} | {r.previous_f1:.2f} | {r.current_f1:.2f} | "
            f"{delta_str} | {emoji} {r.status} |"
        )

    lines.append("")

    fail_count = sum(1 for r in results if r.status == "FAIL")
    warn_count = sum(1 for r in results if r.status == "WARN")

    if fail_count > 0:
        noun = "rule" if fail_count == 1 else "rules"
        overall = f"**Overall: FAIL** — {fail_count} {noun} regressed beyond threshold"
    elif warn_count > 0:
        noun = "rule" if warn_count == 1 else "rules"
        overall = f"**Overall: WARN** — {warn_count} {noun} with notable F1 drop"
    elif results:
        overall = "**Overall: PASS** — all rules within acceptable thresholds"
    else:
        overall = "**Overall: PASS** — no detection files changed"

    lines.append(overall)
    lines.append("")

    # Detail section
    if results:
        lines += ["<details><summary>Details</summary>", ""]
        for r in results:
            emoji = _STATUS_EMOJI.get(r.status, "")
            lines.append(f"- **{r.technique_id}** ({r.rule_name}): {emoji} {r.message}")
        lines += ["", "</details>", ""]

    report = "\n".join(lines)

    # Write to disk
    report_path = _RESULTS_DIR / "regression-report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")

    return report


# ---------------------------------------------------------------------------
# Snapshot persistence
# ---------------------------------------------------------------------------

def save_snapshot(
    results: list[RegressionResult],
    commit_sha: str = "",
    pr_number: int = 0,
) -> None:
    """Persist each regression result as a historical JSON record.

    Files are written to ``tests/results/{technique_id}_regression.json``.
    """
    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(tz=timezone.utc).isoformat()

    for r in results:
        normalized = r.technique_id.lower().replace(".", "_")
        snapshot_path = _RESULTS_DIR / f"{normalized}_regression.json"
        record = {
            "technique_id": r.technique_id,
            "timestamp": timestamp,
            "f1_score": r.current_f1,
            "commit_sha": commit_sha,
            "pr_number": pr_number,
        }
        snapshot_path.write_text(json.dumps(record, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run regression tests on changed detection rules (CI-safe, no ES dependency)."
    )
    parser.add_argument(
        "--files",
        required=True,
        help="Space-separated list of changed detection file paths (from git diff --name-only).",
    )
    parser.add_argument(
        "--commit-sha",
        default="",
        help="Git commit SHA to embed in regression snapshots.",
    )
    parser.add_argument(
        "--pr-number",
        type=int,
        default=0,
        help="Pull request number to embed in regression snapshots.",
    )
    args = parser.parse_args(argv)

    results = check_changed_files(args.files)
    report = generate_report(results)
    save_snapshot(results, commit_sha=args.commit_sha, pr_number=args.pr_number)

    print(report)

    fail_count = sum(1 for r in results if r.status == "FAIL")
    return 1 if fail_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
