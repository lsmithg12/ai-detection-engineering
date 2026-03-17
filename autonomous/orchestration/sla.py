"""SLA tracking for the detection pipeline.

Computes phase-by-phase durations from the changelog stored in each detection
request YAML and reports compliance against configured SLA targets.
"""

import sys
import json
import datetime
from pathlib import Path
from typing import Optional

import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
AUTONOMOUS_DIR = REPO_ROOT / "autonomous"
REQUESTS_DIR = AUTONOMOUS_DIR / "detection-requests"
MONITORING_DIR = REPO_ROOT / "monitoring" / "reports"

SLA_TARGETS_HOURS: dict[str, int] = {
    "critical": 48,
    "high": 168,
    "medium": 336,
    "low": 720,
}

# Ordered pipeline phases used to compute phase durations.
# Each entry is (start_action_keywords, end_action_keywords, label).
# We look for the *first* changelog entry whose action contains any keyword in
# the start set, then the *first* subsequent entry whose action contains any
# keyword in the end set.
_PHASE_SPECS: list[tuple[tuple[str, ...], tuple[str, ...], str]] = [
    (
        ("created",),
        ("AUTHORED", "transition:SCENARIO_BUILT->AUTHORED", "transition:REQUESTED->AUTHORED"),
        "REQUESTED->AUTHORED",
    ),
    (
        ("AUTHORED", "transition:SCENARIO_BUILT->AUTHORED"),
        ("VALIDATED", "transition:AUTHORED->VALIDATED"),
        "AUTHORED->VALIDATED",
    ),
    (
        ("VALIDATED", "transition:AUTHORED->VALIDATED"),
        ("DEPLOYED", "transition:VALIDATED->DEPLOYED"),
        "VALIDATED->DEPLOYED",
    ),
]

# States considered "completed" (SLA assessment is final)
COMPLETED_STATES = {"DEPLOYED", "MONITORING"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    from orchestration.state import StateManager as _StateManager

    def _load_all_requests() -> list[dict]:
        """Load all detection requests via StateManager."""
        sm = _StateManager()
        return sm.list_all()

except Exception:
    # Fallback: read YAML files directly
    def _load_all_requests() -> list[dict]:
        """Load all detection requests directly from YAML files."""
        results: list[dict] = []
        for f in sorted(REQUESTS_DIR.glob("*.yml")):
            if f.name.startswith("_"):
                continue
            try:
                with open(f, encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
                if data:
                    results.append(data)
            except Exception:
                pass
        return results


def _parse_iso(ts: str) -> Optional[datetime.datetime]:
    """Parse an ISO-8601 UTC timestamp to a timezone-aware datetime."""
    if not ts:
        return None
    # Handle both 'Z' suffix and '+00:00' offset
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    try:
        return datetime.datetime.fromisoformat(ts)
    except ValueError:
        return None


def _action_matches(action: str, keywords: tuple[str, ...]) -> bool:
    """Return True if action contains any of the given keyword substrings."""
    action_upper = action.upper()
    for kw in keywords:
        if kw.upper() in action_upper:
            return True
    return False


def _first_timestamp(changelog: list[dict], keywords: tuple[str, ...],
                     after: Optional[datetime.datetime] = None
                     ) -> Optional[datetime.datetime]:
    """
    Return the timestamp of the first changelog entry whose action matches
    *keywords*, optionally restricting to entries after *after*.
    """
    for entry in changelog:
        action = entry.get("action", "")
        if not _action_matches(action, keywords):
            continue
        ts = _parse_iso(entry.get("date", ""))
        if ts is None:
            continue
        if after is not None and ts <= after:
            continue
        return ts
    return None


def _hours_between(start: Optional[datetime.datetime],
                   end: Optional[datetime.datetime]) -> Optional[float]:
    if start is None or end is None:
        return None
    delta = end - start
    return round(delta.total_seconds() / 3600, 2)


# ---------------------------------------------------------------------------
# Core SLA functions
# ---------------------------------------------------------------------------

def calculate_sla(technique_id: str) -> dict:
    """
    Compute SLA information for a single technique.

    Returns a dict with keys:
      technique_id, priority, sla_target_hours, phases, sla_status
    where phases maps phase label -> hours (or None if not yet reached).
    sla_status is one of: "MET", "BREACH", "IN_PROGRESS", "UNKNOWN"
    """
    all_requests = _load_all_requests()
    request: Optional[dict] = None
    for r in all_requests:
        if r.get("technique_id", "").upper() == technique_id.upper():
            request = r
            break

    if request is None:
        return {
            "technique_id": technique_id,
            "priority": "unknown",
            "sla_target_hours": None,
            "phases": {},
            "end_to_end_hours": None,
            "sla_status": "UNKNOWN",
        }

    return _calculate_sla_from_request(request)


def _calculate_sla_from_request(request: dict) -> dict:
    """Internal: compute SLA from a loaded request dict."""
    technique_id = request.get("technique_id", "UNKNOWN")
    priority = (request.get("priority") or "medium").lower()
    sla_target = SLA_TARGETS_HOURS.get(priority, SLA_TARGETS_HOURS["medium"])
    status = request.get("status", "UNKNOWN")
    changelog: list[dict] = request.get("changelog") or []

    # Compute per-phase durations
    phases: dict[str, Optional[float]] = {}
    prev_end_ts: Optional[datetime.datetime] = None

    for start_kws, end_kws, label in _PHASE_SPECS:
        # Find phase start: first entry matching start keywords (after prev phase end)
        start_ts = _first_timestamp(changelog, start_kws, after=prev_end_ts)
        if start_ts is None:
            # If not found after prev_end, search from the beginning (handles
            # cases where the end timestamp of the prior phase IS the start of
            # this one, e.g. same action triggers both)
            start_ts = _first_timestamp(changelog, start_kws)

        end_ts = _first_timestamp(changelog, end_kws, after=start_ts)
        phases[label] = _hours_between(start_ts, end_ts)
        if end_ts is not None:
            prev_end_ts = end_ts

    # End-to-end: from very first changelog entry to DEPLOYED/MONITORING
    first_ts = _first_timestamp(changelog, ("created", "REQUESTED"))
    if first_ts is None and changelog:
        # Fallback: use the very first entry's timestamp
        first_ts = _parse_iso(changelog[0].get("date", ""))

    deployed_ts = _first_timestamp(changelog,
                                   ("DEPLOYED", "transition:VALIDATED->DEPLOYED",
                                    "MONITORING", "transition:DEPLOYED->MONITORING"))

    end_to_end = _hours_between(first_ts, deployed_ts)

    # Determine SLA status
    if status in COMPLETED_STATES:
        if end_to_end is None:
            sla_status = "UNKNOWN"
        elif end_to_end <= sla_target:
            sla_status = "MET"
        else:
            sla_status = "BREACH"
    else:
        # In progress — check if we are already overdue
        if first_ts is not None:
            now = datetime.datetime.now(datetime.timezone.utc)
            elapsed = (now - first_ts).total_seconds() / 3600
            if elapsed > sla_target:
                sla_status = "BREACH"
            else:
                sla_status = "IN_PROGRESS"
        else:
            sla_status = "UNKNOWN"

    return {
        "technique_id": technique_id,
        "priority": priority,
        "sla_target_hours": sla_target,
        "phases": phases,
        "end_to_end_hours": end_to_end,
        "sla_status": sla_status,
    }


def get_all_sla_status() -> list[dict]:
    """Return SLA information for every known detection request."""
    all_requests = _load_all_requests()
    return [_calculate_sla_from_request(r) for r in all_requests]


def check_breaches() -> list[dict]:
    """
    Return only completed (DEPLOYED or MONITORING) detections that have
    breached their SLA (end-to-end hours > SLA target).
    """
    all_requests = _load_all_requests()
    breaches: list[dict] = []
    for r in all_requests:
        if r.get("status") not in COMPLETED_STATES:
            continue
        sla = _calculate_sla_from_request(r)
        if sla["sla_status"] == "BREACH":
            breaches.append(sla)
    return breaches


# ---------------------------------------------------------------------------
# Monthly report
# ---------------------------------------------------------------------------

def generate_monthly_report(month: str | None = None) -> str:
    """
    Generate a Markdown SLA report for *month* (format: "YYYY-MM").
    Defaults to the current month.
    Writes to monitoring/reports/sla-{month}.md and returns the Markdown text.
    """
    if month is None:
        month = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")

    year_str, mon_str = month.split("-")
    year, mon = int(year_str), int(mon_str)
    month_start = datetime.datetime(year, mon, 1, tzinfo=datetime.timezone.utc)
    # First day of next month
    if mon == 12:
        month_end = datetime.datetime(year + 1, 1, 1, tzinfo=datetime.timezone.utc)
    else:
        month_end = datetime.datetime(year, mon + 1, 1, tzinfo=datetime.timezone.utc)

    month_label = month_start.strftime("%B %Y")

    all_requests = _load_all_requests()

    # Filter to detections that completed (reached DEPLOYED or MONITORING)
    # during the report month, or were still in progress within the month.
    completed_in_month: list[dict] = []
    in_progress: list[dict] = []

    for r in all_requests:
        changelog: list[dict] = r.get("changelog") or []
        status = r.get("status", "")

        if status in COMPLETED_STATES:
            # Find when it was first deployed
            deployed_ts = _first_timestamp(
                changelog,
                ("DEPLOYED", "transition:VALIDATED->DEPLOYED",
                 "MONITORING", "transition:DEPLOYED->MONITORING"),
            )
            if deployed_ts and month_start <= deployed_ts < month_end:
                completed_in_month.append(r)
        else:
            # Check if the request was created on or before end of month
            first_ts = _first_timestamp(changelog, ("created", "REQUESTED"))
            if first_ts is None and changelog:
                first_ts = _parse_iso(changelog[0].get("date", ""))
            if first_ts and first_ts < month_end:
                in_progress.append(r)

    # Compute SLA for completed items
    completed_sla = [_calculate_sla_from_request(r) for r in completed_in_month]

    met = [s for s in completed_sla if s["sla_status"] == "MET"]
    breached = [s for s in completed_sla if s["sla_status"] == "BREACH"]
    total_completed = len(completed_sla)

    # Mean end-to-end for completed
    e2e_values = [s["end_to_end_hours"] for s in completed_sla
                  if s["end_to_end_hours"] is not None]
    mean_e2e = round(sum(e2e_values) / len(e2e_values), 1) if e2e_values else None

    compliance_pct = (
        round(len(met) / total_completed * 100, 1) if total_completed > 0 else None
    )

    # Bottleneck: phase with highest average duration across completed items
    phase_totals: dict[str, list[float]] = {}
    for sla in completed_sla:
        for phase_label, hours in sla["phases"].items():
            if hours is not None:
                phase_totals.setdefault(phase_label, []).append(hours)

    bottleneck: Optional[str] = None
    bottleneck_avg: Optional[float] = None
    if phase_totals:
        avgs = {k: sum(v) / len(v) for k, v in phase_totals.items()}
        bottleneck = max(avgs, key=lambda k: avgs[k])
        bottleneck_avg = round(avgs[bottleneck], 1)

    # ---------------------------------------------------------------------------
    # Build Markdown
    # ---------------------------------------------------------------------------
    lines: list[str] = []

    lines.append(f"# SLA Report: {month_label}")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Detections completed: {total_completed}")
    lines.append(
        f"- Mean end-to-end: {mean_e2e}h" if mean_e2e is not None
        else "- Mean end-to-end: N/A"
    )
    if total_completed > 0 and compliance_pct is not None:
        lines.append(
            f"- SLA compliance: {len(met)}/{total_completed} ({compliance_pct}%)"
        )
    else:
        lines.append("- SLA compliance: N/A (no completions this month)")

    if breached:
        lines.append("- SLA breaches:")
        for s in breached:
            lines.append(
                f"  - {s['technique_id']} ({s['priority']}, "
                f"{s['end_to_end_hours']}h vs {s['sla_target_hours']}h target)"
            )
    else:
        lines.append("- SLA breaches: none")

    lines.append("")
    lines.append("## Detail")
    lines.append(
        "| Technique | Priority | Author (h) | Validate (h) | Deploy (h) | Total (h) | SLA |"
    )
    lines.append(
        "|-----------|----------|------------|--------------|------------|-----------|-----|"
    )

    def _fmt(v: Optional[float]) -> str:
        return f"{v}" if v is not None else "—"

    for sla in sorted(completed_sla, key=lambda s: s["technique_id"]):
        p = sla["phases"]
        lines.append(
            f"| {sla['technique_id']} "
            f"| {sla['priority']} "
            f"| {_fmt(p.get('REQUESTED->AUTHORED'))} "
            f"| {_fmt(p.get('AUTHORED->VALIDATED'))} "
            f"| {_fmt(p.get('VALIDATED->DEPLOYED'))} "
            f"| {_fmt(sla['end_to_end_hours'])} "
            f"| {sla['sla_status']} |"
        )

    if not completed_sla:
        lines.append("| — | — | — | — | — | — | — |")

    if in_progress:
        lines.append("")
        lines.append("### In Progress (not yet deployed)")
        lines.append("| Technique | Priority | Status | Elapsed (h) | SLA Target (h) |")
        lines.append("|-----------|----------|--------|-------------|----------------|")
        now = datetime.datetime.now(datetime.timezone.utc)
        for r in sorted(in_progress, key=lambda x: x.get("technique_id", "")):
            changelog: list[dict] = r.get("changelog") or []
            first_ts = _first_timestamp(changelog, ("created", "REQUESTED"))
            if first_ts is None and changelog:
                first_ts = _parse_iso(changelog[0].get("date", ""))
            elapsed = (
                round((now - first_ts).total_seconds() / 3600, 1)
                if first_ts else None
            )
            priority = (r.get("priority") or "medium").lower()
            target = SLA_TARGETS_HOURS.get(priority, SLA_TARGETS_HOURS["medium"])
            lines.append(
                f"| {r.get('technique_id', '?')} "
                f"| {priority} "
                f"| {r.get('status', '?')} "
                f"| {_fmt(elapsed)} "
                f"| {target} |"
            )

    lines.append("")
    lines.append("## Trends")
    if bottleneck and bottleneck_avg is not None:
        lines.append(f"- Bottleneck: **{bottleneck}** (avg {bottleneck_avg}h)")
        for phase_label, vals in sorted(phase_totals.items()):
            avg = round(sum(vals) / len(vals), 1)
            lines.append(f"  - {phase_label}: avg {avg}h")
    else:
        lines.append("- Bottleneck: insufficient data for this month")

    lines.append("")
    lines.append(
        f"*Generated {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}*"
    )

    report = "\n".join(lines)

    # Write to monitoring/reports/
    MONITORING_DIR.mkdir(parents=True, exist_ok=True)
    out_path = MONITORING_DIR / f"sla-{month}.md"
    out_path.write_text(report, encoding="utf-8")

    return report


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    all_sla = get_all_sla_status()

    if not all_sla:
        print("No detection requests found.")
        sys.exit(0)

    # Print a summary table
    header = (
        f"{'Technique':<15} {'Priority':<10} {'Status':<14} "
        f"{'E2E (h)':>8} {'Target (h)':>10} {'SLA':>12}"
    )
    sep = "-" * len(header)
    print(sep)
    print(header)
    print(sep)

    for s in sorted(all_sla, key=lambda x: x["technique_id"]):
        e2e = f"{s['end_to_end_hours']}" if s["end_to_end_hours"] is not None else "—"
        target = f"{s['sla_target_hours']}" if s["sla_target_hours"] is not None else "—"
        print(
            f"{s['technique_id']:<15} {s['priority']:<10} {s['sla_status']:<14} "
            f"{e2e:>8} {target:>10} {s['sla_status']:>12}"
        )

    print(sep)
    breaches = [s for s in all_sla if s["sla_status"] == "BREACH"]
    in_progress = [s for s in all_sla if s["sla_status"] == "IN_PROGRESS"]
    print(
        f"\nTotal: {len(all_sla)}  |  "
        f"Breaches: {len(breaches)}  |  "
        f"In Progress: {len(in_progress)}"
    )
