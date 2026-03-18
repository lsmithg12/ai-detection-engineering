"""Generate a monthly pipeline performance report.

Reads:
  autonomous/budget-log.jsonl          — per-agent run data
  autonomous/orchestration/pipeline-metrics.jsonl — Phase 7 fine-grained metrics
  tests/results/*.json                 — validation F1 scores
  coverage/attack-matrix.md            — overall Fawkes coverage %

Writes:
  monitoring/reports/pipeline-{YYYY-MM}.md

Usage:
  python3 monitoring/generate-pipeline-report.py [YYYY-MM]
  python3 -c "from monitoring.generate_pipeline_report import generate_report; print(generate_report('2026-03'))"
"""

from __future__ import annotations

import json
import sys
import re
import datetime
from collections import defaultdict
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
BUDGET_LOG = REPO_ROOT / "autonomous" / "budget-log.jsonl"
PIPELINE_METRICS = REPO_ROOT / "autonomous" / "orchestration" / "pipeline-metrics.jsonl"
RESULTS_DIR = REPO_ROOT / "tests" / "results"
ATTACK_MATRIX = REPO_ROOT / "coverage" / "attack-matrix.md"
REPORTS_DIR = REPO_ROOT / "monitoring" / "reports"

# Agent display order for the summary table
AGENT_ORDER = [
    "intel",
    "red-team",
    "blue-team",
    "author",
    "validation",
    "deployment",
    "quality",
    "security",
    "tuning",
    "coverage",
]


# ---------------------------------------------------------------------------
# Data loading helpers
# ---------------------------------------------------------------------------

def _load_budget_log(month: str) -> list[dict]:
    """Return all budget-log entries for the given month (YYYY-MM)."""
    entries: list[dict] = []
    if not BUDGET_LOG.exists():
        return entries
    with open(BUDGET_LOG, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = entry.get("timestamp") or entry.get("date", "")
            if ts.startswith(month):
                entries.append(entry)
    return entries


def _load_pipeline_metrics(month: str) -> list[dict]:
    """Return pipeline-metrics entries for the given month, if file exists."""
    entries: list[dict] = []
    if not PIPELINE_METRICS.exists():
        return entries
    with open(PIPELINE_METRICS, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = entry.get("timestamp") or entry.get("date", "")
            if ts.startswith(month):
                entries.append(entry)
    return entries


def _load_f1_scores() -> dict[str, float]:
    """Return {technique_id: f1_score} from tests/results/*.json."""
    scores: dict[str, float] = {}
    if not RESULTS_DIR.exists():
        return scores
    for f in RESULTS_DIR.glob("*.json"):
        try:
            with open(f, encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError):
            continue
        tid = data.get("technique_id", f.stem.upper())
        f1 = (data.get("metrics") or {}).get("f1_score")
        if f1 is not None:
            scores[tid] = float(f1)
    return scores


def _load_coverage_pct() -> Optional[str]:
    """Parse the overall Fawkes coverage percentage from attack-matrix.md."""
    if not ATTACK_MATRIX.exists():
        return None
    try:
        text = ATTACK_MATRIX.read_text(encoding="utf-8")
    except OSError:
        return None
    # Look for a line like: **Fawkes technique coverage**: 14 / 21 core techniques (67%)
    m = re.search(r"Fawkes technique coverage[^:]*:\s*([\d\s/]+core techniques\s*\(\d+%\))", text)
    if m:
        return m.group(1).strip()
    # Simpler fallback: just grab the percentage
    m2 = re.search(r"(\d+\s*/\s*\d+\s+core techniques\s*\(\d+%\))", text)
    if m2:
        return m2.group(1).strip()
    return None


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------

def _agent_run_summary(budget_entries: list[dict]) -> tuple[str, dict[str, dict]]:
    """
    Build the Agent Run Summary table and return (markdown_section, per_agent_stats).
    per_agent_stats: {agent: {runs, total_duration, avg_duration, errors, retries, tokens}}
    """
    stats: dict[str, dict] = defaultdict(lambda: {
        "runs": 0,
        "total_duration": 0.0,
        "errors": 0,
        "retries": 0,
        "tokens": 0,
    })

    for entry in budget_entries:
        agent = entry.get("agent", "unknown")
        s = stats[agent]
        s["runs"] += 1
        s["total_duration"] += entry.get("duration_seconds", 0.0)
        s["tokens"] += entry.get("estimated_tokens", 0)
        status = entry.get("status", "")
        if status == "error" or status == "failed":
            s["errors"] += 1
        if entry.get("retry_count", 0):
            s["retries"] += int(entry.get("retry_count", 0))

    lines: list[str] = []
    lines.append("## Agent Run Summary")
    lines.append("")
    lines.append(
        "| Agent | Runs | Total Duration | Avg Duration | Errors | Retries |"
    )
    lines.append(
        "|-------|------|----------------|--------------|--------|---------|"
    )

    def _fmt_dur(secs: float) -> str:
        if secs < 60:
            return f"{secs:.1f}s"
        mins = secs / 60
        if mins < 60:
            return f"{mins:.1f}m"
        return f"{mins / 60:.1f}h"

    # Show agents in canonical order, then any extras alphabetically
    seen: set[str] = set()
    ordered_agents: list[str] = []
    for a in AGENT_ORDER:
        if a in stats:
            ordered_agents.append(a)
            seen.add(a)
    for a in sorted(stats.keys()):
        if a not in seen:
            ordered_agents.append(a)

    for agent in ordered_agents:
        s = stats[agent]
        runs = s["runs"]
        total_dur = s["total_duration"]
        avg_dur = total_dur / runs if runs > 0 else 0.0
        lines.append(
            f"| {agent} | {runs} | {_fmt_dur(total_dur)} "
            f"| {_fmt_dur(avg_dur)} | {s['errors']} | {s['retries']} |"
        )

    if not ordered_agents:
        lines.append("| — | — | — | — | — | — |")

    return "\n".join(lines), dict(stats)


def _token_section(per_agent_stats: dict[str, dict]) -> str:
    """Build the Token Usage section."""
    lines: list[str] = []
    lines.append("## Token Usage")
    lines.append("")

    total_tokens = sum(s["tokens"] for s in per_agent_stats.values())
    if total_tokens == 0:
        lines.append(
            "- Total estimated tokens: 0 (no runs recorded for this month)"
        )
        return "\n".join(lines)

    lines.append(f"- Total estimated tokens: {total_tokens:,}")

    # Most expensive agent
    most_expensive = max(per_agent_stats.items(), key=lambda kv: kv[1]["tokens"])
    agent_name, agent_stats = most_expensive
    pct = round(agent_stats["tokens"] / total_tokens * 100, 1) if total_tokens else 0
    lines.append(f"- Most expensive agent: {agent_name} ({pct}% of tokens)")

    return "\n".join(lines)


def _effectiveness_section(f1_scores: dict[str, float],
                            coverage_pct: Optional[str]) -> str:
    """Build the Effectiveness section."""
    lines: list[str] = []
    lines.append("## Effectiveness")
    lines.append("")

    if f1_scores:
        # Bucket by quality tier
        auto_deploy = sum(1 for v in f1_scores.values() if v >= 0.90)
        validated = sum(1 for v in f1_scores.values() if 0.75 <= v < 0.90)
        needs_rework = sum(1 for v in f1_scores.values() if v < 0.75)
        mean_f1 = round(sum(f1_scores.values()) / len(f1_scores), 3)

        lines.append("### F1 Score Distribution")
        lines.append(f"- Rules evaluated: {len(f1_scores)}")
        lines.append(f"- Mean F1: {mean_f1}")
        lines.append(f"- Auto-deploy tier (F1 >= 0.90): {auto_deploy}")
        lines.append(f"- Validated tier (0.75 <= F1 < 0.90): {validated}")
        lines.append(f"- Needs rework (F1 < 0.75): {needs_rework}")
    else:
        lines.append("### F1 Score Distribution")
        lines.append("- No test results found in tests/results/")

    lines.append("")
    lines.append("### Coverage")
    if coverage_pct:
        lines.append(f"- Fawkes technique coverage: {coverage_pct}")
    else:
        lines.append(
            "- Coverage: unable to parse coverage/attack-matrix.md"
        )

    return "\n".join(lines)


def _budget_table_section(per_agent_stats: dict[str, dict],
                           budget_entries: list[dict]) -> str:
    """Build the Budget vs Target section."""
    lines: list[str] = []
    lines.append("## Budget vs Target")
    lines.append("")

    # Default token budgets per agent per month (approximate — adjust as needed)
    default_budgets: dict[str, int] = {
        "intel": 50_000,
        "red-team": 30_000,
        "blue-team": 500_000,
        "author": 200_000,
        "validation": 100_000,
        "deployment": 20_000,
        "quality": 50_000,
        "security": 40_000,
        "tuning": 60_000,
        "coverage": 20_000,
    }

    lines.append("| Agent | Budget (tokens) | Used (tokens) | % |")
    lines.append("|-------|-----------------|---------------|---|")

    # Show agents in canonical order, then any extras
    seen: set[str] = set()
    ordered_agents: list[str] = []
    for a in AGENT_ORDER:
        if a in per_agent_stats:
            ordered_agents.append(a)
            seen.add(a)
    for a in sorted(per_agent_stats.keys()):
        if a not in seen:
            ordered_agents.append(a)

    for agent in ordered_agents:
        used = per_agent_stats[agent]["tokens"]
        budget = default_budgets.get(agent, 100_000)
        pct = round(used / budget * 100, 1) if budget else 0
        lines.append(
            f"| {agent} | {budget:,} | {used:,} | {pct}% |"
        )

    if not ordered_agents:
        lines.append("| — | — | — | — |")

    return "\n".join(lines)


def _pipeline_metrics_section(pipeline_entries: list[dict]) -> str:
    """Build optional Phase 7 pipeline metrics section."""
    lines: list[str] = []
    if not PIPELINE_METRICS.exists():
        lines.append("## Pipeline Metrics (Phase 7)")
        lines.append("")
        lines.append(
            "> No pipeline metrics yet — run agents to generate "
            f"`{PIPELINE_METRICS.relative_to(REPO_ROOT)}`"
        )
        return "\n".join(lines)

    if not pipeline_entries:
        lines.append("## Pipeline Metrics (Phase 7)")
        lines.append("")
        lines.append("> No pipeline metrics recorded for this month.")
        return "\n".join(lines)

    lines.append("## Pipeline Metrics (Phase 7)")
    lines.append("")

    # Aggregate by pipeline/stage if present
    stage_counts: dict[str, int] = defaultdict(int)
    stage_durations: dict[str, list[float]] = defaultdict(list)
    for entry in pipeline_entries:
        stage = entry.get("stage") or entry.get("pipeline") or "unknown"
        stage_counts[stage] += 1
        dur = entry.get("duration_seconds")
        if dur is not None:
            stage_durations[stage].append(float(dur))

    lines.append("| Stage | Runs | Avg Duration |")
    lines.append("|-------|------|--------------|")
    for stage in sorted(stage_counts):
        runs = stage_counts[stage]
        durs = stage_durations.get(stage, [])
        avg = round(sum(durs) / len(durs), 1) if durs else None
        avg_str = f"{avg}s" if avg is not None else "—"
        lines.append(f"| {stage} | {runs} | {avg_str} |")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main report generator
# ---------------------------------------------------------------------------

def generate_report(month: str | None = None) -> str:
    """
    Generate a monthly pipeline performance Markdown report.

    Parameters
    ----------
    month : str, optional
        Target month in "YYYY-MM" format. Defaults to the current month.

    Returns
    -------
    str
        The full Markdown report text.
    """
    if month is None:
        month = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")

    year_str, mon_str = month.split("-")
    month_label = datetime.datetime(
        int(year_str), int(mon_str), 1
    ).strftime("%B %Y")

    budget_entries = _load_budget_log(month)
    pipeline_entries = _load_pipeline_metrics(month)
    f1_scores = _load_f1_scores()
    coverage_pct = _load_coverage_pct()

    agent_summary_md, per_agent_stats = _agent_run_summary(budget_entries)
    token_md = _token_section(per_agent_stats)
    effectiveness_md = _effectiveness_section(f1_scores, coverage_pct)
    budget_md = _budget_table_section(per_agent_stats, budget_entries)
    pipeline_md = _pipeline_metrics_section(pipeline_entries)

    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )

    sections = [
        f"# Pipeline Performance: {month_label}",
        "",
        agent_summary_md,
        "",
        token_md,
        "",
        effectiveness_md,
        "",
        budget_md,
        "",
        pipeline_md,
        "",
        f"*Generated {generated_at}*",
    ]

    report = "\n".join(sections)

    # Write to monitoring/reports/
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = REPORTS_DIR / f"pipeline-{month}.md"
    out_path.write_text(report, encoding="utf-8")

    return report


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    target_month: Optional[str] = None
    if len(sys.argv) > 1:
        arg = sys.argv[1].strip()
        if re.match(r"^\d{4}-\d{2}$", arg):
            target_month = arg
        else:
            print(f"Usage: {sys.argv[0]} [YYYY-MM]", file=sys.stderr)
            sys.exit(1)

    report_text = generate_report(target_month)
    print(report_text)
