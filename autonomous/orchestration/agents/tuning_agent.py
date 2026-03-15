"""
Tuning Agent — Reviews deployed detections, tracks health metrics,
and makes tuning/retirement recommendations.

Renamed from quality_agent.py in Phase 4 (Task 4.4) with updated responsibilities:
- All original quality monitoring logic
- Future: feedback file reading from monitoring/feedback/verdicts.jsonl (Task 4.8)

Runs daily. Reads ALL agent journals for cross-agent insights.

Called by agent_runner.py. Implements run(state_manager) interface.
"""

import datetime
import json
from pathlib import Path

import yaml

from orchestration.state import StateManager
from orchestration import learnings
from orchestration import claude_llm

AUTONOMOUS_DIR = Path(__file__).resolve().parent.parent.parent
REPO_ROOT = AUTONOMOUS_DIR.parent
MONITORING_DIR = REPO_ROOT / "monitoring"
REPORTS_DIR = MONITORING_DIR / "reports"
FEEDBACK_DIR = MONITORING_DIR / "feedback"

AGENT_NAME = "tuning"
ALL_AGENTS = ["intel", "red-team", "author", "validation", "deployment", "tuning", "security"]


def _today() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- Health Score Calculation ---

def calculate_health(request: dict) -> dict:
    """
    Calculate composite health score for a deployed detection.

    Weights:
      signal_to_noise: 0.30
      tp_rate:         0.30
      cost:            0.15 (inverted -- lower cost = better)
      recency:         0.10
      stability:       0.15
    """
    tp_rate = request.get("tp_rate", 0.0)
    fp_rate = request.get("fp_rate", 0.0)
    alert_vol = request.get("alert_volume_24h", 0)
    quality_score = request.get("quality_score", 0.0)

    # Signal-to-noise (TP / FP ratio, capped at 1.0)
    if fp_rate > 0:
        stn_raw = (1 - fp_rate) / fp_rate
        stn = min(stn_raw / 10.0, 1.0)  # normalize: 10:1 ratio = 1.0
    else:
        stn = 1.0 if tp_rate > 0 else 0.5

    # Cost estimate (simple heuristic)
    cost_map = {"low": 0.1, "medium": 0.5, "high": 0.9}
    cost = cost_map.get(request.get("cost_estimate", "low"), 0.5)

    # Recency -- has it fired recently?
    recency = 1.0 if alert_vol > 0 else 0.3

    # Stability -- using quality_score as proxy (higher = more stable)
    stability = quality_score

    # Deployed duration
    deployed_date = request.get("deployed_date", "")
    days_deployed = 0
    if deployed_date:
        try:
            deployed_dt = datetime.datetime.fromisoformat(deployed_date.replace("Z", "+00:00"))
            days_deployed = (datetime.datetime.now(datetime.timezone.utc) - deployed_dt).days
        except (ValueError, TypeError):
            pass

    # Composite score
    health_score = (
        stn * 0.30 +
        tp_rate * 0.30 +
        (1 - cost) * 0.15 +
        recency * 0.10 +
        stability * 0.15
    )

    # Determine trend
    if alert_vol == 0 and days_deployed > 14:
        trend = "dead"
    elif alert_vol == 0:
        trend = "stable"
    else:
        trend = "active"

    return {
        "health_score": round(health_score, 3),
        "signal_to_noise": round(stn, 3),
        "tp_rate": tp_rate,
        "fp_rate": fp_rate,
        "cost_estimate": request.get("cost_estimate", "low"),
        "alert_volume_24h": alert_vol,
        "trend": trend,
        "days_deployed": days_deployed,
        "tuning_iterations": len([
            e for e in request.get("changelog", [])
            if "tune" in str(e.get("action", "")).lower()
        ]),
    }


def recommend_action(health: dict) -> tuple[str, str]:
    """
    Determine recommended action based on health score.
    Returns (action, reason).
    """
    score = health["health_score"]
    trend = health["trend"]

    if trend == "dead" and health["days_deployed"] > 14:
        return "INVESTIGATE", "No alerts for 14+ days -- may be broken or unnecessary"

    if score >= 0.80:
        return "HEALTHY", f"Health score {score} -- no action needed"
    elif score >= 0.60:
        reason = f"Health score {score} -- "
        if health["fp_rate"] > 0.10:
            reason += f"FP rate {health['fp_rate']} needs tuning"
        elif health["tp_rate"] < 0.80:
            reason += f"TP rate {health['tp_rate']} below target"
        else:
            reason += "marginal performance, monitor closely"
        return "TUNE", reason
    elif score >= 0.40:
        return "REVIEW", f"Health score {score} -- needs human review"
    else:
        return "RETIRE", f"Health score {score} -- recommend disabling"


def read_cross_agent_journals() -> dict[str, list[dict]]:
    """Read all agent journals for cross-agent insight."""
    journals = {}
    for agent in ALL_AGENTS:
        entries = []
        path = AUTONOMOUS_DIR / "learnings" / f"{agent}.jsonl"
        if path.exists():
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        journals[agent] = entries
    return journals


def read_feedback_verdicts() -> list[dict]:
    """
    Read analyst feedback verdicts from monitoring/feedback/verdicts.jsonl.

    Each line is a JSON object with fields like:
      {"alert_id": "...", "technique_id": "T1055.001", "verdict": "fp",
       "analyst": "...", "timestamp": "...", "notes": "..."}

    Returns list of verdict dicts (empty list if file doesn't exist yet).
    This is a placeholder for Task 4.8 which will create the feedback pipeline.
    """
    verdicts_path = FEEDBACK_DIR / "verdicts.jsonl"
    if not verdicts_path.exists():
        return []

    verdicts = []
    try:
        with open(verdicts_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    verdicts.append(json.loads(line))
    except (json.JSONDecodeError, OSError) as e:
        print(f"    [tuning] Warning: could not read feedback verdicts: {e}")
    return verdicts


def generate_daily_report(
    results: list[dict],
    fleet_stats: dict,
    cross_agent_insights: list[str],
) -> str:
    """Generate a markdown daily quality report."""
    report = f"""# Tuning Agent Report -- {_today()}

## Fleet Summary
- **Total deployed**: {fleet_stats.get('total', 0)}
- **Healthy**: {fleet_stats.get('healthy', 0)}
- **Needs tuning**: {fleet_stats.get('tune', 0)}
- **Needs review**: {fleet_stats.get('review', 0)}
- **Investigate (dead)**: {fleet_stats.get('investigate', 0)}
- **Retire recommended**: {fleet_stats.get('retire', 0)}

## Detection Health

| Technique | Title | Health | Action | Details |
|-----------|-------|--------|--------|---------|
"""
    for r in results:
        report += (
            f"| {r['technique_id']} | {r.get('title', '')[:30]} | "
            f"{r['health']['health_score']} | {r['action']} | {r['reason'][:50]} |\n"
        )

    if cross_agent_insights:
        report += "\n## Cross-Agent Insights\n\n"
        for insight in cross_agent_insights:
            report += f"- {insight}\n"

    report += f"\n---\n*Generated by tuning agent on {_now_iso()}*\n"
    return report


def run(state_manager: StateManager) -> dict:
    """
    Main entry point for the tuning agent.

    1. Load all agent journals for cross-agent insight
    2. Read analyst feedback verdicts (if available)
    3. Query DEPLOYED and MONITORING detections
    4. Calculate health metrics for each
    5. Generate recommendations
    6. Write daily report
    """
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    print(f"  [tuning] Starting tuning agent run {run_id}")

    # 1. Load briefing + cross-agent journals
    briefing = learnings.get_briefing(AGENT_NAME)
    print(f"  [tuning] {briefing}")

    journals = read_cross_agent_journals()
    total_entries = sum(len(v) for v in journals.values())
    print(f"  [tuning] Loaded {total_entries} total journal entries across {len(journals)} agents")

    # Cross-agent insights
    cross_agent_insights = []
    for agent, entries in journals.items():
        if agent == AGENT_NAME:
            continue
        errors = [e for e in entries if e.get("type") == "error" and not e.get("resolved")]
        if errors:
            cross_agent_insights.append(
                f"[{agent}] has {len(errors)} unresolved errors -- "
                f"latest: {errors[-1].get('title', '?')}"
            )

    if cross_agent_insights:
        print(f"  [tuning] Cross-agent insights:")
        for insight in cross_agent_insights:
            print(f"    - {insight}")

    # 2. Read analyst feedback verdicts
    verdicts = read_feedback_verdicts()
    if verdicts:
        print(f"  [tuning] Loaded {len(verdicts)} analyst feedback verdicts")
    else:
        print(f"  [tuning] No analyst feedback available (verdicts.jsonl not yet created)")

    # 3. Query DEPLOYED and MONITORING detections
    deployed = state_manager.query_by_state("DEPLOYED")
    monitoring = state_manager.query_by_state("MONITORING")
    all_active = deployed + monitoring

    if not all_active:
        print("  [tuning] No DEPLOYED or MONITORING detections. Nothing to review.")
        return {"summary": "No active detections to review", "detections_reviewed": 0}

    print(f"  [tuning] Found {len(all_active)} active detections "
          f"({len(deployed)} DEPLOYED, {len(monitoring)} MONITORING)")

    # 4. Calculate health for each
    results = []
    fleet_stats = {"total": len(all_active), "healthy": 0, "tune": 0,
                   "review": 0, "investigate": 0, "retire": 0}

    for request in all_active:
        tid = request["technique_id"]
        health = calculate_health(request)
        action, reason = recommend_action(health)

        print(f"    [{tid}] health={health['health_score']}, "
              f"action={action}: {reason}")

        # Update fleet stats
        action_lower = action.lower()
        if action_lower in fleet_stats:
            fleet_stats[action_lower] += 1

        # Update request with health metrics
        state_manager.update(
            tid, agent=AGENT_NAME,
            alert_volume_24h=health["alert_volume_24h"],
            last_quality_review=_now_iso(),
        )

        results.append({
            "technique_id": tid,
            "title": request.get("title", ""),
            "health": health,
            "action": action,
            "reason": reason,
        })

        # Transition DEPLOYED -> MONITORING if healthy
        if action == "HEALTHY" and request.get("status") == "DEPLOYED":
            try:
                state_manager.transition(tid, "MONITORING", agent=AGENT_NAME,
                                         details=f"Health score {health['health_score']} -- healthy")
                print(f"    [{tid}] Transitioned DEPLOYED -> MONITORING")
            except ValueError:
                pass  # May lack required artifacts, skip silently

    # 5. Ask Claude for fleet analysis (if available)
    llm_insights = []
    if claude_llm.is_available() and results:
        print(f"  [tuning] Asking Claude (sonnet) for fleet analysis...")
        health_summary = "\n".join(
            f"- {r['technique_id']}: health={r['health']['health_score']}, "
            f"action={r['action']}, FP={r['health']['fp_rate']}, TP={r['health']['tp_rate']}"
            for r in results
        )
        llm_result = claude_llm.ask_for_analysis(
            question=(
                "Based on this detection fleet health data, provide 2-3 brief, "
                "actionable recommendations. Focus on: detections that need tuning, "
                "coverage gaps to prioritize, and any concerning trends. "
                "Be concise -- 1-2 sentences per recommendation."
            ),
            context=f"Detection fleet health:\n{health_summary}",
            agent_name=AGENT_NAME,
        )
        if llm_result["success"]:
            llm_insights = [f"[Claude] {llm_result['response']}"]
            print(f"  [tuning] Claude analysis received")
        else:
            print(f"  [tuning] Claude analysis skipped: {llm_result.get('error', 'unknown')}")

    all_insights = cross_agent_insights + llm_insights

    # 6. Generate daily report
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report = generate_daily_report(results, fleet_stats, all_insights)
    report_path = REPORTS_DIR / f"{_today()}.md"
    report_path.write_text(report, encoding="utf-8")
    print(f"\n  [tuning] Report saved: {report_path.relative_to(REPO_ROOT)}")

    # 7. Summary
    summary = (
        f"Reviewed {len(all_active)} detections: "
        f"{fleet_stats['healthy']} healthy, {fleet_stats['tune']} tune, "
        f"{fleet_stats['review']} review, {fleet_stats['retire']} retire"
    )
    print(f"  [tuning] {summary}")

    return {
        "summary": summary,
        "detections_reviewed": len(all_active),
        "fleet_stats": fleet_stats,
        "results": results,
    }
