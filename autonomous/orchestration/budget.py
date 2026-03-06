"""
Token Budget Tracker — Estimates, logs, and throttles token usage
across the Patronus pipeline to stay within Pro plan limits.

Rough estimation is fine. The goal is preventing surprise limit hits,
not precise accounting.
"""

import datetime
import json
from pathlib import Path

import yaml

AUTONOMOUS_DIR = Path(__file__).resolve().parent.parent
BUDGET_LOG = AUTONOMOUS_DIR / "budget-log.jsonl"
CONFIG_PATH = AUTONOMOUS_DIR / "orchestration" / "config.yml"
STATUS_PATH = AUTONOMOUS_DIR.parent / "STATUS.md"

# Default token estimates per agent (rough heuristics)
DEFAULT_ESTIMATES = {
    "intel": 50_000,
    "red-team": 30_000,
    "blue-team": 100_000,
    "quality": 40_000,
    "security": 20_000,
}

# Agents that can be skipped when throttling
NON_CRITICAL_AGENTS = {"quality"}


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def _load_config() -> dict:
    """Load budget config from config.yml."""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            cfg = yaml.safe_load(f) or {}
        return cfg.get("budget", {})
    return {}


def _get_model_multiplier(agent_name: str) -> float:
    """Get cost multiplier based on agent's assigned model."""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            cfg = yaml.safe_load(f) or {}

    agents_cfg = cfg.get("agents", {})
    agent_cfg = agents_cfg.get(agent_name, {})
    model = agent_cfg.get("model", "sonnet")

    budget_cfg = cfg.get("budget", {})
    models = budget_cfg.get("models", {"opus": 1.0, "sonnet": 0.2})
    return models.get(model, 0.5)


# ─── Logging ──────────────────────────────────────────────────────

def log_run(
    agent_name: str,
    duration_seconds: float,
    items_processed: int,
    estimated_tokens: int | None = None,
    status: str = "completed",
    skipped_reason: str = "",
) -> dict:
    """Log a completed agent run to budget-log.jsonl."""
    if estimated_tokens is None:
        base = DEFAULT_ESTIMATES.get(agent_name, 30_000)
        multiplier = _get_model_multiplier(agent_name)
        estimated_tokens = int(base * max(items_processed, 1) * multiplier / 5)

    entry = {
        "timestamp": _now_iso(),
        "date": _today(),
        "agent": agent_name,
        "duration_seconds": round(duration_seconds, 1),
        "items_processed": items_processed,
        "estimated_tokens": estimated_tokens,
        "status": status,
        "skipped_reason": skipped_reason,
    }

    with open(BUDGET_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")

    return entry


def get_daily_usage(date: str | None = None) -> dict:
    """Get estimated token usage for a given date."""
    target_date = date or _today()
    usage = {"total_tokens": 0, "runs": 0, "by_agent": {}}

    if not BUDGET_LOG.exists():
        return usage

    with open(BUDGET_LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("date") != target_date:
                continue
            if entry.get("status") != "completed":
                continue

            tokens = entry.get("estimated_tokens", 0)
            agent = entry.get("agent", "unknown")

            usage["total_tokens"] += tokens
            usage["runs"] += 1
            usage["by_agent"][agent] = usage["by_agent"].get(agent, 0) + tokens

    return usage


# ─── Throttling ───────────────────────────────────────────────────

class BudgetDecision:
    """Result of a budget check."""
    def __init__(self, allowed: bool, mode: str, reason: str):
        self.allowed = allowed
        self.mode = mode  # "normal", "light", "blocked"
        self.reason = reason

    def __repr__(self):
        return f"BudgetDecision(allowed={self.allowed}, mode='{self.mode}', reason='{self.reason}')"


def check_budget(agent_name: str) -> BudgetDecision:
    """
    Check if an agent should run based on current budget usage.

    Returns a BudgetDecision with:
    - allowed: whether the agent should proceed
    - mode: "normal", "light", or "blocked"
    - reason: human-readable explanation
    """
    config = _load_config()
    daily_cap = config.get("daily_cap_tokens", 500_000)
    warn_pct = config.get("warn_at_pct", 80) / 100.0

    usage = get_daily_usage()
    current = usage["total_tokens"]
    pct_used = current / daily_cap if daily_cap > 0 else 0

    # At or over limit — block all
    if pct_used >= 1.0:
        return BudgetDecision(
            allowed=False,
            mode="blocked",
            reason=f"Daily budget exhausted ({current:,}/{daily_cap:,} tokens, {pct_used:.0%})",
        )

    # Over warning threshold
    if pct_used >= warn_pct:
        # Skip non-critical agents entirely
        if agent_name in NON_CRITICAL_AGENTS:
            return BudgetDecision(
                allowed=False,
                mode="blocked",
                reason=f"Budget at {pct_used:.0%} — skipping non-critical agent '{agent_name}'",
            )

        # Critical agents switch to light mode
        return BudgetDecision(
            allowed=True,
            mode="light",
            reason=f"Budget at {pct_used:.0%} — switching to light mode",
        )

    # Under threshold — normal operation
    return BudgetDecision(
        allowed=True,
        mode="normal",
        reason=f"Budget OK ({current:,}/{daily_cap:,} tokens, {pct_used:.0%} used)",
    )


def get_light_mode_config() -> dict:
    """Get light mode limits from config."""
    config = _load_config()
    return config.get("light_mode", {
        "intel_max_reports": 2,
        "blue_max_detections": 2,
        "quality_skip_research": True,
    })


# ─── Weekly Summary ──────────────────────────────────────────────

def generate_weekly_summary() -> str:
    """Generate a weekly budget summary."""
    if not BUDGET_LOG.exists():
        return "No budget data available yet."

    now = datetime.datetime.now(datetime.timezone.utc)
    week_ago = now - datetime.timedelta(days=7)
    week_ago_str = week_ago.strftime("%Y-%m-%d")

    totals = {"tokens": 0, "runs": 0, "skipped": 0}
    by_agent = {}

    with open(BUDGET_LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            if entry.get("date", "") < week_ago_str:
                continue

            agent = entry.get("agent", "unknown")
            tokens = entry.get("estimated_tokens", 0)
            status = entry.get("status", "")

            if status == "completed":
                totals["tokens"] += tokens
                totals["runs"] += 1
                by_agent[agent] = by_agent.get(agent, {"tokens": 0, "runs": 0})
                by_agent[agent]["tokens"] += tokens
                by_agent[agent]["runs"] += 1
            elif status == "skipped":
                totals["skipped"] += 1

    config = _load_config()
    daily_cap = config.get("daily_cap_tokens", 500_000)
    weekly_budget = daily_cap * 7
    pct = totals["tokens"] / weekly_budget if weekly_budget > 0 else 0

    summary = f"""## Weekly Budget Summary ({week_ago_str} to {_today()})

| Agent | Tokens (est.) | Runs |
|-------|--------------|------|
"""
    for agent in sorted(by_agent.keys()):
        data = by_agent[agent]
        summary += f"| {agent} | {data['tokens']:,} | {data['runs']} |\n"

    summary += f"| **Total** | **{totals['tokens']:,}** | **{totals['runs']}** |\n\n"
    summary += f"- Runs skipped (budget): {totals['skipped']}\n"
    summary += f"- Weekly budget: {weekly_budget:,} tokens\n"
    summary += f"- Usage: {pct:.0%}\n"

    if pct > 0.8:
        summary += "- **Recommendation**: Consider reducing intel agent frequency to 3x/week\n"
    elif pct > 0.5:
        summary += "- **Recommendation**: Monitor usage — approaching sustainable limit\n"
    else:
        summary += "- **Recommendation**: Pipeline is within budget\n"

    return summary
