#!/usr/bin/env python3
"""
Patronus Agent Runner

Shared framework that handles boilerplate for all agents:
  - Branch creation
  - Pending work check via state machine
  - Learnings briefing/retrospective injection
  - Git commit/push after agent completes
  - PR creation via GitHub REST API

Usage:
  python orchestration/agent_runner.py --agent intel
  python orchestration/agent_runner.py --agent red-team
  python orchestration/agent_runner.py --agent author
  python orchestration/agent_runner.py --agent validation
  python orchestration/agent_runner.py --agent deployment
  python orchestration/agent_runner.py --agent tuning
  python orchestration/agent_runner.py --agent coverage
  python orchestration/agent_runner.py --agent security --pr 42
  python orchestration/agent_runner.py --pipeline full
"""

import argparse
import datetime
import importlib
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestration.state import StateManager
from orchestration import learnings
from orchestration import budget

AUTONOMOUS_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = AUTONOMOUS_DIR.parent
CONFIG_PATH = AUTONOMOUS_DIR / "orchestration" / "config.yml"


def _emit_pipeline_metrics(
    agent_name: str,
    run_id: str,
    start_time: datetime.datetime,
    end_time: datetime.datetime,
    duration: float,
    result: dict,
):
    """Write per-run metrics to monitoring/pipeline-metrics.jsonl."""
    metrics_path = REPO_ROOT / "monitoring" / "pipeline-metrics.jsonl"
    metrics_path.parent.mkdir(parents=True, exist_ok=True)

    # Extract state transitions from result if present
    state_transitions = result.get("state_transitions", {}) if isinstance(result, dict) else {}
    f1_scores = result.get("f1_scores", {}) if isinstance(result, dict) else {}
    errors = 1 if (isinstance(result, dict) and result.get("error")) else 0

    entry = {
        "timestamp": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "run_id": run_id,
        "agent": agent_name,
        "run_type": "single",
        "duration_minutes": round(duration / 60, 2),
        "tokens_estimated": result.get("tokens_estimated", 0) if isinstance(result, dict) else 0,
        "detections_processed": result.get("detections_reviewed",
                                 result.get("items_processed",
                                 result.get("techniques_processed", 0))) if isinstance(result, dict) else 0,
        "state_transitions": state_transitions,
        "errors": errors,
        "retries": result.get("retries", 0) if isinstance(result, dict) else 0,
        "f1_scores": f1_scores,
        "coverage_delta": result.get("coverage_delta", 0.0) if isinstance(result, dict) else 0.0,
    }

    with open(metrics_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

# Agent module mapping (Phase 4 topology: 8 specialized agents)
AGENT_MODULES = {
    "intel": "orchestration.agents.intel_agent",
    "red-team": "orchestration.agents.red_team_agent",
    "author": "orchestration.agents.author_agent",
    "validation": "orchestration.agents.validation_agent",
    "deployment": "orchestration.agents.deployment_agent",
    "tuning": "orchestration.agents.tuning_agent",
    "coverage": "orchestration.agents.coverage_agent",
    "security": "orchestration.agents.security_agent",
    # Backward compatibility aliases (resolve to new modules)
    "blue-team": "orchestration.agents.blue_team_agent",
    "quality": "orchestration.agents.quality_agent",
}

# Map old agent names to their new equivalents
AGENT_ALIASES = {
    "blue-team": "author",
    "quality": "tuning",
}


def _sanitize_git_output(text: str) -> str:
    """Remove tokens/credentials from git output before logging."""
    import re
    # Redact Basic auth headers and token URLs
    text = re.sub(r'(https?://)[^@\s]+@', r'\1***@', text)
    text = re.sub(r'Authorization: basic \S+', 'Authorization: basic ***', text, flags=re.IGNORECASE)
    return text


def _run_git(args: list[str], cwd: str = None) -> str:
    result = subprocess.run(
        ["git"] + args,
        capture_output=True, text=True,
        cwd=cwd or str(REPO_ROOT),
    )
    if result.returncode != 0:
        safe_err = _sanitize_git_output(result.stderr.strip())
        raise RuntimeError(f"git {' '.join(args)} failed: {safe_err}")
    return result.stdout.strip()


def _generate_run_id() -> str:
    date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d")
    short_id = uuid.uuid4().hex[:6]
    return f"{date}-{short_id}"


def _create_branch(agent_name: str, run_id: str) -> str:
    branch = f"agent/{agent_name}/{run_id}"
    # Ensure we're on main first
    _run_git(["checkout", "main"])
    _run_git(["pull", "origin", "main"])
    _run_git(["checkout", "-b", branch])
    return branch


def _commit_and_push(branch: str, agent_name: str, summary: str):
    _run_git(["add", "-A"])

    # Check if there are staged changes
    result = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        cwd=str(REPO_ROOT),
    )
    if result.returncode == 0:
        print(f"  [{agent_name}] No changes to commit.")
        return False

    message = f"feat(agent): {agent_name} run --{summary}"
    _run_git(["commit", "-m", message])
    _run_git(["push", "-u", "origin", branch])
    return True


def _create_pr(branch: str, agent_name: str, title: str, body: str):
    """Create a PR via GitHub REST API.

    Token resolution order:
    1. GITHUB_TOKEN env var (set by GitHub Actions or manually)
    2. PAT from .mcp.json (local development)
    """
    token = os.environ.get("GITHUB_TOKEN", "")

    if not token:
        mcp_path = REPO_ROOT / ".mcp.json"
        if mcp_path.exists():
            with open(mcp_path) as f:
                mcp = json.load(f)
            token = (mcp.get("mcpServers", {})
                     .get("github", {})
                     .get("env", {})
                     .get("GITHUB_PERSONAL_ACCESS_TOKEN", ""))

    if not token:
        print(f"  [{agent_name}] Warning: No GitHub token found, skipping PR creation.")
        return None

    import urllib.error
    import urllib.request

    url = "https://api.github.com/repos/lsmithg12/ai-detection-engineering/pulls"
    payload = json.dumps({
        "title": title,
        "body": body,
        "head": branch,
        "base": "main",
    }).encode()

    req = urllib.request.Request(url, data=payload, method="POST", headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
    })

    try:
        with urllib.request.urlopen(req) as resp:
            pr_data = json.loads(resp.read())
            pr_url = pr_data.get("html_url", "")
            print(f"  [{agent_name}] PR created: {pr_url}")
            return pr_url
    except urllib.error.HTTPError as e:
        # Log status code and reason only --avoid leaking headers/body
        print(f"  [{agent_name}] PR creation failed: HTTP {e.code} {e.reason}")
        return None
    except Exception as e:
        print(f"  [{agent_name}] PR creation failed: {type(e).__name__}")
        return None


def run_agent(agent_name: str, pr_number: int = None, dry_run: bool = False):
    """Main entry point for running an agent."""
    run_id = _generate_run_id()
    start_time = datetime.datetime.now(datetime.timezone.utc)
    print(f"\n{'='*60}")
    print(f"  Patronus Agent Runner --{agent_name}")
    print(f"  Run ID: {run_id}")
    print(f"  Time: {start_time.isoformat()}")
    print(f"{'='*60}\n")

    # 0. Budget check
    budget_decision = budget.check_budget(agent_name)
    print(f"  [budget] {budget_decision.reason}")
    if not budget_decision.allowed:
        print(f"  [{agent_name}] Skipped due to budget constraints.")
        budget.log_run(agent_name, 0, 0, status="skipped",
                       skipped_reason=budget_decision.reason)
        return
    if budget_decision.mode == "light":
        print(f"  [{agent_name}] Running in LIGHT mode (reduced workload)")

    sm = StateManager()

    # 1. Check for pending work
    # Scheduled agents (intel, quality) always run --they create work or review fleet.
    # Triggered agents (red-team, blue-team) need pending items.
    # Security agent requires a PR number.
    SCHEDULED_AGENTS = {"intel", "tuning", "quality", "coverage"}

    if agent_name == "security":
        if not pr_number:
            print(f"  [{agent_name}] No PR number provided. Nothing to do.")
            return
        print(f"  [{agent_name}] Reviewing PR #{pr_number}")
    elif agent_name in SCHEDULED_AGENTS:
        pending = sm.query_pending(agent_name)
        if pending:
            print(f"  [{agent_name}] Found {len(pending)} pending items:")
            for p in pending:
                print(f"    [{p['status']}] {p['technique_id']} --{p.get('title','')}")
        else:
            print(f"  [{agent_name}] No pending items --running scheduled tasks.")
    else:
        pending = sm.query_pending(agent_name)
        if not pending:
            print(f"  [{agent_name}] No pending work. Exiting.")
            return
        print(f"  [{agent_name}] Found {len(pending)} pending items:")
        for p in pending:
            print(f"    [{p['status']}] {p['technique_id']} --{p.get('title','')}")

    # 2. Load learnings briefing
    briefing = learnings.get_briefing(agent_name)
    print(f"\n  {briefing}\n")

    # 3. Create branch (skip in dry-run)
    branch = None
    if not dry_run:
        branch = _create_branch(agent_name, run_id)
        print(f"  [{agent_name}] Created branch: {branch}")

    # 4. Import and run the agent
    module_name = AGENT_MODULES.get(agent_name)
    if not module_name:
        print(f"  Error: Unknown agent '{agent_name}'")
        return

    try:
        module = importlib.import_module(module_name)
    except ImportError as e:
        print(f"  Error importing agent module: {e}")
        return

    try:
        if agent_name == "security":
            result = module.run(sm, pr_number=pr_number)
        else:
            result = module.run(sm)
    except Exception as e:
        print(f"  [{agent_name}] Agent failed: {e}")
        # Record the failure as a learning
        learnings.record(
            agent_name, run_id, "error", "general",
            f"Agent crashed: {type(e).__name__}",
            str(e),
        )
        result = {"summary": f"Agent failed: {e}", "error": True}

    # 5. Log budget usage
    end_time = datetime.datetime.now(datetime.timezone.utc)
    duration = (end_time - start_time).total_seconds()
    items = 0
    if isinstance(result, dict):
        items = result.get("detections_reviewed", result.get("items_processed",
                result.get("files_scanned", result.get("techniques_processed", 1))))
    budget.log_run(agent_name, duration, items or 1,
                   status="completed" if not result.get("error") else "error")
    print(f"  [budget] Logged run: {duration:.1f}s, {items or 1} items")

    # 5b. Write pipeline performance metrics
    _emit_pipeline_metrics(
        agent_name=agent_name,
        run_id=run_id,
        start_time=start_time,
        end_time=end_time,
        duration=duration,
        result=result,
    )

    # 6. Retrospective prompt
    retro = learnings.get_retrospective_prompt(agent_name, run_id)
    print(f"\n  {retro}\n")

    # 7. Commit, push, PR (skip in dry-run)
    if not dry_run and branch:
        summary = result.get("summary", "completed") if isinstance(result, dict) else "completed"
        try:
            pushed = _commit_and_push(branch, agent_name, summary)
        except RuntimeError as e:
            print(f"  [{agent_name}] Git push failed: {e}")
            pushed = False

        if pushed:
            pr_title = f"[{agent_name.replace('-',' ').title()}] {summary}"
            learnings_section = ""
            recent = learnings.get_relevant_lessons(agent_name, "general", max_entries=3)
            if recent:
                learnings_section = "\n## Learnings\n" + "\n".join(
                    f"- [{e['type']}] {e['title']}: {e['description']}" for e in recent
                )

            pr_body = f"""## Summary
{summary}

## Run Details
- Agent: {agent_name}
- Run ID: {run_id}
- Branch: {branch}
{learnings_section}

---
*Generated by Patronus Agent Runner*
"""
            _create_pr(branch, agent_name, pr_title, pr_body)

    print(f"\n  [{agent_name}] Run {run_id} complete.")


def run_pipeline(pipeline_agents: list[str], dry_run: bool = False):
    """
    Run multiple agents sequentially on a SINGLE branch, creating ONE PR.

    This replaces the manual workflow of:
      red-team ->merge ->blue-team ->merge ->quality ->merge
    With:
      red-team ->blue-team ->quality ->single PR

    The state machine tracks transitions --no merges needed between agents.
    """
    run_id = _generate_run_id()
    start_time = datetime.datetime.now(datetime.timezone.utc)
    pipeline_name = "-".join(pipeline_agents)

    print(f"\n{'='*60}")
    print(f"  Patronus Pipeline --{pipeline_name}")
    print(f"  Run ID: {run_id}")
    print(f"  Agents: {' ->'.join(pipeline_agents)}")
    print(f"  Time: {start_time.isoformat()}")
    print(f"{'='*60}\n")

    sm = StateManager()

    # Create single branch for entire pipeline
    branch = None
    if not dry_run:
        branch = f"agent/pipeline/{run_id}"
        _run_git(["checkout", "main"])
        _run_git(["pull", "origin", "main"])
        _run_git(["checkout", "-b", branch])
        print(f"  [pipeline] Created branch: {branch}")

    all_results = {}
    all_summaries = []

    for agent_name in pipeline_agents:
        print(f"\n{'-'*50}")
        print(f"  Running: {agent_name}")
        print(f"{'-'*50}")

        # Budget check
        budget_decision = budget.check_budget(agent_name)
        if not budget_decision.allowed:
            print(f"  [{agent_name}] Skipped: {budget_decision.reason}")
            continue

        # Import and run
        module_name = AGENT_MODULES.get(agent_name)
        if not module_name:
            print(f"  Error: Unknown agent '{agent_name}'")
            continue

        try:
            module = importlib.import_module(module_name)
            result = module.run(sm)
        except Exception as e:
            print(f"  [{agent_name}] Agent failed: {e}")
            learnings.record(agent_name, run_id, "error", "general",
                             f"Pipeline agent crashed: {type(e).__name__}", str(e))
            result = {"summary": f"Failed: {e}", "error": True}

        all_results[agent_name] = result
        summary = result.get("summary", "completed") if isinstance(result, dict) else "completed"
        all_summaries.append(f"**{agent_name}**: {summary}")

        # Log budget
        budget.log_run(agent_name, 0, 1, status="completed" if not result.get("error") else "error")

        # Commit after each agent (but don't push yet)
        if not dry_run and branch:
            _run_git(["add", "-A"])
            diff_result = subprocess.run(
                ["git", "diff", "--cached", "--quiet"], cwd=str(REPO_ROOT))
            if diff_result.returncode != 0:
                msg = f"feat(agent): {agent_name} run --{summary}"
                _run_git(["commit", "-m", msg])
                print(f"  [{agent_name}] Committed changes")

    # Push and create PR
    if not dry_run and branch:
        try:
            _run_git(["push", "-u", "origin", branch])
        except RuntimeError as e:
            print(f"  [pipeline] Push failed: {e}")
            return

        combined_summary = f"Pipeline run: {pipeline_name}"
        pr_title = f"[Pipeline] {' ->'.join(pipeline_agents)} ({run_id})"
        pr_body = f"""## Pipeline Summary
{chr(10).join('- ' + s for s in all_summaries)}

## Run Details
- Pipeline: {pipeline_name}
- Run ID: {run_id}
- Branch: {branch}
- Agents: {' ->'.join(pipeline_agents)}

---
*Generated by Patronus Pipeline Runner*
"""
        _create_pr(branch, "pipeline", pr_title, pr_body)

    print(f"\n  [pipeline] Pipeline {run_id} complete.")


# Pre-defined pipeline sequences (Phase 4 topology)
PIPELINE_PRESETS = {
    "red-blue": ["red-team", "author", "validation"],
    "red-blue-quality": ["red-team", "author", "validation", "tuning"],
    "full": ["intel", "red-team", "author", "validation", "tuning", "coverage"],
}


def main():
    parser = argparse.ArgumentParser(description="Patronus Agent Runner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--agent",
                       choices=["intel", "red-team", "author", "validation",
                                "deployment", "tuning", "coverage", "security",
                                "blue-team", "quality"])
    group.add_argument("--pipeline",
                       help="Run agents sequentially on one branch. "
                            "Use preset name (red-blue, red-blue-quality, full) "
                            "or comma-separated agents (red-team,blue-team,quality)")
    parser.add_argument("--pr", type=int, default=None,
                        help="PR number (required for security agent)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Run agent without git operations")
    args = parser.parse_args()

    if args.pipeline:
        # Resolve preset or parse comma-separated list
        agents = PIPELINE_PRESETS.get(args.pipeline)
        if not agents:
            agents = [a.strip() for a in args.pipeline.split(",")]
            for a in agents:
                if a not in AGENT_MODULES:
                    parser.error(f"Unknown agent: {a}")
        run_pipeline(agents, dry_run=args.dry_run)
    else:
        run_agent(args.agent, pr_number=args.pr, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
