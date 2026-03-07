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
  python orchestration/agent_runner.py --agent blue-team
  python orchestration/agent_runner.py --agent quality
  python orchestration/agent_runner.py --agent security --pr 42
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

# Agent module mapping
AGENT_MODULES = {
    "intel": "orchestration.agents.intel_agent",
    "red-team": "orchestration.agents.red_team_agent",
    "blue-team": "orchestration.agents.blue_team_agent",
    "quality": "orchestration.agents.quality_agent",
    "security": "orchestration.agents.security_agent",
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

    message = f"feat(agent): {agent_name} run — {summary}"
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
        # Log status code and reason only — avoid leaking headers/body
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
    print(f"  Patronus Agent Runner — {agent_name}")
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
    # Scheduled agents (intel, quality) always run — they create work or review fleet.
    # Triggered agents (red-team, blue-team) need pending items.
    # Security agent requires a PR number.
    SCHEDULED_AGENTS = {"intel", "quality"}

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
                print(f"    [{p['status']}] {p['technique_id']} — {p.get('title','')}")
        else:
            print(f"  [{agent_name}] No pending items — running scheduled tasks.")
    else:
        pending = sm.query_pending(agent_name)
        if not pending:
            print(f"  [{agent_name}] No pending work. Exiting.")
            return
        print(f"  [{agent_name}] Found {len(pending)} pending items:")
        for p in pending:
            print(f"    [{p['status']}] {p['technique_id']} — {p.get('title','')}")

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


def main():
    parser = argparse.ArgumentParser(description="Patronus Agent Runner")
    parser.add_argument("--agent", required=True,
                        choices=["intel", "red-team", "blue-team", "quality", "security"])
    parser.add_argument("--pr", type=int, default=None,
                        help="PR number (required for security agent)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Run agent without git operations")
    args = parser.parse_args()
    run_agent(args.agent, pr_number=args.pr, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
