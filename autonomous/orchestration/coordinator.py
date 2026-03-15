#!/usr/bin/env python3
"""
Coordinator -- Routes work between agents based on state + priority.

The coordinator is NOT an agent itself. It's the orchestration layer that
decides which agent to invoke next and in what order.

Responsibilities:
  1. Scan all detection requests, determine next action for each
  2. Build a priority queue ordered by gap_priority_score
  3. Route each item to the correct agent
  4. Track agent success/failure rates
  5. Enforce daily token budget allocation
  6. Provide queue status for cli.py

Usage:
  python orchestration/coordinator.py --dry-run        # show planned actions
  python orchestration/coordinator.py --run            # execute full pipeline
  python orchestration/coordinator.py --agent author   # run just one agent via coordinator
"""

import argparse
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestration.state import StateManager
from orchestration import budget

PIPELINE_ORDER = [
    "intel",
    "red-team",
    "author",
    "validation",
    "deployment",
    "tuning",
    "coverage",
]

# Map detection state to the agent that should process it
STATE_TO_AGENT = {
    "REQUESTED": "red-team",
    "SCENARIO_BUILT": "author",
    "AUTHORED": "validation",
    "VALIDATED": "deployment",
    "DEPLOYED": "tuning",
    "MONITORING": "tuning",
}

# Agent module mapping (new topology)
AGENT_MODULES = {
    "intel": "orchestration.agents.intel_agent",
    "red-team": "orchestration.agents.red_team_agent",
    "author": "orchestration.agents.author_agent",
    "validation": "orchestration.agents.validation_agent",
    "deployment": "orchestration.agents.deployment_agent",
    "tuning": "orchestration.agents.tuning_agent",
    "coverage": "orchestration.agents.coverage_agent",
    "security": "orchestration.agents.security_agent",
}

# Budget allocation weights
BUDGET_WEIGHTS = {
    "intel": 0.10,
    "red-team": 0.05,
    "author": 0.30,
    "validation": 0.20,
    "deployment": 0.05,
    "tuning": 0.15,
    "coverage": 0.05,
    "security": 0.10,
}


class WorkItem:
    """A single unit of work to be routed to an agent."""
    def __init__(self, technique_id, current_state, target_agent, priority, threat_actors=None):
        self.technique_id = technique_id
        self.current_state = current_state
        self.target_agent = target_agent
        self.priority = priority
        self.threat_actors = threat_actors or []

    def __repr__(self):
        return (f"WorkItem({self.technique_id}, {self.current_state} -> "
                f"{self.target_agent}, priority={self.priority:.2f})")


class Coordinator:
    def __init__(self, state_manager, dry_run=False):
        self.sm = state_manager
        self.dry_run = dry_run
        self.queue = []
        self.results = []

    def build_queue(self):
        """Scan all detection requests and build prioritized work queue."""
        all_requests = self.sm.list_all()
        for req in all_requests:
            state = req.get("status")
            agent = STATE_TO_AGENT.get(state)
            if not agent:
                continue
            priority = req.get("priority_score", req.get("priority", 0.5))
            if isinstance(priority, str):
                priority_map = {"critical": 0.9, "high": 0.7, "medium": 0.5, "low": 0.3}
                priority = priority_map.get(priority, 0.5)
            actors = req.get("threat_actors", [])
            self.queue.append(WorkItem(
                technique_id=req["technique_id"],
                current_state=state,
                target_agent=agent,
                priority=float(priority),
                threat_actors=actors,
            ))
        self.queue.sort(key=lambda w: w.priority, reverse=True)
        return self.queue

    def allocate_budget(self):
        """Distribute daily token budget across agents."""
        config = budget._load_config()
        daily_cap = config.get("daily_cap_tokens", 500_000)
        usage = budget.get_daily_usage()
        used = usage.get("total_tokens", 0)
        remaining = daily_cap - used
        return {agent: int(remaining * w) for agent, w in BUDGET_WEIGHTS.items()}

    def execute(self):
        """Execute the work queue, routing each item to its target agent."""
        if not self.queue:
            self.build_queue()

        budgets = self.allocate_budget()

        # Group by agent to invoke each agent once with all its items
        by_agent = {}
        for item in self.queue:
            by_agent.setdefault(item.target_agent, []).append(item)

        for agent_name in PIPELINE_ORDER:
            items = by_agent.get(agent_name, [])
            if not items:
                continue

            if self.dry_run:
                for item in items:
                    print(f"  [DRY-RUN] {item.technique_id} ({item.current_state}) "
                          f"-> {item.target_agent} (priority: {item.priority:.2f})")
                continue

            agent_budget = budgets.get(agent_name, 0)
            if agent_budget <= 0:
                for item in items:
                    print(f"  [SKIP] {item.technique_id} -- {agent_name} budget exhausted")
                continue

            print(f"\n  --- Running {agent_name} ({len(items)} items) ---")
            result = self._invoke_agent(agent_name)
            self.results.append({
                "agent": agent_name,
                "items": len(items),
                "result": result,
            })

    def _invoke_agent(self, agent_name):
        """Invoke an agent module."""
        module_name = AGENT_MODULES.get(agent_name)
        if not module_name:
            return {"status": "error", "message": f"Unknown agent: {agent_name}"}

        try:
            module = importlib.import_module(module_name)
            result = module.run(self.sm)
            return {"status": "success", "result": result}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def status(self):
        """Return coordinator queue status."""
        if not self.queue:
            self.build_queue()

        by_agent = {}
        for item in self.queue:
            by_agent.setdefault(item.target_agent, []).append(item.technique_id)

        return {
            "queue_size": len(self.queue),
            "by_agent": {k: len(v) for k, v in by_agent.items()},
            "top_priority": self.queue[0].technique_id if self.queue else None,
            "budget_remaining": self.allocate_budget(),
        }


def main():
    parser = argparse.ArgumentParser(description="Patronus Coordinator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--run", action="store_true", help="Execute full pipeline")
    group.add_argument("--dry-run", action="store_true", help="Preview pipeline execution")
    group.add_argument("--status", action="store_true", help="Show queue status")
    group.add_argument("--agent", help="Run just one agent via coordinator")
    args = parser.parse_args()

    sm = StateManager()
    coord = Coordinator(sm, dry_run=args.dry_run)

    if args.status:
        status = coord.status()
        print(f"\n  Work Queue: {status['queue_size']} items")
        for agent, count in status["by_agent"].items():
            print(f"    {agent}: {count} items")
        if status["top_priority"]:
            print(f"  Top priority: {status['top_priority']}")
    elif args.agent:
        result = coord._invoke_agent(args.agent)
        print(f"  Result: {result}")
    else:
        coord.execute()


if __name__ == "__main__":
    main()
