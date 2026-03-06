#!/usr/bin/env python3
"""
Patronus CLI — Detection lifecycle state machine interface.

Usage:
  python orchestration/cli.py status                           # all detections by state
  python orchestration/cli.py pending --agent blue-team        # what needs work?
  python orchestration/cli.py get T1055.001                    # show one request
  python orchestration/cli.py create T1055.001 --title "..." --priority high --intel path/to/report.yml
  python orchestration/cli.py transition T1055.001 VALIDATED --agent blue-team --details "TP 1/1, FP 0"
  python orchestration/cli.py update T1055.001 --agent blue-team --set fp_rate=0.0 tp_rate=1.0
"""

import argparse
import json
import sys
from pathlib import Path

# Allow running from repo root or autonomous/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestration.state import StateManager


def cmd_status(args):
    sm = StateManager()
    summary = sm.status_summary()
    total = 0
    for state in ["REQUESTED", "SCENARIO_BUILT", "AUTHORED", "VALIDATED",
                   "DEPLOYED", "MONITORING", "TUNED", "RETIRED"]:
        techniques = summary.get(state, [])
        total += len(techniques)
        if techniques:
            print(f"\n  {state} ({len(techniques)})")
            for t in techniques:
                print(f"    - {t}")
    if not total:
        print("  No detection requests found.")
    else:
        print(f"\n  Total: {total} detection requests")


def cmd_pending(args):
    sm = StateManager()
    pending = sm.query_pending(args.agent)
    if not pending:
        print(f"  No pending work for agent: {args.agent}")
        return
    print(f"\n  Pending work for {args.agent} ({len(pending)}):")
    for r in pending:
        print(f"    [{r['status']}] {r['technique_id']} — {r.get('title', '')}")


def cmd_get(args):
    sm = StateManager()
    data = sm.get(args.technique_id)
    if not data:
        print(f"  Not found: {args.technique_id}", file=sys.stderr)
        sys.exit(1)
    # Print as YAML-ish for readability
    for k, v in data.items():
        if k == "changelog":
            print(f"  changelog:")
            for entry in v:
                print(f"    - [{entry.get('date','')}] {entry.get('agent','')}: "
                      f"{entry.get('action','')} — {entry.get('details','')}")
        else:
            print(f"  {k}: {v}")


def cmd_create(args):
    sm = StateManager()
    try:
        data = sm.create(
            technique_id=args.technique_id,
            title=args.title or "",
            priority=args.priority or "medium",
            intel_report=args.intel or "",
            requested_by=args.requested_by or "intel_agent",
        )
        print(f"  Created: {data['technique_id']} [{data['status']}]")
    except ValueError as e:
        print(f"  Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_transition(args):
    sm = StateManager()
    try:
        data = sm.transition(
            technique_id=args.technique_id,
            target_state=args.target_state,
            agent=args.agent,
            details=args.details or "",
        )
        print(f"  Transitioned: {data['technique_id']} -> {data['status']}")
    except ValueError as e:
        print(f"  Error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_update(args):
    sm = StateManager()
    updates = {}
    if args.set:
        for pair in args.set:
            key, val = pair.split("=", 1)
            # Try numeric conversion
            try:
                val = float(val)
                if val == int(val):
                    val = int(val)
            except ValueError:
                if val.lower() == "true":
                    val = True
                elif val.lower() == "false":
                    val = False
            updates[key] = val
    try:
        data = sm.update(args.technique_id, agent=args.agent, **updates)
        print(f"  Updated: {data['technique_id']} — {', '.join(updates.keys())}")
    except ValueError as e:
        print(f"  Error: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        prog="patronus",
        description="Patronus Detection Lifecycle CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # status
    sub.add_parser("status", help="Show all detections by state")

    # pending
    p_pending = sub.add_parser("pending", help="Show pending work for an agent")
    p_pending.add_argument("--agent", required=True,
                           choices=["intel", "red-team", "blue-team", "quality", "security"])

    # get
    p_get = sub.add_parser("get", help="Show a single detection request")
    p_get.add_argument("technique_id")

    # create
    p_create = sub.add_parser("create", help="Create a new detection request")
    p_create.add_argument("technique_id")
    p_create.add_argument("--title", default="")
    p_create.add_argument("--priority", default="medium",
                          choices=["critical", "high", "medium", "low"])
    p_create.add_argument("--intel", default="")
    p_create.add_argument("--requested-by", default="intel_agent")

    # transition
    p_trans = sub.add_parser("transition", help="Transition a detection to a new state")
    p_trans.add_argument("technique_id")
    p_trans.add_argument("target_state")
    p_trans.add_argument("--agent", required=True)
    p_trans.add_argument("--details", default="")

    # update
    p_update = sub.add_parser("update", help="Update fields on a detection request")
    p_update.add_argument("technique_id")
    p_update.add_argument("--agent", required=True)
    p_update.add_argument("--set", nargs="+", metavar="KEY=VALUE",
                          help="Fields to update (e.g., fp_rate=0.05 tp_rate=0.95)")

    args = parser.parse_args()
    cmd_map = {
        "status": cmd_status,
        "pending": cmd_pending,
        "get": cmd_get,
        "create": cmd_create,
        "transition": cmd_transition,
        "update": cmd_update,
    }
    cmd_map[args.command](args)


if __name__ == "__main__":
    main()
