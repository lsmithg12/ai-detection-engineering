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


def cmd_deploy(args):
    """Deploy VALIDATED detections with auto_deploy_eligible=True to SIEMs."""
    import yaml
    from orchestration.siem import deploy_to_siems

    sm = StateManager()
    repo_root = Path(__file__).resolve().parent.parent.parent

    validated = sm.query_by_state("VALIDATED")
    eligible = [r for r in validated if r.get("auto_deploy_eligible")]

    if not eligible:
        print("  No VALIDATED detections eligible for deployment.")
        return

    print(f"  Found {len(eligible)} VALIDATED detections eligible for deployment")
    deployed = 0

    for request in eligible:
        tid = request["technique_id"]
        sigma_path = request.get("sigma_rule", "")
        lucene_path = request.get("compiled_lucene", "")
        spl_path = request.get("compiled_spl", "")

        if not sigma_path or not lucene_path:
            print(f"  Skipping {tid} — missing artifacts")
            continue

        sigma_full = repo_root / sigma_path
        lucene_full = repo_root / lucene_path
        spl_full = repo_root / spl_path if spl_path else None

        if not sigma_full.exists() or not lucene_full.exists():
            print(f"  Skipping {tid} — files not found")
            continue

        with open(sigma_full, encoding="utf-8") as f:
            sigma_data = yaml.safe_load(f)
        lucene = lucene_full.read_text(encoding="utf-8").strip()
        spl = spl_full.read_text(encoding="utf-8").strip() if spl_full and spl_full.exists() else ""

        print(f"\n  Deploying {tid} — {request.get('title', '')}")
        deploy_results = deploy_to_siems(request, lucene, spl, sigma_data)

        if deploy_results:
            deploy_details = []
            if "elastic" in deploy_results:
                sm.update(tid, agent="blue-team",
                          elastic_rule_id=deploy_results["elastic"].get("rule_id", ""))
                deploy_details.append("Elastic")
            if "splunk" in deploy_results:
                sm.update(tid, agent="blue-team",
                          splunk_saved_search=deploy_results["splunk"].get("search_name", ""))
                deploy_details.append("Splunk")

            try:
                import datetime
                sm.transition(tid, "DEPLOYED", agent="blue-team",
                              details=f"Post-merge deploy to {' + '.join(deploy_details)}")
                sm.update(tid, agent="blue-team",
                          deployed_date=datetime.datetime.now(
                              datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
                print(f"  {tid} -> DEPLOYED ({' + '.join(deploy_details)})")
                deployed += 1
            except ValueError as e:
                print(f"  DEPLOYED transition failed for {tid}: {e}")
        else:
            print(f"  No SIEMs available for {tid}")

    print(f"\n  Deployed {deployed}/{len(eligible)} detections")


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

    # deploy
    sub.add_parser("deploy", help="Deploy VALIDATED detections to SIEMs (post-merge)")

    args = parser.parse_args()
    cmd_map = {
        "status": cmd_status,
        "pending": cmd_pending,
        "get": cmd_get,
        "create": cmd_create,
        "transition": cmd_transition,
        "update": cmd_update,
        "deploy": cmd_deploy,
    }
    cmd_map[args.command](args)


if __name__ == "__main__":
    main()
