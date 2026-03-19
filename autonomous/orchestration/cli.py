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
  python orchestration/cli.py data-sources                        # report data source gaps
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running from repo root or autonomous/
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestration.state import StateManager


def cmd_status(args):
    sm = StateManager()
    all_requests = sm.list_all()
    summary = sm.status_summary()
    total = 0

    # Build lookup for VALIDATED manual-deploy tier (F1 0.75-0.89)
    manual_deploy = []
    auto_deploy = []
    for r in all_requests:
        if r.get("status") == "VALIDATED":
            if r.get("auto_deploy_eligible"):
                auto_deploy.append(r.get("technique_id", "?"))
            else:
                f1 = r.get("quality_score", 0)
                manual_deploy.append(f"{r.get('technique_id', '?')} (F1={f1})")

    for state in ["REQUESTED", "SCENARIO_BUILT", "AUTHORED", "VALIDATED",
                   "DEPLOYED", "MONITORING", "TUNED", "RETIRED"]:
        techniques = summary.get(state, [])
        total += len(techniques)
        if techniques:
            print(f"\n  {state} ({len(techniques)})")
            for t in techniques:
                print(f"    - {t}")
            # Show sub-tiers for VALIDATED
            if state == "VALIDATED" and (manual_deploy or auto_deploy):
                if auto_deploy:
                    print(f"    [auto-deploy eligible: {len(auto_deploy)}]")
                if manual_deploy:
                    print(f"    [manual deploy needed: {len(manual_deploy)}]")
                    for m in manual_deploy:
                        print(f"      * {m}")
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


def cmd_data_sources(args):
    """Report on data source gap status from gaps/data-sources/*.yml files."""
    import yaml

    repo_root = Path(__file__).resolve().parent.parent.parent
    gaps_dir = repo_root / "gaps" / "data-sources"

    if not gaps_dir.exists():
        print("  No gaps/data-sources/ directory found.")
        return

    gap_files = sorted(gaps_dir.glob("*.yml"))
    if not gap_files:
        print("  No data source gap files found.")
        return

    # Categorize by status
    by_status = {"gap": [], "partially_available": [], "onboarded": []}
    for gap_file in gap_files:
        try:
            with open(gap_file, encoding="utf-8") as f:
                gap = yaml.safe_load(f) or {}
            status = gap.get("status", "gap")
            entry = {
                "gap_id": gap.get("gap_id", gap_file.stem),
                "event_name": gap.get("event_name", "?"),
                "event_id": gap.get("event_id", "?"),
                "priority": gap.get("priority", "?"),
                "affected": gap.get("affected_techniques", []),
                "simulator": gap.get("simulator_support", False),
                "cribl": gap.get("cribl_pipeline") is not None,
            }
            by_status.setdefault(status, []).append(entry)
        except Exception as e:
            print(f"  Error reading {gap_file.name}: {e}")

    total = sum(len(v) for v in by_status.values())
    print(f"\n  Data Source Gaps ({total} tracked)")

    for status, label in [("gap", "GAPS (missing)"),
                          ("partially_available", "PARTIAL (in simulator, no Cribl parser)"),
                          ("onboarded", "ONBOARDED (fully available)")]:
        entries = by_status.get(status, [])
        if entries:
            print(f"\n  {label} ({len(entries)})")
            for e in entries:
                sim = "sim:Y" if e["simulator"] else "sim:N"
                cribl = "cribl:Y" if e["cribl"] else "cribl:N"
                techs = ", ".join(e["affected"][:3])
                if len(e["affected"]) > 3:
                    techs += f" +{len(e['affected'])-3}"
                print(f"    [{e['priority'].upper():8s}] {e['gap_id']:8s} "
                      f"EID {str(e['event_id']):5s} {e['event_name']:20s} "
                      f"[{sim} {cribl}] -> {techs}")


def cmd_queue(args):
    """Show coordinator work queue."""
    from orchestration.coordinator import Coordinator
    sm = StateManager()
    coord = Coordinator(sm)
    status = coord.status()
    print(f"\n  Work Queue: {status['queue_size']} items")
    for agent, count in status["by_agent"].items():
        print(f"    {agent}: {count} items")
    if status["top_priority"]:
        print(f"  Top priority: {status['top_priority']}")
    budgets = status.get("budget_remaining", {})
    if budgets:
        print("\n  Budget remaining (tokens):")
        for agent, tokens in sorted(budgets.items()):
            print(f"    {agent}: {tokens:,}")


def cmd_coverage(args):
    """Generate and display coverage analysis."""
    try:
        from orchestration.agents.coverage_agent import run as run_coverage
        sm = StateManager()
        result = run_coverage(sm)
        print("\n  Coverage report generated.")
        if isinstance(result, dict):
            print(f"  Techniques tracked: {result.get('total_techniques', '?')}")
            print(f"  Detection coverage: {result.get('coverage_pct', '?')}%")
            if result.get("top_gap"):
                print(f"  Top gap: {result['top_gap']}")
    except ImportError:
        # Fallback: read coverage from detection requests
        sm = StateManager()
        summary = sm.status_summary()
        total = sum(len(v) for v in summary.values())
        deployed = len(summary.get("DEPLOYED", [])) + len(summary.get("MONITORING", []))
        validated = len(summary.get("VALIDATED", []))
        print(f"\n  Coverage Summary (from detection requests):")
        print(f"    Total techniques tracked: {total}")
        print(f"    Deployed + Monitoring: {deployed}")
        print(f"    Validated (deploy-ready): {validated}")
        if total > 0:
            print(f"    Coverage rate: {(deployed + validated) / total:.0%}")


def cmd_feedback(args):
    """Record or view analyst feedback."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    feedback_path = repo_root / "monitoring" / "feedback" / "verdicts.jsonl"

    if args.show:
        if not feedback_path.exists():
            print("  No feedback recorded yet.")
            return
        entries = []
        with open(feedback_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    if not args.technique_id or entry.get("technique_id") == args.technique_id:
                        entries.append(entry)
        if not entries:
            if args.technique_id:
                print(f"  No feedback for {args.technique_id}")
            else:
                print("  No feedback.")
            return
        for e in entries[-20:]:
            print(f"  [{e.get('timestamp', '')}] {e.get('technique_id', '')} "
                  f"{e.get('verdict', '')} -- {e.get('reason', '')}")
    elif args.summary:
        if not feedback_path.exists():
            print("  No feedback recorded yet.")
            return
        by_technique = {}
        with open(feedback_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entry = json.loads(line)
                    tid = entry.get("technique_id", "")
                    by_technique.setdefault(tid, {"tp": 0, "fp": 0, "fn": 0})
                    verdict = entry.get("verdict", "")
                    if verdict in by_technique[tid]:
                        by_technique[tid][verdict] += 1
        print("\n  Feedback Summary:")
        print(f"  {'Technique':<12} {'TP':>4} {'FP':>4} {'FN':>4} {'FP Rate':>8}")
        for tid, counts in sorted(by_technique.items()):
            total = counts["tp"] + counts["fp"]
            fp_rate = counts["fp"] / total if total > 0 else 0
            print(f"  {tid:<12} {counts['tp']:>4} {counts['fp']:>4} "
                  f"{counts['fn']:>4} {fp_rate:>8.1%}")
    else:
        # Record a verdict
        if not args.technique_id or not args.verdict:
            print("  Usage: feedback T1055.001 --verdict fp --reason 'McAfee scan'")
            return
        feedback_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "technique_id": args.technique_id,
            "verdict": args.verdict,
            "reason": args.reason or "",
            "analyst": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        }
        with open(feedback_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        print(f"  Recorded: {args.technique_id} = {args.verdict}")


def cmd_compliance(args):
    """List compliance controls."""
    import yaml
    repo_root = Path(__file__).resolve().parent.parent.parent
    detections_dir = repo_root / "detections"

    controls = {}
    for rule_file in detections_dir.rglob("*.yml"):
        if "compiled" in str(rule_file):
            continue
        try:
            with open(rule_file, encoding="utf-8") as f:
                rule = yaml.safe_load(f)
            if not isinstance(rule, dict):
                continue
            custom = rule.get("custom", {})
            if not custom:
                continue
            for ctrl in custom.get("compliance_controls", []):
                framework = ctrl.split("-")[0] if "-" in ctrl else ctrl
                controls.setdefault(framework, []).append({
                    "control": ctrl,
                    "rule": rule.get("title", rule_file.stem),
                    "file": str(rule_file.relative_to(repo_root)),
                })
        except Exception:
            continue

    if not controls:
        print("  No compliance controls mapped yet.")
        print("  Add compliance_controls to Sigma rules under the 'custom' section.")
        return

    if args.framework:
        matched = controls.get(args.framework, [])
        if not matched:
            print(f"  No detections mapped to {args.framework}")
            return
        print(f"\n  {args.framework} Controls ({len(matched)} detections):")
        for c in matched:
            print(f"    {c['control']}: {c['rule']}")
    else:
        print("\n  Compliance Coverage:")
        for fw, items in sorted(controls.items()):
            print(f"    {fw}: {len(items)} detections")


# ---------------------------------------------------------------------------
# Phase 5 commands
# ---------------------------------------------------------------------------

def cmd_data_quality(args):
    """Run data quality checks. Usage: cli.py data-quality [--source ID] [--export]"""
    import yaml  # noqa: F401 — ensure yaml is importable before engine init
    from orchestration.data_quality import DataQualityEngine

    repo_root = Path(__file__).resolve().parent.parent.parent
    expectations_path = Path(__file__).resolve().parent / "source_expectations.yml"

    es_url  = os.getenv("ES_URL",  "http://localhost:9200")
    es_user = os.getenv("ES_USER", "elastic")
    es_pass = os.getenv("ES_PASS", "changeme")

    engine  = DataQualityEngine(es_url, (es_user, es_pass), expectations_path)
    results = engine.run_checks(source_id=getattr(args, "source", None))

    # Print summary table
    print(f"\n  Data Quality Report ({len(results)} sources)")
    print(f"  {'Source':<30} {'Composite':>10} {'Status':<8} {'Freshness':<10} "
          f"{'Completeness':<14} {'Volume':<8}")
    print(f"  {'-'*80}")
    for r in sorted(results, key=lambda x: x.get("composite", 0)):
        status       = r.get("composite_status", "?")
        composite    = r.get("composite", 0)
        freshness    = r.get("freshness", {}).get("status", "?")
        completeness = r.get("completeness", {}).get("score", 0)
        volume       = r.get("volume", {}).get("status", "?")
        print(
            f"  {r['source_id']:<30} {composite:>10.3f} {status:<8} "
            f"{freshness:<10} {completeness:>13.1%} {volume:<8}"
        )

    if getattr(args, "export", False):
        output_dir = str(repo_root / "monitoring" / "data-quality")
        engine.export_json(results, output_dir)
        print(f"\n  Exported to {output_dir}")


def cmd_schema_diff(args):
    """Compare schema versions. Usage: cli.py schema-diff <source> <old_version> <new_version>"""
    import json as _json

    repo_root  = Path(__file__).resolve().parent.parent.parent
    schema_dir = repo_root / "data-sources" / "schemas"

    if not schema_dir.exists():
        print("  No data-sources/schemas/ directory found.")
        return

    old_path = schema_dir / f"{args.source}_{args.old_version}.json"
    new_path = schema_dir / f"{args.source}_{args.new_version}.json"

    if not old_path.exists():
        print(f"  Schema not found: {old_path.name}")
        return
    if not new_path.exists():
        print(f"  Schema not found: {new_path.name}")
        return

    old_schema = _json.loads(old_path.read_text())
    new_schema = _json.loads(new_path.read_text())

    changes = []
    for eid, old_type in old_schema.get("event_types", {}).items():
        new_type = new_schema.get("event_types", {}).get(eid)
        if not new_type:
            changes.append({"type": "event_removed", "event_id": eid, "severity": "CRITICAL"})
            continue
        for field, old_def in old_type.get("ecs_fields", {}).items():
            new_def = new_type.get("ecs_fields", {}).get(field)
            if not new_def:
                changes.append({"type": "field_removed", "event_id": eid,
                                 "field": field, "severity": "CRITICAL"})
            elif new_def.get("type") != old_def.get("type"):
                changes.append({"type": "field_type_changed", "event_id": eid, "field": field,
                                 "old_type": old_def.get("type"), "new_type": new_def.get("type"),
                                 "severity": "HIGH"})
            elif new_def.get("source_field") != old_def.get("source_field"):
                changes.append({"type": "field_renamed", "event_id": eid, "field": field,
                                 "old_source": old_def.get("source_field"),
                                 "new_source": new_def.get("source_field"),
                                 "severity": "HIGH"})
        for field in new_type.get("ecs_fields", {}):
            if field not in old_type.get("ecs_fields", {}):
                changes.append({"type": "field_added", "event_id": eid,
                                 "field": field, "severity": "INFO"})

    if not changes:
        print(f"\n  No changes between {args.source} {args.old_version} -> {args.new_version}")
        return

    print(f"\n  Schema Diff: {args.source} {args.old_version} -> {args.new_version}")
    print(f"  {len(changes)} changes found\n")

    # Impact analysis — find detection rules that reference changed fields
    detections_dir = repo_root / "detections"
    for change in sorted(changes, key=lambda c: {"CRITICAL": 0, "HIGH": 1, "INFO": 2}[c["severity"]]):
        affected = []
        if change.get("field") and detections_dir.exists():
            field = change["field"]
            for rule_file in detections_dir.rglob("*.yml"):
                if "compiled" in str(rule_file):
                    continue
                if field in rule_file.read_text(encoding="utf-8", errors="ignore"):
                    affected.append(rule_file.name)
        impact = (
            f" [impacts: {', '.join(affected[:3])}{'...' if len(affected) > 3 else ''}]"
            if affected else ""
        )
        print(
            f"  [{change['severity']:8s}] EID {change.get('event_id', '?'):3s} "
            f"{change['type']:20s} "
            f"{change.get('field', change.get('event_id', '?'))}{impact}"
        )


def cmd_data_gaps(args):
    """Show technique -> source -> status gap analysis."""
    from orchestration.gap_analyzer import GapAnalyzer

    repo_root = Path(__file__).resolve().parent.parent.parent
    analyzer  = GapAnalyzer(repo_root)
    gaps      = analyzer.analyze_data_gaps()

    print(f"\n  Data Source Gap Analysis \u2014 Fawkes C2 Techniques")
    print(f"  {'='*48}\n")

    labels = {
        "READY":   "READY (data available \u2014 author detection now)",
        "PARTIAL": "PARTIAL (some data \u2014 detection possible with limitations)",
        "BLOCKED": "BLOCKED (data source missing \u2014 onboard first)",
    }

    for actionability in ("READY", "PARTIAL", "BLOCKED"):
        matching = [g for g in gaps if g["actionability"] == actionability]
        if not matching:
            continue
        print(f"  {labels[actionability]}:")
        for gap in matching:
            sources_str = ", ".join(
                f"{s['source']} ({s['status']})" for s in gap["required_sources"]
            )
            print(f"    {gap['technique_id']:12s} {gap['technique_name']}")
            print(f"      Sources: {sources_str}")
            print(f"      \u2192 {gap['recommendation']}")
        print()

    ready   = sum(1 for g in gaps if g["actionability"] == "READY")
    partial = sum(1 for g in gaps if g["actionability"] == "PARTIAL")
    blocked = sum(1 for g in gaps if g["actionability"] == "BLOCKED")
    print(f"  Summary: {ready} READY | {partial} PARTIAL | {blocked} BLOCKED")


# ---------------------------------------------------------------------------
# Phase 6 commands — Content Pack Management
# ---------------------------------------------------------------------------

def cmd_pack_list(args):
    """List all content packs and their status."""
    import yaml
    repo_root = Path(__file__).resolve().parent.parent.parent
    packs_dir = repo_root / "detections" / "packs"

    if not packs_dir.exists():
        print("  No content packs found (detections/packs/ does not exist).")
        return

    packs = []
    for pack_dir in sorted(packs_dir.iterdir()):
        if not pack_dir.is_dir():
            continue
        manifest_path = pack_dir / "pack.yml"
        if not manifest_path.exists():
            continue
        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest = yaml.safe_load(f)
            packs.append((pack_dir.name, manifest))
        except Exception as e:
            print(f"  Warning: could not read {pack_dir.name}/pack.yml: {e}")

    if not packs:
        print("  No packs found.")
        return

    print(f"\n  Content Packs ({len(packs)} total)\n")
    for pack_name, manifest in packs:
        rules = manifest.get("rules", [])
        techniques = manifest.get("mitre_techniques", [])
        status = manifest.get("status", "unknown")
        version = manifest.get("version", "?")
        name = manifest.get("name", pack_name)
        avg_f1 = 0.0
        f1_values = [r.get("f1", 0) for r in rules if r.get("f1") is not None]
        if f1_values:
            avg_f1 = sum(f1_values) / len(f1_values)
        print(f"  {name} v{version}")
        print(f"    Pack: {pack_name} | Status: {status} | Rules: {len(rules)} | Avg F1: {avg_f1:.2f}")
        print(f"    Techniques: {', '.join(techniques)}")
        print()


def cmd_pack_validate(args):
    """Validate all rules in a named pack, checking F1 scores against quality gates."""
    import yaml
    repo_root = Path(__file__).resolve().parent.parent.parent
    packs_dir = repo_root / "detections" / "packs"

    # Find pack
    pack_dir = packs_dir / args.pack_name
    if not pack_dir.exists():
        # Try fuzzy match
        available = [d.name for d in packs_dir.iterdir() if d.is_dir()]
        print(f"  Pack '{args.pack_name}' not found.")
        print(f"  Available: {', '.join(available)}")
        return

    manifest_path = pack_dir / "pack.yml"
    if not manifest_path.exists():
        print(f"  No pack.yml found in {pack_dir}")
        return

    with open(manifest_path, encoding="utf-8") as f:
        manifest = yaml.safe_load(f)

    rules = manifest.get("rules", [])
    quality = manifest.get("quality", {})
    min_f1 = quality.get("min_f1", 0.75)
    max_fp_rate = quality.get("max_fp_rate", 0.15)

    print(f"\n  Validating: {manifest.get('name', args.pack_name)} v{manifest.get('version', '?')}")
    print(f"  Quality gates: min_f1={min_f1}, max_fp_rate={max_fp_rate}\n")

    passed = 0
    failed = 0
    missing = 0

    for rule_ref in rules:
        technique = rule_ref.get("technique", "?")
        rule_path = repo_root / rule_ref.get("path", "")
        rule_type = rule_ref.get("type", "sigma")
        f1 = rule_ref.get("f1")
        status = rule_ref.get("status", "unknown")

        if not rule_path.exists():
            print(f"  [{technique}] MISSING — {rule_ref.get('path', '?')}")
            missing += 1
            continue

        gate_ok = f1 is not None and f1 >= min_f1
        gate_str = f"F1={f1:.2f}" if f1 is not None else "F1=?"
        icon = "PASS" if gate_ok else "FAIL"
        req = "required" if rule_ref.get("required", True) else "optional"
        print(f"  [{technique}] {icon} | {gate_str} | {status} | {req} | type={rule_type}")
        if gate_ok:
            passed += 1
        else:
            failed += 1

    total = passed + failed + missing
    print(f"\n  Result: {passed}/{total} rules pass quality gate (min_f1={min_f1})")
    if missing > 0:
        print(f"  Warning: {missing} rule file(s) not found on disk")
    if failed > 0:
        required_failed = [
            r.get("technique", "?") for r in rules
            if r.get("required", True) and (r.get("f1") is None or r.get("f1", 0) < min_f1)
        ]
        if required_failed:
            print(f"  BLOCKED: Required rules below gate: {', '.join(required_failed)}")
        else:
            print(f"  WARN: Optional rules below gate — pack still deployable")


def cmd_perf(args):
    """Profile detection query performance at scale."""
    from orchestration.performance import (
        profile_detection, profile_all_detections, print_profile_report,
    )

    scale = getattr(args, "scale", "small")

    if getattr(args, "all", False):
        print(f"\n  Profiling all detections at scale={scale}...")
        results = profile_all_detections(scale=scale)
        print_profile_report(results)
    elif getattr(args, "report", False):
        # Show stored results
        repo_root = Path(__file__).resolve().parent.parent.parent
        results_dir = repo_root / "tests" / "results"
        print("  Performance report from stored results (run 'perf --all' to re-profile)")
        for f in sorted(results_dir.glob("*_performance.json")):
            import json as _json
            data = _json.loads(f.read_text())
            verdict = data.get("verdict", "?")
            p95 = data.get("p95_ms", "?")
            print(f"  {f.stem}: P95={p95}ms verdict={verdict}")
    elif args.technique_id:
        import yaml as _yaml
        repo_root = Path(__file__).resolve().parent.parent.parent
        # Find the rule and its compiled query
        for rule_file in (repo_root / "detections").rglob("*.yml"):
            if args.technique_id.lower().replace(".", "_") in rule_file.stem:
                with open(rule_file, encoding="utf-8") as f:
                    rule = _yaml.safe_load(f)
                compiled_dir = rule_file.parent / "compiled"
                lucene_file = compiled_dir / f"{rule_file.stem}.lucene"
                elastic_json = compiled_dir / f"{rule_file.stem}_elastic.json"

                if lucene_file.exists():
                    query = lucene_file.read_text(encoding="utf-8").strip()
                    qtype = "lucene"
                elif elastic_json.exists():
                    import json as _json
                    edata = _json.loads(elastic_json.read_text())
                    query = edata.get("query", "")
                    qtype = "eql" if edata.get("type") == "eql" else "lucene"
                else:
                    print(f"  No compiled query found for {args.technique_id}")
                    return

                result = profile_detection(args.technique_id, query, scale=scale, query_type=qtype)
                if result:
                    if "error" in result:
                        print(f"  Error: {result['error']}")
                    else:
                        print_profile_report([result])
                else:
                    print("  Elasticsearch not reachable — cannot profile")
                return
        print(f"  Rule not found for {args.technique_id}")
    else:
        print("  Usage: perf <technique_id> [--scale small|medium|large]")
        print("         perf --all [--scale small]")
        print("         perf --report")


# ---------------------------------------------------------------------------
# Phase 7 commands — Operational Excellence
# ---------------------------------------------------------------------------

def cmd_sla(args):
    """Show SLA metrics for detections."""
    from orchestration import sla

    if getattr(args, "technique_id", None):
        result = sla.calculate_sla(args.technique_id)
        if getattr(args, "format", "table") == "json":
            print(json.dumps(result, indent=2))
        else:
            print(f"\n  SLA: {result.get('technique_id','?')} [{result.get('sla_status','?')}]")
            print(f"  Priority:     {result.get('priority','?')}")
            print(f"  SLA target:   {result.get('sla_target_hours','?')}h")
            print(f"  End-to-end:   {result.get('end_to_end_hours','N/A')}h")
            phases = result.get("phases", {})
            for phase_name, hours in phases.items():
                if hours is not None:
                    print(f"  {phase_name}: {hours:.1f}h")
    elif getattr(args, "month", None):
        result = sla.generate_monthly_report(args.month)
        print(result)
    elif getattr(args, "breaches", False):
        breaches = sla.check_breaches()
        if not breaches:
            print("  No SLA breaches found.")
            return
        for record in breaches:
            print(f"  [{record.get('sla_status','?')}] {record.get('technique_id','?')} "
                  f"— {record.get('end_to_end_hours','?')}h / {record.get('sla_target_hours','?')}h")
    else:
        all_status = sla.get_all_sla_status()
        fmt = getattr(args, "format", "table")
        if fmt == "json":
            print(json.dumps(all_status, indent=2))
        else:
            print(f"\n  {'Technique':<14} {'Priority':<10} {'End-to-End (h)':>14} {'SLA Target':>10} {'Status':<10}")
            print(f"  {'-'*60}")
            if isinstance(all_status, list):
                for row in all_status:
                    print(
                        f"  {row.get('technique_id', '?'):<14} "
                        f"{row.get('priority', '?'):<10} "
                        f"{str(row.get('end_to_end_hours', '?')):>14} "
                        f"{str(row.get('sla_target_hours', '?')):>10} "
                        f"{row.get('sla_status', '?'):<10}"
                    )
            else:
                print(f"  {all_status}")


def cmd_health_check(args):
    """Run detection health checks."""
    from orchestration.health_monitor import DetectionHealthMonitor

    monitor = DetectionHealthMonitor()
    list_only = getattr(args, "list_only", False)
    no_issues = getattr(args, "no_issues", False)

    create_issues = not (no_issues or list_only)
    result = monitor.run(create_issues=create_issues)

    checks_run = result.get("checks_run", 0) if isinstance(result, dict) else 0
    alerts_found = result.get("alerts_found", 0) if isinstance(result, dict) else 0
    issues_created = result.get("issues_created", 0) if isinstance(result, dict) else 0
    issues_updated = result.get("issues_updated", 0) if isinstance(result, dict) else 0

    print(f"\n  Health Check Results")
    print(f"  Checks run:       {checks_run}")
    print(f"  Alerts found:     {alerts_found}")
    if not list_only:
        print(f"  Issues created:   {issues_created}")
        print(f"  Issues updated:   {issues_updated}")

    if alerts_found == 0:
        print("\n  All deployed rules are healthy — no issues detected.")


def cmd_export_status(args):
    """Generate STATUS.md from state machine ground truth."""
    sm = StateManager()
    all_requests = sm.list_all()
    summary = sm.status_summary()
    repo_root = Path(__file__).resolve().parent.parent.parent

    # Count by state
    by_state = {}
    for state in ["REQUESTED", "SCENARIO_BUILT", "AUTHORED", "VALIDATED",
                   "DEPLOYED", "MONITORING", "TUNED", "RETIRED"]:
        by_state[state] = summary.get(state, [])

    # Count by rule_type
    rule_types = {"sigma": 0, "eql": 0, "threshold": 0}
    for r in all_requests:
        rt = r.get("rule_type", "sigma")
        rule_types[rt] = rule_types.get(rt, 0) + 1

    total = len(all_requests)
    monitoring = len(by_state["MONITORING"])
    validated = len(by_state["VALIDATED"])
    authored = len(by_state["AUTHORED"])
    deployed = len(by_state["DEPLOYED"])

    # Count needs_rework
    needs_rework = sum(1 for r in all_requests
                       if r.get("quality_score", 0) > 0 and r.get("quality_score", 0) < 0.75)

    content = f"""# Detection Pipeline Status

> Auto-generated from state machine on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
> Run `cd autonomous && python3 orchestration/cli.py export-status` to regenerate

## Summary

| Metric | Count |
|--------|-------|
| Total rules | {total} |
| Sigma | {rule_types['sigma']} |
| EQL | {rule_types['eql']} |
| Threshold | {rule_types['threshold']} |
| MONITORING | {monitoring} |
| DEPLOYED | {deployed} |
| VALIDATED | {validated} |
| AUTHORED | {authored} |
| Needs rework | {needs_rework} |

## By State

"""
    for state in ["MONITORING", "DEPLOYED", "VALIDATED", "AUTHORED",
                   "SCENARIO_BUILT", "REQUESTED", "TUNED", "RETIRED"]:
        techniques = by_state.get(state, [])
        if techniques:
            content += f"### {state} ({len(techniques)})\n\n"
            for tid in sorted(techniques):
                req = sm.get(tid)
                title = req.get("title", "") if req else ""
                f1 = req.get("quality_score", "") if req else ""
                f1_str = f" (F1={f1})" if f1 else ""
                content += f"- {tid}: {title}{f1_str}\n"
            content += "\n"

    status_path = repo_root / "STATUS.md"
    status_path.write_text(content, encoding="utf-8")
    print(f"  STATUS.md regenerated ({total} rules)")


def cmd_dashboard_update(args):
    """Push metrics to detection health dashboard."""
    import subprocess as _subprocess

    repo_root = Path(__file__).resolve().parent.parent.parent
    script = repo_root / "monitoring" / "dashboards" / "ingest-metrics.py"

    if not script.exists():
        print(f"  Error: dashboard script not found at {script}")
        return

    cmd = [sys.executable, str(script)]
    if getattr(args, "dry_run", False):
        cmd.append("--dry-run")

    print(f"  Running: {' '.join(cmd)}")
    proc = _subprocess.run(cmd, cwd=str(repo_root))
    if proc.returncode != 0:
        print(f"  dashboard-update exited with code {proc.returncode}")
    else:
        print("  dashboard-update complete.")


def cmd_pack_deploy(args):
    """Deploy all required rules in a pack to active SIEMs."""
    import yaml
    from orchestration.siem import deploy_to_siems

    repo_root = Path(__file__).resolve().parent.parent.parent
    packs_dir = repo_root / "detections" / "packs"

    pack_dir = packs_dir / args.pack_name
    if not pack_dir.exists():
        print(f"  Pack '{args.pack_name}' not found.")
        return

    with open(pack_dir / "pack.yml", encoding="utf-8") as f:
        manifest = yaml.safe_load(f)

    rules = manifest.get("rules", [])
    required_rules = [r for r in rules if r.get("required", True)]

    print(f"\n  Deploying: {manifest.get('name')} v{manifest.get('version')}")
    print(f"  Rules to deploy: {len(required_rules)} required (of {len(rules)} total)\n")

    deployed = 0
    skipped = 0

    for rule_ref in required_rules:
        technique = rule_ref.get("technique", "?")
        sigma_path = repo_root / rule_ref.get("path", "")

        if not sigma_path.exists():
            print(f"  [{technique}] SKIP — rule file not found: {rule_ref.get('path')}")
            skipped += 1
            continue

        # Find compiled artifacts
        compiled_dir = sigma_path.parent / "compiled"
        rule_stem = sigma_path.stem
        lucene_path = compiled_dir / f"{rule_stem}.lucene"
        spl_path = compiled_dir / f"{rule_stem}.spl"

        if not lucene_path.exists():
            print(f"  [{technique}] SKIP — no compiled Lucene query: {lucene_path.name}")
            skipped += 1
            continue

        with open(sigma_path, encoding="utf-8") as f:
            sigma_data = yaml.safe_load(f)
        lucene = lucene_path.read_text(encoding="utf-8").strip()
        spl = spl_path.read_text(encoding="utf-8").strip() if spl_path.exists() else ""

        # Build a minimal request object for deploy_to_siems
        request = {
            "technique_id": technique,
            "title": sigma_data.get("title", technique),
            "sigma_rule": str(sigma_path.relative_to(repo_root)),
            "compiled_lucene": str(lucene_path.relative_to(repo_root)),
        }

        try:
            result = deploy_to_siems(request, lucene, spl, sigma_data)
            if result:
                siems = list(result.keys())
                print(f"  [{technique}] DEPLOYED -> {', '.join(siems)}")
                deployed += 1
            else:
                print(f"  [{technique}] SKIP — no SIEMs available")
                skipped += 1
        except Exception as e:
            print(f"  [{technique}] ERROR — {e}")
            skipped += 1

    print(f"\n  Pack deploy complete: {deployed} deployed, {skipped} skipped")


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
                           choices=["intel", "red-team", "author", "validation",
                                    "deployment", "tuning", "coverage", "security",
                                    "blue-team", "quality"])

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

    # data-sources (Phase 3)
    sub.add_parser("data-sources", help="Report data source gap status")

    # queue (Phase 4 -- coordinator)
    sub.add_parser("queue", help="Show coordinator work queue")

    # coverage (Phase 4 -- coverage analysis)
    sub.add_parser("coverage", help="Generate and display coverage analysis")

    # feedback (Phase 4 -- analyst feedback loop)
    p_fb = sub.add_parser("feedback", help="Record or view analyst feedback")
    p_fb.add_argument("technique_id", nargs="?")
    p_fb.add_argument("--verdict", choices=["tp", "fp", "fn"])
    p_fb.add_argument("--reason", default="")
    p_fb.add_argument("--show", action="store_true")
    p_fb.add_argument("--summary", action="store_true")

    # compliance (Phase 4 -- compliance control mapping)
    p_comp = sub.add_parser("compliance", help="List compliance controls")
    p_comp.add_argument("--framework", help="Filter by framework (e.g., PCI-DSS)")

    # data-quality (Phase 5 -- data quality monitoring)
    p_dq = sub.add_parser("data-quality", help="Run data quality checks on log sources")
    p_dq.add_argument("--source", default=None, metavar="SOURCE_ID",
                      help="Check a single source instead of all")
    p_dq.add_argument("--export", action="store_true",
                      help="Export per-source JSON reports to monitoring/data-quality/")

    # schema-diff (Phase 5 -- schema version comparison)
    p_sd = sub.add_parser("schema-diff", help="Compare two schema versions for a source")
    p_sd.add_argument("source", help="Source name (e.g. sysmon_eid_1)")
    p_sd.add_argument("old_version", help="Old schema version tag (e.g. v1)")
    p_sd.add_argument("new_version", help="New schema version tag (e.g. v2)")

    # data-gaps (Phase 5 -- gap analysis)
    sub.add_parser("data-gaps", help="Show technique/data-source gap analysis for Fawkes C2")

    # perf (Phase 6 -- performance profiling)
    p_perf = sub.add_parser("perf", help="Profile detection query performance")
    p_perf.add_argument("technique_id", nargs="?", help="Technique ID to profile (e.g., T1059.001)")
    p_perf.add_argument("--scale", default="small", choices=["small", "medium", "large"],
                        help="Scale tier: small (10K), medium (100K), large (1M)")
    p_perf.add_argument("--all", action="store_true", help="Profile all detections")
    p_perf.add_argument("--report", action="store_true", help="Show stored performance results")

    # export-status (Fix Pack 1 -- regenerate STATUS.md from state machine)
    sub.add_parser("export-status", help="Regenerate STATUS.md from state machine ground truth")

    # sla (Phase 7 -- SLA metrics)
    p_sla = sub.add_parser("sla", help="Show SLA metrics for detections")
    p_sla.add_argument("technique_id", nargs="?", help="Specific technique ID")
    p_sla.add_argument("--month", help="Month to report (YYYY-MM)")
    p_sla.add_argument("--breaches", action="store_true", help="Show only SLA breaches")
    p_sla.add_argument("--format", choices=["table", "json"], default="table")

    # health-check (Phase 7 -- detection health monitoring)
    p_hc = sub.add_parser("health-check", help="Run detection health checks")
    p_hc.add_argument("--no-issues", action="store_true", help="Don't create GitHub issues")
    p_hc.add_argument("--list-only", action="store_true", help="List alerts without creating issues")

    # dashboard-update (Phase 7 -- push metrics to dashboard)
    p_du = sub.add_parser("dashboard-update", help="Push metrics to detection health dashboard")
    p_du.add_argument("--dry-run", action="store_true", help="Preview without indexing")

    # pack (Phase 6 -- content pack management)
    p_pack = sub.add_parser("pack", help="Content pack management")
    p_pack_sub = p_pack.add_subparsers(dest="pack_command", required=True)
    p_pack_sub.add_parser("list", help="List all content packs")
    p_pack_validate = p_pack_sub.add_parser("validate", help="Validate a content pack")
    p_pack_validate.add_argument("pack_name", help="Pack directory name (e.g., process-injection)")
    p_pack_deploy_cmd = p_pack_sub.add_parser("deploy", help="Deploy a content pack to SIEMs")
    p_pack_deploy_cmd.add_argument("pack_name", help="Pack directory name (e.g., process-injection)")

    args = parser.parse_args()
    cmd_map = {
        "status": cmd_status,
        "pending": cmd_pending,
        "get": cmd_get,
        "create": cmd_create,
        "transition": cmd_transition,
        "update": cmd_update,
        "deploy": cmd_deploy,
        "data-sources": cmd_data_sources,
        "queue": cmd_queue,
        "coverage": cmd_coverage,
        "feedback": cmd_feedback,
        "compliance": cmd_compliance,
        "data-quality": cmd_data_quality,
        "schema-diff": cmd_schema_diff,
        "data-gaps": cmd_data_gaps,
        "perf": cmd_perf,
        "sla": cmd_sla,
        "health-check": cmd_health_check,
        "dashboard-update": cmd_dashboard_update,
        "export-status": cmd_export_status,
    }
    if args.command == "pack":
        pack_cmd_map = {
            "list": cmd_pack_list,
            "validate": cmd_pack_validate,
            "deploy": cmd_pack_deploy,
        }
        pack_cmd_map[args.pack_command](args)
        return
    cmd_map[args.command](args)


if __name__ == "__main__":
    main()
