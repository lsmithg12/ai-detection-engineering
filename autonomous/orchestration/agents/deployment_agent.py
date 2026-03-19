"""
Deployment Agent — Deploys validated detections to SIEMs.

Processes detections in VALIDATED state with auto_deploy_eligible=True:
  VALIDATED -> DEPLOYED

Also supports rollback (stub for future use).

Extracted from blue_team_agent.py and cli.py cmd_deploy in Phase 4 (Task 4.4).

Called by agent_runner.py. Implements run(state_manager) interface.
"""

import datetime
import json
from pathlib import Path

import yaml

from orchestration.state import StateManager
from orchestration import learnings
from orchestration.siem import (
    deploy_to_siems,
    check_elastic,
    check_splunk,
)

AUTONOMOUS_DIR = Path(__file__).resolve().parent.parent.parent
REPO_ROOT = AUTONOMOUS_DIR.parent

AGENT_NAME = "deployment"


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def deploy_single(request: dict, state_manager: StateManager) -> dict:
    """
    Deploy a single VALIDATED detection to available SIEMs.

    Reads sigma rule and compiled queries from disk, calls deploy_to_siems(),
    and transitions to DEPLOYED on success.

    Returns result dict with deployment status.
    """
    tid = request["technique_id"]
    result = {"technique_id": tid, "title": request.get("title", ""), "status": "failed"}

    sigma_path_rel = request.get("sigma_rule", "")
    lucene_path_rel = request.get("compiled_lucene", "")
    spl_path_rel = request.get("compiled_spl", "")
    compiled_artifact_rel = request.get("compiled_artifact", "")
    rule_type = request.get("rule_type", "sigma")

    # Diagnostic error messages (ISSUE-012)
    missing = []
    if not sigma_path_rel:
        missing.append("sigma_rule field empty in detection-request")
    if not lucene_path_rel and not compiled_artifact_rel:
        missing.append("compiled_lucene and compiled_artifact both empty")
    if sigma_path_rel and not (REPO_ROOT / sigma_path_rel).exists():
        missing.append(f"sigma file not found: {sigma_path_rel}")
    if lucene_path_rel and not (REPO_ROOT / lucene_path_rel).exists() and not compiled_artifact_rel:
        missing.append(f"lucene file not found: {lucene_path_rel}")

    if missing:
        details = "; ".join(missing)
        result["error"] = details
        print(f"    [deployment] Skipping {tid} -- {details}")
        return result

    sigma_full = REPO_ROOT / sigma_path_rel
    spl_full = REPO_ROOT / spl_path_rel if spl_path_rel else None

    with open(sigma_full, encoding="utf-8") as f:
        sigma_data = yaml.safe_load(f)
    spl = spl_full.read_text(encoding="utf-8").strip() if spl_full and spl_full.exists() else ""

    # For EQL/threshold rules, use pre-built _elastic.json directly
    elastic_payload = None
    if rule_type in ("eql", "threshold") and compiled_artifact_rel:
        artifact_full = REPO_ROOT / compiled_artifact_rel
        if artifact_full.exists():
            with open(artifact_full, encoding="utf-8") as f:
                elastic_payload = json.load(f)
            lucene = ""  # Not used for EQL/threshold
            print(f"    [deployment] Using pre-built {rule_type} artifact: {compiled_artifact_rel}")
        else:
            result["error"] = f"compiled_artifact not found: {compiled_artifact_rel}"
            print(f"    [deployment] Skipping {tid} -- {result['error']}")
            return result
    else:
        lucene_full = REPO_ROOT / lucene_path_rel
        lucene = lucene_full.read_text(encoding="utf-8").strip()

    print(f"    [deployment] Deploying {tid} -- {request.get('title', '')}")
    deploy_results = deploy_to_siems(request, lucene, spl, sigma_data,
                                      elastic_payload=elastic_payload)

    if not deploy_results:
        result["error"] = "No SIEMs available"
        print(f"    [deployment] No SIEMs available for {tid}")
        return result

    # Record SIEM-specific identifiers
    deploy_details = []
    if "elastic" in deploy_results:
        state_manager.update(
            tid, agent=AGENT_NAME,
            elastic_rule_id=deploy_results["elastic"].get("rule_id", ""),
        )
        deploy_details.append("Elastic")
    if "splunk" in deploy_results:
        state_manager.update(
            tid, agent=AGENT_NAME,
            splunk_saved_search=deploy_results["splunk"].get("search_name", ""),
        )
        deploy_details.append("Splunk")

    # Transition to DEPLOYED
    try:
        state_manager.transition(
            tid, "DEPLOYED", agent=AGENT_NAME,
            details=f"Deployed to {' + '.join(deploy_details)}",
        )
        state_manager.update(
            tid, agent=AGENT_NAME,
            deployed_date=_now_iso(),
        )
        print(f"    [deployment] {tid} -> DEPLOYED ({' + '.join(deploy_details)})")
        result["status"] = "deployed"
        result["siem_targets"] = deploy_details

        # ISSUE-015: If SIEM confirms rule is active, go straight to MONITORING
        rule_active = False
        if "elastic" in deploy_results:
            elastic_r = deploy_results["elastic"]
            # Elastic Detection Engine returns the rule with enabled=true on success
            if elastic_r and elastic_r.get("enabled", elastic_r.get("rule_id")):
                rule_active = True
        if rule_active:
            try:
                state_manager.transition(
                    tid, "MONITORING", agent=AGENT_NAME,
                    details="Rule confirmed active in SIEM after deployment",
                )
                print(f"    [deployment] {tid} -> MONITORING (confirmed active)")
                result["status"] = "monitoring"
            except ValueError:
                pass  # DEPLOYED is fine — tuning agent will promote later
    except ValueError as e:
        result["error"] = f"DEPLOYED transition failed: {e}"
        print(f"    [deployment] DEPLOYED transition failed for {tid}: {e}")

    return result


def verify_deployment(request: dict) -> dict:
    """
    Health-check a deployed detection.

    Returns connectivity results for each SIEM where the rule was deployed.
    """
    tid = request["technique_id"]
    checks = {}

    if request.get("elastic_rule_id"):
        checks["elastic"] = check_elastic()
    if request.get("splunk_saved_search"):
        checks["splunk"] = check_splunk()

    return {
        "technique_id": tid,
        "siem_health": checks,
        "all_healthy": all(checks.values()) if checks else False,
    }


def rollback(request: dict, state_manager: StateManager) -> dict:
    """
    Rollback a deployed detection (stub for future implementation).

    Phase 7 will add:
    - Elastic rule deletion via Detection Engine API
    - Splunk saved search deletion
    - State transition DEPLOYED -> VALIDATED
    - Changelog entry recording the rollback reason
    """
    tid = request["technique_id"]
    print(f"    [deployment] Rollback for {tid} -- not yet implemented (Phase 7)")
    return {
        "technique_id": tid,
        "status": "not_implemented",
        "message": "Rollback will be implemented in Phase 7",
    }


def run(state_manager: StateManager) -> dict:
    """
    Main entry point for the deployment agent.

    1. Load learnings
    2. Check SIEM availability
    3. Query VALIDATED detections with auto_deploy_eligible=True
    4. Deploy each to available SIEMs
    5. Verify deployments
    6. Return summary
    """
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    print(f"  [deployment] Starting deployment agent run {run_id}")

    # 1. Load briefing
    briefing = learnings.get_briefing(AGENT_NAME)
    print(f"  [deployment] {briefing}")

    # 2. Check SIEM availability
    es_up = check_elastic()
    splunk_up = check_splunk()
    if not es_up and not splunk_up:
        print("  [deployment] No SIEMs available. Nothing to deploy.")
        return {"summary": "No SIEMs available", "detections_deployed": 0}

    siem_status = []
    if es_up:
        siem_status.append("Elastic")
    if splunk_up:
        siem_status.append("Splunk")
    print(f"  [deployment] Active SIEMs: {', '.join(siem_status)}")

    # 3. Query VALIDATED detections eligible for deployment
    validated = state_manager.query_by_state("VALIDATED")
    eligible = [r for r in validated if r.get("auto_deploy_eligible")]

    if not eligible:
        print("  [deployment] No VALIDATED detections eligible for deployment.")
        # ISSUE-013: Surface the dead zone — rules validated but not auto-deploy eligible
        manual_deploy = [r for r in validated if not r.get("auto_deploy_eligible")]
        if manual_deploy:
            print(f"  [deployment] {len(manual_deploy)} VALIDATED rules need manual deploy (F1 < 0.90):")
            for r in manual_deploy:
                f1 = r.get("quality_score", 0)
                print(f"    - {r['technique_id']} (F1={f1:.2f}) — deploy manually: cli.py deploy --validated")
        return {"summary": "No eligible detections", "detections_deployed": 0}

    print(f"  [deployment] Found {len(eligible)} VALIDATED detections eligible for deployment")

    # ISSUE-013: Also log skipped manual-deploy rules
    manual_deploy = [r for r in validated if not r.get("auto_deploy_eligible")]
    if manual_deploy:
        print(f"  [deployment] Note: {len(manual_deploy)} additional VALIDATED rules need manual deploy (F1 0.75-0.89)")

    # 4. Deploy each
    results = []
    deployed = 0

    for request in eligible:
        tid = request["technique_id"]
        print(f"\n  [deployment] === Deploying {tid} -- {request.get('title', '')} ===")

        deploy_result = deploy_single(request, state_manager)
        results.append(deploy_result)

        if deploy_result["status"] in ("deployed", "monitoring"):
            deployed += 1

    # 5. Summary
    summary = f"Deployed {deployed}/{len(eligible)} detections to {', '.join(siem_status)}"
    print(f"\n  [deployment] {summary}")

    return {
        "summary": summary,
        "detections_deployed": deployed,
        "siem_targets": siem_status,
        "results": results,
    }
