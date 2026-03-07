"""
Blue Team Agent — Authors Sigma rules, validates against scenarios,
and deploys detections to Elastic/Splunk.

Processes detections in SCENARIO_BUILT state through:
  SCENARIO_BUILT -> AUTHORED -> VALIDATED -> DEPLOYED

Called by agent_runner.py. Implements run(state_manager) interface.
"""

import datetime
import json
import subprocess
from pathlib import Path
from uuid import uuid4


import yaml

from orchestration.state import StateManager
from orchestration import learnings
from orchestration.siem import deploy_to_siems, TACTIC_MAP, SEVERITY_MAP
from orchestration import claude_llm

AUTONOMOUS_DIR = Path(__file__).resolve().parent.parent.parent
REPO_ROOT = AUTONOMOUS_DIR.parent
DETECTIONS_DIR = REPO_ROOT / "detections"
TESTS_DIR = REPO_ROOT / "tests"
TEMPLATES_DIR = REPO_ROOT / "templates"

AGENT_NAME = "blue-team"
MAX_DETECTIONS = 5
AUTO_DEPLOY_THRESHOLD = 0.90
MAX_FP_RATE_AUTO_DEPLOY = 0.05

# Map MITRE technique prefixes to tactic directories
TECHNIQUE_TACTIC_MAP = {
    "T1055": "privilege_escalation",
    "T1134": "credential_access",
    "T1059": "execution",
    "T1053": "persistence",
    "T1547": "persistence",
    "T1543": "persistence",
    "T1070": "defense_evasion",
    "T1562": "defense_evasion",
    "T1027": "defense_evasion",
    "T1197": "defense_evasion",
    "T1071": "command_and_control",
    "T1219": "command_and_control",
    "T1078": "initial_access",
    "T1566": "initial_access",
    "T1087": "discovery",
    "T1047": "execution",
    "T1003": "credential_access",
}


def _load_agent_model() -> str:
    """Get the model name configured for this agent."""
    cfg = claude_llm._load_agent_config(AGENT_NAME)
    return cfg.get("model", "opus")


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


# Sigma logsource categories by Sysmon EID
SYSMON_CATEGORIES = {
    "1": "process_creation",
    "3": "network_connection",
    "7": "image_load",
    "8": "create_remote_thread",
    "10": "process_access",
    "11": "file_event",
    "13": "registry_set",
    "22": "dns_query",
}



def load_scenario(scenario_path: str) -> dict | None:
    """Load a scenario JSON file."""
    full_path = REPO_ROOT / scenario_path
    if not full_path.exists():
        return None
    with open(full_path, encoding="utf-8") as f:
        return json.load(f)


def determine_logsource(scenario: dict) -> dict:
    """Determine Sigma logsource from scenario log_sources_used."""
    log_sources = scenario.get("log_sources_used", [])
    for ls in log_sources:
        if ls.startswith("sysmon_"):
            eid = ls.replace("sysmon_", "")
            cat = SYSMON_CATEGORIES.get(eid, "process_creation")
            return {"category": cat, "product": "windows"}
        if ls.startswith("windows_security"):
            return {"category": "authentication", "product": "windows"}
    return {"category": "process_creation", "product": "windows"}


def generate_sigma_rule(request: dict, scenario: dict) -> str:
    """
    Generate a Sigma rule YAML string from a detection request and scenario.

    This creates a reasonable detection based on the scenario's key_fields
    and attack event patterns. For complex logic, Claude should enhance
    this in interactive mode.
    """
    tid = request["technique_id"]
    tid_under = tid.lower().replace(".", "_")
    title = request.get("title", f"Detection for {tid}")
    tactic_key = request.get("mitre_tactic", "execution")
    tactic_name, tactic_id = TACTIC_MAP.get(tactic_key, ("Execution", "TA0002"))
    logsource = determine_logsource(scenario)
    expected = scenario.get("expected_detection", {})
    attack_events = scenario.get("events", {}).get("attack_sequence", [])

    # Extract detection patterns from attack events
    selection = {}
    if attack_events:
        first = attack_events[0]
        event_code = first.get("event", {}).get("code")
        if event_code:
            selection["event.code"] = str(event_code)

        # Collect attack process names for filter exclusion later
        attack_proc_names = set()
        for evt in attack_events:
            p = evt.get("process", {}).get("name", "")
            if p:
                attack_proc_names.add(p)

        # Extract key field patterns from attack events
        # Use |contains for path-like fields, exact match for names
        key_fields = expected.get("key_fields", [])
        for field in key_fields:
            values = set()
            for evt in attack_events:
                val = _get_nested(evt, field)
                if val and val not in ("{{now}}",):
                    values.add(str(val))
            if not values or len(values) > 5:
                continue
            # For executable/command_line paths, use |contains with key substrings
            if "executable" in field or "command_line" in field:
                contains_vals = []
                for v in sorted(values):
                    # Extract the distinctive part (filename or key argument)
                    parts = v.replace("\\", "/").split("/")
                    fname = parts[-1] if parts else v
                    if fname and fname not in contains_vals:
                        contains_vals.append(fname)
                if contains_vals:
                    selection[f"{field}|contains"] = contains_vals if len(contains_vals) > 1 else contains_vals[0]
            elif field == "process.name":
                selection[field] = sorted(values) if len(values) > 1 else list(values)[0]
            else:
                selection[field] = sorted(values) if len(values) > 1 else list(values)[0]

    # Build filter from benign events — only exclude procs NOT used in attacks
    benign_events = scenario.get("events", {}).get("benign_similar", [])
    filters = {}
    if benign_events:
        benign_only_procs = set()
        for evt in benign_events:
            proc = evt.get("process", {}).get("name", "")
            if proc and proc not in attack_proc_names:
                benign_only_procs.add(proc)
        if benign_only_procs:
            filters["process.name"] = sorted(benign_only_procs)

    # Build the rule dict
    rule = {
        "title": f"{title} [{tid}]",
        "id": str(uuid4()),
        "status": "experimental",
        "description": f"Detects {title.lower()}. {expected.get('notes', '')}",
        "author": "blue-team-agent",
        "date": _today(),
        "modified": _today(),
        "references": [
            f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        ],
        "tags": [
            f"attack.{tactic_key}",
            f"attack.{tid.lower()}",
        ],
        "logsource": logsource,
        "detection": {"selection": selection, "condition": "selection"},
        "falsepositives": [expected.get("notes", "See scenario benign_similar events for known FP patterns")],
        "level": "high",
    }

    # Add Fawkes tag if applicable
    if request.get("fawkes_commands"):
        rule["tags"].append("detection.fawkes")
        rule["references"].append("https://github.com/galoryber/fawkes")

    # Add filter if we have benign patterns
    if filters:
        rule["detection"]["filter_legitimate"] = filters
        rule["detection"]["condition"] = "selection and not filter_legitimate"

    return yaml.dump(rule, default_flow_style=False, sort_keys=False, width=120)


def _get_nested(d: dict, dotted_key: str):
    """Get a nested dict value by dotted key (e.g., 'process.name')."""
    keys = dotted_key.split(".")
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k)
        else:
            return None
    return d


def save_sigma_rule(tactic: str, tid_under: str, sigma_yaml: str) -> Path:
    """Save Sigma rule to detections/<tactic>/."""
    tactic_dir = DETECTIONS_DIR / tactic
    tactic_dir.mkdir(parents=True, exist_ok=True)
    path = tactic_dir / f"{tid_under}.yml"
    path.write_text(sigma_yaml, encoding="utf-8")
    return path


def transpile_sigma(rule_path: Path) -> tuple[str, str]:
    """
    Transpile Sigma rule to Lucene and SPL.
    Returns (lucene_query, spl_query).
    """
    lucene = ""
    spl = ""

    try:
        result = subprocess.run(
            ["sigma", "convert", "-t", "lucene", "-p", "ecs_windows", str(rule_path)],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        if result.returncode == 0:
            lucene = result.stdout.strip()
        else:
            print(f"    [blue-team] Lucene transpile warning: {result.stderr.strip()[:200]}")
            lucene = result.stdout.strip()
    except Exception as e:
        print(f"    [blue-team] Lucene transpile failed: {e}")

    try:
        result = subprocess.run(
            ["sigma", "convert", "-t", "splunk", "--without-pipeline", str(rule_path)],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        if result.returncode == 0:
            spl = result.stdout.strip()
        else:
            print(f"    [blue-team] SPL transpile warning: {result.stderr.strip()[:200]}")
            spl = result.stdout.strip()
    except Exception as e:
        print(f"    [blue-team] SPL transpile failed: {e}")

    return lucene, spl


def save_compiled(tactic: str, tid_under: str, lucene: str, spl: str) -> tuple[Path, Path]:
    """Save compiled queries."""
    compiled_dir = DETECTIONS_DIR / tactic / "compiled"
    compiled_dir.mkdir(parents=True, exist_ok=True)

    lucene_path = compiled_dir / f"{tid_under}.lucene"
    spl_path = compiled_dir / f"{tid_under}.spl"
    lucene_path.write_text(lucene, encoding="utf-8")
    spl_path.write_text(spl, encoding="utf-8")
    return lucene_path, spl_path


def save_test_cases(tid_under: str, scenario: dict):
    """Save TP and TN test cases from scenario events."""
    tp_dir = TESTS_DIR / "true_positives"
    tn_dir = TESTS_DIR / "true_negatives"
    tp_dir.mkdir(parents=True, exist_ok=True)
    tn_dir.mkdir(parents=True, exist_ok=True)

    attack = scenario.get("events", {}).get("attack_sequence", [])
    benign = scenario.get("events", {}).get("benign_similar", [])

    tp_path = tp_dir / f"{tid_under}_tp.json"
    tn_path = tn_dir / f"{tid_under}_tn.json"

    with open(tp_path, "w", encoding="utf-8") as f:
        json.dump(attack, f, indent=2)
    with open(tn_path, "w", encoding="utf-8") as f:
        json.dump(benign, f, indent=2)

    return tp_path, tn_path


def validate_detection(sigma_rule_path: str, scenario: dict) -> dict:
    """
    Validate a detection against scenario events.

    Uses the Sigma rule's selection/filter directly against events
    for reliable matching (avoids Lucene escaping issues).
    """
    attack_events = scenario.get("events", {}).get("attack_sequence", [])
    benign_events = scenario.get("events", {}).get("benign_similar", [])

    # Load the Sigma rule and extract detection logic
    rule_path = REPO_ROOT / sigma_rule_path
    with open(rule_path, encoding="utf-8") as f:
        rule = yaml.safe_load(f)

    detection = rule.get("detection", {})
    selection = detection.get("selection", {})
    filters = {}
    condition = detection.get("condition", "selection")

    # Collect all filter blocks
    for key, val in detection.items():
        if key.startswith("filter"):
            filters[key] = val

    has_filter = "not" in condition and filters

    def event_matches_block(event, block):
        """Check if an event matches ALL conditions in a detection block."""
        for field_expr, expected_vals in block.items():
            # Parse field name and modifier
            parts = field_expr.split("|")
            field = parts[0]
            modifier = parts[1] if len(parts) > 1 else None

            actual = _get_nested(event, field)
            if actual is None:
                return False
            actual_str = str(actual).lower()

            # Normalize expected values to list
            if not isinstance(expected_vals, list):
                expected_vals = [expected_vals]

            if modifier == "contains":
                if not any(str(v).lower() in actual_str for v in expected_vals):
                    return False
            elif modifier == "startswith":
                if not any(actual_str.startswith(str(v).lower()) for v in expected_vals):
                    return False
            elif modifier == "endswith":
                if not any(actual_str.endswith(str(v).lower()) for v in expected_vals):
                    return False
            else:
                # Exact match (OR logic — any value matches)
                if not any(actual_str == str(v).lower() for v in expected_vals):
                    return False
        return True

    def event_detected(event):
        """Apply selection + filter logic."""
        if not event_matches_block(event, selection):
            return False
        if has_filter:
            for fblock in filters.values():
                if event_matches_block(event, fblock):
                    return False  # Filtered out
        return True

    tp = sum(1 for e in attack_events if event_detected(e))
    fp = sum(1 for e in benign_events if event_detected(e))
    fn = len(attack_events) - tp
    tn = len(benign_events) - fp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    tp_rate = recall

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
        "fp_rate": round(fp_rate, 3),
        "tp_rate": round(tp_rate, 3),
        "total_attack": len(attack_events),
        "total_benign": len(benign_events),
    }


def assess_quality(metrics: dict) -> str:
    """
    Determine quality tier based on validation metrics.
    Returns: 'auto_deploy' | 'human_review' | 'needs_rework'
    """
    f1 = metrics.get("f1_score", 0)
    fp_rate = metrics.get("fp_rate", 1)

    if f1 >= AUTO_DEPLOY_THRESHOLD and fp_rate <= MAX_FP_RATE_AUTO_DEPLOY:
        return "auto_deploy"
    elif f1 >= 0.70:
        return "human_review"
    else:
        return "needs_rework"


def author_and_validate(request: dict, state_manager: StateManager, run_id: str) -> dict:
    """
    Full author -> validate -> (optional deploy) cycle for one detection.
    Returns result dict with status and metrics.
    """
    tid = request["technique_id"]
    tid_under = tid.lower().replace(".", "_")
    # Resolve tactic from request, technique map, or default
    tactic = request.get("mitre_tactic") or TECHNIQUE_TACTIC_MAP.get(tid.split(".")[0], "execution")

    result = {"technique_id": tid, "title": request.get("title", ""), "status": "failed"}

    # Load scenario
    scenario_path = request.get("scenario_file", "")
    if not scenario_path:
        result["error"] = "No scenario file"
        return result

    scenario = load_scenario(scenario_path)
    if not scenario:
        result["error"] = f"Scenario file not found: {scenario_path}"
        return result

    # ─── AUTHOR ─────────────────────────────────────────────────
    print(f"    [blue-team] Authoring Sigma rule for {tid}")

    # Try Claude for rule generation (falls back to deterministic if unavailable)
    sigma_yaml = None
    if claude_llm.is_available():
        print(f"    [blue-team] Using Claude ({_load_agent_model()}) for rule authoring")
        attack_events = scenario.get("events", {}).get("attack_sequence", [])
        benign_events = scenario.get("events", {}).get("benign_similar", [])
        detection_lessons = [
            e["description"] for e in
            learnings.get_relevant_lessons(AGENT_NAME, "detection", max_entries=5)
        ]
        llm_result = claude_llm.ask_for_sigma_rule(
            technique_id=tid,
            technique_name=request.get("title", tid),
            attack_events=attack_events,
            benign_events=benign_events,
            lessons=detection_lessons if detection_lessons else None,
        )
        if llm_result["success"]:
            # Validate YAML is parseable before accepting
            try:
                yaml.safe_load(llm_result["sigma_yaml"])
                sigma_yaml = llm_result["sigma_yaml"]
                print(f"    [blue-team] Claude authored rule ({len(sigma_yaml)} chars)")
            except yaml.YAMLError:
                print(f"    [blue-team] Claude output was not valid YAML, falling back")
                sigma_yaml = None
        else:
            print(f"    [blue-team] Claude unavailable: {llm_result.get('error', '?')}, using deterministic")

    if sigma_yaml is None:
        sigma_yaml = generate_sigma_rule(request, scenario)

    rule_path = save_sigma_rule(tactic, tid_under, sigma_yaml)
    print(f"    [blue-team] Saved: {rule_path.relative_to(REPO_ROOT)}")

    # Transpile
    lucene, spl = transpile_sigma(rule_path)
    if lucene:
        lucene_path, spl_path = save_compiled(tactic, tid_under, lucene, spl)
        print(f"    [blue-team] Transpiled: Lucene ({len(lucene)} chars), SPL ({len(spl)} chars)")
    else:
        print(f"    [blue-team] WARNING: Lucene transpilation produced empty output")
        lucene = ""

    # Save test cases
    tp_path, tn_path = save_test_cases(tid_under, scenario)

    # Update request with artifact paths and tactic (used by state machine for path resolution)
    state_manager.update(
        tid, agent=AGENT_NAME,
        sigma_rule=str(rule_path.relative_to(REPO_ROOT)),
        compiled_lucene=str(lucene_path.relative_to(REPO_ROOT)) if lucene else "",
        compiled_spl=str(spl_path.relative_to(REPO_ROOT)) if spl else "",
        mitre_tactic=tactic,
    )

    # Transition to AUTHORED
    try:
        state_manager.transition(tid, "AUTHORED", agent=AGENT_NAME,
                                 details=f"Sigma rule authored, transpiled to Lucene + SPL")
        print(f"    [blue-team] Transitioned {tid} -> AUTHORED")
    except ValueError as e:
        result["error"] = f"AUTHORED transition failed: {e}"
        return result

    # ─── VALIDATE ───────────────────────────────────────────────
    print(f"    [blue-team] Validating against scenario events")

    metrics = validate_detection(str(rule_path.relative_to(REPO_ROOT)), scenario)
    quality_tier = assess_quality(metrics)

    print(f"    [blue-team] Results: TP={metrics['tp']}/{metrics['total_attack']}, "
          f"FP={metrics['fp']}/{metrics['total_benign']}, "
          f"F1={metrics['f1_score']}, FP_rate={metrics['fp_rate']}")
    print(f"    [blue-team] Quality: {quality_tier}")

    # Save test results (required by schema for DEPLOYED transition)
    results_dir = REPO_ROOT / "tests" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    results_file = results_dir / f"{tid_under}.json"
    results_file.write_text(json.dumps({
        "technique_id": tid,
        "date": _now_iso(),
        "sigma_rule": str(rule_path.relative_to(REPO_ROOT)),
        "metrics": metrics,
        "quality_tier": quality_tier,
    }, indent=2), encoding="utf-8")

    # Update metrics on request
    state_manager.update(
        tid, agent=AGENT_NAME,
        quality_score=metrics["f1_score"],
        fp_rate=metrics["fp_rate"],
        tp_rate=metrics["tp_rate"],
    )

    result["metrics"] = metrics
    result["quality_tier"] = quality_tier

    if quality_tier == "needs_rework":
        result["status"] = "needs_rework"
        learnings.record(
            AGENT_NAME, run_id, "improvement", "detection",
            f"Low quality for {tid}: F1={metrics['f1_score']}",
            f"TP={metrics['tp']}, FP={metrics['fp']}, FN={metrics['fn']}. "
            f"Detection logic may need manual refinement.",
            technique_id=tid,
        )
        return result

    # Transition to VALIDATED
    try:
        state_manager.transition(tid, "VALIDATED", agent=AGENT_NAME,
                                 details=f"F1={metrics['f1_score']}, FP_rate={metrics['fp_rate']}, tier={quality_tier}")
        print(f"    [blue-team] Transitioned {tid} -> VALIDATED")
    except ValueError as e:
        result["error"] = f"VALIDATED transition failed: {e}"
        result["status"] = "authored"
        return result

    # ─── DEPLOY (conditional) ───────────────────────────────────
    if quality_tier == "auto_deploy":
        state_manager.update(tid, agent=AGENT_NAME, auto_deploy_eligible=True)
        print(f"    [blue-team] Eligible for auto-deploy (F1={metrics['f1_score']}, "
              f"FP_rate={metrics['fp_rate']})")

        # Load Sigma rule for metadata
        with open(rule_path, encoding="utf-8") as f:
            sigma_data = yaml.safe_load(f)

        # Deploy to available SIEMs
        deploy_results = deploy_to_siems(request, lucene, spl, sigma_data)

        if deploy_results:
            # Transition VALIDATED -> DEPLOYED
            deploy_details = []
            if "elastic" in deploy_results:
                state_manager.update(tid, agent=AGENT_NAME,
                                     elastic_rule_id=deploy_results["elastic"].get("rule_id", ""))
                deploy_details.append("Elastic")
            if "splunk" in deploy_results:
                state_manager.update(tid, agent=AGENT_NAME,
                                     splunk_saved_search=deploy_results["splunk"].get("search_name", ""))
                deploy_details.append("Splunk")

            try:
                state_manager.transition(tid, "DEPLOYED", agent=AGENT_NAME,
                                         details=f"Deployed to {' + '.join(deploy_details)}. "
                                                 f"F1={metrics['f1_score']}, FP_rate={metrics['fp_rate']}")
                state_manager.update(tid, agent=AGENT_NAME, deployed_date=_now_iso())
                print(f"    [blue-team] Transitioned {tid} -> DEPLOYED ({' + '.join(deploy_details)})")
                result["status"] = "deployed"
                result["auto_deployed"] = True
                result["deploy_targets"] = deploy_details
            except ValueError as e:
                print(f"    [blue-team] DEPLOYED transition failed: {e}")
                result["status"] = "validated"
                result["auto_deployed"] = False
        else:
            print(f"    [blue-team] No SIEMs available — staying at VALIDATED")
            result["status"] = "validated"
            result["auto_deployed"] = False
    else:
        result["status"] = "validated"
        result["auto_deployed"] = False
        print(f"    [blue-team] Pending human review for deployment "
              f"(F1={metrics['f1_score']})")

    return result


def run(state_manager: StateManager) -> dict:
    """
    Main entry point for the blue team agent.

    1. Load learnings
    2. Query SCENARIO_BUILT detections
    3. For each: author Sigma rule, validate, optionally deploy
    4. Return summary
    """
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    print(f"  [blue-team] Starting blue team agent run {run_id}")

    # 1. Load briefing
    briefing = learnings.get_briefing(AGENT_NAME)
    print(f"  [blue-team] {briefing}")

    detection_lessons = learnings.get_relevant_lessons(AGENT_NAME, "detection")
    if detection_lessons:
        print(f"  [blue-team] {len(detection_lessons)} detection lessons loaded")

    # 1b. Deploy any VALIDATED detections that are auto-deploy eligible
    validated_pending = state_manager.query_by_state("VALIDATED")
    deploy_pending = [r for r in validated_pending if r.get("auto_deploy_eligible")]
    deployed_count = 0
    if deploy_pending:
        print(f"  [blue-team] Found {len(deploy_pending)} VALIDATED detections pending deployment")
        for request in deploy_pending:
            tid = request["technique_id"]
            sigma_path = request.get("sigma_rule", "")
            lucene_path = request.get("compiled_lucene", "")
            spl_path = request.get("compiled_spl", "")

            if not sigma_path or not lucene_path:
                continue

            # Load files
            sigma_full = REPO_ROOT / sigma_path
            lucene_full = REPO_ROOT / lucene_path
            spl_full = REPO_ROOT / spl_path if spl_path else None

            if not sigma_full.exists() or not lucene_full.exists():
                continue

            with open(sigma_full, encoding="utf-8") as f:
                sigma_data = yaml.safe_load(f)
            lucene = lucene_full.read_text(encoding="utf-8").strip()
            spl = spl_full.read_text(encoding="utf-8").strip() if spl_full and spl_full.exists() else ""

            print(f"\n  [blue-team] === Deploying {tid} — {request.get('title', '')} ===")
            deploy_results = deploy_to_siems(request, lucene, spl, sigma_data)

            if deploy_results:
                deploy_details = []
                if "elastic" in deploy_results:
                    state_manager.update(tid, agent=AGENT_NAME,
                                         elastic_rule_id=deploy_results["elastic"].get("rule_id", ""))
                    deploy_details.append("Elastic")
                if "splunk" in deploy_results:
                    state_manager.update(tid, agent=AGENT_NAME,
                                         splunk_saved_search=deploy_results["splunk"].get("search_name", ""))
                    deploy_details.append("Splunk")

                try:
                    state_manager.transition(tid, "DEPLOYED", agent=AGENT_NAME,
                                             details=f"Deployed to {' + '.join(deploy_details)}")
                    state_manager.update(tid, agent=AGENT_NAME, deployed_date=_now_iso())
                    print(f"    [blue-team] Transitioned {tid} -> DEPLOYED ({' + '.join(deploy_details)})")
                    deployed_count += 1
                except ValueError as e:
                    print(f"    [blue-team] DEPLOYED transition failed: {e}")

        if deployed_count:
            print(f"\n  [blue-team] Deployed {deployed_count} previously validated detections")

    # 2. Get SCENARIO_BUILT detections
    ready = state_manager.query_by_state("SCENARIO_BUILT")
    if not ready and not deploy_pending:
        print("  [blue-team] No SCENARIO_BUILT detections. Nothing to do.")
        return {"summary": "No SCENARIO_BUILT detections", "detections_authored": 0}
    if not ready:
        summary = f"Deployed {deployed_count} previously validated detections"
        print(f"\n  [blue-team] {summary}")
        return {"summary": summary, "detections_deployed": deployed_count}

    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ready.sort(key=lambda r: priority_order.get(r.get("priority", "medium"), 2))

    print(f"  [blue-team] Found {len(ready)} SCENARIO_BUILT detections, "
          f"processing up to {MAX_DETECTIONS}")

    # 3. Process each detection
    results = []
    authored = 0
    validated = 0
    deployed = 0
    needs_rework = 0

    for request in ready[:MAX_DETECTIONS]:
        tid = request["technique_id"]
        print(f"\n  [blue-team] === Processing {tid} — {request.get('title', '')} ===")

        result = author_and_validate(request, state_manager, run_id)
        results.append(result)

        if result["status"] == "deployed":
            deployed += 1
            authored += 1
            validated += 1
        elif result["status"] == "validated":
            validated += 1
            authored += 1
        elif result["status"] == "needs_rework":
            authored += 1
            needs_rework += 1
        elif result["status"] == "authored":
            authored += 1

    # 4. Summary
    summary = (
        f"Authored {authored}, validated {validated}, "
        f"auto-deploy eligible {deployed}, needs rework {needs_rework}"
    )
    print(f"\n  [blue-team] {summary}")

    return {
        "summary": summary,
        "detections_authored": authored,
        "detections_validated": validated,
        "detections_deployed": deployed,
        "detections_needs_rework": needs_rework,
        "results": results,
    }
