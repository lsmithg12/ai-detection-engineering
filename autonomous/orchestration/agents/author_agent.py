"""
Author Agent — Writes Sigma detection rules from scenarios.

Processes detections in SCENARIO_BUILT state:
  SCENARIO_BUILT -> AUTHORED

Extracted from blue_team_agent.py in Phase 4 (Task 4.4).
Validation is now handled by validation_agent.py.
Deployment is now handled by deployment_agent.py.

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
from orchestration.siem import TACTIC_MAP, SEVERITY_MAP
from orchestration import claude_llm

AUTONOMOUS_DIR = Path(__file__).resolve().parent.parent.parent
REPO_ROOT = AUTONOMOUS_DIR.parent
DETECTIONS_DIR = REPO_ROOT / "detections"
TESTS_DIR = REPO_ROOT / "tests"
TEMPLATES_DIR = REPO_ROOT / "templates"

AGENT_NAME = "author"
MAX_DETECTIONS = 5

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
    "T1490": "impact",
    "T1569": "execution",
    "T1046": "discovery",
    "T1083": "discovery",
}

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


def _load_agent_model() -> str:
    """Get the model name configured for this agent."""
    cfg = claude_llm._load_agent_config(AGENT_NAME)
    return cfg.get("model", "opus")


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def _get_nested(d: dict, dotted_key: str):
    """Get a nested dict value by dotted key (e.g., 'process.name')."""
    keys = dotted_key.split(".")
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k)
        else:
            return None
    return d


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

    # Build filter from benign events -- only exclude procs NOT used in attacks
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
        "author": "author-agent",
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
            print(f"    [author] Lucene transpile warning: {result.stderr.strip()[:200]}")
            lucene = result.stdout.strip()
    except Exception as e:
        print(f"    [author] Lucene transpile failed: {e}")

    try:
        result = subprocess.run(
            ["sigma", "convert", "-t", "splunk", "--without-pipeline", str(rule_path)],
            capture_output=True, text=True, cwd=str(REPO_ROOT),
        )
        if result.returncode == 0:
            spl = result.stdout.strip()
        else:
            print(f"    [author] SPL transpile warning: {result.stderr.strip()[:200]}")
            spl = result.stdout.strip()
    except Exception as e:
        print(f"    [author] SPL transpile failed: {e}")

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


def author_detection(request: dict, state_manager: StateManager, run_id: str) -> dict:
    """
    Author a single detection: generate Sigma rule, transpile, save test cases.
    Transitions SCENARIO_BUILT -> AUTHORED.

    Returns result dict with status and artifact paths.
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

    # --- AUTHOR ---
    print(f"    [author] Authoring Sigma rule for {tid}")

    # Try Claude for rule generation (falls back to deterministic if unavailable)
    sigma_yaml = None
    if claude_llm.is_available():
        print(f"    [author] Using Claude ({_load_agent_model()}) for rule authoring")
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
                parsed = yaml.safe_load(llm_result["sigma_yaml"])
                if isinstance(parsed, dict) and "detection" in parsed:
                    sigma_yaml = llm_result["sigma_yaml"]
                    print(f"    [author] Claude authored rule ({len(sigma_yaml)} chars)")
                else:
                    print(f"    [author] Claude output is not a valid Sigma rule (missing detection block), falling back")
            except yaml.YAMLError:
                print(f"    [author] Claude output was not valid YAML, falling back")
                sigma_yaml = None
        else:
            print(f"    [author] Claude unavailable: {llm_result.get('error', '?')}, using deterministic")

    if sigma_yaml is None:
        sigma_yaml = generate_sigma_rule(request, scenario)

    rule_path = save_sigma_rule(tactic, tid_under, sigma_yaml)
    print(f"    [author] Saved: {rule_path.relative_to(REPO_ROOT)}")

    # Transpile
    lucene, spl = transpile_sigma(rule_path)
    lucene_path = None
    spl_path = None
    if lucene:
        lucene_path, spl_path = save_compiled(tactic, tid_under, lucene, spl)
        print(f"    [author] Transpiled: Lucene ({len(lucene)} chars), SPL ({len(spl)} chars)")
    else:
        print(f"    [author] WARNING: Lucene transpilation produced empty output")
        lucene = ""

    # Save test cases
    tp_path, tn_path = save_test_cases(tid_under, scenario)

    # Update request with artifact paths and tactic (used by state machine for path resolution)
    state_manager.update(
        tid, agent=AGENT_NAME,
        sigma_rule=str(rule_path.relative_to(REPO_ROOT)),
        compiled_lucene=str(lucene_path.relative_to(REPO_ROOT)) if lucene_path else "",
        compiled_spl=str(spl_path.relative_to(REPO_ROOT)) if spl_path else "",
        mitre_tactic=tactic,
    )

    # Transition to AUTHORED
    try:
        state_manager.transition(tid, "AUTHORED", agent=AGENT_NAME,
                                 details=f"Sigma rule authored, transpiled to Lucene + SPL")
        print(f"    [author] Transitioned {tid} -> AUTHORED")
    except ValueError as e:
        result["error"] = f"AUTHORED transition failed: {e}"
        return result

    result["status"] = "authored"
    result["sigma_rule"] = str(rule_path.relative_to(REPO_ROOT))
    result["compiled_lucene"] = str(lucene_path.relative_to(REPO_ROOT)) if lucene_path else ""
    result["compiled_spl"] = str(spl_path.relative_to(REPO_ROOT)) if spl_path else ""
    return result


def run(state_manager: StateManager) -> dict:
    """
    Main entry point for the author agent.

    1. Load learnings
    2. Query SCENARIO_BUILT detections
    3. For each: author Sigma rule, transpile, save test cases
    4. Return summary
    """
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    print(f"  [author] Starting author agent run {run_id}")

    # 1. Load briefing
    briefing = learnings.get_briefing(AGENT_NAME)
    print(f"  [author] {briefing}")

    detection_lessons = learnings.get_relevant_lessons(AGENT_NAME, "detection")
    if detection_lessons:
        print(f"  [author] {len(detection_lessons)} detection lessons loaded")

    # 2. Get SCENARIO_BUILT detections
    ready = state_manager.query_by_state("SCENARIO_BUILT")
    if not ready:
        print("  [author] No SCENARIO_BUILT detections. Nothing to do.")
        return {"summary": "No SCENARIO_BUILT detections", "detections_authored": 0}

    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ready.sort(key=lambda r: priority_order.get(r.get("priority", "medium"), 2))

    print(f"  [author] Found {len(ready)} SCENARIO_BUILT detections, "
          f"processing up to {MAX_DETECTIONS}")

    # 3. Process each detection
    results = []
    authored = 0

    for request in ready[:MAX_DETECTIONS]:
        tid = request["technique_id"]
        print(f"\n  [author] === Processing {tid} -- {request.get('title', '')} ===")

        result = author_detection(request, state_manager, run_id)
        results.append(result)

        if result["status"] == "authored":
            authored += 1

    # 4. Summary
    summary = f"Authored {authored} detections"
    print(f"\n  [author] {summary}")

    return {
        "summary": summary,
        "detections_authored": authored,
        "results": results,
    }
