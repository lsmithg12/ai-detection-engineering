"""
Blue Team Agent — Authors Sigma rules and validates against scenarios.

Processes detections in SCENARIO_BUILT state through:
  SCENARIO_BUILT -> AUTHORED -> VALIDATED

SIEM deployment is handled post-merge by deploy-rules.yml or `cli.py deploy`.
This ensures rules are only live after human review.

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
from orchestration.siem import TACTIC_MAP, SEVERITY_MAP, check_elastic
from orchestration.validation import validate_against_elasticsearch
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
MAX_TUNE_RETRIES = 2  # Max attempts to refine a rule when F1 < threshold

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


def event_matches_block(event: dict, block: dict) -> bool:
    """Check if an event matches ALL conditions in a Sigma detection block."""
    if not block:
        return False  # Empty block matches nothing (prevents accidental match-all)
    for field_expr, expected_vals in block.items():
        # Parse field name and modifier
        parts = field_expr.split("|")
        field = parts[0]
        modifier = parts[1] if len(parts) > 1 else None

        actual = _get_nested(event, field)
        if actual is None:
            return False
        # Normalize backslashes: YAML single-quoted '\\' stays literal double-backslash,
        # but JSON '\\' decodes to single backslash. Normalize both to single.
        actual_str = str(actual).lower().replace("\\\\", "\\")

        # Normalize expected values to list
        if not isinstance(expected_vals, list):
            expected_vals = [expected_vals]

        def _norm(v):
            return str(v).lower().replace("\\\\", "\\")

        if modifier == "contains":
            if not any(_norm(v) in actual_str for v in expected_vals):
                return False
        elif modifier == "startswith":
            if not any(actual_str.startswith(_norm(v)) for v in expected_vals):
                return False
        elif modifier == "endswith":
            if not any(actual_str.endswith(_norm(v)) for v in expected_vals):
                return False
        else:
            # Exact match (OR logic — any value matches)
            if not any(actual_str == _norm(v) for v in expected_vals):
                return False
    return True


def _tokenize_condition(condition_str: str) -> list:
    """Tokenize a Sigma condition string into a list of tokens.

    Handles parentheses, keywords (and, or, not, 1, all, of, them),
    and block names (selection_*, filter_*).
    """
    import re
    # Normalize multi-line conditions
    cond = " ".join(condition_str.split())
    tokens = []
    i = 0
    while i < len(cond):
        if cond[i] in " \t":
            i += 1
            continue
        if cond[i] == "(":
            tokens.append("(")
            i += 1
        elif cond[i] == ")":
            tokens.append(")")
            i += 1
        elif cond[i] == "|":
            # Sigma pipe operator — treat rest as transformation, stop parsing
            break
        else:
            # Read a word token
            j = i
            while j < len(cond) and cond[j] not in " \t()":
                j += 1
            word = cond[i:j]
            tokens.append(word)
            i = j
    return tokens


def _evaluate_sigma_condition(condition_str: str, all_blocks: dict, event) -> bool:
    """Evaluate a Sigma condition against a single event using recursive descent.

    Supports: and, or, not, parentheses, ``1 of pattern``, ``all of pattern``,
    ``1 of them``, ``all of them``, and bare block names.
    """
    import fnmatch

    tokens = _tokenize_condition(condition_str)
    pos = [0]  # mutable position counter

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def advance():
        tok = tokens[pos[0]] if pos[0] < len(tokens) else None
        pos[0] += 1
        return tok

    def _resolve_pattern(pattern: str) -> list:
        """Resolve a glob pattern like 'selection_*' or 'filter_*' to block names."""
        if pattern == "them":
            return list(all_blocks.keys())
        return [k for k in all_blocks if fnmatch.fnmatch(k, pattern)]

    def _match_block(name: str) -> bool:
        block = all_blocks.get(name, {})
        return event_matches_block(event, block)

    def parse_or():
        """OR has lowest precedence."""
        left = parse_and()
        while peek() == "or":
            advance()  # consume 'or'
            right = parse_and()
            left = left or right
        return left

    def parse_and():
        """AND has higher precedence than OR."""
        left = parse_not()
        while peek() == "and":
            advance()  # consume 'and'
            right = parse_not()
            left = left and right
        return left

    def parse_not():
        """NOT is a unary prefix with highest precedence."""
        if peek() == "not":
            advance()  # consume 'not'
            return not parse_not()
        return parse_atom()

    def parse_atom():
        tok = peek()
        if tok is None:
            return False

        # Parenthesized sub-expression
        if tok == "(":
            advance()  # consume '('
            result = parse_or()
            if peek() == ")":
                advance()  # consume ')'
            return result

        # Quantifier: "1 of pattern", "all of pattern"
        if tok in ("1", "all"):
            quantifier = advance()  # consume '1' or 'all'
            if peek() == "of":
                advance()  # consume 'of'
                pattern = advance()  # consume pattern (e.g., 'selection_*', 'them')
                if pattern is None:
                    return False
                names = _resolve_pattern(pattern)
                if quantifier == "all":
                    return all(_match_block(n) for n in names)
                else:
                    return any(_match_block(n) for n in names)
            else:
                # '1' or 'all' used as a block name (unlikely but safe fallback)
                return _match_block(quantifier)

        # Bare block name (e.g., 'selection', 'selection_parent', 'filter_system')
        name = advance()
        return _match_block(name)

    if not tokens:
        return False
    return parse_or()


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

    if not isinstance(rule, dict):
        # Rule file is not valid Sigma YAML (e.g. plain string from bad Claude output)
        return {
            "tp": 0, "fp": 0, "fn": len(attack_events), "tn": len(benign_events),
            "precision": 0.0, "recall": 0.0, "f1_score": 0.0,
            "fp_rate": 0.0, "tp_rate": 0.0,
            "total_attack": len(attack_events), "total_benign": len(benign_events),
        }

    detection = rule.get("detection", {})
    condition = detection.get("condition", "selection")

    # Collect all detection blocks (selections + filters) for the condition evaluator
    all_blocks = {}
    for key, val in detection.items():
        if key == "condition":
            continue
        all_blocks[key] = val

    # Fallback: if no blocks found, nothing matches
    if not all_blocks:
        all_blocks = {"selection": {}}

    def event_detected(event):
        """Evaluate the full Sigma condition against a single event."""
        return _evaluate_sigma_condition(condition, all_blocks, event)

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


def _event_detected_by_rule(rule_path: Path, event: dict) -> bool:
    """Check if a single event would be detected by the Sigma rule at rule_path."""
    with open(rule_path, encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    if not isinstance(rule, dict):
        return False
    detection = rule.get("detection", {})
    condition = detection.get("condition", "selection")

    all_blocks = {}
    for key, val in detection.items():
        if key == "condition":
            continue
        all_blocks[key] = val

    if not all_blocks:
        return False

    return _evaluate_sigma_condition(condition, all_blocks, event)


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
                parsed = yaml.safe_load(llm_result["sigma_yaml"])
                if isinstance(parsed, dict) and "detection" in parsed:
                    sigma_yaml = llm_result["sigma_yaml"]
                    print(f"    [blue-team] Claude authored rule ({len(sigma_yaml)} chars)")
                else:
                    print(f"    [blue-team] Claude output is not a valid Sigma rule (missing detection block), falling back")
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
    # Prefer SIEM-based validation (Elasticsearch) when available.
    # Falls back to local Python matching when ES is offline (e.g., CI).
    validation_method = "local_json"
    validation_details = {}
    siem_errors = []

    use_siem = getattr(author_and_validate, '_use_siem_validation', False)

    if use_siem and lucene:
        print(f"    [blue-team] Validating against Elasticsearch (SIEM-based)")
        attack_events = scenario.get("events", {}).get("attack_sequence", [])
        benign_events = scenario.get("events", {}).get("benign_similar", [])

        siem_metrics = validate_against_elasticsearch(
            compiled_lucene=lucene,
            attack_events=attack_events,
            benign_events=benign_events,
            technique_id=tid,
        )

        if siem_metrics is not None:
            validation_method = "elasticsearch"
            siem_errors = siem_metrics.get("errors", [])
            validation_details = {
                "index": siem_metrics.get("index_used", ""),
                "query": siem_metrics.get("query_used", "")[:200],
                "events_ingested": siem_metrics.get("events_ingested", 0),
                "query_hits": siem_metrics.get("query_hits", 0),
                "query_time_ms": siem_metrics.get("query_time_ms", 0),
                "errors": siem_errors,
            }
            # Use SIEM metrics (same shape as local metrics)
            metrics = {
                "tp": siem_metrics["tp"], "fp": siem_metrics["fp"],
                "fn": siem_metrics["fn"], "tn": siem_metrics["tn"],
                "precision": siem_metrics["precision"], "recall": siem_metrics["recall"],
                "f1_score": siem_metrics["f1_score"],
                "fp_rate": siem_metrics["fp_rate"], "tp_rate": siem_metrics["tp_rate"],
                "total_attack": siem_metrics["total_attack"],
                "total_benign": siem_metrics["total_benign"],
            }
            if siem_errors:
                print(f"    [blue-team] SIEM validation warnings: {'; '.join(siem_errors[:2])}")
        else:
            print(f"    [blue-team] ES unreachable, falling back to local validation")
            metrics = validate_detection(str(rule_path.relative_to(REPO_ROOT)), scenario)
    else:
        if not use_siem:
            print(f"    [blue-team] Validating locally (ES not available)")
        else:
            print(f"    [blue-team] Validating locally (no Lucene query available)")
        metrics = validate_detection(str(rule_path.relative_to(REPO_ROOT)), scenario)

    quality_tier = assess_quality(metrics)

    print(f"    [blue-team] Results: TP={metrics['tp']}/{metrics['total_attack']}, "
          f"FP={metrics['fp']}/{metrics['total_benign']}, "
          f"F1={metrics['f1_score']}, FP_rate={metrics['fp_rate']}")
    print(f"    [blue-team] Quality: {quality_tier}")

    # ─── RETRY-WITH-FEEDBACK (if F1 < threshold and Claude available) ───
    if metrics["f1_score"] < AUTO_DEPLOY_THRESHOLD and claude_llm.is_available():
        attack_events = scenario.get("events", {}).get("attack_sequence", [])
        benign_events = scenario.get("events", {}).get("benign_similar", [])

        for attempt in range(1, MAX_TUNE_RETRIES + 1):
            print(f"    [blue-team] Retry {attempt}/{MAX_TUNE_RETRIES}: "
                  f"F1={metrics['f1_score']} < {AUTO_DEPLOY_THRESHOLD}, asking Claude to refine")

            current_rule_yaml = rule_path.read_text(encoding="utf-8")

            # Use validate_detection to identify FN/FP events precisely
            fn_events = [evt for evt in attack_events
                         if not _event_detected_by_rule(rule_path, evt)]
            fp_events = [evt for evt in benign_events
                         if _event_detected_by_rule(rule_path, evt)]

            fn_summary = json.dumps(fn_events[:3], indent=2)[:1500] if fn_events else "None"
            fp_summary = json.dumps(fp_events[:3], indent=2)[:1500] if fp_events else "None"

            # Include SIEM-specific errors if available (query syntax issues, etc.)
            siem_error_context = ""
            if siem_errors:
                siem_error_context = f"""
Elasticsearch query errors (the compiled Lucene query failed):
{chr(10).join('- ' + e for e in siem_errors)}
The compiled Lucene query was: {lucene[:300] if lucene else 'N/A'}
Fix the Sigma rule to avoid generating Lucene syntax that Elasticsearch rejects.
"""

            refine_prompt = f"""This Sigma rule scored F1={metrics['f1_score']} (target >= {AUTO_DEPLOY_THRESHOLD}).

Attack events that SHOULD have triggered but DIDN'T (false negatives):
{fn_summary}

Benign events that SHOULD NOT have triggered but DID (false positives):
{fp_summary}
{siem_error_context}
Current rule:
{current_rule_yaml}

Fix the rule. The field names in the events are the source of truth — your rule's
selection fields must match the event field paths exactly.
Return ONLY the corrected Sigma YAML — no markdown fences, no explanation."""

            refine_result = claude_llm.ask(
                prompt=refine_prompt,
                agent_name="blue-team",
                system_prompt=(
                    "You are a senior detection engineer fixing a Sigma rule. "
                    "Output ONLY valid Sigma YAML. Match field names from the events exactly."
                ),
                allowed_tools=[],
                max_turns=1,
                timeout_seconds=150,
            )

            if refine_result["success"]:
                refined_yaml = refine_result["response"].strip()
                # Strip markdown fences
                if refined_yaml.startswith("```"):
                    lines = refined_yaml.split("\n")
                    if lines[0].startswith("```"):
                        lines = lines[1:]
                    if lines and lines[-1].strip() == "```":
                        lines = lines[:-1]
                    refined_yaml = "\n".join(lines)

                try:
                    parsed_refined = yaml.safe_load(refined_yaml)
                    if not isinstance(parsed_refined, dict) or "detection" not in parsed_refined:
                        print(f"    [blue-team] Retry {attempt}: output is not a valid Sigma rule")
                        continue
                    rule_path.write_text(refined_yaml, encoding="utf-8")
                    print(f"    [blue-team] Claude refined rule ({len(refined_yaml)} chars)")

                    # Re-transpile
                    lucene, spl = transpile_sigma(rule_path)
                    if lucene:
                        save_compiled(tactic, tid_under, lucene, spl)

                    # Re-validate (prefer SIEM when available)
                    if use_siem and lucene:
                        siem_retry = validate_against_elasticsearch(
                            compiled_lucene=lucene,
                            attack_events=attack_events,
                            benign_events=benign_events,
                            technique_id=tid,
                        )
                        if siem_retry is not None:
                            validation_method = "elasticsearch"
                            siem_errors = siem_retry.get("errors", [])
                            validation_details = {
                                "index": siem_retry.get("index_used", ""),
                                "query": siem_retry.get("query_used", "")[:200],
                                "events_ingested": siem_retry.get("events_ingested", 0),
                                "query_hits": siem_retry.get("query_hits", 0),
                                "query_time_ms": siem_retry.get("query_time_ms", 0),
                                "errors": siem_errors,
                            }
                            metrics = {
                                "tp": siem_retry["tp"], "fp": siem_retry["fp"],
                                "fn": siem_retry["fn"], "tn": siem_retry["tn"],
                                "precision": siem_retry["precision"],
                                "recall": siem_retry["recall"],
                                "f1_score": siem_retry["f1_score"],
                                "fp_rate": siem_retry["fp_rate"],
                                "tp_rate": siem_retry["tp_rate"],
                                "total_attack": siem_retry["total_attack"],
                                "total_benign": siem_retry["total_benign"],
                            }
                        else:
                            metrics = validate_detection(str(rule_path.relative_to(REPO_ROOT)), scenario)
                            validation_method = "local_json"
                    else:
                        metrics = validate_detection(str(rule_path.relative_to(REPO_ROOT)), scenario)
                    quality_tier = assess_quality(metrics)

                    print(f"    [blue-team] After retry {attempt}: "
                          f"TP={metrics['tp']}/{metrics['total_attack']}, "
                          f"FP={metrics['fp']}/{metrics['total_benign']}, "
                          f"F1={metrics['f1_score']}, FP_rate={metrics['fp_rate']}")
                    print(f"    [blue-team] Quality: {quality_tier}")

                    if metrics["f1_score"] >= AUTO_DEPLOY_THRESHOLD:
                        print(f"    [blue-team] F1 target met after {attempt} retry(ies)")
                        break
                except yaml.YAMLError:
                    print(f"    [blue-team] Retry {attempt}: Claude output was not valid YAML")
            else:
                print(f"    [blue-team] Retry {attempt}: Claude error: {refine_result.get('error')}")
                break  # Don't retry if Claude itself is failing

    # Save test results (required by schema for DEPLOYED transition)
    results_dir = REPO_ROOT / "tests" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    results_file = results_dir / f"{tid_under}.json"
    result_data = {
        "technique_id": tid,
        "date": _now_iso(),
        "sigma_rule": str(rule_path.relative_to(REPO_ROOT)),
        "metrics": metrics,
        "quality_tier": quality_tier,
        "validation_method": validation_method,
        "validated_by": "blue-team-agent",
        "siem_targets": ["elasticsearch", "splunk"],
        "sigma_rule_path": str(rule_path.relative_to(REPO_ROOT)),
        "scenario_path": scenario_path,
        "attack_event_count": len(scenario.get("events", {}).get("attack_sequence", [])),
        "benign_event_count": len(scenario.get("events", {}).get("benign_similar", [])),
        "quality_tier_criteria": {
            "auto_deploy": "F1 >= 0.90 AND FP_rate <= 0.05",
            "validated": "F1 >= 0.75",
            "needs_rework": "F1 < 0.75",
        },
    }
    if validation_details:
        result_data["validation_details"] = validation_details
    results_file.write_text(json.dumps(result_data, indent=2), encoding="utf-8")

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

    # ─── POST-MERGE DEPLOY (mark eligible, don't deploy yet) ───
    # Deployment now happens AFTER human review + PR merge, not here.
    # See: .github/workflows/deploy-rules.yml or `cli.py deploy --validated`
    if quality_tier == "auto_deploy":
        state_manager.update(tid, agent=AGENT_NAME, auto_deploy_eligible=True)
        result["status"] = "validated"
        result["auto_deploy_eligible"] = True
        print(f"    [blue-team] Eligible for post-merge deploy (F1={metrics['f1_score']}, "
              f"FP_rate={metrics['fp_rate']}). Will deploy after PR merge.")
    else:
        result["status"] = "validated"
        result["auto_deploy_eligible"] = False
        print(f"    [blue-team] Pending human review (F1={metrics['f1_score']})")

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

    # NOTE: SIEM deployment is now post-merge only.
    # See .github/workflows/deploy-rules.yml or `cli.py deploy --validated`

    # Check ES availability once (avoid per-detection health checks)
    use_siem = check_elastic()
    if use_siem:
        print(f"  [blue-team] Elasticsearch available — using SIEM-based validation")
    else:
        print(f"  [blue-team] Elasticsearch not available — using local validation")
    # Store on function object so author_and_validate can access it
    author_and_validate._use_siem_validation = use_siem

    # 2. Get SCENARIO_BUILT detections
    ready = state_manager.query_by_state("SCENARIO_BUILT")
    if not ready:
        print("  [blue-team] No SCENARIO_BUILT detections. Nothing to do.")
        return {"summary": "No SCENARIO_BUILT detections", "detections_authored": 0}

    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ready.sort(key=lambda r: priority_order.get(r.get("priority", "medium"), 2))

    print(f"  [blue-team] Found {len(ready)} SCENARIO_BUILT detections, "
          f"processing up to {MAX_DETECTIONS}")

    # 3. Process each detection
    results = []
    authored = 0
    validated = 0
    deploy_eligible = 0
    needs_rework = 0

    for request in ready[:MAX_DETECTIONS]:
        tid = request["technique_id"]
        print(f"\n  [blue-team] === Processing {tid} — {request.get('title', '')} ===")

        result = author_and_validate(request, state_manager, run_id)
        results.append(result)

        if result["status"] == "validated":
            validated += 1
            authored += 1
            if result.get("auto_deploy_eligible"):
                deploy_eligible += 1
        elif result["status"] == "needs_rework":
            authored += 1
            needs_rework += 1
        elif result["status"] == "authored":
            authored += 1

    # 4. Summary
    summary = (
        f"Authored {authored}, validated {validated}, "
        f"deploy-eligible {deploy_eligible}, needs rework {needs_rework}"
    )
    print(f"\n  [blue-team] {summary}")

    return {
        "summary": summary,
        "detections_authored": authored,
        "detections_validated": validated,
        "detections_deploy_eligible": deploy_eligible,
        "detections_needs_rework": needs_rework,
        "results": results,
    }
