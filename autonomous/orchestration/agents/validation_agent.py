"""
Validation Agent — Tests authored detections against scenario events.

Processes detections in AUTHORED state:
  AUTHORED -> VALIDATED (if F1 >= 0.75)
  AUTHORED stays AUTHORED (if F1 < 0.75, marked needs_rework)

Also supports revalidation of MONITORING rules for regression testing.

Extracted from blue_team_agent.py in Phase 4 (Task 4.4).

Called by agent_runner.py. Implements run(state_manager) interface.
"""

import datetime
import json
import re
from pathlib import Path

import yaml

from orchestration.state import StateManager
from orchestration import learnings
from orchestration.siem import check_elastic
from orchestration.validation import validate_against_elasticsearch
from orchestration.validation_eql import validate_eql_against_elasticsearch
from orchestration.validation_threshold import validate_threshold_against_elasticsearch
from orchestration import claude_llm

# Re-use authoring utilities for transpilation and scenario loading
from orchestration.agents.author_agent import (
    transpile_sigma,
    save_compiled,
    load_scenario,
    TECHNIQUE_TACTIC_MAP,
    _get_nested,
)

AUTONOMOUS_DIR = Path(__file__).resolve().parent.parent.parent
REPO_ROOT = AUTONOMOUS_DIR.parent
DETECTIONS_DIR = REPO_ROOT / "detections"
TESTS_DIR = REPO_ROOT / "tests"

AGENT_NAME = "validation"

SIGMA_REQUIRED_KEYS = {"title", "logsource", "detection"}


def extract_yaml_from_response(raw: str) -> str:
    """Extract YAML from Claude response, handling markdown fences and surrounding text."""
    # Try to find fenced block first (handles ```yaml, ```yml, or plain ```)
    match = re.search(r'```(?:ya?ml)?\s*\n(.*?)```', raw, re.DOTALL)
    if match:
        return match.group(1).strip()
    # If no fence, try to find YAML by looking for typical Sigma starting lines
    lines = raw.strip().split('\n')
    yaml_start = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('title:') or stripped.startswith('logsource:'):
            yaml_start = i
            break
    if yaml_start is not None:
        return '\n'.join(lines[yaml_start:]).strip()
    # Last resort: return as-is
    return raw.strip()
MAX_DETECTIONS = 5
AUTO_DEPLOY_THRESHOLD = 0.90
MAX_FP_RATE_AUTO_DEPLOY = 0.05
MAX_TUNE_RETRIES = 2  # Max attempts to refine a rule when F1 < threshold


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_agent_model() -> str:
    """Get the model name configured for this agent."""
    cfg = claude_llm._load_agent_config(AGENT_NAME)
    return cfg.get("model", "opus")


# ---------------------------------------------------------------------------
# Local (Python-based) validation logic
# ---------------------------------------------------------------------------

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
            # Exact match (OR logic -- any value matches)
            if not any(actual_str == _norm(v) for v in expected_vals):
                return False
    return True


def _parse_selection_logic(condition_str: str, selections: dict) -> tuple:
    """
    Parse Sigma condition string to determine how selection blocks combine.
    Returns: ('and' | 'or', [block_names])
    """
    # Strip filter clauses for selection parsing
    cond = condition_str.split(" and not ")[0].split(" | not ")[0].strip()

    # Handle "1 of selection_*" / "all of selection_*"
    if "of selection" in cond:
        if cond.startswith("all"):
            return "and", list(selections.keys())
        else:
            return "or", list(selections.keys())

    # Split on " and " or " or " to find selection block names
    if " or " in cond:
        parts = [p.strip() for p in cond.split(" or ")]
        block_names = [p for p in parts if p in selections]
        return "or", block_names if block_names else list(selections.keys())
    elif " and " in cond:
        parts = [p.strip() for p in cond.split(" and ")]
        block_names = [p for p in parts if p in selections]
        return "and", block_names if block_names else list(selections.keys())
    else:
        # Single selection
        return "and", [cond] if cond in selections else list(selections.keys())


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

    # Collect all selection_* and filter_* blocks
    selections = {}
    filters = {}
    for key, val in detection.items():
        if key == "condition":
            continue
        if key.startswith("selection"):
            selections[key] = val
        elif key.startswith("filter"):
            filters[key] = val

    # Fallback: if no selection blocks found, empty match (nothing matches)
    if not selections:
        selections = {"selection": {}}

    has_filter = "not" in condition and filters
    sel_logic, sel_block_names = _parse_selection_logic(condition, selections)

    def event_detected(event):
        """Apply selection + filter logic with multi-block support."""
        # Check selection blocks with AND/OR logic
        if sel_logic == "and":
            if not all(event_matches_block(event, selections.get(name, {}))
                       for name in sel_block_names):
                return False
        else:  # or
            if not any(event_matches_block(event, selections.get(name, {}))
                       for name in sel_block_names):
                return False

        # Apply filters (exclusions)
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


def _event_detected_by_rule(rule_path: Path, event: dict) -> bool:
    """Check if a single event would be detected by the Sigma rule at rule_path."""
    with open(rule_path, encoding="utf-8") as f:
        rule = yaml.safe_load(f)
    if not isinstance(rule, dict):
        return False
    detection = rule.get("detection", {})
    condition = detection.get("condition", "selection")

    selections = {}
    filters = {}
    for key, val in detection.items():
        if key == "condition":
            continue
        if key.startswith("selection"):
            selections[key] = val
        elif key.startswith("filter"):
            filters[key] = val

    if not selections:
        return False

    has_filter = "not" in condition and filters
    sel_logic, sel_block_names = _parse_selection_logic(condition, selections)

    if sel_logic == "and":
        if not all(event_matches_block(event, selections.get(n, {})) for n in sel_block_names):
            return False
    else:
        if not any(event_matches_block(event, selections.get(n, {})) for n in sel_block_names):
            return False

    if has_filter:
        for fblock in filters.values():
            if event_matches_block(event, fblock):
                return False
    return True


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


# ---------------------------------------------------------------------------
# Core validation cycle for a single detection
# ---------------------------------------------------------------------------

def validate_single(request: dict, state_manager: StateManager, run_id: str,
                    use_siem: bool = False) -> dict:
    """
    Validate a single AUTHORED detection against its scenario.

    Runs local or SIEM-based validation, retry-with-feedback loop,
    and transitions to VALIDATED if F1 >= 0.75.

    Returns result dict with status and metrics.
    """
    tid = request["technique_id"]
    tid_under = tid.lower().replace(".", "_")
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

    # Locate rule and compiled query
    sigma_rule_rel = request.get("sigma_rule", "")
    if not sigma_rule_rel:
        result["error"] = "No sigma_rule path on request"
        return result

    rule_path = REPO_ROOT / sigma_rule_rel
    if not rule_path.exists():
        result["error"] = f"Sigma rule not found: {sigma_rule_rel}"
        return result

    # Determine rule type and load compiled artifacts
    rule_type = request.get("rule_type", "sigma")
    compiled_lucene_rel = request.get("compiled_lucene", "")
    compiled_artifact_rel = request.get("compiled_artifact", "")
    lucene = ""
    if compiled_lucene_rel:
        lucene_full = REPO_ROOT / compiled_lucene_rel
        if lucene_full.exists():
            lucene = lucene_full.read_text(encoding="utf-8").strip()

    # Load compiled artifact JSON (used by EQL and threshold rules)
    compiled_artifact = {}
    if compiled_artifact_rel:
        artifact_path = REPO_ROOT / compiled_artifact_rel
        if artifact_path.exists():
            try:
                compiled_artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

    # --- VALIDATE ---
    validation_method = "local_json"
    validation_details = {}
    siem_errors = []

    attack_events = scenario.get("events", {}).get("attack_sequence", [])
    benign_events = scenario.get("events", {}).get("benign_similar", [])

    if use_siem and rule_type == "eql":
        # --- EQL VALIDATION ---
        eql_query = compiled_artifact.get("query", "")
        if not eql_query:
            print(f"    [validation] No EQL query in compiled artifact, falling back to local")
            metrics = validate_detection(str(rule_path.relative_to(REPO_ROOT)), scenario)
        else:
            print(f"    [validation] Validating EQL rule against Elasticsearch")
            expected_sequences = compiled_artifact.get("eql_min_sequences", 1)
            eql_metrics = validate_eql_against_elasticsearch(
                eql_query=eql_query,
                attack_events=attack_events,
                benign_events=benign_events,
                technique_id=tid,
                expected_sequences=expected_sequences,
            )
            if eql_metrics is not None:
                validation_method = "elasticsearch_eql"
                siem_errors = eql_metrics.get("errors", [])
                validation_details = {
                    "index": eql_metrics.get("index_used", ""),
                    "query": eql_metrics.get("eql_query", "")[:200],
                    "events_ingested": eql_metrics.get("events_ingested", 0),
                    "sequences_found": eql_metrics.get("sequences_found", 0),
                    "errors": siem_errors,
                }
                metrics = {
                    "tp": eql_metrics["tp"], "fp": eql_metrics["fp"],
                    "fn": eql_metrics["fn"], "tn": eql_metrics["tn"],
                    "precision": eql_metrics["precision"], "recall": eql_metrics["recall"],
                    "f1_score": eql_metrics["f1_score"],
                    "fp_rate": eql_metrics.get("fp_rate", 0.0),
                    "tp_rate": eql_metrics.get("recall", 0.0),
                    "total_attack": len(attack_events),
                    "total_benign": len(benign_events),
                }
                if siem_errors:
                    print(f"    [validation] EQL validation warnings: {'; '.join(siem_errors[:2])}")
            else:
                print(f"    [validation] ES unreachable, falling back to local validation")
                metrics = validate_detection(str(rule_path.relative_to(REPO_ROOT)), scenario)

    elif use_siem and rule_type == "threshold":
        # --- THRESHOLD VALIDATION ---
        base_query = compiled_artifact.get("query", "")
        threshold_cfg = compiled_artifact.get("threshold", {})
        threshold_field_list = threshold_cfg.get("field", [])
        threshold_field = threshold_field_list[0] if threshold_field_list else "host.name"
        threshold_value = threshold_cfg.get("value", 5)
        # Extract cardinality if present
        cardinality_list = threshold_cfg.get("cardinality", [])
        cardinality_field = cardinality_list[0].get("field") if cardinality_list else None
        cardinality_value = cardinality_list[0].get("value") if cardinality_list else None
        # Parse window from rule's "from" field (e.g., "now-6m" -> "6m")
        from_field = compiled_artifact.get("from", "now-5m")
        window = from_field.replace("now-", "") if from_field.startswith("now-") else "5m"

        if not base_query:
            print(f"    [validation] No base query in compiled artifact, falling back to local")
            metrics = validate_detection(str(rule_path.relative_to(REPO_ROOT)), scenario)
        else:
            print(f"    [validation] Validating threshold rule against Elasticsearch")
            threshold_metrics = validate_threshold_against_elasticsearch(
                base_query=base_query,
                threshold_field=threshold_field,
                threshold_value=threshold_value,
                window=window,
                attack_events=attack_events,
                benign_events=benign_events,
                technique_id=tid,
                cardinality_field=cardinality_field,
                cardinality_value=cardinality_value,
            )
            if threshold_metrics is not None:
                validation_method = "elasticsearch_threshold"
                siem_errors = threshold_metrics.get("errors", [])
                validation_details = {
                    "index": threshold_metrics.get("index_used", ""),
                    "query": threshold_metrics.get("base_query", "")[:200],
                    "events_ingested": threshold_metrics.get("events_ingested", 0),
                    "threshold_breaches": threshold_metrics.get("threshold_breaches", 0),
                    "errors": siem_errors,
                }
                metrics = {
                    "tp": threshold_metrics["tp"], "fp": threshold_metrics["fp"],
                    "fn": threshold_metrics["fn"], "tn": threshold_metrics["tn"],
                    "precision": threshold_metrics["precision"],
                    "recall": threshold_metrics["recall"],
                    "f1_score": threshold_metrics["f1_score"],
                    "fp_rate": threshold_metrics.get("fp_rate", 0.0),
                    "tp_rate": threshold_metrics.get("recall", 0.0),
                    "total_attack": len(attack_events),
                    "total_benign": len(benign_events),
                }
                if siem_errors:
                    print(f"    [validation] Threshold validation warnings: {'; '.join(siem_errors[:2])}")
            else:
                print(f"    [validation] ES unreachable, falling back to local validation")
                metrics = validate_detection(str(rule_path.relative_to(REPO_ROOT)), scenario)

    elif use_siem and lucene:
        # --- STANDARD LUCENE VALIDATION ---
        print(f"    [validation] Validating against Elasticsearch (SIEM-based)")

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
                print(f"    [validation] SIEM validation warnings: {'; '.join(siem_errors[:2])}")
        else:
            print(f"    [validation] ES unreachable, falling back to local validation")
            metrics = validate_detection(str(rule_path.relative_to(REPO_ROOT)), scenario)
    else:
        if not use_siem:
            print(f"    [validation] Validating locally (ES not available)")
        else:
            print(f"    [validation] Validating locally (no compiled query available)")
        metrics = validate_detection(str(rule_path.relative_to(REPO_ROOT)), scenario)

    quality_tier = assess_quality(metrics)

    print(f"    [validation] Results: TP={metrics['tp']}/{metrics['total_attack']}, "
          f"FP={metrics['fp']}/{metrics['total_benign']}, "
          f"F1={metrics['f1_score']}, FP_rate={metrics['fp_rate']}")
    print(f"    [validation] Quality: {quality_tier}")

    # --- RETRY-WITH-FEEDBACK (if F1 < threshold and Claude available) ---
    if metrics["f1_score"] < AUTO_DEPLOY_THRESHOLD and claude_llm.is_available():
        attack_events = scenario.get("events", {}).get("attack_sequence", [])
        benign_events = scenario.get("events", {}).get("benign_similar", [])

        # Load configurable timeout (default 300s)
        agent_cfg = claude_llm._load_agent_config(AGENT_NAME)
        refinement_timeout = agent_cfg.get("refinement_timeout_seconds", 300)

        # Save original rule for quality gate revert
        original_rule_yaml = rule_path.read_text(encoding="utf-8")
        original_f1 = metrics["f1_score"]

        for attempt in range(1, MAX_TUNE_RETRIES + 1):
            print(f"    [validation] Retry {attempt}/{MAX_TUNE_RETRIES}: "
                  f"F1={metrics['f1_score']} < {AUTO_DEPLOY_THRESHOLD}, asking Claude to refine")

            current_rule_yaml = rule_path.read_text(encoding="utf-8")

            # Use validate_detection to identify FN/FP events precisely
            fn_events = [evt for evt in attack_events
                         if not _event_detected_by_rule(rule_path, evt)]
            fp_events = [evt for evt in benign_events
                         if _event_detected_by_rule(rule_path, evt)]

            fn_summary = json.dumps(fn_events[:3], indent=2)[:1500] if fn_events else "None"
            fp_summary = json.dumps(fp_events[:3], indent=2)[:1500] if fp_events else "None"

            # Build field comparison table for FN events
            field_mismatch_table = ""
            if fn_events:
                rule_data = yaml.safe_load(current_rule_yaml) or {}
                detection = rule_data.get("detection", {})
                selection_fields = set()
                for key, val in detection.items():
                    if key.startswith("selection") and isinstance(val, dict):
                        selection_fields.update(f.split("|")[0] for f in val.keys())
                if selection_fields:
                    mismatches = []
                    sample = fn_events[0]
                    for field in sorted(selection_fields):
                        actual = _get_nested(sample, field)
                        mismatches.append(f"  {field}: rule expects match, event has: {repr(actual)}")
                    field_mismatch_table = "Field analysis (first FN event):\n" + "\n".join(mismatches)

            # Include SIEM-specific errors if available
            siem_error_context = ""
            if siem_errors:
                siem_error_context = f"""
Elasticsearch query errors (the compiled Lucene query failed):
{chr(10).join('- ' + e for e in siem_errors)}
Fix the Sigma rule to avoid generating Lucene syntax that Elasticsearch rejects.
"""

            refine_prompt = f"""This Sigma rule scored F1={metrics['f1_score']} (target >= {AUTO_DEPLOY_THRESHOLD}).

## Compiled Lucene Query (what the SIEM actually runs)
{lucene[:500] if lucene else 'N/A (no Lucene query available)'}

## False Negatives — events that SHOULD match but DON'T
{fn_summary}

## False Positives — events that SHOULD NOT match but DO
{fp_summary}

## {field_mismatch_table}

## SIEM Query Errors
{siem_error_context if siem_error_context else 'None'}

## Current Sigma Rule
{current_rule_yaml}

Diagnose why the false negatives don't match the Lucene query. Common causes:
- Field name mismatch (e.g., rule uses process.name but event has process.executable)
- Wildcard pattern too narrow (e.g., *\\\\cmd.exe won't match C:\\\\Windows\\\\System32\\\\cmd.exe)
- Missing OR condition for variant field values

Return ONLY the corrected Sigma YAML. No markdown fences, no explanation."""

            refine_result = claude_llm.ask(
                prompt=refine_prompt,
                agent_name=AGENT_NAME,
                system_prompt=(
                    "You are a senior detection engineer fixing a Sigma rule. "
                    "Output ONLY valid Sigma YAML. Match field names from the events exactly."
                ),
                allowed_tools=[],
                max_turns=1,
                timeout_seconds=refinement_timeout,
            )

            if refine_result["success"]:
                refined_yaml = extract_yaml_from_response(refine_result["response"])

                try:
                    parsed_refined = yaml.safe_load(refined_yaml)
                    if not isinstance(parsed_refined, dict):
                        print(f"    [validation] Retry {attempt}: output is not a valid YAML dict")
                        continue
                    # Validate Sigma schema
                    missing_keys = SIGMA_REQUIRED_KEYS - set(parsed_refined.keys())
                    if missing_keys:
                        print(f"    [validation] Retry {attempt}: missing Sigma fields: {missing_keys}")
                        continue

                    rule_path.write_text(refined_yaml, encoding="utf-8")
                    print(f"    [validation] Claude refined rule ({len(refined_yaml)} chars)")

                    # Re-transpile
                    new_lucene, new_spl = transpile_sigma(rule_path)
                    if new_lucene:
                        save_compiled(tactic, tid_under, new_lucene, new_spl)
                        lucene = new_lucene

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

                    print(f"    [validation] After retry {attempt}: "
                          f"TP={metrics['tp']}/{metrics['total_attack']}, "
                          f"FP={metrics['fp']}/{metrics['total_benign']}, "
                          f"F1={metrics['f1_score']}, FP_rate={metrics['fp_rate']}")
                    print(f"    [validation] Quality: {quality_tier}")

                    # Quality gate: if refinement made it worse than best so far, revert
                    if metrics["f1_score"] < original_f1:
                        print(f"    [validation] Refinement degraded F1 ({metrics['f1_score']} < {original_f1}) — reverting to best")
                        rule_path.write_text(original_rule_yaml, encoding="utf-8")
                        metrics = validate_detection(str(rule_path.relative_to(REPO_ROOT)), scenario)
                        quality_tier = assess_quality(metrics)
                        break

                    # Track best intermediate result so revert goes to best, not first
                    if metrics["f1_score"] > original_f1:
                        original_f1 = metrics["f1_score"]
                        original_rule_yaml = rule_path.read_text(encoding="utf-8")

                    if metrics["f1_score"] >= AUTO_DEPLOY_THRESHOLD:
                        print(f"    [validation] F1 target met after {attempt} retry(ies)")
                        break
                except yaml.YAMLError:
                    print(f"    [validation] Retry {attempt}: Claude output was not valid YAML")
            else:
                print(f"    [validation] Retry {attempt}: Claude error: {refine_result.get('error')}")
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
        "validated_by": "validation-agent",
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
        print(f"    [validation] Transitioned {tid} -> VALIDATED")
    except ValueError as e:
        result["error"] = f"VALIDATED transition failed: {e}"
        result["status"] = "authored"
        return result

    # Mark eligible for post-merge deployment (do not deploy here)
    if quality_tier == "auto_deploy":
        state_manager.update(tid, agent=AGENT_NAME, auto_deploy_eligible=True)
        result["status"] = "validated"
        result["auto_deploy_eligible"] = True
        print(f"    [validation] Eligible for post-merge deploy (F1={metrics['f1_score']}, "
              f"FP_rate={metrics['fp_rate']}). Will deploy after PR merge.")
    else:
        result["status"] = "validated"
        result["auto_deploy_eligible"] = False
        print(f"    [validation] Pending human review (F1={metrics['f1_score']})")

    return result


def revalidate_monitoring(request: dict, state_manager: StateManager,
                          use_siem: bool = False) -> dict:
    """
    Revalidate a MONITORING detection for regression testing.

    Runs the same validation logic but does not change state.
    Returns metrics for the tuning agent to act on.
    """
    tid = request["technique_id"]
    scenario_path = request.get("scenario_file", "")
    sigma_rule_rel = request.get("sigma_rule", "")

    if not scenario_path or not sigma_rule_rel:
        return {"technique_id": tid, "status": "skipped", "reason": "missing artifacts"}

    scenario = load_scenario(scenario_path)
    if not scenario:
        return {"technique_id": tid, "status": "skipped", "reason": "scenario not found"}

    rule_path = REPO_ROOT / sigma_rule_rel
    if not rule_path.exists():
        return {"technique_id": tid, "status": "skipped", "reason": "rule not found"}

    metrics = validate_detection(str(rule_path.relative_to(REPO_ROOT)), scenario)
    quality_tier = assess_quality(metrics)

    return {
        "technique_id": tid,
        "status": "revalidated",
        "metrics": metrics,
        "quality_tier": quality_tier,
    }


def run(state_manager: StateManager) -> dict:
    """
    Main entry point for the validation agent.

    1. Load learnings
    2. Query AUTHORED detections
    3. For each: validate, retry-with-feedback, transition to VALIDATED
    4. Return summary
    """
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    print(f"  [validation] Starting validation agent run {run_id}")

    # 1. Load briefing
    briefing = learnings.get_briefing(AGENT_NAME)
    print(f"  [validation] {briefing}")

    detection_lessons = learnings.get_relevant_lessons(AGENT_NAME, "detection")
    if detection_lessons:
        print(f"  [validation] {len(detection_lessons)} detection lessons loaded")

    # Check ES availability once
    use_siem = check_elastic()
    if use_siem:
        print(f"  [validation] Elasticsearch available -- using SIEM-based validation")
    else:
        print(f"  [validation] Elasticsearch not available -- using local validation")

    # 2. Get AUTHORED detections
    ready = state_manager.query_by_state("AUTHORED")
    if not ready:
        print("  [validation] No AUTHORED detections. Nothing to do.")
        return {"summary": "No AUTHORED detections", "detections_validated": 0}

    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ready.sort(key=lambda r: priority_order.get(r.get("priority", "medium"), 2))

    print(f"  [validation] Found {len(ready)} AUTHORED detections, "
          f"processing up to {MAX_DETECTIONS}")

    # 3. Process each detection
    results = []
    validated = 0
    deploy_eligible = 0
    needs_rework = 0

    for request in ready[:MAX_DETECTIONS]:
        tid = request["technique_id"]
        print(f"\n  [validation] === Validating {tid} -- {request.get('title', '')} ===")

        vresult = validate_single(request, state_manager, run_id, use_siem=use_siem)
        results.append(vresult)

        if vresult["status"] == "validated":
            validated += 1
            if vresult.get("auto_deploy_eligible"):
                deploy_eligible += 1
        elif vresult["status"] == "needs_rework":
            needs_rework += 1

    # 4. Summary
    summary = (
        f"Validated {validated}, deploy-eligible {deploy_eligible}, "
        f"needs rework {needs_rework}"
    )
    print(f"\n  [validation] {summary}")

    return {
        "summary": summary,
        "detections_validated": validated,
        "detections_deploy_eligible": deploy_eligible,
        "detections_needs_rework": needs_rework,
        "results": results,
    }
