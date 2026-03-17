"""
Evasion Validation Module — Tests detection rules against adversary evasion variants.

Evasion testing answers: "Does our detection rule catch modified attack events
that attempt to bypass detection?" This is distinct from standard validation
(does the rule catch the baseline attack?) and extends Phase 6 quality metrics
to include evasion resilience scoring.

Phase 6 deliverable — Task 6.4: Evasion Testing Framework.
"""

import json
from pathlib import Path
from typing import Optional

from orchestration.validation import validate_against_elasticsearch


def load_evasion_tests(evasion_dir: Optional[str] = None) -> list:
    """
    Load all evasion test cases from the tests/evasion/ directory.

    Returns list of dicts with evasion test metadata and events.
    """
    if evasion_dir is None:
        repo_root = Path(__file__).resolve().parent.parent.parent
        evasion_dir = repo_root / "tests" / "evasion"
    else:
        evasion_dir = Path(evasion_dir)

    if not evasion_dir.exists():
        return []

    tests = []
    for test_file in sorted(evasion_dir.glob("*.json")):
        try:
            with open(test_file, encoding="utf-8") as f:
                test_data = json.load(f)
            meta = test_data.get("_evasion", {})
            events = test_data.get("events", [])
            tests.append({
                "file": str(test_file),
                "technique": meta.get("technique", "unknown"),
                "variant": meta.get("evasion_variant", test_file.stem),
                "description": meta.get("description", ""),
                "expected_result": meta.get("expected_result", "SHOULD_ALERT"),
                "bypass_attempt": meta.get("bypass_attempt", ""),
                "notes": meta.get("notes", ""),
                "remediation": meta.get("remediation", ""),
                "events": events,
            })
        except Exception as e:
            print(f"  Warning: could not load evasion test {test_file.name}: {e}")

    return tests


def run_evasion_test(
    compiled_lucene: str,
    evasion_test: dict,
    technique_id: str = "",
) -> dict:
    """
    Run a single evasion test against a compiled Lucene detection rule.

    Args:
        compiled_lucene: The detection rule's Lucene query
        evasion_test: Evasion test dict (from load_evasion_tests)
        technique_id: MITRE technique ID for tagging

    Returns:
        dict with evasion test results:
        {
            "variant": "ppid_spoofing",
            "expected": "SHOULD_ALERT",
            "detected": True/False,
            "result": "PASS" / "FAIL" / "KNOWN_GAP",
            "f1": 0.0-1.0,
            "notes": "...",
        }
    """
    events = evasion_test.get("events", [])
    expected = evasion_test.get("expected_result", "SHOULD_ALERT")

    if not events:
        return {
            "variant": evasion_test.get("variant", "?"),
            "expected": expected,
            "detected": False,
            "result": "SKIP",
            "f1": 0.0,
            "notes": "No events in evasion test",
        }

    # Run the evasion events through the detection rule.
    # Attack events = the evasion variant events (what we're testing).
    # No benign events for evasion tests (we only care about TP/FN).
    validation_result = validate_against_elasticsearch(
        compiled_lucene=compiled_lucene,
        attack_events=events,
        benign_events=[],
        technique_id=technique_id,
    )

    if validation_result is None:
        return {
            "variant": evasion_test.get("variant", "?"),
            "expected": expected,
            "detected": False,
            "result": "ES_OFFLINE",
            "f1": 0.0,
            "notes": "Elasticsearch not available for evasion test",
        }

    detected = validation_result.get("tp", 0) > 0
    f1 = validation_result.get("f1_score", 0.0)

    # Determine result based on expected outcome
    if expected == "SHOULD_ALERT":
        # Rule should catch this variant
        result = "PASS" if detected else "FAIL"
    elif expected == "EVASION_SUCCEEDS":
        # This is a documented known gap — not a failure of the test suite
        result = "KNOWN_GAP"
    else:
        result = "PASS" if detected else "FAIL"

    return {
        "variant": evasion_test.get("variant", "?"),
        "technique": evasion_test.get("technique", "?"),
        "expected": expected,
        "detected": detected,
        "result": result,
        "f1": round(f1, 4),
        "bypass_attempt": evasion_test.get("bypass_attempt", ""),
        "notes": evasion_test.get("notes", ""),
        "remediation": evasion_test.get("remediation", ""),
    }


def run_evasion_tests_for_technique(
    technique_id: str,
    compiled_lucene: str,
    evasion_dir: Optional[str] = None,
) -> dict:
    """
    Run all evasion tests matching a technique ID.

    Returns summary dict with resilience score and per-variant results.
    """
    all_tests = load_evasion_tests(evasion_dir)
    technique_tests = [t for t in all_tests if t.get("technique", "").startswith(technique_id)]

    if not technique_tests:
        return {
            "technique_id": technique_id,
            "evasion_tests_run": 0,
            "evasion_resilience": None,
            "results": [],
            "known_gaps": [],
        }

    results = []
    for test in technique_tests:
        result = run_evasion_test(compiled_lucene, test, technique_id)
        results.append(result)

    # Calculate evasion resilience score
    # = (PASS tests) / (PASS + FAIL tests) — excludes KNOWN_GAP
    active_tests = [r for r in results if r["result"] in ("PASS", "FAIL")]
    known_gaps = [r for r in results if r["result"] == "KNOWN_GAP"]
    passes = sum(1 for r in active_tests if r["result"] == "PASS")
    resilience = passes / len(active_tests) if active_tests else None

    return {
        "technique_id": technique_id,
        "evasion_tests_run": len(results),
        "evasion_resilience": round(resilience, 4) if resilience is not None else None,
        "passes": passes,
        "failures": len(active_tests) - passes,
        "known_gaps": [g["variant"] for g in known_gaps],
        "results": results,
    }


def generate_evasion_report(evasion_dir: Optional[str] = None) -> dict:
    """
    Generate a full evasion resilience report for all techniques.

    Groups results by technique and calculates overall resilience score.
    """
    all_tests = load_evasion_tests(evasion_dir)

    # Group by technique
    by_technique = {}
    for test in all_tests:
        tid = test.get("technique", "unknown")
        by_technique.setdefault(tid, []).append(test)

    report = {
        "total_evasion_tests": len(all_tests),
        "techniques_covered": list(by_technique.keys()),
        "by_technique": {},
        "overall_resilience": None,
        "known_gaps": [],
    }

    all_gaps = []

    for tid, tests in by_technique.items():
        # Categorize without running (no ES call needed for the report structure)
        should_alert = [t for t in tests if t.get("expected_result") == "SHOULD_ALERT"]
        evasion_succeed = [t for t in tests if t.get("expected_result") == "EVASION_SUCCEEDS"]
        all_gaps.extend([{
            "technique": tid,
            "variant": t["variant"],
            "description": t["description"],
            "remediation": t.get("remediation", ""),
        } for t in evasion_succeed])
        report["by_technique"][tid] = {
            "total_tests": len(tests),
            "should_alert_tests": len(should_alert),
            "known_gap_tests": len(evasion_succeed),
            "variants": [t["variant"] for t in tests],
        }

    report["known_gaps"] = all_gaps
    return report
