"""
Detection Performance Profiler — Measures query execution time at scale.

Generates synthetic event volumes and benchmarks each detection query
against Elasticsearch to identify expensive rules before production deployment.

Phase 6 deliverable — Task 6.6: Detection Performance Profiling.
"""

import json
import random
import string
import time
from pathlib import Path
from uuid import uuid4

import yaml

from orchestration.validation import (
    _es_request,
    _check_es_reachable,
    _cleanup_index,
)
from orchestration.siem import _load_infra_config


SCALE_TIERS = {
    "small": 10_000,
    "medium": 100_000,
    "large": 1_000_000,
}

PERFORMANCE_BUDGET_MS = {
    "small": 500,
    "medium": 2000,
    "large": 5000,
}

# Realistic field values for synthetic events
_PROCESS_NAMES = [
    "svchost.exe", "explorer.exe", "chrome.exe", "notepad.exe",
    "cmd.exe", "powershell.exe", "conhost.exe", "taskhostw.exe",
    "RuntimeBroker.exe", "SearchIndexer.exe", "dwm.exe", "csrss.exe",
    "lsass.exe", "services.exe", "System", "smss.exe", "wininit.exe",
    "spoolsv.exe", "msiexec.exe", "WmiPrvSE.exe",
]

_HOSTNAMES = [
    "WORKSTATION-01", "WORKSTATION-02", "WORKSTATION-03",
    "SERVER-DC01", "SERVER-FS01", "SERVER-WEB01",
    "LAPTOP-ADMIN", "LAPTOP-DEV01", "LAPTOP-HR01",
]

_USERNAMES = ["jsmith", "admin", "svc_backup", "jdoe", "SYSTEM", "LOCAL SERVICE"]

_EVENT_CODES = ["1", "3", "7", "8", "10", "11", "13"]


def _generate_scale_events(count: int) -> list[dict]:
    """
    Generate synthetic ECS-formatted Sysmon-like events for performance testing.

    Mix: 99% benign baseline, 1% attack-like events with suspicious process names.
    """
    events = []
    attack_count = max(1, count // 100)
    benign_count = count - attack_count

    base_ts = int(time.time()) - 3600  # Start 1 hour ago

    for i in range(benign_count):
        ts_offset = (3600 * i) // benign_count
        events.append({
            "@timestamp": f"2026-03-15T{10 + (ts_offset // 3600):02d}:{(ts_offset % 3600) // 60:02d}:{ts_offset % 60:02d}.000Z",
            "event": {"code": random.choice(_EVENT_CODES), "category": "process"},
            "process": {
                "name": random.choice(_PROCESS_NAMES),
                "executable": f"C:\\Windows\\System32\\{random.choice(_PROCESS_NAMES)}",
                "command_line": f"{random.choice(_PROCESS_NAMES)} /normal /flag",
                "pid": random.randint(100, 65535),
            },
            "host": {"name": random.choice(_HOSTNAMES)},
            "user": {"name": random.choice(_USERNAMES)},
            "_simulation": {"type": "baseline"},
        })

    # Attack events — use suspicious patterns
    attack_processes = ["powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe",
                        "cscript.exe", "regsvr32.exe", "certutil.exe"]
    for i in range(attack_count):
        ts_offset = random.randint(0, 3600)
        events.append({
            "@timestamp": f"2026-03-15T{10 + (ts_offset // 3600):02d}:{(ts_offset % 3600) // 60:02d}:{ts_offset % 60:02d}.000Z",
            "event": {"code": random.choice(["1", "8", "10"]), "category": "process"},
            "process": {
                "name": random.choice(attack_processes),
                "executable": f"C:\\Windows\\System32\\{random.choice(attack_processes)}",
                "command_line": f"powershell.exe -ExecutionPolicy Bypass -File C:\\temp\\{''.join(random.choices(string.ascii_lowercase, k=8))}.ps1",
                "pid": random.randint(100, 65535),
            },
            "host": {"name": random.choice(_HOSTNAMES)},
            "user": {"name": random.choice(_USERNAMES)},
            "winlog": {"event_data": {"GrantedAccess": "0x1F0FFF"}},
            "_simulation": {"type": "attack"},
        })

    return events


def _flatten_event(event: dict, parent_key: str = "", sep: str = ".") -> dict:
    """Flatten nested dict into dotted-key format for ES ingest."""
    items = {}
    for k, v in event.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.update(_flatten_event(v, new_key, sep))
        else:
            items[new_key] = v
    return items


def _build_perf_bulk_body(index_name: str, events: list[dict],
                          batch_start: int = 0) -> str:
    """Build Elasticsearch Bulk API NDJSON body for performance events."""
    lines = []
    for i, event in enumerate(events):
        flat = _flatten_event(event)
        action = json.dumps({"index": {"_index": index_name, "_id": f"perf-{batch_start + i}"}})
        doc = json.dumps(flat)
        lines.append(action)
        lines.append(doc)
    return "\n".join(lines) + "\n"


def profile_detection(
    technique_id: str,
    compiled_query: str,
    scale: str = "medium",
    query_type: str = "lucene",
    iterations: int = 3,
    es_url: str = None,
    es_auth: tuple = None,
    cleanup: bool = True,
) -> dict | None:
    """
    Profile a detection query's performance at the given scale.

    Args:
        technique_id: MITRE technique ID
        compiled_query: Compiled Lucene query string
        scale: "small" (10K), "medium" (100K), or "large" (1M)
        query_type: "lucene" or "eql"
        iterations: Number of times to run query (for averaging)
        es_url: Elasticsearch URL (reads from config if None)
        es_auth: (user, password) tuple (reads from config if None)
        cleanup: Delete ephemeral index after test

    Returns:
        dict with performance metrics, or None if ES unreachable.
    """
    if es_url is None or es_auth is None:
        infra = _load_infra_config()
        es = infra.get("elasticsearch", {})
        if es_url is None:
            es_url = es.get("url", "http://localhost:9200")
        if es_auth is None:
            es_auth = (es.get("user", "elastic"), es.get("pass", "changeme"))

    if not _check_es_reachable(es_url, es_auth):
        return None

    event_count = SCALE_TIERS.get(scale, 100_000)
    budget = PERFORMANCE_BUDGET_MS.get(scale, 2000)
    index_name = f"sim-perf-{uuid4().hex[:8]}"

    try:
        # Create index with performance-oriented settings
        _es_request(
            f"{es_url}/{index_name}",
            method="PUT",
            data={"settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "refresh_interval": "-1",  # Disable auto-refresh during ingest
            }},
            auth=es_auth,
        )

        # Generate and ingest events in batches
        batch_size = 5000
        total_ingested = 0
        for batch_start in range(0, event_count, batch_size):
            batch_count = min(batch_size, event_count - batch_start)
            events = _generate_scale_events(batch_count)
            bulk_body = _build_perf_bulk_body(index_name, events, batch_start)
            try:
                _es_request(
                    f"{es_url}/{index_name}/_bulk",
                    method="POST",
                    data=bulk_body,
                    auth=es_auth,
                    content_type="application/x-ndjson",
                    timeout=60,
                )
                total_ingested += batch_count
            except Exception:
                break  # Stop on error, profile what we have

        # Refresh index for search
        _es_request(f"{es_url}/{index_name}/_refresh", method="POST", auth=es_auth)

        # Run query multiple times, measure timing
        times = []
        for _ in range(iterations):
            if query_type == "eql":
                query_body = {
                    "query": compiled_query,
                    "tiebreaker_field": "@timestamp",
                    "size": 0,
                }
                endpoint = f"{es_url}/{index_name}/_eql/search"
            else:
                query_body = {
                    "query": {"query_string": {
                        "query": compiled_query,
                        "analyze_wildcard": True,
                    }},
                    "size": 0,
                    "profile": True,
                }
                endpoint = f"{es_url}/{index_name}/_search"

            start = time.monotonic()
            try:
                status, response = _es_request(
                    endpoint, method="POST", data=query_body,
                    auth=es_auth, timeout=30,
                )
            except Exception:
                times.append(30000)  # Timeout = 30s
                continue
            elapsed_ms = (time.monotonic() - start) * 1000
            times.append(elapsed_ms)

        if not times:
            return {"technique_id": technique_id, "error": "No query runs completed"}

        avg_ms = sum(times) / len(times)
        sorted_times = sorted(times)
        p95_idx = min(int(len(sorted_times) * 0.95), len(sorted_times) - 1)
        p95_ms = sorted_times[p95_idx]

        # Determine verdict
        if p95_ms <= budget:
            verdict = "PASS"
        elif p95_ms <= budget * 1.25:
            verdict = "WARN"
        else:
            verdict = "FAIL"

        return {
            "technique_id": technique_id,
            "scale": scale,
            "query_type": query_type,
            "events_count": total_ingested,
            "query": compiled_query[:200] + "..." if len(compiled_query) > 200 else compiled_query,
            "query_times_ms": [round(t, 1) for t in times],
            "avg_ms": round(avg_ms, 1),
            "p95_ms": round(p95_ms, 1),
            "budget_ms": budget,
            "within_budget": p95_ms <= budget,
            "optimization_hints": _generate_hints(compiled_query, avg_ms, budget),
            "verdict": verdict,
            "index_used": index_name,
        }

    except Exception as e:
        return {"technique_id": technique_id, "error": str(e)}

    finally:
        if cleanup:
            _cleanup_index(es_url, index_name, es_auth)


def _generate_hints(query: str, avg_ms: float, budget: float) -> list[str]:
    """Generate optimization suggestions for expensive queries."""
    hints = []
    if avg_ms <= budget:
        return hints

    wildcard_count = query.count("*")
    if wildcard_count > 2:
        hints.append(
            f"Multiple wildcards ({wildcard_count}) detected — "
            "consider using keyword field with exact match"
        )
    or_count = query.upper().count(" OR ")
    if or_count > 5:
        hints.append(
            f"Many OR clauses ({or_count}) — "
            "consider using terms query with array instead"
        )
    if "regex" in query.lower() or "/.*/" in query:
        hints.append(
            "Regex in query — very expensive at scale. "
            "Use wildcard or keyword match"
        )
    if "NOT " in query.upper() and wildcard_count > 0:
        hints.append(
            "NOT + wildcard combination — consider restructuring "
            "as positive match with filter context"
        )
    if not hints:
        hints.append("Query is expensive — review ES profile for specific bottleneck")
    return hints


def profile_all_detections(
    scale: str = "small",
    rule_types: list[str] = None,
) -> list[dict]:
    """
    Profile all detection rules in the repository.

    Args:
        scale: Scale tier for profiling
        rule_types: Filter by rule type (["sigma", "eql", "threshold"]), None = all

    Returns:
        List of profile result dicts.
    """
    repo_root = Path(__file__).resolve().parent.parent.parent
    detections_dir = repo_root / "detections"
    results = []

    for rule_file in sorted(detections_dir.rglob("*.yml")):
        if "compiled" in str(rule_file) or "packs" in str(rule_file):
            continue

        try:
            with open(rule_file, encoding="utf-8") as f:
                rule = yaml.safe_load(f)
            if not isinstance(rule, dict):
                continue
        except Exception:
            continue

        detection_type = rule.get("detection_type", "sigma")
        if rule_types and detection_type not in rule_types:
            continue

        # Extract technique ID from tags
        technique_id = ""
        for tag in rule.get("tags", []):
            if tag.startswith("attack.t"):
                technique_id = tag.replace("attack.", "").upper()
                break

        # Find compiled query
        compiled_dir = rule_file.parent / "compiled"
        if detection_type == "eql":
            elastic_json = compiled_dir / f"{rule_file.stem}_elastic.json"
            if elastic_json.exists():
                with open(elastic_json, encoding="utf-8") as f:
                    elastic_rule = json.load(f)
                compiled_query = elastic_rule.get("query", "")
                query_type = "eql"
            else:
                continue
        elif detection_type == "threshold":
            elastic_json = compiled_dir / f"{rule_file.stem}_elastic.json"
            if elastic_json.exists():
                with open(elastic_json, encoding="utf-8") as f:
                    elastic_rule = json.load(f)
                compiled_query = elastic_rule.get("query", "")
                query_type = "lucene"  # Threshold queries are Lucene with aggregation
            else:
                continue
        else:
            lucene_file = compiled_dir / f"{rule_file.stem}.lucene"
            if lucene_file.exists():
                compiled_query = lucene_file.read_text(encoding="utf-8").strip()
                query_type = "lucene"
            else:
                continue

        if not compiled_query:
            continue

        print(f"  Profiling {technique_id or rule_file.stem} ({detection_type})...")
        result = profile_detection(
            technique_id=technique_id or rule_file.stem,
            compiled_query=compiled_query,
            scale=scale,
            query_type=query_type,
        )
        if result:
            results.append(result)

    return results


def print_profile_report(results: list[dict]) -> None:
    """Print a formatted performance profile report."""
    if not results:
        print("  No profiling results.")
        return

    print(f"\n  Detection Performance Profile ({len(results)} rules)")
    print(f"  {'Technique':<16} {'Scale':<8} {'Avg (ms)':>10} {'P95 (ms)':>10} "
          f"{'Budget':>8} {'Verdict':<6}")
    print(f"  {'-' * 65}")

    for r in sorted(results, key=lambda x: x.get("p95_ms", 0), reverse=True):
        if "error" in r:
            print(f"  {r['technique_id']:<16} ERROR: {r['error']}")
            continue
        print(
            f"  {r['technique_id']:<16} {r['scale']:<8} {r['avg_ms']:>10.1f} "
            f"{r['p95_ms']:>10.1f} {r['budget_ms']:>8} {r['verdict']:<6}"
        )
        for hint in r.get("optimization_hints", []):
            print(f"    -> {hint}")

    passed = sum(1 for r in results if r.get("verdict") == "PASS")
    warned = sum(1 for r in results if r.get("verdict") == "WARN")
    failed = sum(1 for r in results if r.get("verdict") == "FAIL")
    print(f"\n  Summary: {passed} PASS | {warned} WARN | {failed} FAIL")
