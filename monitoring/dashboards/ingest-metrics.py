#!/usr/bin/env python3
"""
Task 7.1 — Detection Health Metrics Ingestion
Collects detection health metrics from test results and detection requests,
then bulk-indexes them into Elasticsearch .detection-metrics-{YYYY.MM} index.

Usage:
    python3 monitoring/dashboards/ingest-metrics.py
    python3 monitoring/dashboards/ingest-metrics.py --es-url http://localhost:9200 --es-user elastic --es-pass changeme
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import request as urllib_request
from urllib.error import URLError, HTTPError
import base64

# ---------------------------------------------------------------------------
# Index template
# ---------------------------------------------------------------------------

INDEX_TEMPLATE: dict[str, Any] = {
    "index_patterns": [".detection-metrics-*"],
    "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "metric_type": {"type": "keyword"},
                "technique_id": {"type": "keyword"},
                "rule_name": {"type": "keyword"},
                "f1_score": {"type": "float"},
                "alert_count_24h": {"type": "integer"},
                "fp_rate": {"type": "float"},
                "state": {"type": "keyword"},
                "validation_method": {"type": "keyword"},
                "tactic": {"type": "keyword"},
                "priority": {"type": "keyword"},
                "platform": {"type": "keyword"},
            }
        },
    },
}

# ---------------------------------------------------------------------------
# Repo root
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _auth_header(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"


def _es_request(
    method: str,
    url: str,
    auth: str,
    body: str | None = None,
    content_type: str = "application/json",
) -> tuple[int, dict[str, Any]]:
    """Make a single HTTP request to Elasticsearch and return (status_code, parsed_json)."""
    data = body.encode("utf-8") if body is not None else None
    req = urllib_request.Request(url, data=data, method=method)
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", content_type)
    try:
        with urllib_request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read())
    except HTTPError as exc:
        try:
            err_body = json.loads(exc.read())
        except Exception:
            err_body = {"error": str(exc)}
        return exc.code, err_body


# ---------------------------------------------------------------------------
# Ensure index template exists
# ---------------------------------------------------------------------------

def ensure_index_template(es_url: str, auth: str) -> None:
    url = f"{es_url}/_index_template/detection-metrics"
    status, body = _es_request("GET", url, auth)
    if status == 200:
        return  # already exists
    status, body = _es_request(
        "PUT", url, auth, body=json.dumps(INDEX_TEMPLATE)
    )
    if status not in (200, 201):
        print(f"  WARNING: could not create index template: {body}", file=sys.stderr)
    else:
        print("  Created index template: detection-metrics")


# ---------------------------------------------------------------------------
# Collect metrics
# ---------------------------------------------------------------------------

def load_test_results() -> dict[str, dict[str, Any]]:
    """Return a mapping of technique_id (upper) -> result dict."""
    results: dict[str, dict[str, Any]] = {}
    results_dir = REPO_ROOT / "tests" / "results"
    if not results_dir.exists():
        return results

    for path in results_dir.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        tech_id = data.get("technique_id", "").upper()
        if not tech_id:
            # Derive from filename
            tech_id = path.stem.upper().replace("_", ".")
        results[tech_id] = data

    return results


def load_detection_requests() -> dict[str, dict[str, Any]]:
    """Return a mapping of technique_id (upper) -> detection-request dict."""
    requests_map: dict[str, dict[str, Any]] = {}
    req_dir = REPO_ROOT / "autonomous" / "detection-requests"
    if not req_dir.exists():
        return requests_map

    try:
        import yaml
        _yaml = yaml
    except ImportError:
        _yaml = None  # type: ignore[assignment]

    for path in req_dir.glob("*.yml"):
        if path.name.startswith("_"):
            continue
        try:
            if _yaml is not None:
                data = _yaml.safe_load(path.read_text(encoding="utf-8"))
            else:
                # Minimal fallback: parse key: value lines (no nested structures)
                data = {}
                for line in path.read_text(encoding="utf-8").splitlines():
                    if ":" in line and not line.startswith(" "):
                        k, _, v = line.partition(":")
                        data[k.strip()] = v.strip().strip("'\"")
        except Exception:
            continue

        if not isinstance(data, dict):
            continue
        tech_id = str(data.get("technique_id", "")).upper()
        if not tech_id:
            tech_id = path.stem.upper().replace("_", ".")
        requests_map[tech_id] = data

    return requests_map


def load_budget_log_summary() -> dict[str, Any]:
    """
    Read budget-log.jsonl and build a daily summary for today / the most recent date.
    Returns a dict with agent run counts, total tokens, total items.
    """
    budget_path = REPO_ROOT / "autonomous" / "budget-log.jsonl"
    if not budget_path.exists():
        return {}

    entries: list[dict[str, Any]] = []
    for line in budget_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except Exception:
            continue

    if not entries:
        return {}

    # Group by date, use the most recent date available
    by_date: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        date_key = entry.get("date") or entry.get("timestamp", "")[:10]
        by_date.setdefault(date_key, []).append(entry)

    latest_date = max(by_date.keys())
    day_entries = by_date[latest_date]

    agent_counts: dict[str, int] = {}
    total_tokens = 0
    total_items = 0
    statuses: list[str] = []

    for e in day_entries:
        agent = e.get("agent", "unknown")
        agent_counts[agent] = agent_counts.get(agent, 0) + 1
        total_tokens += int(e.get("estimated_tokens", 0))
        total_items += int(e.get("items_processed", 0))
        statuses.append(e.get("status", "unknown"))

    completed = sum(1 for s in statuses if s == "completed")
    failed = sum(1 for s in statuses if s not in ("completed", "skipped"))

    return {
        "date": latest_date,
        "agent_run_counts": agent_counts,
        "total_runs": len(day_entries),
        "completed_runs": completed,
        "failed_runs": failed,
        "total_tokens_estimated": total_tokens,
        "total_items_processed": total_items,
    }


# ---------------------------------------------------------------------------
# Build metric documents
# ---------------------------------------------------------------------------

def build_detection_metrics(
    test_results: dict[str, dict[str, Any]],
    detection_requests: dict[str, dict[str, Any]],
    now_iso: str,
) -> list[dict[str, Any]]:
    """Build one metric document per technique that has test results."""
    docs: list[dict[str, Any]] = []

    # Union of technique IDs from both sources
    all_techniques = set(test_results.keys()) | set(detection_requests.keys())

    for tech_id in sorted(all_techniques):
        result = test_results.get(tech_id, {})
        req = detection_requests.get(tech_id, {})

        # Extract metrics sub-dict if nested (format from t1027.json)
        metrics: dict[str, Any] = result.get("metrics", {})
        f1 = float(
            metrics.get("f1_score")
            or result.get("f1_score")
            or req.get("quality_score")
            or 0.0
        )
        fp_rate = float(
            metrics.get("fp_rate")
            or result.get("fp_rate")
            or req.get("fp_rate")
            or 0.0
        )
        tp = int(metrics.get("tp") or result.get("tp") or 0)
        fp = int(metrics.get("fp") or result.get("fp") or 0)
        fn = int(metrics.get("fn") or result.get("fn") or 0)
        tn = int(metrics.get("tn") or result.get("tn") or 0)

        state = str(
            req.get("status")
            or result.get("quality_tier", "UNKNOWN")
        ).upper()

        tactic = str(
            req.get("mitre_tactic")
            or result.get("mitre_tactic", "")
        )
        # Normalise tactic from file path if available
        sigma_rule_path = req.get("sigma_rule", "") or result.get("sigma_rule_path", "")
        if not tactic and sigma_rule_path:
            parts = Path(sigma_rule_path).parts
            # Path like detections/defense_evasion/t1027.yml
            if len(parts) >= 2:
                tactic = parts[-2] if parts[-2] != "detections" else ""

        rule_name = str(req.get("title") or tech_id)
        priority = str(req.get("priority") or "medium")
        validation_method = str(
            result.get("validation_method") or req.get("validation_method") or "local_json"
        )
        alert_count_24h = int(
            req.get("alert_volume_24h") or result.get("alert_count_24h") or 0
        )

        doc: dict[str, Any] = {
            "@timestamp": now_iso,
            "metric_type": "detection_health",
            "technique_id": tech_id,
            "rule_name": rule_name,
            "f1_score": round(f1, 4),
            "fp_rate": round(fp_rate, 4),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "state": state,
            "tactic": tactic,
            "priority": priority,
            "validation_method": validation_method,
            "alert_count_24h": alert_count_24h,
        }
        docs.append(doc)

    return docs


def build_pipeline_summary(
    budget_summary: dict[str, Any],
    now_iso: str,
) -> dict[str, Any] | None:
    if not budget_summary:
        return None
    return {
        "@timestamp": now_iso,
        "metric_type": "pipeline_run_summary",
        "report_date": budget_summary.get("date", ""),
        "total_runs": budget_summary.get("total_runs", 0),
        "completed_runs": budget_summary.get("completed_runs", 0),
        "failed_runs": budget_summary.get("failed_runs", 0),
        "total_tokens_estimated": budget_summary.get("total_tokens_estimated", 0),
        "total_items_processed": budget_summary.get("total_items_processed", 0),
        "agent_run_counts": budget_summary.get("agent_run_counts", {}),
    }


# ---------------------------------------------------------------------------
# Bulk index
# ---------------------------------------------------------------------------

def bulk_index(
    docs: list[dict[str, Any]],
    index_name: str,
    es_url: str,
    auth: str,
) -> int:
    """Bulk index docs into the given ES index. Returns number of docs indexed."""
    if not docs:
        return 0

    lines: list[str] = []
    for doc in docs:
        action = json.dumps({"index": {"_index": index_name}})
        lines.append(action)
        lines.append(json.dumps(doc))
    ndjson_body = "\n".join(lines) + "\n"

    url = f"{es_url}/_bulk"
    status, body = _es_request("POST", url, auth, body=ndjson_body, content_type="application/x-ndjson")

    if status not in (200, 201):
        print(f"  ERROR bulk indexing: HTTP {status} — {body}", file=sys.stderr)
        return 0

    # Count successful items
    items = body.get("items", [])
    success = sum(
        1 for item in items if item.get("index", {}).get("status") in (200, 201)
    )
    if body.get("errors"):
        failed = [
            item["index"].get("error")
            for item in items
            if item.get("index", {}).get("status") not in (200, 201)
        ]
        print(f"  WARNING: {len(failed)} bulk errors: {failed[:3]}", file=sys.stderr)

    return success


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect detection health metrics and index into Elasticsearch"
    )
    parser.add_argument(
        "--es-url",
        default=os.getenv("ES_URL", "http://localhost:9200"),
        help="Elasticsearch URL (default: http://localhost:9200 or $ES_URL)",
    )
    parser.add_argument(
        "--es-user",
        default=os.getenv("ES_USER", "elastic"),
        help="Elasticsearch username (default: elastic or $ES_USER)",
    )
    parser.add_argument(
        "--es-pass",
        default=os.getenv("ES_PASS", "changeme"),
        help="Elasticsearch password (default: changeme or $ES_PASS)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print metrics without indexing into Elasticsearch",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    now = datetime.now(tz=timezone.utc)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    month_suffix = now.strftime("%Y.%m")
    index_name = f".detection-metrics-{month_suffix}"
    auth = _auth_header(args.es_user, args.es_pass)

    print(f"[ingest-metrics] {now_iso}")
    print(f"  Target index : {index_name}")
    print(f"  Elasticsearch: {args.es_url}")

    # --- Collect data ---
    print("\n[1/4] Loading test results ...")
    test_results = load_test_results()
    print(f"  Found {len(test_results)} test result(s)")

    print("[2/4] Loading detection requests ...")
    detection_requests = load_detection_requests()
    print(f"  Found {len(detection_requests)} detection request(s)")

    print("[3/4] Loading budget log ...")
    budget_summary = load_budget_log_summary()
    if budget_summary:
        print(f"  Most recent run date: {budget_summary.get('date')} "
              f"({budget_summary.get('total_runs')} runs)")
    else:
        print("  No budget log data found")

    # --- Build documents ---
    detection_docs = build_detection_metrics(test_results, detection_requests, now_iso)
    pipeline_doc = build_pipeline_summary(budget_summary, now_iso)
    all_docs = detection_docs + ([pipeline_doc] if pipeline_doc else [])

    print(f"\n[4/4] Preparing to index {len(detection_docs)} detection metrics "
          f"+ {1 if pipeline_doc else 0} pipeline summary ...")

    if args.dry_run:
        print("\n  [DRY RUN] — documents NOT sent to Elasticsearch")
        for doc in all_docs[:5]:
            print(f"    {json.dumps(doc, indent=2)}")
        if len(all_docs) > 5:
            print(f"    ... and {len(all_docs) - 5} more")
        return

    # --- Ensure template and index ---
    try:
        ensure_index_template(args.es_url, auth)
    except (URLError, OSError) as exc:
        print(f"  WARNING: could not reach Elasticsearch at {args.es_url}: {exc}",
              file=sys.stderr)
        print("  Metrics were NOT indexed. Start Elasticsearch and re-run.", file=sys.stderr)
        sys.exit(1)

    # --- Bulk index ---
    indexed = bulk_index(all_docs, index_name, args.es_url, auth)

    print(
        f"\nIndexed {indexed - (1 if pipeline_doc else 0)} detection metrics "
        f"+ {1 if pipeline_doc else 0} pipeline summary "
        f"to {index_name}"
    )


if __name__ == "__main__":
    main()
