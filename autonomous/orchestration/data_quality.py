#!/usr/bin/env python3
"""
Data Quality Monitoring Engine — Phase 5, Task 5.1

Runs health checks against Elasticsearch log sources defined in source_expectations.yml.
Produces composite health scores per source with freshness, completeness, volume, and
schema sub-scores. Exports per-source JSON reports to monitoring/data-quality/.

All ES queries use stdlib urllib.request — no external dependencies.
"""

import base64
import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:
    yaml = None  # handled at load time


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

# Freshness: minutes since last event
FRESH_GREEN_MINUTES = 5
FRESH_YELLOW_MINUTES = 15
FRESH_DEAD_MINUTES = 60

# Completeness: fraction of docs with required field populated
COMPLETE_GREEN = 0.95
COMPLETE_YELLOW = 0.80

# Volume: allowed deviation from expected_volume_24h
VOLUME_GREEN_BAND = 0.20   # ±20 %
VOLUME_YELLOW_BAND = 0.50  # ±50 %

# Schema: fraction of sampled docs that contain all expected fields
SCHEMA_GREEN = 0.99
SCHEMA_YELLOW = 0.95

# Composite weights
W_FRESHNESS    = 0.30
W_COMPLETENESS = 0.30
W_VOLUME       = 0.20
W_SCHEMA       = 0.20


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _status_from_score(score: float) -> str:
    if score >= 0.9:
        return "green"
    if score >= 0.6:
        return "yellow"
    if score > 0.0:
        return "red"
    return "dead"


class DataQualityEngine:
    """
    Runs data quality checks for each source defined in source_expectations.yml.

    Parameters
    ----------
    es_url          : Elasticsearch base URL, e.g. "http://localhost:9200"
    es_auth         : (username, password) tuple for Basic auth
    expectations_path : Path to source_expectations.yml
    """

    def __init__(self, es_url: str, es_auth: tuple, expectations_path):
        self.es_url = es_url.rstrip("/")
        self.es_auth = es_auth
        self.expectations_path = Path(expectations_path)
        self._sources: dict = {}
        self._load_expectations()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_checks(self, source_id: Optional[str] = None) -> list:
        """
        Run all health checks.

        Parameters
        ----------
        source_id : if given, only run checks for that single source.

        Returns
        -------
        List of health dicts, one per source.
        """
        sources = self._sources
        if source_id:
            if source_id not in sources:
                return [{"source_id": source_id, "error": "source not found in expectations",
                         "composite": 0.0, "composite_status": "unknown"}]
            sources = {source_id: sources[source_id]}

        results = []
        for sid, src_cfg in sources.items():
            src = dict(src_cfg)
            src["source_id"] = sid
            result = self.compute_health_score(sid)
            results.append(result)
        return results

    def compute_health_score(self, source_id: str) -> dict:
        """
        Compute composite health score for a single source.

        Returns
        -------
        Dict with freshness/completeness/volume/schema sub-dicts and composite fields.
        """
        if source_id not in self._sources:
            return {"source_id": source_id, "error": "not found", "composite": 0.0,
                    "composite_status": "unknown"}

        src = dict(self._sources[source_id])
        src["source_id"] = source_id

        freshness_result    = self._check_freshness(src)
        completeness_result = self._check_completeness(src)
        volume_result       = self._check_volume(src)
        schema_result       = self._check_schema(src)

        composite = (
            freshness_result["score"]    * W_FRESHNESS
            + completeness_result["score"] * W_COMPLETENESS
            + volume_result["score"]       * W_VOLUME
            + schema_result["score"]       * W_SCHEMA
        )
        composite = round(composite, 4)

        return {
            "source_id":        source_id,
            "checked_at":       datetime.now(timezone.utc).isoformat(),
            "freshness":        freshness_result,
            "completeness":     completeness_result,
            "volume":           volume_result,
            "schema":           schema_result,
            "composite":        composite,
            "composite_status": _status_from_score(composite),
        }

    def export_json(self, results: list, output_dir: str):
        """
        Write per-source JSON files to output_dir.

        Files are named <source_id>.json. Also writes a summary.json.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        for r in results:
            sid = r.get("source_id", "unknown")
            dest = out / f"{sid}.json"
            dest.write_text(json.dumps(r, indent=2), encoding="utf-8")

        # Write summary
        summary = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_sources": len(results),
            "green":  sum(1 for r in results if r.get("composite_status") == "green"),
            "yellow": sum(1 for r in results if r.get("composite_status") == "yellow"),
            "red":    sum(1 for r in results if r.get("composite_status") == "red"),
            "dead":   sum(1 for r in results if r.get("composite_status") == "dead"),
            "unknown":sum(1 for r in results if r.get("composite_status") == "unknown"),
            "sources": [
                {
                    "source_id":        r.get("source_id"),
                    "composite":        r.get("composite"),
                    "composite_status": r.get("composite_status"),
                }
                for r in results
            ],
        }
        (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # ------------------------------------------------------------------
    # Check implementations
    # ------------------------------------------------------------------

    def _check_freshness(self, source: dict) -> dict:
        """
        Query max(@timestamp) for this source.
        Score: 1.0 (green) if < 5 min, 0.7 (yellow) < 15 min,
               0.3 (red) < 60 min, 0.0 (dead) >= 60 min.
        """
        index   = source.get("index_pattern", "sim-*")
        flt     = source.get("filter", {"match_all": {}})
        source_id = source.get("source_id", "?")

        query = {
            "size": 0,
            "query": {"bool": {"filter": [flt]}},
            "aggs": {
                "max_ts": {"max": {"field": "@timestamp"}}
            }
        }

        try:
            resp = self._es_search(index, query)
        except Exception as exc:
            return {"score": 0.0, "status": "unknown", "error": str(exc),
                    "age_minutes": None}

        max_ts_ms = (resp.get("aggregations", {})
                         .get("max_ts", {})
                         .get("value"))

        if max_ts_ms is None:
            return {"score": 0.0, "status": "dead",
                    "age_minutes": None, "note": "no documents found"}

        now_ms     = datetime.now(timezone.utc).timestamp() * 1000
        age_minutes = (now_ms - max_ts_ms) / 60_000

        if age_minutes < FRESH_GREEN_MINUTES:
            score, status = 1.0, "green"
        elif age_minutes < FRESH_YELLOW_MINUTES:
            score, status = 0.7, "yellow"
        elif age_minutes < FRESH_DEAD_MINUTES:
            score, status = 0.3, "red"
        else:
            score, status = 0.0, "dead"

        return {
            "score":       round(score, 4),
            "status":      status,
            "age_minutes": round(age_minutes, 1),
        }

    def _check_completeness(self, source: dict) -> dict:
        """
        For each expected field, count docs where that field exists and is non-null.
        Score is the mean completeness fraction across all required fields.
        """
        index           = source.get("index_pattern", "sim-*")
        flt             = source.get("filter", {"match_all": {}})
        expected_fields = source.get("expected_fields", [])

        if not expected_fields:
            return {"score": 1.0, "status": "green", "note": "no expected fields defined",
                    "field_scores": {}}

        # Get total doc count for this source
        total_query = {
            "size": 0,
            "query": {"bool": {"filter": [flt]}}
        }
        try:
            resp = self._es_search(index, total_query)
            total = resp.get("hits", {}).get("total", {}).get("value", 0)
        except Exception as exc:
            return {"score": 0.0, "status": "unknown", "error": str(exc), "field_scores": {}}

        if total == 0:
            return {"score": 0.0, "status": "dead", "note": "no documents", "field_scores": {}}

        # Per-field completeness via exists queries
        field_scores = {}
        for field in expected_fields:
            exists_query = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            flt,
                            {"exists": {"field": field}}
                        ]
                    }
                }
            }
            try:
                resp = self._es_search(index, exists_query)
                count = resp.get("hits", {}).get("total", {}).get("value", 0)
                field_scores[field] = count / total if total > 0 else 0.0
            except Exception:
                field_scores[field] = 0.0

        mean_score = sum(field_scores.values()) / len(field_scores) if field_scores else 0.0

        if mean_score >= COMPLETE_GREEN:
            score, status = 1.0, "green"
        elif mean_score >= COMPLETE_YELLOW:
            score, status = 0.7, "yellow"
        else:
            score, status = 0.3, "red"

        return {
            "score":        round(score, 4),
            "status":       status,
            "mean_fill_pct": round(mean_score, 4),
            "field_scores": {k: round(v, 4) for k, v in field_scores.items()},
        }

    def _check_volume(self, source: dict) -> dict:
        """
        Count docs in last 24 h, compare to expected_volume_24h.
        Score: 1.0 (green) within ±20%, 0.7 (yellow) within ±50%,
               0.3 (red) outside ±50%, 0.0 if zero docs.
        """
        index    = source.get("index_pattern", "sim-*")
        flt      = source.get("filter", {"match_all": {}})
        expected = source.get("expected_volume_24h", 0)

        volume_query = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        flt,
                        {"range": {"@timestamp": {"gte": "now-24h/h", "lte": "now"}}}
                    ]
                }
            }
        }

        try:
            resp  = self._es_search(index, volume_query)
            actual = resp.get("hits", {}).get("total", {}).get("value", 0)
        except Exception as exc:
            return {"score": 0.0, "status": "unknown", "error": str(exc),
                    "actual_24h": None, "expected_24h": expected}

        if actual == 0:
            return {"score": 0.0, "status": "dead",
                    "actual_24h": 0, "expected_24h": expected}

        if expected <= 0:
            # No expectation set — can't score volume meaningfully
            return {"score": 0.7, "status": "yellow",
                    "actual_24h": actual, "expected_24h": expected,
                    "note": "no expected_volume_24h configured"}

        deviation = abs(actual - expected) / expected

        if deviation <= VOLUME_GREEN_BAND:
            score, status = 1.0, "green"
        elif deviation <= VOLUME_YELLOW_BAND:
            score, status = 0.7, "yellow"
        else:
            score, status = 0.3, "red"

        return {
            "score":        round(score, 4),
            "status":       status,
            "actual_24h":   actual,
            "expected_24h": expected,
            "deviation_pct": round(deviation * 100, 1),
        }

    def _check_schema(self, source: dict) -> dict:
        """
        Sample up to 100 docs and check that each expected field is present in the doc.
        Score is the fraction of docs that contain ALL expected fields.
        """
        index           = source.get("index_pattern", "sim-*")
        flt             = source.get("filter", {"match_all": {}})
        expected_fields = source.get("expected_fields", [])

        if not expected_fields:
            return {"score": 1.0, "status": "green",
                    "note": "no expected fields defined", "docs_sampled": 0}

        sample_query = {
            "size": 100,
            "query": {"bool": {"filter": [flt]}},
            "_source": expected_fields,
        }

        try:
            resp = self._es_search(index, sample_query)
            hits = resp.get("hits", {}).get("hits", [])
        except Exception as exc:
            return {"score": 0.0, "status": "unknown", "error": str(exc), "docs_sampled": 0}

        if not hits:
            return {"score": 0.0, "status": "dead", "note": "no documents", "docs_sampled": 0}

        def _field_present(doc_source: dict, field_path: str) -> bool:
            """Traverse dot-notation field path in nested dict."""
            parts = field_path.split(".")
            node = doc_source
            for part in parts:
                if not isinstance(node, dict) or part not in node:
                    return False
                node = node[part]
            return node is not None

        full_docs   = 0
        missing_by_field: dict = {f: 0 for f in expected_fields}

        for hit in hits:
            src = hit.get("_source", {})
            all_present = True
            for field in expected_fields:
                if not _field_present(src, field):
                    missing_by_field[field] = missing_by_field.get(field, 0) + 1
                    all_present = False
            if all_present:
                full_docs += 1

        docs_sampled = len(hits)
        complete_fraction = full_docs / docs_sampled

        if complete_fraction >= SCHEMA_GREEN:
            score, status = 1.0, "green"
        elif complete_fraction >= SCHEMA_YELLOW:
            score, status = 0.7, "yellow"
        else:
            score, status = 0.3, "red"

        return {
            "score":             round(score, 4),
            "status":            status,
            "docs_sampled":      docs_sampled,
            "complete_fraction": round(complete_fraction, 4),
            "missing_by_field":  {k: v for k, v in missing_by_field.items() if v > 0},
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_expectations(self):
        """Parse source_expectations.yml into self._sources."""
        if not self.expectations_path.exists():
            self._sources = {}
            return

        if yaml is None:
            raise ImportError("PyYAML is required to load source expectations.")

        with open(self.expectations_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        self._sources = data.get("sources", {})

    def _make_auth_header(self) -> str:
        user, password = self.es_auth
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        return f"Basic {token}"

    def _es_search(self, index: str, query: dict) -> dict:
        """
        Execute an Elasticsearch search using urllib.request.
        Raises urllib.error.URLError or ValueError on failure.
        """
        url  = f"{self.es_url}/{index}/_search"
        body = json.dumps(query).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": self._make_auth_header(),
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                raw = response.read()
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            raise ValueError(f"ES HTTP {exc.code}: {body_text[:200]}") from exc
        except urllib.error.URLError as exc:
            raise ConnectionError(f"ES unreachable ({url}): {exc.reason}") from exc
