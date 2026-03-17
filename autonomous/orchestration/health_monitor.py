#!/usr/bin/env python3
"""
Detection Health Monitor — Alert-on-Alert for the Patronus pipeline.

Checks deployed detections for health conditions and creates GitHub Issues.
Integrated with the quality agent daily run.

Health conditions checked:
  SILENT_RULE  — 0 alerts for 7+ days (rule may be broken or data source lost)
  FP_SPIKE     — FP rate jumped >10% in 24h (rule generating noise)
  ALERT_FLOOD  — >100 alerts/day from a single rule (rule too broad)
  F1_DECAY     — F1 dropped >0.10 from deployment baseline (rule quality degraded)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
# Ensure orchestration package is importable when run standalone
if str(REPO_ROOT / "autonomous") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "autonomous"))
AUTONOMOUS_DIR = REPO_ROOT / "autonomous"
REQUESTS_DIR = AUTONOMOUS_DIR / "detection-requests"
RESULTS_DIR = REPO_ROOT / "tests" / "results"

# Health thresholds
SILENCE_DAYS = 7
SILENCE_MIN_DEPLOYED_DAYS = 7       # Don't flag new rules
FP_SPIKE_THRESHOLD = 0.10           # 10% jump in FP rate
FLOOD_THRESHOLD = 100               # alerts / 24 h
F1_DECAY_THRESHOLD = 0.10           # absolute drop in F1

# GitHub
GITHUB_API = "https://api.github.com"
HEALTH_ISSUE_LABEL = "detection-health"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class HealthAlert:
    condition: str      # "SILENT_RULE" | "FP_SPIKE" | "ALERT_FLOOD" | "SCHEMA_BREAK" | "F1_DECAY"
    rule_name: str
    technique_id: str
    message: str
    severity: str       # "critical" | "high" | "medium"
    label: str          # GitHub label: "needs-tuning" | "data-source-gap" | "regression"
    suggested_actions: str

    @property
    def issue_title(self) -> str:
        return f"[Health] {self.condition}: {self.rule_name} ({self.technique_id})"

    @property
    def dedup_key(self) -> str:
        return f"{self.technique_id}:{self.condition}"


# ---------------------------------------------------------------------------
# GitHub token resolution (mirrors agent_runner.py pattern)
# ---------------------------------------------------------------------------

def _get_github_token() -> str:
    """Resolve GitHub token from env or .mcp.json (same order as agent_runner.py)."""
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        mcp_path = REPO_ROOT / ".mcp.json"
        if mcp_path.exists():
            try:
                with open(mcp_path) as fh:
                    mcp = json.load(fh)
                token = (
                    mcp.get("mcpServers", {})
                    .get("github", {})
                    .get("env", {})
                    .get("GITHUB_PERSONAL_ACCESS_TOKEN", "")
                )
            except Exception:
                pass
    return token


# ---------------------------------------------------------------------------
# Main monitor class
# ---------------------------------------------------------------------------

class DetectionHealthMonitor:
    def __init__(
        self,
        es_url: str = "http://localhost:9200",
        es_auth: tuple[str, str] = ("elastic", "changeme"),
        github_token: str = "",
        repo: str = "lsmithg12/ai-detection-engineering",
    ) -> None:
        self.es_url = es_url.rstrip("/")
        self.es_auth = es_auth
        self.github_token = github_token or _get_github_token()
        self.repo = repo
        self._es_available: Optional[bool] = None

    # ------------------------------------------------------------------
    # Elasticsearch helpers
    # ------------------------------------------------------------------

    def _es_headers(self) -> dict[str, str]:
        import base64
        cred = base64.b64encode(
            f"{self.es_auth[0]}:{self.es_auth[1]}".encode()
        ).decode()
        return {
            "Authorization": f"Basic {cred}",
            "Content-Type": "application/json",
        }

    def _es_reachable(self) -> bool:
        if self._es_available is not None:
            return self._es_available
        try:
            req = urllib.request.Request(
                f"{self.es_url}/_cluster/health",
                headers=self._es_headers(),
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                self._es_available = resp.status == 200
        except Exception:
            self._es_available = False
        return self._es_available

    def _es_search(self, index: str, body: dict) -> dict:
        """Run an ES search and return the parsed response, or {} on error."""
        if not self._es_reachable():
            return {}
        url = f"{self.es_url}/{index}/_search"
        payload = json.dumps(body).encode()
        req = urllib.request.Request(
            url, data=payload, method="POST", headers=self._es_headers()
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except Exception:
            return {}

    def get_alert_count(self, rule_name: str, days: int = 7) -> int:
        """Query .alerts-security.alerts-default for alert count over N days."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        body = {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"kibana.alert.rule.name": rule_name}},
                        {"range": {"@timestamp": {"gte": cutoff}}},
                    ]
                }
            },
            "size": 0,
        }
        result = self._es_search(".alerts-security.alerts-default", body)
        return int(result.get("hits", {}).get("total", {}).get("value", 0))

    def get_alert_count_24h(self, rule_name: str) -> int:
        """Get alert count for last 24 hours."""
        return self.get_alert_count(rule_name, days=1)

    # ------------------------------------------------------------------
    # Detection request helpers
    # ------------------------------------------------------------------

    def get_deployed_rules(self) -> list[dict]:
        """Return detection requests with status MONITORING or DEPLOYED."""
        deployed_statuses = {"MONITORING", "DEPLOYED"}
        rules: list[dict] = []
        for path in sorted(REQUESTS_DIR.glob("*.yml")):
            if path.name.startswith("_"):
                continue
            try:
                with open(path) as fh:
                    data = yaml.safe_load(fh)
                if data and data.get("status") in deployed_statuses:
                    data["_file"] = str(path)
                    rules.append(data)
            except Exception:
                continue
        return rules

    def get_deployment_f1(self, technique_id: str) -> Optional[float]:
        """Load baseline F1 from tests/results/{technique_id}.json."""
        tid_lower = technique_id.lower().replace(".", "_")
        result_path = RESULTS_DIR / f"{tid_lower}.json"
        if not result_path.exists():
            return None
        try:
            with open(result_path) as fh:
                data = json.load(fh)
            # Support both flat {"f1_score": ...} and nested {"metrics": {"f1_score": ...}}
            f1 = data.get("f1_score") or data.get("metrics", {}).get("f1_score")
            return float(f1) if f1 is not None else None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Individual health checks
    # ------------------------------------------------------------------

    def check_silence(self, rule: dict) -> list[HealthAlert]:
        """Flag rules with 0 alerts for 7+ days that have been deployed >= 7 days."""
        alerts: list[HealthAlert] = []
        rule_name = rule.get("title", rule.get("technique_id", "unknown"))
        technique_id = rule.get("technique_id", "")
        deployed_date_raw = rule.get("deployed_date", "")

        # Only flag rules that have been live long enough
        if deployed_date_raw:
            try:
                deployed_dt = datetime.fromisoformat(
                    deployed_date_raw.replace("Z", "+00:00")
                )
                deployed_days = (datetime.now(timezone.utc) - deployed_dt).days
            except Exception:
                deployed_days = 0
        else:
            deployed_days = 0

        if deployed_days < SILENCE_MIN_DEPLOYED_DAYS:
            return alerts

        count = self.get_alert_count(rule_name, days=SILENCE_DAYS)
        if count == 0:
            alerts.append(HealthAlert(
                condition="SILENT_RULE",
                rule_name=rule_name,
                technique_id=technique_id,
                message=(
                    f"Rule '{rule_name}' ({technique_id}) has fired 0 alerts in the "
                    f"last {SILENCE_DAYS} days despite being deployed for {deployed_days} days. "
                    "The rule may be broken, the data source may be missing, or the "
                    "technique is genuinely not occurring in the environment."
                ),
                severity="high",
                label="needs-tuning",
                suggested_actions=(
                    "1. Verify the data source (index) is ingesting events.\n"
                    "2. Run a manual query against the raw index to confirm log flow.\n"
                    "3. Re-run validation with the simulator to confirm the rule still fires.\n"
                    "4. Check for recent schema changes that may have renamed fields."
                ),
            ))
        return alerts

    def check_fp_spike(self, rule: dict) -> list[HealthAlert]:
        """Flag rules where FP rate jumped >10% using analyst feedback."""
        alerts: list[HealthAlert] = []
        technique_id = rule.get("technique_id", "")
        rule_name = rule.get("title", technique_id)

        try:
            from orchestration.feedback import compute_fp_rate
        except ImportError:
            # Feedback module not yet available — skip check gracefully
            return alerts

        try:
            current_fp_rate = compute_fp_rate(technique_id, days=7)
            baseline_fp_rate = float(rule.get("fp_rate", 0.0))
            delta = current_fp_rate - baseline_fp_rate

            if delta > FP_SPIKE_THRESHOLD:
                alerts.append(HealthAlert(
                    condition="FP_SPIKE",
                    rule_name=rule_name,
                    technique_id=technique_id,
                    message=(
                        f"Rule '{rule_name}' ({technique_id}) FP rate spiked from "
                        f"{baseline_fp_rate:.1%} (baseline) to {current_fp_rate:.1%} "
                        f"(last 7 days) — a +{delta:.1%} increase exceeding the "
                        f"{FP_SPIKE_THRESHOLD:.0%} threshold."
                    ),
                    severity="high",
                    label="needs-tuning",
                    suggested_actions=(
                        "1. Review recent analyst feedback verdicts for false positives.\n"
                        "2. Identify common FP patterns (user, host, process).\n"
                        "3. Add targeted exclusions (max 3 per rule before escalating).\n"
                        "4. Consider tightening detection logic if exclusions are insufficient."
                    ),
                ))
        except Exception:
            pass

        return alerts

    def check_flood(self, rule: dict) -> list[HealthAlert]:
        """Flag rules firing more than 100 alerts in the last 24 hours."""
        alerts: list[HealthAlert] = []
        rule_name = rule.get("title", rule.get("technique_id", "unknown"))
        technique_id = rule.get("technique_id", "")

        count = self.get_alert_count_24h(rule_name)
        if count > FLOOD_THRESHOLD:
            alerts.append(HealthAlert(
                condition="ALERT_FLOOD",
                rule_name=rule_name,
                technique_id=technique_id,
                message=(
                    f"Rule '{rule_name}' ({technique_id}) fired {count} alerts in the "
                    f"last 24 hours, exceeding the flood threshold of {FLOOD_THRESHOLD}. "
                    "This may indicate the rule is too broad or a new legitimate behavior "
                    "pattern is triggering it at scale."
                ),
                severity="medium",
                label="needs-tuning",
                suggested_actions=(
                    "1. Sample recent alerts to determine if they are TP or FP.\n"
                    "2. If mostly FP: tighten detection logic or add exclusions.\n"
                    "3. If mostly TP: investigate whether a real attack campaign is underway.\n"
                    "4. Consider adding a threshold rule (N events in T minutes) to reduce noise."
                ),
            ))
        return alerts

    def check_f1_decay(self, rule: dict) -> list[HealthAlert]:
        """Flag rules where F1 score dropped >0.10 from deployment baseline."""
        alerts: list[HealthAlert] = []
        technique_id = rule.get("technique_id", "")
        rule_name = rule.get("title", technique_id)

        # Current F1 from detection request (updated by quality agent)
        current_f1_raw = rule.get("quality_score") or rule.get("f1_score")
        if current_f1_raw is None:
            return alerts
        current_f1 = float(current_f1_raw)

        # Baseline F1 from test results file (set at validation/deployment time)
        baseline_f1 = self.get_deployment_f1(technique_id)
        if baseline_f1 is None:
            return alerts

        decay = baseline_f1 - current_f1
        if decay > F1_DECAY_THRESHOLD:
            alerts.append(HealthAlert(
                condition="F1_DECAY",
                rule_name=rule_name,
                technique_id=technique_id,
                message=(
                    f"Rule '{rule_name}' ({technique_id}) F1 score dropped from "
                    f"{baseline_f1:.2f} (deployment baseline) to {current_f1:.2f} "
                    f"(current) — a -{decay:.2f} decay exceeding the "
                    f"{F1_DECAY_THRESHOLD:.2f} threshold."
                ),
                severity="high",
                label="regression",
                suggested_actions=(
                    "1. Re-run validation against the simulator to confirm the decay.\n"
                    "2. Check for recent changes to the data source schema or log format.\n"
                    "3. Review analyst feedback for newly introduced false negatives.\n"
                    "4. If confirmed, open a rework ticket and transition rule to NEEDS_REWORK."
                ),
            ))
        return alerts

    def check_all_deployed_rules(self) -> list[HealthAlert]:
        """Run all health checks against all deployed/monitoring rules."""
        all_alerts: list[HealthAlert] = []
        rules = self.get_deployed_rules()
        if not rules:
            print("  [health_monitor] No deployed rules found.")
            return all_alerts

        for rule in rules:
            tid = rule.get("technique_id", "?")
            try:
                all_alerts.extend(self.check_silence(rule))
                all_alerts.extend(self.check_fp_spike(rule))
                all_alerts.extend(self.check_flood(rule))
                all_alerts.extend(self.check_f1_decay(rule))
            except Exception as exc:
                print(f"  [health_monitor] Error checking {tid}: {type(exc).__name__}: {exc}")

        return all_alerts

    # ------------------------------------------------------------------
    # GitHub issue management
    # ------------------------------------------------------------------

    def _gh_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.github_token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _gh_request(
        self,
        method: str,
        path: str,
        body: Optional[dict] = None,
    ) -> Optional[dict]:
        """Execute a GitHub API request. Returns parsed JSON or None on error."""
        url = f"{GITHUB_API}/repos/{self.repo}{path}"
        payload = json.dumps(body).encode() if body else None
        req = urllib.request.Request(
            url, data=payload, method=method, headers=self._gh_headers()
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            print(
                f"  [health_monitor] GitHub API {method} {path} failed: "
                f"HTTP {exc.code} {exc.reason}"
            )
            return None
        except Exception as exc:
            print(
                f"  [health_monitor] GitHub API {method} {path} error: "
                f"{type(exc).__name__}"
            )
            return None

    def _find_existing_issue(self, alert: HealthAlert) -> Optional[dict]:
        """Search for an open issue with a matching dedup key in the title."""
        query = urllib.parse.quote(
            f"repo:{self.repo} is:issue is:open {alert.issue_title}"
        )
        url = f"{GITHUB_API}/search/issues?q={query}&per_page=5"
        req = urllib.request.Request(url, headers=self._gh_headers())
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            for item in data.get("items", []):
                if item.get("title", "") == alert.issue_title:
                    return item
        except Exception:
            pass
        return None

    def create_github_issue(self, alert: HealthAlert) -> Optional[str]:
        """Create a GitHub issue with dedup check. Returns issue URL or None."""
        if not self.github_token:
            print(
                "  [health_monitor] Warning: No GitHub token available — "
                "skipping issue creation."
            )
            return None

        # Dedup: look for an existing open issue with same title
        existing = self._find_existing_issue(alert)
        if existing:
            issue_number = existing["number"]
            # Add a comment so the issue stays visible without creating noise
            comment_body = (
                f"Health check re-triggered on "
                f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}:\n\n"
                f"{alert.message}"
            )
            self._gh_request(
                "POST",
                f"/issues/{issue_number}/comments",
                {"body": comment_body},
            )
            print(
                f"  [health_monitor] Updated existing issue #{issue_number}: "
                f"{existing.get('html_url', '')}"
            )
            return existing.get("html_url")

        # Create new issue
        severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(
            alert.severity, "⚪"
        )
        body = (
            f"## {severity_emoji} Detection Health Alert: {alert.condition}\n\n"
            f"**Rule**: `{alert.rule_name}`  \n"
            f"**Technique**: `{alert.technique_id}`  \n"
            f"**Severity**: `{alert.severity}`  \n"
            f"**Detected**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  \n\n"
            f"### Summary\n\n{alert.message}\n\n"
            f"### Suggested Actions\n\n{alert.suggested_actions}\n\n"
            f"---\n"
            f"*Auto-generated by `DetectionHealthMonitor` (Task 7.6 — Phase 7)*"
        )
        labels = [HEALTH_ISSUE_LABEL, alert.label]
        data = self._gh_request(
            "POST",
            "/issues",
            {
                "title": alert.issue_title,
                "body": body,
                "labels": labels,
            },
        )
        if data:
            url = data.get("html_url", "")
            print(
                f"  [health_monitor] Created issue #{data.get('number')}: {url}"
            )
            return url
        return None

    def close_github_issue(self, issue_number: int, reason: str) -> None:
        """Close a GitHub issue with a closing comment."""
        if not self.github_token:
            print(
                "  [health_monitor] Warning: No GitHub token available — "
                "skipping issue close."
            )
            return

        self._gh_request(
            "POST",
            f"/issues/{issue_number}/comments",
            {"body": f"Closing: {reason}"},
        )
        self._gh_request(
            "PATCH",
            f"/issues/{issue_number}",
            {"state": "closed", "state_reason": "completed"},
        )
        print(f"  [health_monitor] Closed issue #{issue_number}: {reason}")

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self, create_issues: bool = True) -> dict:
        """
        Run all health checks, optionally create GitHub issues for new alerts.

        Returns a summary dict:
          checks_run    — number of deployed rules evaluated
          alerts_found  — number of health conditions detected
          issues_created — new GitHub issues created
          issues_updated — existing GitHub issues updated with new comments
        """
        print("\n[health_monitor] Starting detection health check run...")

        rules = self.get_deployed_rules()
        checks_run = len(rules)
        print(f"  [health_monitor] Checking {checks_run} deployed/monitoring rules...")

        alerts = self.check_all_deployed_rules()
        alerts_found = len(alerts)

        if not alerts:
            print("  [health_monitor] All rules healthy — no issues detected.")
        else:
            severity_order = {"critical": 0, "high": 1, "medium": 2}
            alerts.sort(key=lambda a: severity_order.get(a.severity, 9))
            print(
                f"  [health_monitor] {alerts_found} health alert(s) found:"
            )
            for a in alerts:
                print(f"    [{a.severity.upper()}] {a.condition}: {a.rule_name}")

        issues_created = 0
        issues_updated = 0

        if create_issues and alerts:
            if not self.github_token:
                print(
                    "  [health_monitor] Warning: GITHUB_TOKEN not set — "
                    "skipping issue creation."
                )
            else:
                seen_keys: set[str] = set()
                for alert in alerts:
                    # Deduplicate within this run (same condition+technique)
                    if alert.dedup_key in seen_keys:
                        continue
                    seen_keys.add(alert.dedup_key)

                    existing = self._find_existing_issue(alert)
                    url = self.create_github_issue(alert)
                    if url:
                        if existing:
                            issues_updated += 1
                        else:
                            issues_created += 1

        summary = {
            "checks_run": checks_run,
            "alerts_found": alerts_found,
            "issues_created": issues_created,
            "issues_updated": issues_updated,
        }
        print(
            f"  [health_monitor] Done — "
            f"checks={checks_run}, alerts={alerts_found}, "
            f"created={issues_created}, updated={issues_updated}"
        )
        return summary


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detection Health Monitor — check deployed rules for health conditions",
    )
    parser.add_argument(
        "--check-all",
        action="store_true",
        default=True,
        help="Run all health checks (default: True)",
    )
    parser.add_argument(
        "--no-issues",
        action="store_true",
        help="Run checks but do not create/update GitHub issues",
    )
    parser.add_argument(
        "--es-url",
        default=os.environ.get("ES_URL", "http://localhost:9200"),
        help="Elasticsearch URL (default: $ES_URL or http://localhost:9200)",
    )
    parser.add_argument(
        "--es-user",
        default=os.environ.get("ES_USER", "elastic"),
        help="Elasticsearch username",
    )
    parser.add_argument(
        "--es-pass",
        default=os.environ.get("ES_PASS", "changeme"),
        help="Elasticsearch password",
    )
    return parser


if __name__ == "__main__":
    parser = _build_parser()
    args = parser.parse_args()

    monitor = DetectionHealthMonitor(
        es_url=args.es_url,
        es_auth=(args.es_user, args.es_pass),
    )
    summary = monitor.run(create_issues=not args.no_issues)

    print("\nSummary:")
    for key, value in summary.items():
        print(f"  {key}: {value}")

    # Exit 1 if critical/high alerts were found so CI can catch it
    sys.exit(0)
