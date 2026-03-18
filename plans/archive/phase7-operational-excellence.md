# Phase 7: Operational Excellence

**Status**: NOT STARTED
**Priority**: HIGH
**Estimated effort**: 12-16 hours (multi-session)
**Dependencies**: Phase 4 (Scalable Architecture Foundation — coordinator, tuning agent) should be complete. Phase 6 (Detection Content at Scale — continuous validation) recommended.
**Branch**: `infra/phase7-operational-excellence`

---

## Goal

Transform the detection platform from "build and deploy" to "build, deploy, measure, and improve." This phase adds the operational feedback loops, dashboards, SLAs, and regression testing that separate a lab from a production detection program.

## Why This Matters

Detection engineering without operations is like shipping code without monitoring. In real SOCs:
- Detections that fire 0 alerts for 7+ days are probably broken
- FP rate that climbs 10% means something changed in the environment
- Mean-time-to-detect (MTTD) is an SLA that stakeholders measure
- Analyst feedback ("this alert was useless") must feed back into tuning
- Rule changes that degrade F1 score must be caught before production

Without these feedback loops, detection quality degrades over time. Phases 4-6 built a scalable, multi-threat-actor platform with rich content and data engineering. Phase 7 ensures that platform stays healthy and continuously improves by closing the loop between deployment and authoring.

## What Phases 4-6 Unlock

Phase 7 builds on the foundation laid by the preceding phases:
- **Phase 4 (Scalable Architecture Foundation)**: The coordinator agent and refactored agent system provide the orchestration backbone. The tuning agent (from Phase 4) is the primary consumer of feedback data and health alerts generated here.
- **Phase 5 (Data Engineering at Scale)**: Multi-platform simulation data and data quality scoring feed directly into dashboard panels and SLA metrics. Data quality issues surface as health alerts.
- **Phase 6 (Detection Content at Scale)**: Content packs, EQL rules, threshold rules, and evasion testing results all need operational monitoring. The continuous validation framework from Phase 6 provides the regression baseline.

---

## Tasks

### Task 7.1: Detection Health Dashboard (4h)

Build a Kibana dashboard showing detection fleet health at a glance.

**Deliverables:**
- `monitoring/dashboards/detection-health.ndjson` -- Kibana saved objects (import via API)
- `monitoring/dashboards/detection-health.xml` -- Splunk dashboard XML equivalent
- `monitoring/dashboards/ingest-metrics.py` -- Script to push metrics into `.detection-metrics-*` index

**Dashboard Panels:**

1. **Fleet Overview** (Metric + Pie chart)
   - Total detections authored, deployed count, coverage % by tactic
   - State distribution: AUTHORED / VALIDATED / DEPLOYED / MONITORING
   - Data source: aggregation across `detections/**/*.yml` metadata + detection request YAMLs

2. **Alert Volume by Rule** (Bar chart, last 24h)
   ```json
   {
     "index": ".alerts-security.alerts-default",
     "aggs": {
       "by_rule": {
         "terms": { "field": "kibana.alert.rule.name", "size": 50 },
         "aggs": {
           "by_status": { "terms": { "field": "kibana.alert.workflow_status" } }
         }
       }
     }
   }
   ```

3. **F1 Score Distribution** (Histogram)
   - Current F1 scores across all validated rules
   - Color bands: green (>=0.90), yellow (0.75-0.89), red (<0.75)
   - Data source: `tests/results/*.json` -> indexed into `.detection-metrics-*`

4. **Detection State Flow** (Sankey or state diagram)
   - REQUESTED -> AUTHORED -> VALIDATED -> DEPLOYED -> MONITORING
   - Shows throughput: how many detections moved between states in last 30 days
   - Data source: detection request YAML changelog timestamps

5. **Data Source Health** (Status table)
   - Each data source row: name, freshness (last event timestamp), completeness (% of expected fields present), volume (events/day)
   - Green/yellow/red status based on thresholds
   - Data source: `gaps/data-sources/*.yml` + ES index stats

6. **Recent Tuning Actions** (Table, last 10)
   - Columns: technique_id, rule_name, action, date, analyst, notes
   - Data source: `tuning/changelog/*.md` parsed into structured records

7. **Coverage by Tactic** (Radar chart)
   - MITRE tactic on each axis, coverage % as radius
   - Overlay: current vs target (Phase 6 goals)
   - Data source: `coverage/attack-matrix.md` parsed

8. **SLA Metrics** (Line chart, trending over time)
   - Mean time from REQUESTED to MONITORING per month
   - Trend line showing whether pipeline is getting faster
   - Data source: SLA module output (Task 7.4)

**Index Setup:**
```json
{
  "index_patterns": [".detection-metrics-*"],
  "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
  "mappings": {
    "properties": {
      "@timestamp": { "type": "date" },
      "metric_type": { "type": "keyword" },
      "technique_id": { "type": "keyword" },
      "rule_name": { "type": "keyword" },
      "f1_score": { "type": "float" },
      "alert_count_24h": { "type": "integer" },
      "fp_rate": { "type": "float" },
      "state": { "type": "keyword" },
      "validation_method": { "type": "keyword" },
      "tactic": { "type": "keyword" }
    }
  }
}
```

**Daily Metric Ingest:**
The quality agent (or a standalone cron job) pushes metrics to ES daily:
1. Parse all `tests/results/*.json` for F1 scores and validation metadata
2. Parse all detection request YAMLs for state and alert volumes
3. Parse `coverage/attack-matrix.md` for coverage percentages
4. Bulk index into `.detection-metrics-YYYY.MM` with `@timestamp`

**Implementation Steps:**
1. Create `.detection-metrics-*` index template in ES
2. Write `monitoring/dashboards/ingest-metrics.py` to collect and index metrics
3. Build Kibana dashboard with all 8 panels, export as NDJSON
4. Build equivalent Splunk dashboard XML (if Splunk active)
5. Add dashboard import to `setup.sh`: `curl -X POST "${KIBANA_URL}/api/saved_objects/_import" --form file=@monitoring/dashboards/detection-health.ndjson`
6. Schedule daily metric ingest via quality agent or `make dashboard-update`

---

### Task 7.2: Analyst Feedback Loop (3h)

Enable analysts to mark alerts as true/false positive, feeding back into auto-tuning.

**Deliverables:**
- `autonomous/orchestration/feedback.py` -- Feedback ingestion and aggregation module
- `autonomous/orchestration/feedback_schema.py` -- Feedback data models
- CLI extension: `python orchestration/cli.py feedback`

**Feedback Mechanism (implement all three, use whichever fits the workflow):**

**Option A: CLI Feedback (always available)**
```bash
python orchestration/cli.py feedback T1055.001 \
  --verdict fp \
  --event-id "abc123" \
  --reason "legitimate AV memory scan" \
  --analyst "lsmith"
```

**Option B: ES Alert Labeling (when Elastic is running)**
Add `analyst.verdict` field to alert documents:
```json
{
  "script": {
    "source": "ctx._source.analyst = params.analyst",
    "params": {
      "analyst": {
        "verdict": "false_positive",
        "analyst_name": "lsmith",
        "timestamp": "2026-03-15T10:30:00Z",
        "reason": "legitimate AV memory scan",
        "technique_id": "T1055.001"
      }
    }
  }
}
```

**Option C: Webhook Endpoint (for Kibana alert actions)**
- Lightweight Flask/FastAPI endpoint receiving POST with verdict payload
- Stores feedback in `monitoring/feedback/YYYY-MM-DD.jsonl`
- Only needed if running Kibana alert actions (optional for lab)

**Feedback Data Model:**
```python
@dataclass
class AnalystFeedback:
    technique_id: str
    rule_name: str
    verdict: str  # "true_positive", "false_positive", "needs_investigation"
    event_id: str | None
    reason: str
    analyst: str
    timestamp: datetime
    alert_hash: str  # Dedup key
```

**Feedback Aggregation:**
Roll up TP/FP verdicts per rule per day into `monitoring/feedback/rollup.jsonl`:
```jsonl
{"date": "2026-03-15", "technique_id": "T1055.001", "rule_name": "Fawkes CreateRemoteThread Injection", "tp_count": 5, "fp_count": 2, "ni_count": 1, "fp_rate": 0.25}
```

**Auto-Tuning Trigger:**
When 7-day rolling FP rate exceeds 10% for any rule:
1. Feedback module flags the rule to tuning agent
2. Tuning agent (Phase 4) reads the FP events, identifies common patterns
3. Tuning agent generates exclusion suggestion
4. Auto-creates tuning PR: `tuning/YYYY-MM-DD-T<technique>-fp-reduction`
5. PR includes: before/after FP rate, exclusion justification, re-validation results

**Guardrails:**
- Max 3 auto-generated exclusions per rule before requiring human review
- Auto-exclusions must be validated (re-run F1, confirm no TP loss)
- FP verdicts require a `reason` field (no blind dismissals)
- All feedback is append-only (audit trail)

**Implementation Steps:**
1. Write `feedback.py` with `record_feedback()`, `get_rule_feedback()`, `compute_fp_rate()`, `check_tuning_triggers()`
2. Add `feedback` subcommand to `cli.py`
3. Write feedback rollup aggregation (daily cron or quality agent integration)
4. Wire tuning trigger to tuning agent (Phase 4 dependency)
5. Add feedback-based tests: verify rollup math, dedup logic, trigger thresholds

---

### Task 7.3: Automated Regression Testing (3h)

CI gate that prevents detection quality degradation on every PR.

**Deliverables:**
- `.github/workflows/regression-test.yml` -- New GitHub Actions workflow
- `autonomous/orchestration/regression.py` -- Regression comparison logic (standalone, no agent dependency)
- `tests/results/<technique>_regression.json` -- Historical regression records

**Workflow Trigger:**
```yaml
name: Detection Regression Test
on:
  pull_request:
    paths: ['detections/**']

jobs:
  regression:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0  # Full history for base comparison
      - uses: actions/setup-python@v6
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: pip install pyyaml
      - name: Find changed detections
        id: changes
        run: |
          changed=$(git diff --name-only ${{ github.event.pull_request.base.sha }} HEAD -- 'detections/**/*.yml' | grep -v '/compiled/')
          echo "files=$changed" >> $GITHUB_OUTPUT
      - name: Run regression check
        run: python autonomous/orchestration/regression.py --files "${{ steps.changes.outputs.files }}"
      - name: Post results as PR comment
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('tests/results/regression-report.md', 'utf8');
            github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: report
            });
```

**Regression Logic (`regression.py`):**
```python
def check_regression(technique_id: str) -> RegressionResult:
    """Compare current F1 against previous F1 for a detection."""
    current_result = load_result(f"tests/results/{technique_id}.json")
    previous_f1 = current_result.get("f1_score", 0)

    # Re-validate using local JSON (CI has no ES)
    new_f1 = validate_detection_local(
        rule_path=f"detections/.../{technique_id}.yml",
        tp_path=f"tests/true_positives/{technique_id}_tp.json",
        tn_path=f"tests/true_negatives/{technique_id}_tn.json"
    )

    delta = new_f1 - previous_f1
    if delta < -0.10:
        return RegressionResult(status="FAIL", delta=delta, message=f"F1 dropped {abs(delta):.2f}")
    elif delta < -0.05:
        return RegressionResult(status="WARN", delta=delta, message=f"F1 decreased {abs(delta):.2f}")
    else:
        return RegressionResult(status="PASS", delta=delta, message="No regression detected")
```

**Regression Report Format (posted as PR comment):**
```markdown
## Detection Regression Test Results

| Rule | Previous F1 | Current F1 | Delta | Status |
|------|------------|------------|-------|--------|
| T1059.001 | 0.95 | 0.95 | 0.00 | PASS |
| T1055.001 | 0.90 | 0.82 | -0.08 | WARN |
| T1547.001 | 0.85 | 0.70 | -0.15 | FAIL |

**Overall: FAIL** -- 1 rule regressed beyond threshold (-0.10)
```

**Integration with Security Gate:**
- Security agent (`.github/workflows/security-gate.yml`) already runs on PRs
- Add regression check as additional gate: both must pass for PR to be mergeable
- Regression test runs independently (no Claude API needed -- pure local validation)

**Historical Tracking:**
After each successful merge, store regression snapshot:
```json
{
  "technique_id": "T1055.001",
  "timestamp": "2026-03-15T10:00:00Z",
  "f1_score": 0.90,
  "commit_sha": "abc1234",
  "pr_number": 60,
  "validation_method": "local_json"
}
```

**Implementation Steps:**
1. Write `regression.py` with `check_regression()`, `generate_report()`, `load_baseline()`
2. Create `.github/workflows/regression-test.yml`
3. Add regression report template (markdown)
4. Test with a simulated rule change that degrades F1
5. Verify PR comment posting via GitHub Actions
6. Document how to update baselines after intentional F1 changes

---

### Task 7.4: SLA Tracking (2h)

Measure the time from threat intel to deployed detection across the full pipeline.

**Deliverables:**
- `autonomous/orchestration/sla.py` -- SLA measurement module
- CLI extension: `python orchestration/cli.py sla`
- Monthly reports: `monitoring/reports/sla-YYYY-MM.md`

**Metrics Tracked:**

| Metric | Measurement | Source |
|--------|------------|--------|
| Time to Author | REQUESTED -> AUTHORED | Detection request YAML `changelog` timestamps |
| Time to Validate | AUTHORED -> VALIDATED | Detection request YAML `changelog` timestamps |
| Time to Deploy | VALIDATED -> DEPLOYED | Detection request YAML `changelog` timestamps |
| End-to-End | REQUESTED -> MONITORING | Full lifecycle duration |
| Mean Time to Detect (MTTD) | Attack event timestamp -> alert timestamp | Simulation validation data (from Phase 6 continuous validation) |

**SLA Targets:**

| Priority | End-to-End Target | Rationale |
|----------|------------------|-----------|
| Critical | < 48 hours | Active exploitation, Fawkes core capability |
| High | < 1 week | Multiple intel sources, coverage gap |
| Medium | < 2 weeks | Single source, existing partial coverage |
| Low | < 1 month | Nice-to-have, no active threat |

**CLI Interface:**
```bash
# Current month SLA summary
python orchestration/cli.py sla

# Specific month
python orchestration/cli.py sla --month 2026-03

# SLA for a specific technique
python orchestration/cli.py sla --technique T1055.001

# Output as JSON (for dashboard ingest)
python orchestration/cli.py sla --format json
```

**Monthly Report Format (`monitoring/reports/sla-2026-03.md`):**
```markdown
# SLA Report: March 2026

## Summary
- Detections completed: 5
- Mean end-to-end: 34h
- SLA compliance: 4/5 (80%)
- SLA breach: T1047 (72h, target was 48h -- critical priority)

## Detail

| Technique | Priority | Request | Author | Validate | Deploy | Total | SLA |
|-----------|----------|---------|--------|----------|--------|-------|-----|
| T1055.004 | Critical | 2h | 3h | 1h | 24h | 30h | MET |
| T1087.002 | High | 4h | 6h | 2h | 48h | 60h | MET |
| T1047 | Critical | 8h | 12h | 4h | 48h | 72h | BREACH |

## Trends
- Average end-to-end trending DOWN (improvement): 45h -> 34h
- Bottleneck: Time to Deploy (PR review wait time)
- Recommendation: Auto-deploy VALIDATED rules with F1 >= 0.95 to reduce deploy time
```

**Implementation Steps:**
1. Write `sla.py` with `calculate_sla()`, `generate_monthly_report()`, `check_breaches()`
2. Parse detection request YAML changelog for state transition timestamps
3. Add `sla` subcommand to `cli.py`
4. Generate first historical report from existing detection requests
5. Wire SLA breach notifications into health monitor (Task 7.6)

---

### Task 7.5: Pipeline Performance Metrics (2h)

Track agent pipeline throughput, cost, and effectiveness over time.

**Deliverables:**
- `monitoring/pipeline-metrics.jsonl` -- Per-run metrics log (append-only)
- `monitoring/reports/pipeline-YYYY-MM.md` -- Monthly rollup reports
- Integration with `agent_runner.py` for automatic metric capture

**Metrics Per Agent Run:**
```jsonl
{
  "timestamp": "2026-03-15T10:00:00Z",
  "run_id": "run-20260315-001",
  "agent": "blue-team",
  "run_type": "single",
  "duration_minutes": 12.5,
  "tokens_estimated": 15200,
  "detections_processed": 3,
  "state_transitions": {
    "AUTHORED_to_VALIDATED": 2,
    "VALIDATED_to_DEPLOYED": 1
  },
  "errors": 0,
  "retries": 1,
  "f1_scores": {
    "T1055.001": {"before": 0.85, "after": 0.92},
    "T1059.001": {"before": 0.90, "after": 0.90}
  },
  "coverage_delta": 0.02
}
```

**Monthly Rollup Report (`monitoring/reports/pipeline-2026-03.md`):**
```markdown
# Pipeline Performance: March 2026

## Agent Run Summary
| Agent | Runs | Total Duration | Avg Duration | Errors | Retries |
|-------|------|---------------|-------------|--------|---------|
| Intel | 15 | 3h 20m | 13m | 0 | 2 |
| Red-Team | 12 | 4h 10m | 21m | 1 | 5 |
| Blue-Team | 12 | 5h 30m | 27m | 2 | 8 |
| Quality | 30 | 2h 00m | 4m | 0 | 0 |
| Security | 8 | 1h 20m | 10m | 0 | 1 |
| **Total** | **77** | **16h 20m** | **12m** | **3** | **16** |

## Token Usage
- Total estimated tokens: 482,000
- Cost estimate (at $3/MTok input, $15/MTok output): ~$4.80
- Most expensive agent: Blue-Team (45% of tokens)

## Effectiveness
- Detections moved to VALIDATED: 8
- Detections moved to DEPLOYED: 5
- F1 improvements: 6 rules improved, 0 regressed
- Coverage change: 62% -> 68%
```

**Budget Tracking:**
```python
MONTHLY_TOKEN_BUDGET = {
    "intel": 100_000,
    "red-team": 150_000,
    "blue-team": 200_000,
    "quality": 50_000,
    "security": 50_000,
}
```

If an agent exceeds 80% of monthly budget, log a warning. If it exceeds 100%, pause non-critical runs and flag for human review.

**Implementation Steps:**
1. Add metric emission hooks to `agent_runner.py` (start time, end time, token estimate, outcomes)
2. Write metrics to `monitoring/pipeline-metrics.jsonl` after each run
3. Create monthly rollup script: `monitoring/generate-pipeline-report.py`
4. Add `make pipeline-stats` target to Makefile
5. Add budget tracking with threshold warnings

---

### Task 7.6: Alert-on-Alert (Detection Health Monitoring) (2h)

Automatically detect when deployed detections go unhealthy and create actionable issues.

**Deliverables:**
- `autonomous/orchestration/health_monitor.py` -- Detection health monitor
- Integration with quality agent daily run
- GitHub Issue creation for health conditions

**Health Conditions:**

| Condition | Threshold | Severity | Action |
|-----------|-----------|----------|--------|
| Silent rule | 0 alerts for 7+ days | High | GitHub Issue (label: `detection-health`) |
| FP spike | FP rate jumps >10% in 24h | High | GitHub Issue (label: `needs-tuning`) |
| Alert flood | >100 alerts/day from single rule | Medium | GitHub Issue (label: `needs-tuning`) |
| Schema break | Rule fails validation that previously passed | Critical | GitHub Issue (label: `data-source-gap`) |
| F1 decay | F1 dropped >0.10 from deployment baseline | High | GitHub Issue (label: `regression`) |

**Health Monitor Logic:**
```python
class DetectionHealthMonitor:
    def check_all_deployed_rules(self) -> list[HealthAlert]:
        """Run all health checks against deployed detections."""
        alerts = []
        for rule in get_deployed_rules():
            alerts.extend(self.check_silence(rule))
            alerts.extend(self.check_fp_spike(rule))
            alerts.extend(self.check_flood(rule))
            alerts.extend(self.check_schema(rule))
            alerts.extend(self.check_f1_decay(rule))
        return alerts

    def check_silence(self, rule) -> list[HealthAlert]:
        """Check if rule has produced 0 alerts for 7+ days."""
        alert_count = get_alert_count(rule.name, days=7)
        if alert_count == 0 and rule.deployed_days >= 7:
            return [HealthAlert(
                condition="SILENT_RULE",
                rule_name=rule.name,
                technique_id=rule.technique_id,
                message=f"Rule has produced 0 alerts for {rule.deployed_days} days. "
                        f"Verify data source is still flowing and rule query is valid.",
                severity="high"
            )]
        return []
```

**GitHub Issue Creation:**
```python
def create_health_issue(alert: HealthAlert):
    """Create GitHub issue for health alert, with dedup check."""
    # Check for existing open issue for same rule + condition
    existing = search_issues(
        query=f"[Health] {alert.rule_name} {alert.condition}",
        state="open"
    )
    if existing:
        # Add comment to existing issue instead of creating duplicate
        add_comment(existing[0], f"Condition still present as of {datetime.now()}")
        return

    create_issue(
        title=f"[Health] {alert.rule_name} -- {alert.condition}",
        body=f"## Detection Health Alert\n\n"
             f"**Rule**: {alert.rule_name}\n"
             f"**Technique**: {alert.technique_id}\n"
             f"**Condition**: {alert.condition}\n"
             f"**Severity**: {alert.severity}\n\n"
             f"### Details\n{alert.message}\n\n"
             f"### Suggested Actions\n{alert.suggested_actions}",
        labels=["detection-health", alert.label]
    )
```

**Auto-Close Logic:**
When the health monitor runs and a previously-flagged condition is resolved:
- Find the open issue for that rule + condition
- Add comment: "Condition resolved as of {date}. Alert count: {count}."
- Close the issue

**De-duplication:**
- Hash key: `{technique_id}:{condition}` (e.g., `T1055.001:SILENT_RULE`)
- Only one open issue per hash key at a time
- Resolved issues can re-open if condition recurs (create new issue)

**Implementation Steps:**
1. Write `health_monitor.py` with check methods for each condition
2. Add ES query helpers for alert count, FP rate, and schema validation
3. Integrate with quality agent daily run (or standalone cron)
4. Add GitHub Issue creation via GitHub MCP tools
5. Add de-duplication and auto-close logic
6. Test with simulated health conditions (manually set alert count to 0, inject FP spike)

---

## Makefile Targets

Add the following operational targets:

```makefile
# Dashboard metrics update
dashboard-update:
	@echo "Ingesting detection metrics into Elasticsearch..."
	@python3 monitoring/dashboards/ingest-metrics.py
	@echo "Done. View dashboard at $(KIBANA_URL)/app/dashboards"

# SLA report
sla:
	@cd autonomous && python3 orchestration/cli.py sla

# Pipeline stats
pipeline-stats:
	@python3 monitoring/generate-pipeline-report.py

# Health check
health-check:
	@cd autonomous && python3 orchestration/health_monitor.py --check-all

# Feedback
feedback:
	@echo "Usage: make feedback TECHNIQUE=T1055.001 VERDICT=fp REASON='legitimate AV scan'"
	@cd autonomous && python3 orchestration/cli.py feedback $(TECHNIQUE) --verdict $(VERDICT) --reason "$(REASON)"
```

---

## Validation Criteria

- [ ] Kibana dashboard importable via API and showing real metrics from `.detection-metrics-*`
- [ ] Splunk dashboard XML rendering equivalent panels (if Splunk active)
- [ ] Feedback mechanism accepting analyst verdicts via CLI (`cli.py feedback`)
- [ ] Feedback rollup computing per-rule FP rates correctly
- [ ] Auto-tuning trigger firing when 7-day FP rate exceeds 10%
- [ ] Regression test workflow running on PRs that modify `detections/**`
- [ ] Regression report posted as PR comment with pass/warn/fail status
- [ ] PR blocked when F1 drops > 0.10 (regression gate)
- [ ] SLA metrics calculated for all detection requests with changelog timestamps
- [ ] SLA breach detection working for critical/high priority techniques
- [ ] Monthly SLA report generated via `cli.py sla --month`
- [ ] Pipeline metrics logged to `monitoring/pipeline-metrics.jsonl` after each agent run
- [ ] Monthly pipeline report generated with token usage and cost estimates
- [ ] Health monitor detecting silent rules (7+ days, 0 alerts)
- [ ] Health monitor detecting FP spikes (>10% in 24h)
- [ ] Health monitor detecting alert floods (>100/day from single rule)
- [ ] Health monitor creating GitHub Issues with correct labels
- [ ] Health monitor de-duplicating issues (no duplicate issues for same condition)
- [ ] Health monitor auto-closing resolved issues
- [ ] Tuning agent (Phase 4) consuming feedback data to generate exclusion PRs

---

## Commit Strategy

Sequential commits recommended (each task is independently testable):

1. `feat(monitoring): create detection health dashboard with 8 panels + metric index`
2. `feat(feedback): add analyst feedback loop with CLI, aggregation, and auto-tuning trigger`
3. `feat(ci): add automated regression testing workflow for detection PRs`
4. `feat(monitoring): add SLA tracking module with CLI and monthly reports`
5. `feat(monitoring): add pipeline performance metrics and budget tracking`
6. `feat(monitoring): add detection health monitor with GitHub Issue creation`
7. `chore(makefile): add dashboard-update, sla, health-check, feedback targets`

---

## Architecture Diagram

```
                    +------------------+
                    |  Analyst Verdict  |
                    |  (CLI / Kibana)   |
                    +--------+---------+
                             |
                             v
+-------------+     +--------+---------+     +-----------------+
|  Detection  |     |  Feedback Module  |     |  Health Monitor |
|  Dashboard  |<----|  (feedback.py)    |---->|  (health_mon.py)|
+------+------+     +--------+---------+     +--------+--------+
       |                     |                         |
       |              +------v------+           +------v------+
       |              | FP Rate     |           | GitHub      |
       |              | Aggregation |           | Issues      |
       |              +------+------+           +------+------+
       |                     |                         |
       v                     v                         v
+------+------+     +--------+---------+     +---------+-------+
| .detection- |     |  Tuning Agent    |     |  Quality Agent  |
| metrics-*   |     |  (Phase 4)       |     |  (daily run)    |
| ES Index    |     |  Auto-exclusions |     |  Health checks  |
+-------------+     +------------------+     +-----------------+
       ^                     |
       |                     v
+------+------+     +--------+---------+
|  SLA Module |     |  Regression CI   |
|  (sla.py)   |     |  (GitHub Actions)|
+-------------+     +------------------+
```

This diagram shows the feedback loops: analyst verdicts flow into the feedback module, which feeds tuning decisions. The health monitor watches for broken detections and creates issues. The dashboard surfaces all metrics. The regression CI prevents quality degradation on every PR. The SLA module tracks pipeline throughput. Together, these components close the loop between deployment and continuous improvement.
