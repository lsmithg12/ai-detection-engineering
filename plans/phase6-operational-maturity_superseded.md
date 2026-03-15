# Phase 6: Operational Maturity

**Status**: NOT STARTED
**Priority**: MEDIUM
**Estimated effort**: 8-12 hours (multi-session)
**Dependencies**: Phase 1 (DONE), Phase 2 (DONE). Phase 4 (quality upgrades) helps.
**Branch**: `infra/phase6-ops-maturity`

---

## Context

The lab currently operates in a "build and deploy" mode. This phase adds production-grade
operational capabilities: dashboards, regression testing, performance metrics, and SLA tracking.

## Tasks

### Task 6.1: Detection Health Dashboard (Kibana)

Create a Kibana dashboard showing detection fleet health at a glance.

**Panels**:

1. **Detection Coverage Summary** (Metric)
   - Total detections: X
   - Deployed: Y
   - Coverage %: Z

2. **Alert Volume by Rule** (Bar chart, last 24h)
   ```json
   {
     "aggs": {
       "by_rule": {
         "terms": { "field": "kibana.alert.rule.name", "size": 30 },
         "aggs": {
           "by_status": { "terms": { "field": "kibana.alert.workflow_status" }}
         }
       }
     }
   }
   ```

3. **F1 Score Trend** (Line chart over time)
   - Data source: `monitoring/metrics/*.jsonl`
   - X: date, Y: F1 score, Series: technique_id

4. **Detection State Distribution** (Donut chart)
   - AUTHORED / VALIDATED / DEPLOYED / MONITORING

5. **Recent Quality Actions** (Table)
   - Technique, action (HEALTHY/TUNE/REVIEW/RETIRE), date, notes

6. **Data Source Status** (Status map)
   - Green: available, Yellow: partial, Red: gap

**Steps**:
1. Create dashboard JSON export: `monitoring/dashboards/detection-health.ndjson`
2. Add import step to `setup.sh`: `curl POST ${KIBANA_URL}/api/saved_objects/_import`
3. Create corresponding Splunk dashboard XML if Splunk is running

### Task 6.2: Automated Regression Testing

Run detection validation on every PR that modifies a rule.

**New workflow**: `.github/workflows/regression-test.yml`
```yaml
name: Regression Test
on:
  pull_request:
    paths: ['detections/**']
jobs:
  regression:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
      - run: pip install pyyaml
      - run: |
          # Find changed detection files
          changed=$(git diff --name-only ${{ github.event.pull_request.base.sha }} HEAD -- 'detections/**/*.yml')
          for file in $changed; do
            technique=$(basename "$file" .yml)
            # Validate Sigma syntax
            sigma check "$file" || exit 1
            # Run local validation against scenario
            python3 autonomous/orchestration/validate_rule.py "$file" "tests/true_positives/${technique}_tp.json" "tests/true_negatives/${technique}_tn.json"
          done
```

**Steps**:
1. Extract validation logic into standalone `validate_rule.py` (can reuse
   `validation.validate_against_elasticsearch()` from Phase 2 when ES is available,
   or `blue_team_agent.validate_detection()` for CI without ES)
2. Accept: Sigma rule path, TP test path, TN test path
3. Output: PASS/FAIL with F1 score and validation method used
4. Fail the PR if F1 drops below previous value (regression)
5. Post F1 results as PR comment including validation method

### Task 6.3: Pipeline Performance Metrics

Track how the autonomous pipeline performs over time.

**Metrics to track** (`monitoring/pipeline-metrics.jsonl`):
```jsonl
{
  "date": "2026-03-13",
  "run_type": "full",
  "agents_run": ["intel", "red-team", "blue-team", "quality"],
  "duration_minutes": 45,
  "tokens_used": 67600,
  "detections_processed": 5,
  "new_detections": 2,
  "retries": 3,
  "failures": 0,
  "f1_scores": {"T1055.001": 0.95, "T1046": 0.85},
  "coverage_before": 0.43,
  "coverage_after": 0.48
}
```

**Steps**:
1. Modify `agent_runner.py` to emit pipeline metrics after each run
2. Include: duration, token cost, detections processed, success/failure counts
3. Create `monitoring/reports/` monthly rollup script
4. Add `make pipeline-stats` target to Makefile

### Task 6.4: Alert-on-Alert (Detection Health Monitoring)

Detect when a deployed detection stops working or FP rate spikes.

**Implementation**:
1. **Detection Silence Alert**: If a deployed detection produces 0 alerts for 7+ days, create GitHub issue
2. **FP Spike Alert**: If FP rate jumps >10% in 24h, create GitHub issue

**Steps**:
1. Quality agent checks alert volumes during daily run
2. Compare to 7-day rolling average
3. If silence detected: `[Alert] Detection <name> silent for <N> days — verify data source`
4. If FP spike: `[Alert] Detection <name> FP rate spiked to <X>% — investigate`

### Task 6.5: SLA Tracking (Intel-to-Deploy Time)

Measure how quickly the pipeline converts intel to deployed detection.

**Metrics**:
- **Time to Author**: `requested_date → authored_date`
- **Time to Validate**: `authored_date → validated_date`
- **Time to Deploy**: `validated_date → deployed_date`
- **End-to-End**: `requested_date → deployed_date`

**Steps**:
1. Parse changelog from each detection request YAML
2. Extract timestamps for each state transition
3. Calculate durations
4. Generate SLA report in `monitoring/reports/sla-{month}.md`:
   ```
   | Technique | Request → Author | Author → Validate | Validate → Deploy | Total |
   |-----------|-----------------|-------------------|-------------------|-------|
   | T1059.001 | 2h              | 1h                | 24h (PR review)   | 27h   |
   | T1547.001 | 3h              | 2h                | 48h               | 53h   |
   | Average   | 2.5h            | 1.5h              | 36h               | 40h   |
   ```
5. Track averages over time — pipeline should get faster as agents improve

### Task 6.6: Makefile Enhancements

Add operational targets to the Makefile.

```makefile
# Detection validation
validate-rules:
	@echo "Validating all Sigma rules..."
	@find detections/ -name "*.yml" -not -path "*/compiled/*" | while read f; do \
		sigma check "$$f" 2>&1 | grep -q "error" && echo "FAIL: $$f" || echo "OK: $$f"; \
	done

# Coverage summary
coverage:
	@echo "Detection Coverage:"
	@echo "  Authored: $$(find detections/ -name '*.yml' -not -path '*/compiled/*' | wc -l)"
	@echo "  Compiled: $$(find detections/ -path '*/compiled/*' | wc -l)"
	@echo "  Requests: $$(ls autonomous/detection-requests/*.yml 2>/dev/null | grep -v template | wc -l)"

# Pipeline stats
pipeline-stats:
	@python3 -c "import json; \
		lines = open('autonomous/budget-log.jsonl').readlines(); \
		total = sum(json.loads(l).get('estimated_tokens',0) for l in lines); \
		print(f'Total tokens: {total:,}'); \
		print(f'Total runs: {len(lines)}')"

# Clean stale branches
clean-branches:
	@git branch --merged main | grep -v main | xargs -r git branch -d
	@echo "Cleaned merged branches"
```

---

## Verification Checklist

- [ ] Kibana dashboard importable via `setup.sh`
- [ ] Regression test workflow runs on detection PRs
- [ ] `validate_rule.py` works standalone (not tied to agent)
- [ ] Pipeline metrics logged after each agent run
- [ ] Quality agent creates issues for silent/FP-spiking detections
- [ ] SLA report generated for all deployed detections
- [ ] Makefile has `validate-rules`, `coverage`, `pipeline-stats` targets

---

## Commit Strategy

1. `feat(monitoring): add Kibana detection health dashboard`
2. `feat(ci): add regression test workflow for detection PRs`
3. `refactor(validation): extract validate_rule.py as standalone tool`
4. `feat(monitoring): pipeline performance metrics tracking`
5. `feat(quality): alert-on-alert for silent/FP-spiking detections`
6. `docs(monitoring): add SLA tracking report`
7. `chore(makefile): add validate-rules, coverage, pipeline-stats targets`
