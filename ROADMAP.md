# Patronus Lab — Improvement Roadmap

Master plan for enhancing the AI Detection Engineering Lab from a single-threat-actor lab
to an enterprise-grade, scalable detection engineering platform.

**Last reviewed**: 2026-03-22
**Current state**: 42 authored rule files (35 Sigma + 3 EQL + 4 threshold), 16 MONITORING, 17 VALIDATED, 8 AUTHORED, 71 total detection requests tracked, 10 specialized agents + coordinator, 2 SIEMs active, Phases 1-7 complete
**Architecture redesign**: Phases 4-8 rebuilt around real-world scaling concerns (see `plans/architecture-scalable-detection-platform.md`)

---

## How to Use This File

Each phase links to a detailed plan in `plans/`. To start work on any phase:

```
Read ROADMAP.md for context, then read plans/<phase-file>.md for step-by-step instructions.
```

For the architectural vision behind the new phases:
```
Read plans/architecture-scalable-detection-platform.md for the full system design.
```

Phases 4-8 have dependencies noted in each plan. Phases 1-3 are complete and independent.

---

## Why the Redesign (Phases 4-8)

The original phases 4-7 were designed for a lab focused on one C2 agent (Fawkes). That doesn't
translate to how detection engineering works at enterprise scale. Real detection engineering is:

- **60% data engineering** — log source onboarding, schema mapping, data quality monitoring
- **20% content lifecycle** — authoring, testing, versioning, tuning, deprecating detections
- **15% threat intelligence** — multiple threat actors, campaigns, evolving TTPs
- **5% operational feedback** — analyst verdicts, SLA tracking, health dashboards

The redesigned phases address these proportions directly:

| Old Phase | Old Focus | New Phase | New Focus |
|-----------|----------|-----------|-----------|
| Phase 4: Agent Upgrades | Make 5 agents smarter | Phase 4: Scalable Architecture | 10 specialized agents, threat model registry, log source registry |
| Phase 5: Coverage Expansion | More Fawkes rules | Phase 5: Data Engineering | Multi-platform simulation, data quality, schema evolution |
| Phase 6: Operational Maturity | Dashboards | Phase 6: Detection Content | Content packs, EQL, threshold rules, evasion testing |
| Phase 7: Advanced Capabilities | Agent SDK, live C2 | Phase 7: Operational Excellence | Feedback loops, regression testing, SLAs, health monitoring |
| — | — | Phase 8: Advanced Capabilities | Agent SDK, live C2, behavioral analytics, marketplace |

---

## Phase 1: Detection Quality Remediation — COMPLETED

**Status**: COMPLETED — Merged to main via PR #52 (2026-03-13)

**Plan**: [plans/phase1-detection-quality.md](plans/phase1-detection-quality.md)

**Delivered**:
- Fixed T1046, T1562.006, T1569.002 (stuck at AUTHORED due to backslash + non-dict bugs)
- Rewrote T1562.001 AMSI bypass rule with path-based patterns
- Compiled Lucene + SPL for all 29 rules
- Split multi-event scenarios into single-event TP tests + integration/ kill chains
- Populated tuning changelog with audit trail
- Enriched all 29 result files with operational metadata
- Updated coverage/attack-matrix.md to reflect actual state

---

## Phase 2: SIEM-Based Validation — COMPLETED

**Status**: COMPLETED — Merged to main via PR #54 (2026-03-14)

**Plan**: [plans/phase2-siem-validation.md](plans/phase2-siem-validation.md)

**Delivered**:
- `validation.py` module (~280 lines) with `validate_against_elasticsearch()`
- Scenario JSON -> ES bulk ingest -> Lucene query -> F1 score
- Falls back to local JSON validation when ES offline (CI environments)
- Fixed critical template shadowing bug (ES composable template priority)
- Fixed `process.command_line` mapping (text -> keyword for wildcard queries)
- ILM policy for automatic validation index cleanup (1-hour safety net)
- SIEM query errors fed into retry-with-feedback loop
- Splunk validation permanently deferred (Elastic-only)

---

## Phase 3: Data Pipeline — Raw Logs through Cribl — COMPLETED

**Status**: COMPLETED (2026-03-14)

**Plan**: [plans/phase3-data-pipeline.md](plans/phase3-data-pipeline.md)

**Delivered**:
- `simulator/raw_events.py` — raw vendor event converter (Windows Event XML, Sysmon text)
- Cribl `cim_normalize` pipeline extended with regex parsers for raw events
- Full streaming validation path: raw events → Cribl HEC → normalize → ES → F1 score
- Structured data source gap tracking in `gaps/data-sources/` (YAML per technique)
- Intel agent tags detection requests with `data_source_requirements` field
- `cli.py data-sources` command to list gap status per technique

---

## Phase 4: Scalable Architecture Foundation — COMPLETED

**Status**: COMPLETED — Merged to main via PR #62 (2026-03-15)

**Plan**: [plans/phase4-scalable-architecture.md](plans/phase4-scalable-architecture.md)

**Architecture**: [plans/architecture-scalable-detection-platform.md](plans/architecture-scalable-detection-platform.md)

**Delivered**:
- **Threat model registry**: Pluggable YAML-based threat models (`threat-intel/models/`) — Fawkes, LockBit, Scattered Spider, generic schema
- **Log source registry**: Structured `data-sources/registry/` with health check specs, field mappings, volume estimates
- **Agent architecture refactor**: 5 monolithic → 10 specialized agents (31 files, 4,934 insertions):
  - `author_agent.py` (465 lines), `validation_agent.py` (693 lines), `coverage_agent.py` (1,056 lines)
  - `deployment_agent.py` (221 lines), `tuning_agent.py` (374 lines)
- **Coordinator**: `autonomous/orchestration/coordinator.py` — routes work by priority + state
- **CLI expansion**: `cli.py` extended with Phase 4 commands (+186 lines)
- **State management**: Schema-enforced YAML with SQLite-ready design

**State after Phase 4**: 5 → 10 agents, 3 threat models registered (Fawkes + 2 non-Fawkes), coordinator active

---

## Phase 5: Data Engineering at Scale — COMPLETED

**Status**: COMPLETED — Merged to main via PR #63 (2026-03-15)

**Plan**: [plans/phase5-data-engineering.md](plans/phase5-data-engineering.md)

**Delivered**:
- **Data quality monitoring engine**: Per-source health scoring (freshness, completeness, volume, schema compliance)
- **Multi-platform simulation**: Linux auditd, AWS CloudTrail, Zeek network, macOS unified log generators added to `simulator/`
- **Schema evolution management**: Versioned schema definitions in `gaps/data-sources/` with diff tool and detection impact analysis
- **Raw event converter expansion**: `simulator/raw_events.py` extended for Linux, CloudTrail, Zeek formats
- **Per-source Cribl pipelines**: Replaced monolithic `cim_normalize` with dynamic per-source routing in Cribl Stream
- **Automated gap analysis**: `feat(gaps)` — cross-references coverage gaps with source registry; auto-creates GitHub Issues for data source gaps
- **Security hardening**: Scanner false positives fixed, credentials scrubbed from simulation scenario files

**State after Phase 5**: Multi-platform simulation active, data quality scoring live, Cribl per-source routing deployed

---

## Phase 6: Detection Content at Scale — COMPLETED

**Status**: COMPLETED — Merged to main via PR #65 (2026-03-17)

**Plan**: [plans/phase6-detection-content.md](plans/phase6-detection-content.md)

**Delivered**:
- **Content pack framework**: 9 versioned packs with `pack.yml` + `CHANGELOG.md` (8 tactic-based + process-injection)
- **EQL rule support**: 3 new EQL rules (T1055 sequence, T1059+T1547 cross-tactic, T1087.002 discovery burst)
  - New validation module: `autonomous/orchestration/validation_eql.py`
  - New template: `templates/eql-template.yml`
- **Threshold rule support**: 4 new threshold rules (T1110.001 brute force, T1087.002 discovery burst, T1486 file encryption, T1489 mass service stop)
  - New validation module: `autonomous/orchestration/validation_threshold.py`
  - New template: `templates/threshold-template.yml`
- **Evasion resilience testing**: 5 evasion test cases for T1055.001, T1059.001, T1071.001, T1547.001 bypass variants
  - New module: `autonomous/orchestration/validation_evasion.py`
  - Test files in `tests/evasion/`
- **Continuous validation CI**: `.github/workflows/continuous-validation.yml` (7th workflow) — weekly re-validation + regression detection
- **Detection performance profiling**: `autonomous/orchestration/performance.py` — 3 scale tiers (10K/100K/1M events)
- **New Sigma rule**: T1055.004 APC injection (QueueUserAPC via Sysmon EID 8)
- **CLI extensions**: `pack list/validate/deploy` + `perf` commands in `cli.py`
- **Bugs found & fixed**: 5 bugs patched (f1_score naming, TP test structure, unused filter condition, wrong MITRE URL, wrong technique ID extraction in EQL validation)
- **New coverage**: T1055.004 (was gap) + Impact tactic (T1486 threshold + T1489) — 9 tactics total

**State after Phase 6**: 37 rules (30 Sigma + 3 EQL + 4 threshold), 14/21 Fawkes coverage (67%), 9 MITRE tactics

---

## Phase 7: Operational Excellence

**Status**: COMPLETED — Merged to main via PR #68 (2026-03-18)

**Plan**: [plans/phase7-operational-excellence.md](plans/phase7-operational-excellence.md)

**Goal**: Close the operational feedback loop — build, deploy, measure, improve. This separates a lab from a production detection program.

**Delivered**:
- **Detection health dashboards**: `monitoring/dashboards/detection-health.xml` (Kibana) + `monitoring/dashboards/ingest-metrics.py` (Splunk)
- **Analyst feedback loop**: `autonomous/orchestration/feedback.py` + `feedback_schema.py` — verdict capture (TP/FP/FN labels) stored in `monitoring/feedback/verdicts.jsonl`
- **Automated regression testing**: `autonomous/orchestration/regression.py` + `.github/workflows/regression-test.yml` — CI gate blocks PRs if F1 drops > 0.10
- **SLA tracking**: `autonomous/orchestration/sla.py` — time from REQUESTED to MONITORING per priority level, breach detection
- **Pipeline performance metrics**: `monitoring/generate-pipeline-report.py` — monthly pipeline + SLA reports in `monitoring/reports/`
- **Health monitor with alert-on-alert**: `autonomous/orchestration/health_monitor.py` — detects silent rules, FP spikes, alert floods; auto-creates GitHub Issues

**State after Phase 7**: 9 CI workflows (regression-test.yml added), feedback loop active, SLA tracking live, regression baseline established for 3 rules

---

## Phase 8: Advanced Capabilities (Priority: LOW — STRATEGIC)

**Status**: NOT STARTED
**Estimated effort**: 40+ hours (multi-week, capability-independent)
**Dependencies**: Phases 4-7 provide the foundation; each capability can start independently

**Plan**: [plans/phase8-advanced-capabilities.md](plans/phase8-advanced-capabilities.md)

**Goal**: Research-grade features that push the platform into innovation territory.

**Scope**:
- **8.1 Claude Agent SDK integration**: Replace CLI wrappers with proper Agent SDK using tool definitions
- **8.2 Live adversary simulation**: Connect real Mythic/Fawkes C2 for gold-standard validation
- **8.3 Behavioral analytics engine**: Statistical baselines, anomaly scoring, unsupervised detection
- **8.4 Multi-SIEM abstraction layer**: Portable detections across Elastic, Splunk, Sentinel, Chronicle
- **8.5 Detection marketplace**: Publish validated packs as community content
- **8.6 SOAR integration**: Automated response playbooks, enrichment, case management

Each capability is independent and can be pursued based on interest and available resources.

---

## Quick Reference: Current State vs Target

| Metric | Phases 1-7 (Current) | Phase 8 Target |
|--------|---------------------|----------------|
| Threat actors | 3 registered (Fawkes, LockBit, Scattered Spider) | N |
| Platforms | Win + Linux + Cloud + Network (sim) | All |
| Detection requests | 71 tracked (42 authored files: 35 Sigma + 3 EQL + 4 threshold) | 60+ authored |
| Deployed | 16 MONITORING | 50+ |
| Coverage (Fawkes) | ~16/21 techniques | 90%+ |
| Agents | 10 specialized + coordinator | SDK-based |
| Data quality | Monitored + scored + per-source Cribl (Phase 5) | Monitored |
| Feedback loop | Analyst TP/FP + auto-tune + evasion testing (Phase 7) | SOAR |
| CI gates | 9 (regression-test + schema-validate added Phases 7+) | 10+ |

---

## Superseded Plans (for reference only)

The following old plan files are kept for historical reference but are no longer active:

- `plans/phase4-agent-upgrades.md` — Superseded by `plans/phase4-scalable-architecture.md`
- `plans/phase5-coverage-expansion.md` — Scope absorbed into Phases 5-6
- `plans/phase6-operational-maturity.md` — Superseded by `plans/phase7-operational-excellence.md`
- `plans/phase7-advanced-capabilities.md` — Superseded by `plans/phase8-advanced-capabilities.md`

---

## Notes for Future Claude Sessions

1. **Always read CLAUDE.md first** — it has the full agent identity and workflow
2. **Read `plans/architecture-scalable-detection-platform.md`** — it explains the multi-agent architecture
3. **Check MEMORY.md** — contains infrastructure state, known bugs, lessons learned
4. **Check git status** — active branches may have in-progress work
5. **Run `cd autonomous && python3 orchestration/cli.py status`** to see detection pipeline state
6. **Never commit to main** — always feature branches with PRs
7. **Templates matter** — read `templates/detection-authoring-rules.md` before writing any rule
