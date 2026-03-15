# Patronus Lab — Improvement Roadmap

Master plan for enhancing the AI Detection Engineering Lab from a single-threat-actor lab
to an enterprise-grade, scalable detection engineering platform.

**Last reviewed**: 2026-03-15
**Current state**: 29 detection rules, 11 deployed (MONITORING), 5 agents operational, 2 SIEMs active, Phases 1-3 complete
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

## Phase 4: Scalable Architecture Foundation (Priority: HIGH)

**Status**: NOT STARTED
**Estimated effort**: 16-24 hours (multi-session)
**Dependencies**: Phase 3 (complete)

**Plan**: [plans/phase4-scalable-architecture.md](plans/phase4-scalable-architecture.md)

**Architecture**: [plans/architecture-scalable-detection-platform.md](plans/architecture-scalable-detection-platform.md)

**Goal**: Transform from single-threat-actor lab to scalable, multi-threat, multi-platform architecture.

**Scope**:
- **Threat model registry**: Pluggable YAML-based threat models (`threat-intel/models/`) — Fawkes, Scattered Spider, LockBit, generic RAT
- **Log source registry**: Structured `data-sources/registry/` with health check specs, field mappings, volume estimates
- **Coverage analyst agent**: Auto-generates coverage matrix from detection state + all threat models
- **Agent architecture refactor**: Split 5 monolithic agents into 10 specialized agents (3 tiers):
  - **Tier 1 (Foundation)**: Data Onboarding, Threat Intel, Coverage Analyst
  - **Tier 2 (Content)**: Detection Author, Scenario Engineer, Validation
  - **Tier 3 (Operations)**: Deployment, Tuning, Security Gate
  - **Orchestrator**: Coordinator agent for routing work and managing priorities
- **State management**: Schema-enforced YAML with SQLite readiness

**Key deliverables**: 4 threat models, log source registry, 10 specialized agents, coordinator, auto-generated coverage matrix

---

## Phase 5: Data Engineering at Scale (Priority: HIGH)

**Status**: NOT STARTED
**Estimated effort**: 16-20 hours (multi-session)
**Dependencies**: Phase 4 (log source registry, agent refactoring)

**Plan**: [plans/phase5-data-engineering.md](plans/phase5-data-engineering.md)

**Goal**: Build the data engineering infrastructure real detection teams need: multi-platform simulation, data quality monitoring, schema evolution management.

**Scope**:
- **Data quality monitoring engine**: Per-source health scoring (freshness, completeness, volume, schema compliance)
- **Multi-platform simulation**: Linux auditd, AWS CloudTrail, Zeek network, macOS unified log generators
- **Schema evolution management**: Versioned schema definitions, diff tool, detection impact analysis
- **Raw event converter expansion**: Linux, cloud, network raw format converters
- **Per-source Cribl pipelines**: Replace monolithic `cim_normalize` with source-specific pipelines
- **Data source gap auto-detection**: Cross-reference coverage gaps with source registry

**Key deliverables**: Data quality engine, 4 new platform simulators, schema versioning, per-source Cribl pipelines

---

## Phase 6: Detection Content at Scale (Priority: HIGH)

**Status**: NOT STARTED
**Estimated effort**: 16-20 hours (multi-session)
**Dependencies**: Phase 4 (agent refactoring), Phase 5 recommended

**Plan**: [plans/phase6-detection-content.md](plans/phase6-detection-content.md)

**Goal**: Scale from 29 individual Sigma rules to a comprehensive detection library with content packs, multi-rule-type support, evasion testing, and continuous validation.

**Scope**:
- **Content pack framework**: Group related detections into versioned, deployable packs
- **EQL rule support**: Multi-event correlation rules (kill chain sequences)
- **Threshold rule support**: Volume-based aggregation rules (brute force, discovery bursts)
- **Evasion resilience testing**: Systematic testing against adversary tradecraft variants
- **Continuous validation**: Weekly re-validation of deployed rules, regression detection
- **Detection performance profiling**: Query cost measurement at simulated scale
- **Coverage expansion sprint**: Close gaps to 75%+ Fawkes coverage + non-Fawkes detections

**Key deliverables**: Content packs, EQL rules, threshold rules, evasion test suite, continuous validation CI, coverage to 75%+

---

## Phase 7: Operational Excellence (Priority: HIGH)

**Status**: NOT STARTED
**Estimated effort**: 12-16 hours (multi-session)
**Dependencies**: Phase 4 (coordinator, tuning agent), Phase 6 recommended

**Plan**: [plans/phase7-operational-excellence.md](plans/phase7-operational-excellence.md)

**Goal**: Close the operational feedback loop — build, deploy, measure, improve. This separates a lab from a production detection program.

**Scope**:
- **Detection health dashboard**: Kibana + Splunk dashboards with 8 panels (fleet overview, alert volume, F1 distribution, coverage radar, SLA trends)
- **Analyst feedback loop**: CLI + ES-based verdict capture, FP aggregation, auto-tuning triggers
- **Automated regression testing**: CI gate on PRs that modify detections (F1 drop > 0.10 = block)
- **SLA tracking**: Time from REQUESTED to MONITORING per priority level, breach detection
- **Pipeline performance metrics**: Per-agent run metrics, token budget tracking, monthly reports
- **Alert-on-alert**: Detect silent rules, FP spikes, alert floods; auto-create GitHub Issues

**Key deliverables**: Health dashboard, feedback loop, regression CI, SLA module, health monitor with GitHub Issues

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

| Metric | Phase 3 (Current) | Phase 4 | Phase 5 | Phase 6 | Phase 7 | Phase 8 |
|--------|-------------------|---------|---------|---------|---------|---------|
| Threat actors | 1 (Fawkes) | 4+ | 4+ | 4+ | 4+ | N |
| Platforms | Windows | Windows | Win/Linux/Cloud/Net | All | All | All |
| Detections | 29 Sigma | 29 | 29+ | 45+ (Sigma+EQL+threshold) | 50+ | 60+ |
| Deployed | 11 | 11 | 15+ | 35+ | 40+ | 50+ |
| Coverage (Fawkes) | 62% | 62% | 65% | 75%+ | 80%+ | 90%+ |
| Agents | 5 monolithic | 10 specialized | 10 | 10 | 10 | SDK-based |
| Data quality | None | Registered | Monitored + scored | Monitored | Monitored + alerted | Monitored |
| Feedback loop | None | None | None | Evasion testing | Analyst TP/FP + auto-tune | SOAR |
| CI gates | 6 workflows | 6 | 6 | 7 (continuous validation) | 8 (regression) | 10+ |

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
