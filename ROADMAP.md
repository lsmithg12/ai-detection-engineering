# Patronus Lab — Improvement Roadmap

Master plan for enhancing the AI Detection Engineering Lab. Each phase is self-contained
so future Claude sessions can pick up any phase independently.

**Last reviewed**: 2026-03-13
**Current state**: 28 detections authored, 8 deployed, 5 agents operational, 2 SIEMs active

---

## How to Use This File

Each phase links to a detailed plan in `plans/`. To start work on any phase:

```
Read ROADMAP.md for context, then read plans/<phase-file>.md for step-by-step instructions.
```

Phases are independent unless noted. Work any phase in any order.

---

## Phase 1: Detection Quality Remediation (Priority: IMMEDIATE)

**Goal**: Fix broken/stuck detections, compile missing outputs, get all 28 rules deployable.

**Plan**: [plans/phase1-detection-quality.md](plans/phase1-detection-quality.md)

**Scope**:
- Re-run T1046, T1562.006, T1569.002 (stuck at AUTHORED due to bugs now fixed)
- Fix T1562.001 malformed Sigma rule (hard-coded process name, broken filter)
- Compile missing Elastic JSON for 25/28 rules
- Split multi-event test scenarios (T1046, T1027) into single-event TP tests
- Populate tuning changelog with audit trail
- Enrich result files with timestamps and SIEM metadata
- Update coverage/attack-matrix.md to reflect actual state

**Success criteria**: All 28 rules pass sigma-cli transpilation. All have compiled Lucene + SPL.

---

## Phase 2: SIEM-Based Validation (Priority: HIGH)

**Goal**: Replace local JSON matching with actual Elasticsearch/Splunk query validation.

**Plan**: [plans/phase2-siem-validation.md](plans/phase2-siem-validation.md)

**Scope**:
- Blue-team agent ingests scenario events into `sim-validation` index
- Runs compiled Lucene query against ingested data
- Counts TP/FP from actual search results (not local JSON matching)
- Falls back to local validation when SIEMs offline (CI environment)
- Splunk parallel validation using SPL saved searches

**Why**: Current local JSON matching misses field mapping errors, Lucene syntax issues,
and normalization failures — the exact problems that cause detections to fail in production.

**Dependencies**: Docker services must be running for SIEM validation path.

---

## Phase 3: Data Pipeline — Raw Logs through Cribl (Priority: HIGH)

**Goal**: Implement the full data pipeline vision: raw vendor events → Cribl → normalized → SIEM.

**Plan**: [plans/phase3-data-pipeline.md](plans/phase3-data-pipeline.md)

**Scope**:
- Red-team generates raw vendor-format events (Windows Event XML, syslog)
- Cribl `cim_normalize` pipeline parses, maps to ECS/CIM, drops noise
- Blue-team validates against normalized output in SIEM
- Data source gap tracking via structured YAML in `gaps/data-sources/`
- Intel agent tags requests with `data_source_requirements`

**Dependencies**: Phase 2 (SIEM validation) should be complete first. Cribl must be running.

---

## Phase 4: Agent Intelligence Upgrades (Priority: MEDIUM)

**Goal**: Make each agent smarter, more autonomous, and more collaborative.

**Plan**: [plans/phase4-agent-upgrades.md](plans/phase4-agent-upgrades.md)

**Scope**:
- **Intel agent**: Structured report parsing, source diversity scoring, auto-prioritization
- **Red-team agent**: Multi-stage kill chain scenarios, evasion variant generation
- **Blue-team agent**: EQL/correlation rule support, multi-event detection, threshold rules
- **Quality agent**: Live SIEM alert metrics, automated tuning PRs, regression detection
- **Security agent**: Auto-fix capability, expanded rule quality checks

---

## Phase 5: Coverage Expansion — Close ATT&CK Gaps (Priority: MEDIUM)

**Goal**: Grow detection coverage from 43% to 75%+ of Fawkes techniques.

**Plan**: [plans/phase5-coverage-expansion.md](plans/phase5-coverage-expansion.md)

**Scope**:
- Add missing data sources (WMI EID 19-21, timestomping EID 2, process tampering EID 25)
- Build detections for 0% coverage tactics: Lateral Movement, Collection
- Add behavioral/statistical detections (discovery burst correlation, beaconing analysis)
- Expand beyond Fawkes: Scattered Spider, commodity ransomware, initial access brokers
- Purple team validation exercises

---

## Phase 6: Operational Maturity (Priority: MEDIUM)

**Goal**: Production-grade ops: dashboards, metrics, alerting on detection health.

**Plan**: [plans/phase6-operational-maturity.md](plans/phase6-operational-maturity.md)

**Scope**:
- Detection health dashboard (Kibana/Splunk)
- Automated regression testing on every PR
- Pipeline performance metrics and cost tracking
- Alert-on-alert: notify when detection stops firing or FP spikes
- SLA tracking: time from intel to deployed detection

---

## Phase 7: Advanced Capabilities (Priority: LOW — STRATEGIC)

**Goal**: Next-gen features that push the lab into research territory.

**Plan**: [plans/phase7-advanced-capabilities.md](plans/phase7-advanced-capabilities.md)

**Scope**:
- **Claude Agent SDK integration**: Replace `claude -p` CLI with proper agent SDK
- **Live adversary simulation**: Connect real Mythic/Fawkes C2 for validation
- **Multi-SIEM abstraction**: Add Sentinel, Chronicle, QRadar backends
- **Detection marketplace**: Publish validated rules as community packages
- **Feedback loops**: SOAR integration for response automation
- **Threat model swapping**: Hot-swap Fawkes for other C2 frameworks

---

## Quick Reference: Current State vs Target

| Metric | Current | Phase 1 | Phase 3 | Phase 5 | Phase 7 |
|--------|---------|---------|---------|---------|---------|
| Detections authored | 28 | 28 (all fixed) | 28 | 40+ | 60+ |
| Deployed to SIEM | 8 | 20+ | 25+ | 35+ | 50+ |
| Fawkes coverage | 43% | 43% | 50% | 75% | 90%+ |
| Validation method | Local JSON | Local JSON | SIEM queries | SIEM queries | Live C2 |
| Data pipeline | Pre-normalized | Pre-normalized | Raw → Cribl → SIEM | Full pipeline | Full pipeline |
| Agent intelligence | Deterministic + Claude | Improved prompts | Schema-aware | Correlation rules | Agent SDK |
| CI/CD | 6 workflows | 6 workflows | 7 workflows | 8 workflows | 10+ workflows |

---

## Notes for Future Claude Sessions

1. **Always read CLAUDE.md first** — it has the full agent identity and workflow
2. **Check MEMORY.md** — contains infrastructure state, known bugs, lessons learned
3. **Check git status** — active branches may have in-progress work
4. **Run `cd autonomous && python3 orchestration/cli.py status`** to see detection pipeline state
5. **Never commit to main** — always feature branches with PRs
6. **Templates matter** — read `templates/detection-authoring-rules.md` before writing any rule
