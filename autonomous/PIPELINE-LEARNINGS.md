# Pipeline Learnings & Follow-Up Fixes

Tracking file for issues discovered during pipeline runs. Updated after each cycle.

## 2026-03-10 — Pipeline Improvements v1

### Changes Implemented
| Fix | Description | Status |
|-----|-------------|--------|
| 1a | ECS field standardization in red-team Claude prompt | Done |
| 1b | ECS field matching instruction in blue-team Claude prompt | Done |
| 1c | Retry-with-feedback loop (max 2 retries when F1 < 0.90) | Done |
| 1d | Multi-block Sigma selection validator (AND/OR/1-of/all-of) | Done |
| 2 | Post-merge deploy (removed auto-deploy from blue-team) | Done |
| 3 | Pipeline mode (`--pipeline red-blue-quality`) | Done |
| 4 | GH_PAT fallback on all agent workflows | Done |
| 5 | Deleted 29 stale remote branches | Done |

### Gotchas to Watch During Testing
- [ ] Empty selection blocks should return `False` (no match-all) — verify F1 scores change
- [ ] Retry loop requires Claude CLI available — won't activate in CI (expected)
- [ ] Post-merge deploy requires SIEMs running — `cli.py deploy` will skip if offline
- [ ] Pipeline mode commits per-agent but pushes once — check git log has separate commits
- [ ] `deploy-rules.yml` needs ES_URL/KIBANA_URL/SPLUNK_URL secrets if deploying from CI
- [ ] Actions "Allow GitHub Actions to create and approve pull requests" must be enabled

### Follow-Up Items (Not Yet Implemented)
- [ ] Multi-event scenario scoring: rule checks EID 1, scenario has EID 1+3+11 → inflated FN
  - **Fix**: Filter attack events to only count events matching rule's logsource/event.code
- [ ] Data pipeline vision: raw vendor logs → Cribl → SIEM-based validation
  - Long-term — requires raw log generators and Cribl pipeline integration
- [ ] Data source onboarding tracking in `gaps/data-sources/*.yml`
- [ ] Intel agent `data_source_requirements` tagging on requests
- [ ] T1486 F1=1.0 was accidental — re-validate after multi-block fix
- [ ] Close stale auto PRs (#24, #26, #29, #31) if still open

### Run Log
| Date | Pipeline | Result | Notes |
|------|----------|--------|-------|
| (pending) | red-blue-quality | — | First end-to-end test of improvements |
