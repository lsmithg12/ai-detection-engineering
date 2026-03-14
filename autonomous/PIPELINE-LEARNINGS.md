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

### Follow-Up Items
- [x] Multi-event scenario scoring — FIXED in Phase 1 (split into single-event TP tests + integration/ kill chains)
- [x] SIEM-based validation — DONE in Phase 2 (validation.py with ES ingest → Lucene query → F1 score)
- [x] T1486 F1=1.0 re-validation — Confirmed valid after multi-block fix (Phase 1)
- [x] Close stale auto PRs (#24, #26, #29, #31) — All stale branches deleted 2026-03-10
- [ ] Data pipeline vision: raw vendor logs → Cribl → normalized → ES — Phase 3 (not started)
- [ ] Data source onboarding tracking in `gaps/data-sources/*.yml` — Phase 3 (not started)
- [ ] Intel agent `data_source_requirements` tagging on requests — Phase 3 (not started)

### Run Log
| Date | Pipeline | Result | Notes |
|------|----------|--------|-------|
| 2026-03-10 | full (5 agents) | SUCCESS | First full pipeline run — 29 stale branches cleaned |
| 2026-03-11 | red-blue-quality | SUCCESS | Backslash fix validated, 4 new detections authored |
| 2026-03-12 | intel + quality | SUCCESS | 4 reports processed, 11 detections healthy |
| 2026-03-13 | quality | SUCCESS | Phase 1 fixes validated, all 11 MONITORING healthy |
