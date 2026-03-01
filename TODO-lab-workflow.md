# Lab Workflow Progress — Full Setup Test (2026-03-01)

Branch: `detection/batch-full-lab-test`

## Completed
- [x] Fresh `--full` lab start (Elastic + Splunk + Cribl + Simulator)
- [x] All 5 services healthy (ES, Kibana, Splunk, Cribl, Simulator)
- [x] Cribl HEC routing verified (simulator → Cribl → both SIEMs)
- [x] Fixed `configure-cribl.sh` — all API calls now work correctly
- [x] Data flowing: 2,280+ baseline events, attack scenarios generating
- [x] T1059.001 PowerShell Bypass detection written (Sigma rule)
- [x] Transpiled to Lucene + SPL, compiled outputs saved
- [x] TP validation: 1/1 (100%) — detects Fawkes powershell command
- [x] FP validation: 0 false positives in 2,280+ baseline events
- [x] Deployed to Elastic Security (rule ID: b7a9d54f, enabled, 5m interval)
- [x] Deployed to Splunk (saved search: PowerShell Bypass T1059.001)
- [x] Coverage matrix updated (1/21 techniques, 5%)

## Cribl Fixes Applied (for PR)
- `configure-cribl.sh` completely rewritten:
  - HEC input: PATCH `in_splunk_hec` (not POST new input)
  - Pipeline: `conf.functions` wrapper required
  - ES output: type `elastic` (not `elasticsearch`), requires `url` field
  - Splunk output: `token` field (not `hecToken`)
  - Routes: PATCH `default` group (not POST)
  - Added `elastic_attack` output for sim-attack index
  - Routes split: attack → sim-attack + splunk, baseline → sim-baseline + splunk
  - Commit step added to persist changes

## Files Changed
- `pipeline/configure-cribl.sh` — Complete rewrite with correct API calls
- `detections/execution/t1059_001_powershell_bypass.yml` — Sigma rule
- `detections/execution/compiled/t1059_001_powershell_bypass.lucene` — Elastic query
- `detections/execution/compiled/t1059_001_powershell_bypass.spl` — Splunk query
- `detections/execution/compiled/t1059_001_powershell_bypass_elastic.json` — Elastic rule
- `tests/true_positives/t1059_001_powershell_bypass_tp.json` — TP test case
- `tests/true_negatives/t1059_001_powershell_bypass_tn.json` — TN test case
- `coverage/attack-matrix.md` — Updated with T1059.001 coverage

## Next Priorities
- [ ] T1547.001 Registry Run Keys (persist -method registry) — EID 13
- [ ] T1134.001 LSASS Token Theft (steal-token) — EID 10
- [ ] T1071.001 C2 Beaconing — EID 3
- [ ] T1562.001 AMSI/ETW Patching (start-clr) — EID 7
