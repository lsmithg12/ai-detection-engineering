# Detection Authoring Rules & Lessons Learned

A living reference for writing high-quality detections. **Check this file before writing every new detection.** Add new entries whenever you encounter a syntax issue, SIEM quirk, or quality pattern worth remembering.

---

## Sigma Rule Syntax

### Field Names
- Use ECS field names in Sigma rules: `process.executable`, `process.command_line`, `registry.path`
- Do NOT use Sysmon XML field names (Image, CommandLine, TargetObject) in Sigma — those are CIM aliases created by Cribl, not the source fields
- Sysmon EventID maps to `event.code` in ECS (string, not integer)
- `logsource.category` must match Sigma taxonomy: `process_creation`, `process_access`, `registry_set`, `image_load`, `network_connection`, `file_event`

### Wildcards & Escaping
- Sigma wildcards: `*` (any chars), `?` (single char)
- Backslashes in Sigma: use single `\` — the transpiler handles escaping per backend
- For `|contains`, `|startswith`, `|endswith` modifiers, do NOT wrap in wildcards — Sigma adds them automatically
- `|contains|all` requires ALL values to be present (AND logic), plain `|contains` is OR

### Filter Blocks
- Name filter blocks descriptively: `filter_legitimate`, `filter_system_processes`, `filter_microsoft`
- Always use `condition: selection and not filter_*` pattern
- Never filter on process.pid or timing — too fragile

---

## Elastic Security (Lucene/KQL)

### Wildcard Queries on Keyword Fields
- **CRITICAL**: Backslash escaping in Lucene wildcard queries on `keyword` fields is unreliable
- Registry paths like `HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Foo` stored with single backslashes
- Sigma-generated `registry.path:(*\\\\CurrentVersion\\\\Run\\\\*)` often fails to match
- **Workaround**: Use simplified wildcard patterns that skip backslash matching entirely:
  ```
  registry.path:(*CurrentVersion*Run* OR *CurrentVersion*RunOnce*)
  ```
- This is less precise but reliably matches. Compensate with process exclusion filters.

### Compiled Rule JSON (Elastic Detection Engine)
- `type` must be `"query"` for Lucene-based rules
- `language` must be `"lucene"` (not `"kql"` — Lucene supports wildcards better)
- `index` must be `["sim-*"]` (array, not string)
- `interval` and `from` should overlap: `"interval": "5m"`, `"from": "now-6m"` (1min overlap catches late events)
- `risk_score` range: 0-100. Use: informational=21, low=47, medium=73, high=73, critical=99
- `severity` must match `risk_score`: low(1-21), medium(22-47), high(48-73), critical(74-99)
- `threat` array uses MITRE ATT&CK framework format — see existing rules for structure
- `rule_id` must be a valid UUID v4 — generate with `python3 -c "import uuid; print(uuid.uuid4())"`
- `enabled: true` to activate immediately on deployment

### Deployment
- POST to `${KIBANA_URL}/api/detection_engine/rules`
- Headers: `kbn-xsrf: true`, `Content-Type: application/json`
- Auth: `-u elastic:changeme`
- Kibana requires `XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY` env var for detection engine

---

## Splunk (SPL)

### Field Names
- Splunk uses CIM field names created by Cribl pipeline + blue_team_lab app field extractions
- Key extracted fields: `EventCode`, `CommandLine`, `Image`, `ParentImage`, `TargetObject`, `Details`, `DestinationIp`, `DestinationPort`
- These are extracted from ECS JSON by the blue_team_lab Splunk app (props.conf/transforms.conf)
- Index for baseline: `sysmon` | Index for attacks: both `sysmon` and `attack_simulation`

### SPL Query Patterns
- Always specify index: `index=sysmon`
- Backslash escaping: use single `\` in SPL — Splunk handles it
- Wildcard: `*` works naturally in SPL
- Stats/table at end: `| table _time, host, user, CommandLine` for readability

### Saved Search Deployment
- POST to `${SPLUNK_URL}/servicesNS/admin/search/saved/searches`
- Auth: `-sk -u admin:BlueTeamLab1!`
- **CRITICAL**: Use `--data-urlencode` for `name`, `search`, `cron_schedule`, `alert_comparator`, and `alert_type` — any value with spaces, special chars, or `*` will fail with bare `-d`
- Key fields: `name`, `search`, `is_scheduled=1`, `cron_schedule="*/5 * * * *"`
- Alert fields: `alert_type="number of events"` (with space, NOT `number_of_events`), `alert_comparator="greater than"`, `alert_threshold=0`
- Severity: `alert.severity=4` (high), `alert.severity=3` (medium)
- Use `-sf` flag carefully — it suppresses error responses. Use `-sk` (insecure but show output) for debugging.

---

## Sigma Transpilation

### To Elastic (Lucene)
```bash
sigma convert -t lucene -p ecs_windows detections/<tactic>/<rule>.yml
```
- Output may need manual review for backslash escaping issues (see Wildcard section above)
- Always test the generated query against live data before deploying

### To Splunk (SPL)
```bash
sigma convert -t splunk --without-pipeline detections/<tactic>/<rule>.yml
```
- `--without-pipeline` avoids adding field mapping transforms that conflict with our Cribl pipeline
- Field names may need adjustment (ECS → CIM mapping)

### Common Transpilation Issues
- Sigma `|contains` with backslash paths often over-escapes in Lucene output
- SPL output may use `source` as a field name — conflicts with Splunk reserved field
- If transpiled output looks wrong, write the compiled query manually and note the issue here

---

## Test Cases

### True Positive (TP) Files
- Location: `tests/true_positives/tXXXX_XXX_<short_name>_tp.json`
- Must be a full ECS event JSON with `_simulation` metadata block
- Must include: `description`, `technique`, `fawkes_command`, `expected_result: "ALERT"`
- Event should match the exact artifact the Fawkes command generates

### True Negative (TN) Files
- Location: `tests/true_negatives/tXXXX_XXX_<short_name>_tn.json`
- Must be a realistic benign event that could superficially resemble the attack
- `expected_result: "NO_ALERT"`
- Good TN examples: legitimate software doing similar operations (msiexec writing registry, svchost network connections)

### Validation Against Live Data
- Always query both `sim-attack` (should match) and `sim-baseline` (should NOT match)
- Record exact counts: "TP: 2/2, FP: 0/1394"
- If FP > 0, add exclusions and re-validate before deploying

---

## Quality Checklist (Before Committing Any Detection)

- [ ] Sigma rule has complete metadata (title, id, status, description, author, date, references, tags)
- [ ] Tags include `attack.<tactic>`, `attack.tXXXX.XXX`, `detection.fawkes`
- [ ] At least one TP test case exists and validated
- [ ] At least one TN test case exists and validated
- [ ] Compiled to both Lucene (.lucene) and SPL (.spl)
- [ ] Elastic JSON rule file created with correct schema
- [ ] Deployed to running Elastic Security (if available)
- [ ] Deployed to running Splunk (if available)
- [ ] Coverage matrix updated (`coverage/attack-matrix.md`)
- [ ] False positive documentation in Sigma rule AND Elastic JSON
- [ ] No more than 3 exclusions without human review

---

## Lessons Learned Log

| Date | Detection | Issue | Resolution |
|---|---|---|---|
| 2026-03-01 | T1055.001 | Sigma `tags` need namespace prefix | Use `detection.fawkes` not just `fawkes` |
| 2026-03-01 | T1059.001 | sigma-cli `-t elasticsearch` is wrong | Use `-t lucene -p ecs_windows` |
| 2026-03-01 | T1547.001 | Lucene backslash wildcards fail on keyword fields | Use simplified patterns: `*CurrentVersion*Run*` |
| 2026-03-01 | T1547.001 | ES risk_score/severity mismatch causes deploy error | risk_score 73 = severity "high" (must align) |
| 2026-03-01 | All | Cribl `source` field conflicts with ECS source object | Pipeline removes `source` field in eval cleanup |
| 2026-03-01 | All | Splunk `-d` flag fails with spaces/wildcards in values | Use `--data-urlencode` for name, search, cron, alert_type, alert_comparator |
| 2026-03-01 | All | Splunk `alert_type` value has a space | Use `"number of events"` not `"number_of_events"` |
| 2026-03-01 | All | `curl -sf` suppresses Splunk API error bodies | Use `-sk` during debugging, only add `-f` for scripted success checks |
