# Claude Code Starter Prompts

Copy-paste these into Claude Code to kick off different workflows.

---

## Full Detection Engineering Lifecycle

The complete workflow — from raw logs through Cribl normalization to deployed, validated, tuned detections. This is the primary prompt for the lab.

> **Note**: Phases 2-3 (Cribl pipeline) are optional — skip them if you're not running with `--cribl` or `--full`. Jump from Phase 1 straight to Phase 4.

```
Read CLAUDE.md, then run the full detection engineering lifecycle:

=== PHASE 1: SETUP VERIFICATION ===

1. Check all services are healthy:
   - Elasticsearch: curl -u elastic:changeme http://localhost:9200/_cluster/health
   - Kibana: curl http://localhost:5601/api/status
   - Splunk (if running): curl -sk -u admin:BlueTeamLab1! https://localhost:8089/services/server/health
   - Cribl Stream (if running): Use cribl_health MCP tool

2. Confirm logs are flowing into the simulation indices:
   - Elastic: GET sim-baseline/_count and sim-attack/_count
   - Splunk (if running): search index=sysmon | head 5

3. (SKIP if Cribl is not running) Confirm Cribl is receiving and forwarding events:
   - cribl_list_inputs → find 'lab_hec_in'
   - cribl_get_metrics → check events_in > 0
   - cribl_test_output for each configured output

=== PHASE 2: LOG ONBOARDING — REVIEW INCOMING DATA (SKIP if no Cribl) ===

4. Pull 10 live sample events from the Cribl HEC input:
   - cribl_get_input_samples(input_id='lab_hec_in', count=10)

5. Preview how the current pipeline transforms these samples:
   - cribl_get_pipeline(id='cim_normalize')
   - cribl_preview_pipeline(pipeline_id='cim_normalize', sample_events=<the 10 samples>)

6. Identify field gaps — for each of the following, note if the field is present and correctly mapped:
   Required fields for detection rules:
   - event.code (Sysmon EID as keyword)
   - process.name, process.executable, process.command_line
   - winlog.event_data.TargetImage, winlog.event_data.GrantedAccess
   - registry.path, registry.value
   - source.ip, destination.ip, destination.port
   - user.name, host.name
   - _simulation.technique (MITRE ATT&CK ID)

   Required Splunk CIM fields (for SPL detections):
   - src_ip, dest_ip, dest_port, user, host, process, CommandLine, EventCode

=== PHASE 3: WRITE CRIBL PARSERS — CIM COMPLIANCE & LOG REDUCTION (SKIP if no Cribl) ===

7. For each field gap found in Phase 2, add a pipeline function. Always test with
   cribl_preview_pipeline BEFORE applying to the live pipeline.

   a) For missing/malformed ECS field extractions — add regex_extract function:
      Example: extract EventCode from _raw if event.code is missing
      {type:'regex_extract', filter:'true', conf:{field:'_raw', regex:'EventCode=(?<EventCode>\\d+)'}}

   b) For Splunk CIM field aliases — add eval function:
      Example: map ECS fields to CIM names
      {type:'eval', filter:'true', conf:{add:[
        {name:'src_ip', value:"__e['source.ip'] || __e['src_ip']"},
        {name:'dest_ip', value:"__e['destination.ip'] || __e['dest_ip']"},
        {name:'CommandLine', value:"__e['process.command_line']"},
        {name:'EventCode', value:"__e['event.code']"}
      ]}}

   c) For log reduction — add drop function for known-noisy, low-value events:
      Example: drop 80% of routine svchost.exe network connections
      {type:'drop', filter:"__e['process.name']=='svchost.exe' && __e['destination.port']==53 && Math.random()<0.8"}

   d) For attack event enrichment — add eval to tag MITRE technique:
      {type:'eval', filter:"__e['_simulation'] && __e['_simulation']['type']=='attack'", conf:{add:[
        {name:'mitre_technique', value:"__e['_simulation']['technique']"},
        {name:'fawkes_command', value:"__e['_simulation']['fawkes_command']"}
      ]}}

8. After each change, verify with cribl_preview_pipeline against the same 10 samples.
   Confirm all required fields are present and correctly mapped.

9. Check the new reduction ratio: cribl_get_metrics()
   - Document: bytes_in, bytes_out, reduction_pct per pipeline
   - Target: 20-50% reduction without dropping attack-relevant events

=== PHASE 4: ANALYZE NORMALIZED LOGS IN SIEM ===

10. Query Elasticsearch for attack events (confirm field normalization worked):
    GET sim-attack/_search with aggregation on _simulation.technique
    Verify: event.code, process.name, winlog.event_data.* are keyword-mappable

11. If Splunk is running, run an equivalent SPL query:
    search index=attack_simulation | stats count by mitre_technique, fawkes_command
    Verify: CIM fields (src_ip, dest_ip, CommandLine) appear correctly

12. Note any remaining field normalization issues for a second Cribl tuning pass.

=== PHASE 5: THREAT INTEL REVIEW ===

13. Read threat-intel/fawkes/fawkes-ttp-mapping.md — understand the full Fawkes capability set.

14. Read coverage/attack-matrix.md — identify all uncovered techniques.

15. Read coverage/detection-backlog.md — confirm ranked priority list.

16. Select the highest-priority technique with:
    - Available data in sim-attack (can verify with _simulation.technique query)
    - No existing detection in detections/
    - Required fields confirmed present after Phase 3 normalization

=== PHASE 6: BUILD DETECTIONS ===

17. Create a feature branch: git checkout -b detection/t<ID>-<short-name>

18. For the selected technique, author a Sigma rule following templates/sigma-template.yml:
    - Full metadata: title, description, author, date, MITRE ATT&CK tags
    - Detection logic using the ECS fields confirmed in Phase 4
    - False positive section documenting known benign patterns
    - Save to detections/<tactic>/<rule>.yml

19. Transpile to KQL:
    sigma convert -t lucene -p ecs_windows detections/<tactic>/<rule>.yml
    Save output to detections/<tactic>/compiled/<rule>.kql

20. If Splunk is running, also transpile to SPL:
    sigma convert -t splunk --without-pipeline detections/<tactic>/<rule>.yml
    Save to detections/<tactic>/compiled/<rule>.spl

=== PHASE 7: VALIDATE DETECTIONS ===

21. Validate KQL against Elastic attack data:
    POST sim-attack/_search with the KQL query scoped to _simulation.technique
    Expected: TP count > 0

22. Validate against baseline data for FP check:
    POST sim-baseline/_search with the same query
    Expected: FP count = 0 (or very low)

23. If Attack Range sample data is available (attack-range-samples index):
    Also validate against that for broader technique coverage.

24. Record in tests/<technique>_test.md:
    - TP count, sample TP event
    - FP count, sample FP event (if any)
    - TP rate = TP/(TP+FN), FP rate = FP/(FP+TN)

=== PHASE 8: DEPLOY ===

25. Deploy to Elastic Security (create scheduled rule):
    POST -u elastic:changeme http://localhost:5601/api/detection_engine/rules
    Use the compiled JSON rule. Set interval=5m, enabled=true.

26. If Splunk is running, deploy as saved search:
    POST admin:BlueTeamLab1! https://localhost:8089/servicesNS/admin/search/saved/searches
    With the compiled SPL, is_scheduled=1, cron_schedule="*/5 * * * *"

27. Confirm rule is active and running. Check for any syntax errors.

=== PHASE 9: TUNE ===

28. Wait 5-10 minutes for the rule to run against accumulating data.
    Check alert volume: GET .alerts-security.alerts-default/_search (ES)
                        GET search results for saved search (Splunk)

29. If FP rate > 10%:
    a) Identify the most common FP pattern (what process/path/user triggers it?)
    b) Add exclusion to the Sigma rule
    c) BETTER: Add Cribl drop function upstream (prevents FPs from ever reaching SIEM):
       - Test drop filter with cribl_preview_pipeline first
       - Apply with cribl_add_pipeline_function
    d) GUARDRAIL: If more than 3 exclusions needed → flag for human review, do not add more

30. If TP rate < 90%:
    a) Check if attack events are reaching the SIEM (sim-attack query)
    b) Check if Cribl pipeline is dropping attack events inadvertently (cribl_get_metrics)
    c) Broaden detection logic (widen GrantedAccess mask, remove overly strict conditions)

31. CRITICAL — Tuning changes require a PR (do not commit directly to detection branch):
    a) Create branch: git checkout -b tuning/<date>-<technique>-reduce-fp
    b) Commit: fix(detection): tune <title> — reduce FP from X% to Y%
       Include in body: before/after logic, TP/FP counts, Cribl pipeline changes made
    c) Push branch, create GitHub PR:
       Title: [Tuning] <Rule Name> — FP reduction
       Body: validation results, Cribl changes, exclusion rationale
       Labels: tuning, needs-review
    d) DO NOT MERGE — leave for human review and approval

=== PHASE 10: COVERAGE UPDATE & ITERATE ===

32. Update coverage/attack-matrix.md — mark technique as detected
33. Update tuning/changelog/<rule>.md with tuning decisions

34. Commit all changes (rule + tests + coverage + tuning docs):
    feat(detection): add <title> (T<ID>)
    Body: Fawkes command, data sources, TP/FP rates, Cribl pipeline dependencies

35. Push feature branch, create GitHub PR:
    Title: [Detection] <Title> (T<ID>)
    Body: detection summary, validation results, coverage impact, Fawkes commands detected
    Reference: Closes #<issue-number> (if there's an open gap issue)
    Labels: detection, <tactic>
    DO NOT MERGE — wait for human review

36. Return to Phase 5 — select the next priority technique and iterate.
```

---

## First Run — Environment Setup & Discovery

```
Read the CLAUDE.md file, then:

1. Check all services: Elasticsearch (elastic/changeme), Kibana, Splunk (admin/BlueTeamLab1!), Cribl (cribl_health)
2. Verify git remote is configured (git remote -v)
3. Verify GitHub MCP is connected
4. Use Elasticsearch MCP to list indices, get mappings, sample data
5. Use cribl_list_inputs, cribl_list_pipelines, cribl_get_metrics to understand Cribl state
6. Compare against coverage/data-sources.md and update it
7. Review threat-intel/fawkes/fawkes-ttp-mapping.md
8. Build/confirm the top 10 detection backlog in coverage/detection-backlog.md
9. Create GitHub Issues for each coverage gap
10. Commit, push, create PR
```

---

## Build First Detection — Process Injection

```
Build a detection for Fawkes vanilla-injection (T1055.001):

The Fawkes vanilla-injection command uses: VirtualAllocEx → WriteProcessMemory → CreateRemoteThread

1. Check what process injection telemetry exists:
   GET sim-attack/_search with _simulation.technique:T1055.001

2. Preview the data through the CIM normalize pipeline:
   cribl_get_input_samples + cribl_preview_pipeline — confirm injection fields present

3. Author detections/privilege_escalation/t1055_001_create_remote_thread.yml
4. Transpile: sigma convert -t lucene -p ecs_windows <rule>.yml
5. Validate TP rate against sim-attack, FP rate against sim-baseline
6. Deploy to Kibana: POST /api/detection_engine/rules
7. Create tests and triage playbook
8. Update coverage matrix
9. Commit on branch detection/t1055-001-create-remote-thread, create PR
```

---

## Cribl Log Pipeline Review & Optimization

```
Perform a full Cribl pipeline audit and optimization pass:

1. Health check: cribl_health — confirm version and group status
2. List all inputs: cribl_list_inputs — find all data sources and their assigned pipelines
3. Get sample events from each active input: cribl_get_input_samples for each

4. For each pipeline:
   a) cribl_get_pipeline — review all functions in order
   b) cribl_preview_pipeline with samples — see exactly what transforms are applied
   c) Check for:
      - Missing ECS fields needed by detection rules
      - Missing CIM fields needed by Splunk detections (src_ip, dest_ip, user, CommandLine)
      - Opportunities to drop high-volume, low-value events
      - Fields that are malformed (wrong type, embedded in nested objects)

5. For each gap found:
   - Design the fix (regex_extract, eval, or drop function)
   - Test with cribl_preview_pipeline BEFORE applying
   - Apply with cribl_add_pipeline_function

6. Measure impact: cribl_get_metrics — report reduction_pct per pipeline before and after

7. Test all output destinations: cribl_list_outputs → cribl_test_output for each

8. Review routing: cribl_get_routes — confirm attack events go to both SIEMs, baseline to Elastic only

9. Document all changes in tuning/changelog/cribl-pipeline-<date>.md
10. Commit changes
```

---

## Bulk Build — All Persistence Detections

```
Build detections for all Fawkes persistence mechanisms. Follow the
full lifecycle (intel→cribl review→author→validate→deploy→report) for each:

1. Registry Run Keys (T1547.001) — Fawkes `persist -method registry`
   Detect writes to HKCU/HKLM\Software\Microsoft\Windows\CurrentVersion\Run

2. Startup Folder (T1547.001) — Fawkes `persist -method startup-folder`
   Detect file creation in shell:startup directories

3. Scheduled Task (T1053.005) — Fawkes `schtask -action create`
   Detect schtasks.exe creating tasks pointing to unusual executables

4. Windows Service (T1543.003) — Fawkes `service -action create`
   Detect service creation with suspicious binary paths

5. Crontab (T1053.003) — Fawkes `crontab -action add`
   Detect crontab modifications by non-standard processes

For each: preview data in Cribl, validate rule, deploy, check coverage.
Batch validate all rules, deploy those that pass, flag data gaps.
Update attack-matrix.md when done.
```

---

## Tuning Session

```
Run a tuning session across all deployed detections:

1. Query Elastic alerts: GET .alerts-security.alerts-default/_search (group by rule name, last 24h)
2. For any rule with > 50 alerts, pull 10 samples and classify: TP or FP?
3. For rules with FP rate > 20%:
   a) Identify the common benign pattern
   b) FIRST: add Cribl drop rule upstream (test with cribl_preview_pipeline)
   c) SECOND: add exclusion to Sigma rule
   d) Show before/after logic, wait for my approval before deploying
4. For rules with 0 alerts but active data:
   - Investigate: data dropped by Cribl? Query syntax wrong? Missing fields?
   - Check cribl_get_metrics for the relevant pipeline — are events being dropped?
5. All tuning changes → tuning/<date>-<description> branch + PR (do not merge)
6. Update tuning/changelog/ with all decisions
```

---

## Coverage Gap Analysis

```
Perform a full coverage gap analysis:

1. Scan all detection files in detections/, extract MITRE ATT&CK technique IDs
2. Compare against threat-intel/fawkes/fawkes-ttp-mapping.md (all 59 commands)
3. Identify:
   a) Techniques with deployed detections (covered)
   b) Techniques with data in sim-attack but no detection (build now)
   c) Techniques with no data source (document gap, check Cribl pipeline)
4. Rebuild coverage/attack-matrix.md with current state
5. Create GitHub Issues for all uncovered techniques with required data
6. Recommend the next 5 detections to build
```

---

## Attack Range Data Integration

```
Load supplemental attack telemetry from Splunk Attack Range / BOTS datasets:

1. Run: ./pipeline/fetch-attack-range-data.sh samples
   (No large download — generates representative events for T1059.001, T1003.001, T1547.001)

2. Verify data in Elastic: GET attack-range-samples/_search
   And in Splunk: search index=attack_simulation source=attack_range

3. Compare Attack Range techniques against current Fawkes detections:
   - Do our detection rules fire on Attack Range data too?
   - Are there any technique coverage gaps revealed by the new data?

4. Validate each deployed detection against the Attack Range events
5. If full BOTS dataset needed: ./pipeline/fetch-attack-range-data.sh bots-v3
```

---

## Full PR Workflow — Single Detection

```
Build a detection for T1053.005 (Scheduled Task) using the full branch + PR workflow:

1. git checkout -b detection/t1053-005-scheduled-task
2. Preview sim-attack data for T1053.005 through Cribl: cribl_get_input_samples + cribl_preview_pipeline
3. Confirm all detection fields (process.name, process.command_line) are present
4. Write detections/persistence/t1053_005_scheduled_task_persistence.yml
5. Transpile to KQL and SPL, save compiled outputs
6. Create true positive and true negative test cases in tests/
7. Validate: TP > 0 in sim-attack, FP = 0 in sim-baseline
8. Deploy to Kibana Detection Engine
9. Write triage playbook: detections/persistence/playbooks/t1053_005_triage.md
10. Update coverage/attack-matrix.md
11. Commit all (rule + tests + playbook + coverage) with conventional commit message
12. Push branch, create GitHub PR:
    Title: [Detection] Scheduled Task Persistence (T1053.005)
    Body: technique summary, Fawkes command (schtask), TP/FP results, Cribl field dependencies
    Closes: #<issue-number>
    Labels: detection, persistence
    DO NOT MERGE
```

---

## Security Review

```
/security-review

Then also:
1. Are credentials hardcoded anywhere in pipeline scripts or detection files?
2. Is the Cribl pipeline dropping events that should reach the SIEM (use cribl_get_metrics)?
3. Are detection exclusions being added without tracking in tuning/changelog/?
4. Is the docker-compose exposing unnecessary ports?
5. Are there more than 3 exclusions on any single rule? Flag for human review.
```
