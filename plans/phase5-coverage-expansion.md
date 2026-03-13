# Phase 5: Coverage Expansion — Close ATT&CK Gaps

**Status**: NOT STARTED
**Priority**: MEDIUM
**Estimated effort**: 16-24 hours (multi-session)
**Dependencies**: Phase 1 (DONE), Phase 2 (DONE — SIEM validation available). Phase 3 (data pipeline) recommended but not required.
**Branch**: Per-technique branches `detection/TXXXX-YYY-short-name`

### Phase 2 Leverage

New detections authored in Phase 5 will automatically benefit from SIEM-based validation
if Elasticsearch is running. The blue-team agent will validate Lucene queries against real
ES indices, catching field mapping issues that local validation misses. This is especially
valuable for the more complex detections (EQL correlation, threshold rules) planned here.

---

## Context

Current coverage: 9/21 Fawkes techniques deployed (43%), 28 total detections authored.
Target: 75%+ Fawkes coverage, 40+ total detections.

### Coverage Gaps by Tactic

| Tactic | Current | Gap | Target |
|--------|---------|-----|--------|
| Execution | 1/5 (20%) | WMI, inline-assembly, BOF, spawn | 4/5 |
| Process Injection | 1/5 (20%) | APC, threadless, PoolParty, Opus | 3/5 |
| Persistence | 2/6 (33%) | startup-folder, service, crontab, launchagent | 4/6 |
| Credential Access | 1/5 (20%) | keylog, make-token, keychain, ssh-keys | 3/5 |
| Defense Evasion | 2/5 (40%) | timestomp, binary-inflate, sleep | 3/5 |
| Discovery | 0/10 (0%) | All discovery commands | 3/10 |
| Lateral Movement | 0/2 (0%) | SOCKS5, WMI remote | 1/2 |
| Collection | 0/3 (0%) | clipboard, screenshot, download | 1/3 |
| C2 | 1/3 (33%) | domain fronting, TLS pinning | 2/3 |

## Task Groups

### Group A: Close Data Source Gaps (Prerequisite for Many Detections)

#### A1: Add WMI Event Logging (EID 19-21)

Enables: T1047 (WMI Execution), T1546.003 (WMI Event Subscription)

**Steps**:
1. Add WMI event generator to `simulator/simulator.py`:
   - EID 19 (WmiEventFilter): Filter creation
   - EID 20 (WmiEventConsumer): Consumer creation
   - EID 21 (WmiEventConsumerToFilter): Filter-to-consumer binding
2. Generate attack scenario: Fawkes `wmi` command creating persistent WMI subscription
3. Generate benign scenario: SCCM/ConfigMgr legitimate WMI usage
4. Author Sigma rule detecting suspicious WMI event chains
5. Create raw events for Cribl pipeline (if Phase 3 complete)

#### A2: Add File Timestomping (EID 2)

Enables: T1070.006 (Timestomping)

**Steps**:
1. Add Sysmon EID 2 generator: `FileCreateTime` event
2. Attack scenario: Fawkes `timestomp` command modifying file creation time to match system files
3. Benign scenario: Legitimate file operations (copy, extract) that naturally modify timestamps
4. Sigma detection: file creation time changed to a date before the file's actual first-seen date

#### A3: Add Process Tampering (EID 25)

Enables: Improved T1055 evasion detection

**Steps**:
1. Add Sysmon EID 25 generator: Process tampering detection
2. Attack scenario: Process hollowing, herpaderping
3. Link to existing T1055.001 detection as complementary rule

### Group B: Injection Techniques (Fawkes Core Capability)

#### B1: APC Injection (T1055.004)

Fawkes command: `apc-injection`

**Detection approach**:
- Primary: Sysmon EID 8 (CreateRemoteThread) with `QueueUserAPC` call stack
- Secondary: Sysmon EID 10 (Process Access) with `PROCESS_ALL_ACCESS`
- Correlation: Process A opens Process B → writes memory → queues APC

**Steps**:
1. Generate scenario with EID 8/10 events showing APC injection pattern
2. Key indicators: target process is suspended, APC queued to main thread
3. Filter: exclude debuggers (windbg, Visual Studio)
4. Expected FP sources: .NET runtime, some AV products

#### B2: Threadless Injection (T1055 variant)

Fawkes command: `threadless-inject`

**Detection approach**:
- Image load of injected DLL from unusual path
- DLL function hooking (export table modification)
- No CreateRemoteThread — detectable via DLL load anomaly

**Steps**:
1. Generate scenario with EID 7 (Image Load) events
2. Key indicators: DLL loaded from `%TEMP%`, unsigned, first-seen
3. Correlation with EID 10 (process access to target)

#### B3: PoolParty Injection (T1055 variant)

Fawkes command: `poolparty-injection` (8 variants)

**Detection approach**:
- Thread pool manipulation (NtSetInformationWorkerFactory)
- Unusual thread creation patterns
- Limited to behavioral detection (low-signal per event)

**Steps**:
1. Generate behavioral scenario (multiple events over time)
2. Consider threshold rule: unusual thread pool activity from non-system process
3. This may require EQL correlation rule (Phase 4, Task 3A)

### Group C: Zero-Coverage Tactics

#### C1: Discovery Burst Detection (T1087.002 + related)

Fawkes commands: `ps`, `whoami`, `net-enum`, `net-shares`, `net-stat`, `arp`, `ifconfig`

**Detection approach**:
- Threshold rule: 3+ reconnaissance commands from same process tree within 60 seconds
- List of recon binaries: whoami.exe, net.exe, systeminfo.exe, ipconfig.exe, arp.exe, netstat.exe, nltest.exe

**Steps**:
1. Generate scenario: rapid-fire recon (Fawkes `shell` command running multiple discovery tools)
2. Author threshold/EQL rule:
   ```
   sequence by host.name, user.name with maxspan=60s
     [process where process.name in ("whoami.exe", "net.exe", "systeminfo.exe")] with runs=3
   ```
3. Expected FPs: sysadmin troubleshooting, monitoring scripts
4. Filter: exclude known monitoring service accounts

#### C2: Lateral Movement — SOCKS5 Proxy (T1090.001)

Fawkes command: `socks5`

**Detection approach**:
- Unusual outbound connections from Fawkes agent process
- SOCKS5 protocol handshake detection (if network flow available)
- Proxy-like behavior: single process making connections to many internal hosts

**Steps**:
1. Generate scenario: Fawkes agent establishing SOCKS5 tunnel
2. Network connection events (EID 3) showing many internal destinations from one process
3. Threshold: >10 unique internal IPs from non-browser, non-service process in 5 minutes

#### C3: Collection — Clipboard Access (T1115)

Fawkes command: `clipboard`

**Detection approach**:
- API monitoring for `OpenClipboard`, `GetClipboardData`
- Requires ETW or Elastic Endpoint telemetry
- Alternative: detect process accessing clipboard repeatedly (if PowerShell-based)

**Note**: May need to document as DATA_SOURCE_GAP if no ETW available.

### Group D: Expand Beyond Fawkes

#### D1: Scattered Spider TTPs

Already extracted from CISA advisory. Key techniques not covered by Fawkes detections:
- T1078.004: Cloud account abuse (DEPLOYED — but expand)
- T1566.004: Vishing (DEPLOYED)
- T1621: MFA interception (new)
- T1556.006: MFA modification (new)

**Steps**:
1. Review `threat-intel/analysis/scattered-spider/` for extracted TTPs
2. Prioritize techniques with existing data sources
3. Author 3-5 Scattered Spider-specific detections
4. Tag with `[SS]` in coverage matrix

#### D2: Commodity Ransomware Indicators

Build detections for common ransomware behaviors (not Fawkes-specific):
- T1486: Data encrypted for impact (DEPLOYED — expand variants)
- T1490: Inhibit system recovery (VALIDATED — deploy)
- T1489: Service stop (new — `net stop` commands targeting security services)
- T1491.001: Internal defacement (new — ransom note creation)

### Group E: Purple Team Validation

#### E1: Detection Evasion Testing

For each deployed detection, systematically test evasion methods:

| Detection | Evasion Test | Method |
|-----------|-------------|--------|
| T1059.001 PowerShell | Caret insertion | `p^ow^er^sh^ell` |
| T1059.001 PowerShell | String concatenation | `"power" + "shell"` |
| T1547.001 Registry | Direct registry API (no reg.exe) | Use PowerShell `Set-ItemProperty` |
| T1055.001 Injection | Syscall-direct (no API) | Direct NtCreateThreadEx |
| T1071.001 C2 | Domain fronting | CDN-fronted HTTPS |

**Steps**:
1. For each deployed detection, generate 2-3 evasion variant scenarios
2. Run evasion scenarios against detection
3. If detected: good — detection is resilient
4. If evaded: create GitHub issue, link to detection, suggest improvement

#### E2: Coverage Heat Map Visualization

Create a visual representation of detection coverage.

**Steps**:
1. Generate ATT&CK Navigator layer JSON:
   ```json
   {
     "name": "Patronus Lab Coverage",
     "techniques": [
       {"techniqueID": "T1059.001", "color": "#00ff00", "comment": "DEPLOYED"},
       {"techniqueID": "T1055.001", "color": "#ffff00", "comment": "VALIDATED"},
       {"techniqueID": "T1047", "color": "#ff0000", "comment": "NO COVERAGE"}
     ]
   }
   ```
2. Export to `coverage/navigator-layer.json`
3. Can be imported into MITRE ATT&CK Navigator for visualization

---

## Priority Order

| Priority | Group | Techniques | Effort | Impact |
|----------|-------|-----------|--------|--------|
| 1 | B1 | T1055.004 APC Injection | 3h | High (core Fawkes) |
| 2 | C1 | Discovery Burst | 3h | High (0% tactic coverage) |
| 3 | A1 | WMI Events (EID 19-21) | 4h | Medium (unblocks T1047) |
| 4 | C2 | SOCKS5 Proxy | 2h | High (0% lateral movement) |
| 5 | D2 | Ransomware Indicators | 4h | High (universal threat) |
| 6 | B2 | Threadless Injection | 3h | Medium (advanced technique) |
| 7 | D1 | Scattered Spider | 4h | Medium (threat diversity) |
| 8 | E1 | Evasion Testing | 4h | High (quality assurance) |
| 9 | E2 | Navigator Layer | 1h | Low (visualization) |

---

## Verification Checklist

- [ ] 5+ new detections authored and validated
- [ ] At least 1 detection in Lateral Movement tactic
- [ ] At least 1 detection in Collection tactic
- [ ] Discovery burst correlation rule working
- [ ] WMI events (if added) generating correctly
- [ ] Coverage matrix updated with new detections
- [ ] ATT&CK Navigator layer exported
- [ ] Evasion variants tested against top 5 deployed detections

---

## Commit Strategy

Per-technique branches (standard workflow):
- `detection/t1055-004-apc-injection`
- `detection/batch-discovery`
- `detection/t1090-001-socks5-proxy`
- `detection/batch-ransomware`
