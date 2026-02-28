# Data Source Inventory — Blue Team Detection Lab

**Last updated**: _run setup.sh to populate_
**SIEM status**: _not yet started_
**Cluster**: blue-team-lab (single node)
**Note**: Run `./setup.sh` then use the first-run prompt from PROMPTS.md to validate data sources

---

## Infrastructure Status

| Component | Status | URL | Notes |
|---|---|---|---|
| Elasticsearch | ONLINE | http://localhost:9200 | v8.17.0, cluster=blue-team-lab, green |
| Kibana | ONLINE | http://localhost:5601 | v8.17.0, status=available |
| Splunk | ONLINE | http://localhost:8000 | v9.3.9, REST on 8089, HEC on 8288 |
| Cribl Stream | NOT STARTED | http://localhost:9000 | Available via `--cribl` profile |
| Log Simulator | RUNNING | — | mixed mode, 5 EPS baseline + attack bursts every 300s |
| GitHub MCP | NOT CONFIGURED | — | Set PAT in .mcp.json (copy from mcp-config.example.json) |

**Index template**: `sim-logs` (priority 500) applied to `sim-*`
**Note**: Renamed from `logs-simulation-*` to `sim-*` to avoid Elastic 8.x data stream auto-creation.
Simulator creates the template on startup; setup.sh also creates it as a belt-and-suspenders measure.

---

## Available Indices (Live — Confirmed)

| Index | Source | Data Type | Volume | Validated |
|---|---|---|---|---|
| `sim-baseline` | log-simulator | Baseline Windows/Linux ECS events | ~5 EPS continuous | Yes |
| `sim-attack` | log-simulator | Fawkes TTP attack scenarios (ECS) | Burst every 300s | Yes |
| `attack-range-samples` | fetch-attack-range-data.sh | ATT&CK sim events (AtomicRedTeam) | Static on import | Optional |
| `sim-*` (via Cribl) | Cribl Stream pipeline | Same indices, routed via Cribl | ~5 EPS when Cribl active | Optional |
| `.internal.alerts-security.alerts-default-000001` | Elastic Security | Generated security alerts | On rule fire | Index exists, 0 alerts |

**Elasticsearch auth**: `elastic` / `changeme`
```bash
curl -u elastic:changeme http://localhost:9200/sim-baseline/_count
curl -u elastic:changeme http://localhost:9200/sim-attack/_count
```

---

## Event Types by Sysmon Event ID

### Confirmed Present in Simulation

| Sysmon EID | ECS Event Code | Event Name | Fields Available | Used By Detections |
|---|---|---|---|---|
| 1 | `"1"` | Process Create | `process.name`, `process.executable`, `process.command_line`, `process.parent.name`, `process.parent.executable`, `user.name`, `user.domain`, `host.name` | T1059.001, T1053.005, T1087, T1033, T1057 |
| 3 | `"3"` | Network Connect | `source.ip`, `source.port`, `destination.ip`, `destination.port`, `network.direction`, `network.transport`, `process.name` | T1071.001 |
| 7 | `"7"` | Image Load | `file.name`, `file.path`, `process.name`, `process.executable` | T1562.001 |
| 8 | `"8"` | CreateRemoteThread | `process.name`, `process.executable`, `winlog.event_data.TargetImage`, `winlog.event_data.StartAddress` | T1055.001 |
| 10 | `"10"` | Process Access | `process.name`, `process.executable`, `winlog.event_data.TargetImage`, `winlog.event_data.GrantedAccess` | T1055.001, T1134.001 |
| 13 | `"13"` | Registry Value Set | `registry.path`, `registry.value`, `process.name`, `process.command_line` | T1547.001 |
| 4624 | `"4624"` | Windows Logon | `winlog.logon.type`, `winlog.logon.id`, `user.name`, `user.domain`, `source.ip`, `event.outcome` | T1134.003 |

### Missing from Simulation (Gap)

| Sysmon EID | Event Name | Needed For | Gap Severity |
|---|---|---|---|
| 2 | File creation time change | T1070.006 timestomping | Medium |
| 5 | Process terminate | Process lifecycle correlation | Low |
| 11 | File create | Startup folder persistence (T1547.001), file drops | High |
| 12/14 | Registry create/delete | Registry persistence (T1547.001) full coverage | Medium |
| 17/18 | Pipe created/connected | Named pipe-based C2, lateral movement | High |
| 19/20/21 | WMI events | T1047 WMI execution | High |
| 22 | DNS query | T1071.001 domain fronting, C2 DNS | High |
| 23 | File delete | Anti-forensics, timestomping | Low |
| 25 | Process tampering | T1055 injection detection aid | High |
| 7045 | Service install | T1543.003 Windows service creation | High |

---

## ECS Field Reference (Simulation Schema)

The simulation uses ECS (Elastic Common Schema) with these core field groups:

### Process Fields
```
process.pid              (long)
process.name             (keyword)
process.executable       (keyword)
process.command_line     (text + keyword)
process.parent.pid       (long)
process.parent.name      (keyword)
process.parent.executable (keyword)
```

### Event Fields
```
event.category           (keyword) — process | network | registry | authentication
event.type               (keyword) — start | stop | change | access | connection
event.action             (keyword) — human-readable action name
event.code               (keyword) — Sysmon EID or Windows Event ID
event.outcome            (keyword) — success | failure
```

### User / Host / Agent
```
user.name                (keyword)
user.domain              (keyword)
host.name                (keyword)
host.os.platform         (keyword) — windows | linux
agent.type               (keyword) — sysmon | winlogbeat | auditbeat  ✓ fixed in sim-logs template
```

### Registry (Sysmon EID 13)
```
registry.path            (keyword)
registry.value           (keyword)
```

### Network (Sysmon EID 3)
```
source.ip                (ip)
source.port              (long)
destination.ip           (ip)
destination.port         (long)
network.direction        (keyword)
network.transport        (keyword)
```

### File (Sysmon EID 7)
```
file.name                (keyword)
file.path                (keyword)
```

### Winlog (Sysmon supplementary fields)
```
winlog.event_data.TargetImage      (keyword)
winlog.event_data.GrantedAccess    (keyword)
winlog.event_data.StartAddress     (keyword)
winlog.logon.type                  (keyword)
winlog.logon.id                    (keyword)
```

### Simulation Metadata
```
_simulation.type              (keyword) — baseline | attack
_simulation.technique         (keyword) — MITRE technique ID (e.g., T1055.001)
_simulation.fawkes_command    (keyword) — Fawkes command name
_simulation.label             (keyword) — short human label
```

---

## Agent Types in Simulation

| Agent | Data Generated | Index |
|---|---|---|
| `sysmon` | Process, network, registry, image load, injection events | `sim-*` |
| `winlogbeat` | Authentication events (EID 4624) | `sim-*` |
| `auditbeat` | Linux process events | `sim-*` |

---

## Data Source Gaps vs. Fawkes Capabilities

| Fawkes Capability | Required Data Source | Status |
|---|---|---|
| vanilla-injection (T1055.001) | Sysmon EID 8 + 10 | AVAILABLE |
| powershell (T1059.001) | Sysmon EID 1 | AVAILABLE |
| persist-registry (T1547.001) | Sysmon EID 13 | AVAILABLE |
| steal-token (T1134.001) | Sysmon EID 10 (LSASS access) | AVAILABLE |
| sleep/beacon (T1071.001) | Sysmon EID 3 | AVAILABLE |
| schtask (T1053.005) | Sysmon EID 1 | AVAILABLE |
| start-clr/autopatch (T1562.001) | Sysmon EID 7 | AVAILABLE |
| net-enum/whoami (T1087.002) | Sysmon EID 1 | AVAILABLE |
| apc-injection (T1055.004) | Sysmon EID 8 | PARTIAL — EID 8 not explicitly labelled |
| service (T1543.003) | Windows EID 7045 | GAP — not in simulation |
| persist startup-folder (T1547.001) | Sysmon EID 11 | GAP — not in simulation |
| timestomp (T1070.006) | Sysmon EID 2 | GAP — not in simulation |
| wmi (T1047) | Sysmon EID 19/20/21 | GAP — not in simulation |
| keylog (T1056.001) | ETW / Sysmon EID 10 | GAP — not in simulation |
| make-token (T1134.003) | Windows EID 4688 / 4624 | PARTIAL — logon EID 4624 present |
| inline-assembly (T1620) | Sysmon EID 7 (.NET CLR DLLs) | AVAILABLE (CLR detection) |
| socks5 (T1090.001) | Sysmon EID 3 | AVAILABLE |
| clipboard (T1115) | ETW / API monitoring | GAP |
| screenshot (T1113) | File write events | GAP |

---

## Live Validation Results (2026-02-25)

**Baseline index** (`sim-baseline`):
- ~5 EPS continuous
- Event codes: `1` (ProcessCreate), `3` (NetworkConnect), `13` (RegistryValueSet), `4624` (Logon)
- Categories: process, network, registry, authentication
- Labels: normal_process_create, normal_network, normal_linux, normal_logon, normal_registry
- Agent types: sysmon, winlogbeat, auditbeat

**Attack index** (`sim-attack`):
- Attack bursts every 300s (configurable via `SIM_ATTACK_INTERVAL`)
- Techniques: T1055.001, T1059.001, T1134.001, T1547.001, T1053.005, T1562.001, T1071.001, T1087+T1057+T1033+T1016 (discovery burst)
- Event codes generated: EID 1, 3, 7, 8, 10, 13 (all 8 attack scenarios confirmed in simulator.py)

**Field mapping** (resolved in rebaseline):
- ✓ `agent.type`: keyword (was text)
- ✓ `winlog.logon.id`: keyword (was text)
- ✓ `winlog.logon.type`: keyword (was text)
- Fixed via `sim-logs` index template (priority 500) — auto-created by simulator on startup

## Next Steps

1. ~~Start lab~~ — DONE (--both: Elastic + Splunk + simulator)
2. ~~Verify indices~~ — DONE (sim-baseline + sim-attack confirmed)
3. ~~Fix field mappings~~ — DONE (sim-logs template)
4. ~~Configure GitHub MCP~~ — DONE (PAT in .mcp.json, gitignored; mcp-config.example.json committed)
5. **Start building detections** — see `coverage/detection-backlog.md` rank 1 (T1055.001)
6. **(Optional)** Load Attack Range data: `./pipeline/fetch-attack-range-data.sh samples`
7. **(Optional)** Enable Cribl: `./setup.sh --cribl` then `./pipeline/configure-cribl.sh`
