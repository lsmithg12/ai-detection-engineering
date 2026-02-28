# AI Detection Engineering Lab

A template for building an **AI-powered detection engineering pipeline** using Claude Code
as an autonomous blue team agent. Deploy a full SIEM lab, generate simulated attack
telemetry, and let an AI agent build, validate, tune, and deploy security detections —
all mapped to the MITRE ATT&CK framework.

## What This Does

An AI agent (Claude Code) acts as a senior detection engineer, executing the full lifecycle:

```
INTEL → DISCOVER → AUTHOR → VALIDATE → DEPLOY → TUNE → REPORT
```

For each detection the agent:
1. Reads threat intel about the Fawkes C2 agent (59 commands mapped to ATT&CK)
2. Discovers available log data in your SIEM
3. Authors a Sigma rule with full MITRE ATT&CK mapping
4. Validates against simulated attack telemetry (true positive + false positive testing)
5. Deploys to Elastic Security and/or Splunk saved searches
6. Tunes based on alert feedback — adding exclusions, tightening thresholds
7. Updates coverage tracking and commits to git with conventional messages

## Lab Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      Lab Network (Docker)                         │
│                                                                    │
│  ┌──────────────┐    ┌─────────────────┐    ┌─────────────────┐  │
│  │ Log Simulator│───▶│  Cribl Stream   │───▶│ Elasticsearch   │  │
│  │ Fawkes TTPs  │    │ :9000 (optional)│    │ :9200           │  │
│  │ + baseline   │    │ CIM normalize   │───▶│ Kibana :5601    │  │
│  └──────────────┘    │ Log reduction   │    └─────────────────┘  │
│         │             │ Route by tactic │                          │
│         │             └─────────────────┘    ┌─────────────────┐  │
│         └───────────────────────────────────▶│ Splunk          │  │
│                                              │ :8000 (optional)│  │
│                      ┌───────────────┐       └─────────────────┘  │
│                      │  Claude Code  │                            │
│                      │  (AI Agent)   │ ◀── MCP: Elasticsearch     │
│                      └───────────────┘                            │
└──────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# 1. Clone the repo
git clone <your-repo-url>
cd ai-detection-engineering

# 2. Run setup (interactive — picks your SIEM, installs tooling)
./setup.sh

# 3. Launch the AI agent
claude
# Paste the first-run prompt from PROMPTS.md
```

See [QUICKSTART.md](QUICKSTART.md) for a detailed walkthrough.

## Startup Options

| Command | What Runs |
|---|---|
| `./setup.sh --elastic` | Elasticsearch + Kibana + Simulator |
| `./setup.sh --splunk` | Splunk + Simulator |
| `./setup.sh --both` | Both SIEMs + Simulator |
| `./setup.sh --cribl` | Elastic + Cribl Stream + Simulator |
| `./setup.sh --full` | Everything |

Or use `make setup` for the same interactive experience.

## Credentials

| Service | URL | Username | Password |
|---|---|---|---|
| Kibana | http://localhost:5601 | elastic | changeme |
| Elasticsearch | http://localhost:9200 | elastic | changeme |
| Splunk Web | http://localhost:8000 | admin | BlueTeamLab1! |
| Splunk REST API | https://localhost:8089 | admin | BlueTeamLab1! |
| Splunk HEC | http://localhost:8288 | — | blue-team-lab-hec-token |
| Cribl Stream | http://localhost:9000 | admin | admin |

## Data Sources

### Simulated Telemetry (Always Available)

| Index (Elastic) | Index (Splunk) | Content |
|---|---|---|
| `sim-baseline` | `sysmon` | Normal enterprise Windows/Linux activity |
| `sim-attack` | `attack_simulation` | Fawkes C2 TTP simulations |

Event types generated: Sysmon EID 1, 3, 7, 8, 10, 13 + WinEvent 4624

### Attack Scenarios

The simulator generates 8 attack scenarios matching Fawkes C2 capabilities:
- Process injection (vanilla-injection) — EID 8 + 10
- Registry persistence — EID 13
- PowerShell with bypass flags — EID 1
- Scheduled task creation — EID 1
- Discovery command burst — EID 1
- LSASS token theft — EID 10
- C2 beaconing — EID 3
- AMSI/CLR bypass — EID 7

## Primary Threat: Fawkes C2 Agent

[Fawkes](https://github.com/galoryber/fawkes) is a Golang-based Mythic C2 agent with 59 commands:

| Category | Commands | ATT&CK Techniques |
|---|---|---|
| Process Injection | vanilla-injection, apc-injection, threadless-inject, poolparty, opus | T1055.001-005 |
| Credential Access | steal-token, make-token, keylog | T1134.001, T1056.001 |
| Persistence | persist (registry, startup, schtask, service, crontab) | T1547.001, T1053.005 |
| Defense Evasion | autopatch, start-clr, timestomp, binary-inflation | T1562.001, T1027 |
| Discovery | ps, whoami, net-enum, arp, ifconfig, av-detect | T1057, T1033, T1087 |
| Lateral Movement | socks5, wmi | T1090, T1047 |
| C2 | sleep, domain-fronting, tls-cert-pin | T1071.001 |

Full TTP mapping: [threat-intel/fawkes/fawkes-ttp-mapping.md](threat-intel/fawkes/fawkes-ttp-mapping.md)

## Project Structure

```
ai-detection-engineering/
├── CLAUDE.md                    # AI agent instructions (role, workflow, guardrails)
├── PROMPTS.md                   # Starter prompts for the agent
├── QUICKSTART.md                # New user walkthrough
├── docker-compose.yml           # Lab infrastructure (Elastic, Splunk, Cribl, Simulator)
├── setup.sh                     # One-command interactive setup
├── Makefile                     # Quick commands (make setup, make agent, etc.)
├── simulator/                   # Log generator (Fawkes TTPs + baseline)
├── cribl/                       # Cribl Stream MCP server + config
├── pipeline/                    # Deployment & automation scripts
├── detections/                  # Detection-as-Code (Sigma rules by MITRE tactic)
│   └── <tactic>/compiled/       # Transpiled KQL/SPL
├── tests/                       # True positive & true negative test cases
├── templates/                   # Sigma rule template
├── threat-intel/fawkes/         # Fawkes C2 → ATT&CK TTP mapping
├── coverage/                    # ATT&CK coverage matrix & detection backlog
├── gaps/                        # Data source and detection gaps
├── tuning/                      # Exclusion lists & tuning changelog
└── mcp-config.example.json      # MCP server config template
```

## MCP Configuration

The AI agent uses MCP (Model Context Protocol) for direct Elasticsearch access and
optionally GitHub/GitLab for PR workflows:

```bash
# Copy the template to the project root
cp mcp-config.example.json .mcp.json

# Edit .mcp.json and optionally add your GitHub/GitLab PAT
```

The Elasticsearch MCP server runs as a Docker container on the `blue-team-lab` network.

## Cribl Stream (Optional)

When running with `--cribl`, Cribl Stream provides:
- **CIM normalization**: ECS fields mapped to Splunk CIM aliases
- **Log reduction**: Drop noisy baseline events before indexing
- **Routing**: Attack events to both SIEMs, baseline to Elastic only
- **Attack enrichment**: MITRE technique tags added to events

Configure Cribl: `./pipeline/configure-cribl.sh`

## Prerequisites

- **Docker Desktop** (macOS/Windows) or Docker Engine + Compose (Linux)
- **Git**
- **~8 GB RAM**, ~20 GB free disk
- **Claude Pro subscription** (includes Claude Code)
- **Python + pip** (optional — for sigma-cli transpilation)

## Using as a Template

This project is designed to be forked/cloned and customized:

1. **Fork or clone** this repo
2. **Run `./setup.sh`** to start the lab
3. **Launch Claude Code** and paste a prompt from `PROMPTS.md`
4. **Watch** the agent discover data, review threat intel, and build detections
5. **Customize**: swap Fawkes for your own threat model, add data sources, etc.

### Customizing the Threat Model

To target a different adversary:
1. Replace `threat-intel/fawkes/` with your own TTP mapping
2. Update `coverage/detection-backlog.md` with your priority techniques
3. Update `CLAUDE.md` to reference your threat actor
4. Modify `simulator/simulator.py` to generate matching attack telemetry

## Useful Commands

```bash
# Lab management
docker compose ps                           # Check service status
docker compose logs -f log-simulator        # Watch simulated events
docker compose down                         # Stop everything
docker compose down -v                      # Full reset (delete all data)

# Elasticsearch
curl -u elastic:changeme http://localhost:9200/_cluster/health
curl -u elastic:changeme http://localhost:9200/sim-attack/_count

# Splunk
curl -sk https://localhost:8089/services/server/health -u admin:BlueTeamLab1!

# Sigma transpilation
sigma convert -t lucene -p ecs_windows detections/<tactic>/<rule>.yml
sigma convert -t splunk --without-pipeline detections/<tactic>/<rule>.yml
```

## License

This project is licensed under [MIT](LICENSE).

Third-party components (Elasticsearch, Splunk, Cribl, etc.) have their own licenses.
See [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md) for details. No third-party
binaries are redistributed — Docker pulls official images at runtime.
