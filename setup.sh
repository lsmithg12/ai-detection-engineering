#!/usr/bin/env bash
# =============================================================================
# Blue Team Detection Engineering Lab — One-Command Setup
#
# Usage:
#   ./setup.sh                    # Interactive — asks what you want
#   ./setup.sh --elastic          # Elastic + simulator
#   ./setup.sh --splunk           # Splunk + simulator
#   ./setup.sh --both             # Both SIEMs + simulator
#   ./setup.sh --cribl            # Elastic + Cribl Stream + simulator
#   ./setup.sh --full             # Both SIEMs + Cribl + simulator
#
# Credentials:
#   Elastic:  elastic / changeme    → http://localhost:5601
#   Splunk:   admin / BlueTeamLab1! → http://localhost:8000
#   Cribl:    admin / admin    → http://localhost:9000
#
# Prerequisites: Docker Desktop, Git
# Note: On Windows, run this in Git Bash or WSL2
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║       Blue Team Detection Engineering Lab                    ║${NC}"
    echo -e "${CYAN}║       Autonomous Detection Agent — Claude Code               ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

log_info()  { echo -e "${BLUE}[*]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
log_err()   { echo -e "${RED}[✗]${NC} $1"; }
log_step()  { echo -e "\n${CYAN}━━━ $1 ━━━${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# ─── Parse Arguments ─────────────────────────────────────────────
SIEM_MODE=""
INCLUDE_SIMULATOR=true
INCLUDE_CRIBL=false
SKIP_CHECKS=false

for arg in "$@"; do
    case "$arg" in
        --elastic)  SIEM_MODE="elastic" ;;
        --splunk)   SIEM_MODE="splunk" ;;
        --both)     SIEM_MODE="both" ;;
        --cribl)    SIEM_MODE="elastic"; INCLUDE_CRIBL=true ;;
        --full)     SIEM_MODE="both"; INCLUDE_CRIBL=true ;;
        --no-sim)   INCLUDE_SIMULATOR=false ;;
        --skip-checks) SKIP_CHECKS=true ;;
        --help|-h)
            echo "Usage: $0 [--elastic|--splunk|--both|--cribl|--full] [--no-sim] [--skip-checks]"
            echo ""
            echo "  --elastic      Elastic SIEM (Elasticsearch + Kibana)"
            echo "  --splunk       Splunk SIEM (free 500MB/day)"
            echo "  --both         Both SIEMs side-by-side"
            echo "  --cribl        Elastic + Cribl Stream log pipeline"
            echo "  --full         All SIEMs + Cribl Stream"
            echo "  --no-sim       Skip the log simulator"
            echo "  --skip-checks  Skip prerequisite checks"
            exit 0
            ;;
    esac
done

banner

# Windows notice
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    log_warn "Running on Windows. Using Git Bash is recommended."
    log_warn "If Docker commands fail, ensure Docker Desktop is running."
    echo ""
fi

# ─── Interactive Mode ────────────────────────────────────────────
if [ -z "$SIEM_MODE" ]; then
    echo "Which SIEM would you like to use?"
    echo ""
    echo "  1) Elastic  (Elasticsearch + Kibana — fully free, good API)"
    echo "  2) Splunk   (Free tier 500MB/day — matches most corp environments)"
    echo "  3) Both     (Run both side-by-side, detections work in either)"
    echo "  4) Cribl    (Elastic + Cribl Stream log pipeline — full lifecycle)"
    echo ""
    read -p "Choose [1/2/3/4]: " choice
    case "$choice" in
        1) SIEM_MODE="elastic" ;;
        2) SIEM_MODE="splunk" ;;
        3) SIEM_MODE="both" ;;
        4) SIEM_MODE="elastic"; INCLUDE_CRIBL=true ;;
        *) log_err "Invalid choice"; exit 1 ;;
    esac
    echo ""
fi

# ─── Prerequisite Checks ────────────────────────────────────────
if [ "$SKIP_CHECKS" = false ]; then
    log_step "Checking Prerequisites"

    MISSING=()

    if ! command -v docker &>/dev/null; then
        MISSING+=("docker")
        log_err "Docker not found. Install Docker Desktop: https://www.docker.com/products/docker-desktop/"
    else
        log_ok "Docker: $(docker --version | head -1)"
    fi

    if ! docker compose version &>/dev/null 2>&1; then
        MISSING+=("docker-compose-v2")
        log_err "Docker Compose v2 not found. Update Docker Desktop."
    else
        log_ok "Docker Compose: $(docker compose version --short 2>/dev/null || echo 'v2')"
    fi

    if ! command -v git &>/dev/null; then
        MISSING+=("git")
    else
        log_ok "Git: $(git --version)"
    fi

    if ! command -v node &>/dev/null; then
        log_warn "Node.js not found — needed for GitHub MCP server (optional)"
    else
        log_ok "Node.js: $(node --version)"
    fi

    # Check available memory (Linux/Mac only)
    if command -v free &>/dev/null; then
        TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
        if [ "$TOTAL_MEM" -lt 4000 ]; then
            log_warn "Only ${TOTAL_MEM}MB RAM available. Recommend 8GB+ for smooth operation."
        else
            log_ok "Memory: ${TOTAL_MEM}MB available"
        fi
    fi

    if [ ${#MISSING[@]} -gt 0 ]; then
        log_err "Missing prerequisites: ${MISSING[*]}"
        echo "    Install these and re-run setup."
        exit 1
    fi

    # Verify Docker daemon is running
    if ! docker info &>/dev/null 2>&1; then
        log_err "Docker daemon is not running. Start Docker Desktop and try again."
        exit 1
    fi
fi

# ─── Install Cribl MCP Server Dependencies ──────────────────────
if command -v node &>/dev/null && [ -f "cribl/mcp-server/package.json" ]; then
    log_step "Installing Cribl MCP Server"
    log_info "Installing Node.js dependencies for Cribl MCP server..."
    (cd cribl/mcp-server && npm install --quiet 2>/dev/null) && \
        log_ok "Cribl MCP server ready (cribl/mcp-server/index.js)" || \
        log_warn "npm install failed — run manually: cd cribl/mcp-server && npm install"
fi

# ─── Install Python Tools (optional, skip if pip not available) ─
log_step "Installing Detection Tooling"

if command -v pip3 &>/dev/null || command -v pip &>/dev/null; then
    PIP=$(command -v pip3 || command -v pip)
    if ! command -v sigma &>/dev/null; then
        log_info "Installing sigma-cli..."
        $PIP install sigma-cli --break-system-packages --quiet 2>/dev/null || \
        $PIP install sigma-cli --quiet 2>/dev/null || \
        log_warn "sigma-cli install failed — install manually: pip install sigma-cli"
    fi

    if command -v sigma &>/dev/null; then
        log_info "Installing Sigma backends..."
        sigma plugin install elasticsearch 2>/dev/null || true
        sigma plugin install splunk 2>/dev/null || true
        log_ok "sigma-cli ready with Elastic + Splunk backends"
    fi
else
    log_warn "pip not found — sigma-cli not installed (needed for rule transpilation)"
    log_warn "Install Python + pip, then: pip install sigma-cli"
fi

# ─── Scaffold Directory Structure ───────────────────────────────
log_step "Scaffolding Repository Directories"

DIRS=(
    "detections/credential_access/compiled"
    "detections/defense_evasion/compiled"
    "detections/discovery/compiled"
    "detections/execution/compiled"
    "detections/lateral_movement/compiled"
    "detections/persistence/compiled"
    "detections/privilege_escalation/compiled"
    "detections/collection/compiled"
    "detections/command_and_control/compiled"
    "tests/true_positives"
    "tests/true_negatives"
    "tuning/changelog"
    "pipeline"
    "monitoring"
    "splunk/apps"
)

for dir in "${DIRS[@]}"; do
    mkdir -p "$dir"
    # Create .gitkeep if empty
    if [ -z "$(ls -A "$dir" 2>/dev/null)" ]; then
        touch "$dir/.gitkeep"
    fi
done
log_ok "Directory structure ready"

# ─── Build Docker Profiles ──────────────────────────────────────
log_step "Building Lab Infrastructure"

PROFILES=()
case "$SIEM_MODE" in
    elastic) PROFILES=("--profile" "elastic") ;;
    splunk)  PROFILES=("--profile" "splunk") ;;
    both)    PROFILES=("--profile" "elastic" "--profile" "splunk") ;;
esac

if [ "$INCLUDE_CRIBL" = true ]; then
    PROFILES+=("--profile" "cribl")
fi

if [ "$INCLUDE_SIMULATOR" = true ]; then
    PROFILES+=("--profile" "simulator")
fi

log_info "Building containers (first run downloads images — may take a few minutes)..."
docker compose "${PROFILES[@]}" build 2>&1 | tail -5

log_info "Starting services..."
docker compose "${PROFILES[@]}" up -d

# ─── Wait for Services ──────────────────────────────────────────
log_step "Waiting for Services to Initialize"

if [[ "$SIEM_MODE" == "elastic" || "$SIEM_MODE" == "both" ]]; then
    log_info "Waiting for Elasticsearch (auth: elastic/changeme)..."
    for i in $(seq 1 60); do
        if curl -sf -u elastic:changeme http://localhost:9200/_cluster/health 2>/dev/null | grep -qE '"status":"(green|yellow)"'; then
            log_ok "Elasticsearch is ready"
            break
        fi
        [ "$i" -eq 60 ] && log_warn "Elasticsearch may still be starting — check: curl -u elastic:changeme http://localhost:9200"
        sleep 5
    done

    log_info "Waiting for Kibana..."
    for i in $(seq 1 60); do
        if curl -sf http://localhost:5601/api/status 2>/dev/null | grep -q '"level":"available"'; then
            log_ok "Kibana is ready → http://localhost:5601 (elastic / changeme)"
            break
        fi
        [ "$i" -eq 60 ] && log_warn "Kibana still starting — check http://localhost:5601"
        sleep 5
    done
fi

if [[ "$SIEM_MODE" == "splunk" || "$SIEM_MODE" == "both" ]]; then
    log_info "Waiting for Splunk (this takes ~2-3 min)..."
    SPLUNK_READY=false
    for i in $(seq 1 90); do
        if curl -sf -k https://localhost:8089/services/server/health -u admin:BlueTeamLab1! &>/dev/null; then
            log_ok "Splunk is ready → http://localhost:8000 (admin / BlueTeamLab1!)"
            SPLUNK_READY=true
            break
        fi
        [ "$i" -eq 90 ] && log_warn "Splunk still starting — check http://localhost:8000"
        sleep 5
    done

    # Create simulation indexes (default.yml index creation is unreliable)
    if [ "$SPLUNK_READY" = true ]; then
        log_info "Creating Splunk indexes..."
        for idx in sysmon attack_simulation wineventlog linux network; do
            curl -sf -k -u admin:BlueTeamLab1! -X POST "https://localhost:8089/services/data/indexes" \
                -d name="$idx" -d datatype=event > /dev/null 2>&1 || true
        done
        log_ok "Splunk indexes created (sysmon, attack_simulation, wineventlog, linux, network)"
    fi
fi

if [ "$INCLUDE_CRIBL" = true ]; then
    log_info "Waiting for Cribl Stream..."
    CRIBL_READY=false
    for i in $(seq 1 30); do
        if curl -sf http://localhost:9000/api/v1/health 2>/dev/null | grep -q '"healthy"'; then
            log_ok "Cribl Stream is ready → http://localhost:9000 (admin / admin)"
            CRIBL_READY=true
            break
        fi
        [ "$i" -eq 30 ] && log_warn "Cribl Stream still starting — check http://localhost:9000"
        sleep 5
    done

    if [ "$CRIBL_READY" = true ] && [ -f "pipeline/configure-cribl.sh" ]; then
        log_info "Auto-configuring Cribl Stream pipeline..."
        bash pipeline/configure-cribl.sh 2>&1 | grep -E '^\s+\[' || \
            log_warn "Cribl auto-config had issues — open http://localhost:9000 to configure manually"
    fi
fi

# ─── Elasticsearch Index Template ───────────────────────────────
if [[ "$SIEM_MODE" == "elastic" || "$SIEM_MODE" == "both" ]] && [ "$INCLUDE_SIMULATOR" = true ]; then
    log_step "Creating Elasticsearch Index Templates"

    # The simulator auto-creates its own template on startup.
    # This is a belt-and-suspenders creation in case the sim hasn't run yet.
    curl -sf -u elastic:changeme -X PUT "http://localhost:9200/_index_template/sim-logs" \
        -H "Content-Type: application/json" \
        -d '{
      "index_patterns": ["sim-*"],
      "priority": 500,
      "template": {
        "settings": {"number_of_shards": 1, "number_of_replicas": 0},
        "mappings": {
          "properties": {
            "@timestamp":               {"type": "date"},
            "agent.type":               {"type": "keyword"},
            "event.category":           {"type": "keyword"},
            "event.type":               {"type": "keyword"},
            "event.action":             {"type": "keyword"},
            "event.code":               {"type": "keyword"},
            "process.pid":              {"type": "long"},
            "process.name":             {"type": "keyword"},
            "process.executable":       {"type": "keyword"},
            "process.command_line":     {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
            "process.parent.pid":       {"type": "long"},
            "process.parent.name":      {"type": "keyword"},
            "process.parent.executable":{"type": "keyword"},
            "user.name":                {"type": "keyword"},
            "user.domain":              {"type": "keyword"},
            "host.name":                {"type": "keyword"},
            "host.os.platform":         {"type": "keyword"},
            "source.ip":                {"type": "ip"},
            "destination.ip":           {"type": "ip"},
            "destination.port":         {"type": "long"},
            "registry.path":            {"type": "keyword"},
            "registry.value":           {"type": "keyword"},
            "file.name":                {"type": "keyword"},
            "file.path":                {"type": "keyword"},
            "network.direction":        {"type": "keyword"},
            "winlog.logon.id":          {"type": "keyword"},
            "winlog.logon.type":        {"type": "keyword"},
            "winlog.event_data.TargetUserName": {"type": "keyword"},
            "winlog.event_data.LogonType":      {"type": "keyword"},
            "_simulation.type":         {"type": "keyword"},
            "_simulation.technique":    {"type": "keyword"},
            "_simulation.fawkes_command":{"type": "keyword"},
            "_simulation.label":        {"type": "keyword"}
          }
        }
      }
    }' > /dev/null 2>&1 && log_ok "Index template 'sim-*' created" || log_warn "Template may already exist"
fi

# ─── Load Attack Range Sample Data (if available) ───────────────
if [ -d "pipeline/attack-range-data" ] && [[ "$SIEM_MODE" == "splunk" || "$SIEM_MODE" == "both" ]]; then
    log_step "Loading Splunk Attack Range Sample Data"
    if [ -f "pipeline/ingest-attack-range.sh" ]; then
        bash pipeline/ingest-attack-range.sh 2>&1 | grep -E '^\[' || true
    fi
fi

# ─── MCP Configuration ──────────────────────────────────────────
log_step "Configuring MCP for Claude Code"

if [ ! -f ".mcp.json" ]; then
    # Build .mcp.json dynamically based on available tools
    MCP_SERVERS='    "elasticsearch": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--network", "blue-team-lab",
        "-e", "ES_URL=http://elastic:changeme@elasticsearch:9200",
        "docker.elastic.co/mcp/elasticsearch"
      ]
    }'

    if command -v node &>/dev/null; then
        if [ "$INCLUDE_CRIBL" = true ]; then
            MCP_SERVERS="$MCP_SERVERS"',
    "cribl": {
      "command": "node",
      "args": ["./cribl/mcp-server/index.js"],
      "env": {
        "CRIBL_URL":   "http://localhost:9000",
        "CRIBL_USER":  "admin",
        "CRIBL_PASS":  "admin"
      }
    }'
        fi
        MCP_SERVERS="$MCP_SERVERS"',
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "<YOUR_GITHUB_PAT>"
      }
    }'
        log_warn "Edit .mcp.json and replace <YOUR_GITHUB_PAT> with your Personal Access Token"
        log_warn "Create a PAT at: https://github.com/settings/tokens (scopes: repo, issues, pull_requests)"
    else
        log_warn "Node.js not installed — GitHub and Cribl MCP servers not added to .mcp.json"
        log_warn "Install Node.js and re-run setup, or copy entries from mcp-config.example.json"
    fi

    cat > .mcp.json <<MCPEOF
{
  "mcpServers": {
$MCP_SERVERS
  }
}
MCPEOF
    log_ok "MCP config generated at .mcp.json"
else
    log_ok ".mcp.json already exists (not overwritten)"
fi

# ─── Git Check ─────────────────────────────────────────────────
log_step "Git Repository"

if [ ! -d ".git" ]; then
    git init
    git add .
    git commit -m "chore: initial project scaffolding

Blue Team Detection Engineering Lab
- Docker Compose with Elastic/Splunk/Cribl support
- Log simulator with Fawkes TTP attack scenarios
- Detection-as-Code framework with Sigma rules
- MITRE ATT&CK coverage tracking"
    log_ok "Git repo initialized with initial commit"
    log_warn "Add your remote: git remote add origin <your-repo-url>"
else
    log_ok "Git repo already initialized ($(git branch --show-current 2>/dev/null || echo 'detached'))"
fi

# ─── Summary ─────────────────────────────────────────────────────
log_step "Setup Complete!"

echo ""
echo -e "${GREEN}Your lab is running:${NC}"
echo ""

if [[ "$SIEM_MODE" == "elastic" || "$SIEM_MODE" == "both" ]]; then
    echo -e "  ${CYAN}Kibana${NC}:          http://localhost:5601"
    echo -e "  ${CYAN}               ${NC}   Login: ${YELLOW}elastic${NC} / ${YELLOW}changeme${NC}"
    echo -e "  ${CYAN}Elasticsearch${NC}:   http://localhost:9200"
    echo -e "  ${CYAN}               ${NC}   Auth:  ${YELLOW}elastic${NC} / ${YELLOW}changeme${NC}"
fi

if [[ "$SIEM_MODE" == "splunk" || "$SIEM_MODE" == "both" ]]; then
    echo -e "  ${CYAN}Splunk Web${NC}:      http://localhost:8000"
    echo -e "  ${CYAN}               ${NC}   Login: ${YELLOW}admin${NC} / ${YELLOW}BlueTeamLab1!${NC}"
    echo -e "  ${CYAN}Splunk API${NC}:      https://localhost:8089"
    echo -e "  ${CYAN}HEC Token${NC}:       ${YELLOW}blue-team-lab-hec-token${NC}"
fi

if [ "$INCLUDE_CRIBL" = true ]; then
    echo -e "  ${CYAN}Cribl Stream${NC}:    http://localhost:9000"
    echo -e "  ${CYAN}               ${NC}   Login: ${YELLOW}admin${NC} / ${YELLOW}admin${NC}"
fi

if [ "$INCLUDE_SIMULATOR" = true ]; then
    echo ""
    echo -e "  ${CYAN}Log Simulator${NC}:   Running (mixed mode — baseline + attack bursts)"
    echo -e "               ${NC}    Indices: ${YELLOW}sim-baseline${NC} / ${YELLOW}sim-attack${NC}"
fi

echo ""
echo -e "${GREEN}Next steps:${NC}"
echo ""
echo "  1. Open Claude Code in this directory:"
echo -e "     ${YELLOW}claude${NC}"
echo ""
echo "  2. Paste the first-run prompt from PROMPTS.md"
echo ""
echo "  3. The agent will discover data, review Fawkes intel, and"
echo "     start building detections autonomously"
echo ""

echo -e "${CYAN}Quick commands:${NC}"
echo "  docker compose logs -f log-simulator    # Watch simulated events"
echo "  docker compose ps                       # Check service status"
echo "  docker compose down                     # Stop everything"
echo "  docker compose down -v                  # Stop + delete data (full reset)"
echo ""
echo -e "${YELLOW}Indices:${NC} sim-baseline (normal activity) | sim-attack (Fawkes TTPs)"
echo ""
