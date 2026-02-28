#!/usr/bin/env bash
# =============================================================================
# Cribl Stream — Auto-Configure for Blue Team Lab
#
# Sets up Cribl Stream as a log pipeline between the simulator and SIEMs:
#   Simulator → Cribl HEC (port 8088) → Elastic (9200) + Splunk (8088)
#
# Cribl pipeline features configured:
#   1. HEC input (receives from simulator/forwarders on port 8088)
#   2. CIM normalization pipeline (ECS → Splunk CIM field mapping)
#   3. Log reduction (drop noisy svchost/MsMpEng events)
#   4. Elasticsearch output destination
#   5. Splunk HEC output destination (optional — if Splunk is running)
#   6. Routing rules (attack events → both SIEMs, baseline → Elastic only)
#
# Usage: ./pipeline/configure-cribl.sh
# Run AFTER Cribl is healthy (setup.sh calls this automatically)
# =============================================================================

set -euo pipefail

CRIBL_URL="${CRIBL_URL:-http://localhost:9000}"
CRIBL_USER="${CRIBL_USER:-admin}"
CRIBL_PASS="${CRIBL_PASS:-admin}"
ES_URL="${ES_URL:-http://elasticsearch:9200}"
SPLUNK_HEC_URL="${SPLUNK_HEC_URL:-http://splunk:8088}"
SPLUNK_HEC_TOKEN="${SPLUNK_HEC_TOKEN:-blue-team-lab-hec-token}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "  \033[0;34m[*]\033[0m $1"; }
log_ok()    { echo -e "  ${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "  ${YELLOW}[!]${NC} $1"; }
log_err()   { echo -e "  ${RED}[✗]${NC} $1"; }

# ─── Get Auth Token ──────────────────────────────────────────────
get_auth_token() {
    local response
    response=$(curl -sf -X POST "$CRIBL_URL/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\": \"$CRIBL_USER\", \"password\": \"$CRIBL_PASS\"}" 2>/dev/null) || {
        log_err "Failed to authenticate with Cribl at $CRIBL_URL"
        log_err "Is Cribl running? Try: docker compose --profile cribl up -d"
        exit 1
    }
    echo "$response" | grep -o '"token":"[^"]*"' | cut -d'"' -f4
}

# ─── API Helper ──────────────────────────────────────────────────
cribl_api() {
    local method="$1"
    local path="$2"
    local data="${3:-}"
    local token="$AUTH_TOKEN"

    if [ -n "$data" ]; then
        curl -sf -X "$method" "$CRIBL_URL/api/v1$path" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            -d "$data" 2>/dev/null || true
    else
        curl -sf -X "$method" "$CRIBL_URL/api/v1$path" \
            -H "Authorization: Bearer $token" 2>/dev/null || true
    fi
}

# ─── Wait for Cribl ──────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━ Configuring Cribl Stream ━━━${NC}"
log_info "Waiting for Cribl at $CRIBL_URL..."

for i in $(seq 1 30); do
    if curl -sf "$CRIBL_URL/api/v1/health" 2>/dev/null | grep -q '"healthy"'; then
        log_ok "Cribl is ready"
        break
    fi
    [ "$i" -eq 30 ] && { log_err "Cribl not responding after 30 attempts"; exit 1; }
    sleep 3
done

# ─── Authenticate ────────────────────────────────────────────────
log_info "Authenticating..."
AUTH_TOKEN=$(get_auth_token)
if [ -z "$AUTH_TOKEN" ]; then
    log_err "Could not get auth token. Check credentials: $CRIBL_USER / $CRIBL_PASS"
    exit 1
fi
log_ok "Authenticated as $CRIBL_USER"

# ─── Create HEC Input ────────────────────────────────────────────
log_info "Creating HEC input (port 8088)..."
cribl_api POST "/m/default/inputs" '{
  "id": "lab_hec_in",
  "type": "http",
  "disabled": false,
  "port": 8088,
  "authTokens": ["blue-team-lab-hec-token"],
  "description": "Lab log ingestion — receives from simulator and Attack Range data",
  "pipeline": "cim_normalize"
}' > /dev/null
log_ok "HEC input configured on port 8088"

# ─── Create CIM Normalization Pipeline ───────────────────────────
log_info "Creating CIM normalization pipeline..."
cribl_api POST "/m/default/pipelines" '{
  "id": "cim_normalize",
  "description": "Normalize ECS fields to Splunk CIM + drop noisy events for log reduction",
  "functions": [
    {
      "id": "drop",
      "filter": "process.name == \"svchost.exe\" && _simulation.type == \"baseline\"",
      "description": "Drop ~30% of baseline svchost events (noisy, low-value)",
      "conf": {
        "filter": "__e[\"process.name\"] == \"svchost.exe\" && __e[\"_simulation\"] && __e[\"_simulation\"][\"type\"] == \"baseline\" && Math.random() < 0.7"
      }
    },
    {
      "id": "eval",
      "filter": "true",
      "description": "Add ECS-to-CIM field aliases for Splunk compatibility",
      "conf": {
        "add": [
          {"name": "src_ip",    "value": "__e[\"source.ip\"] || __e[\"src_ip\"]"},
          {"name": "dest_ip",   "value": "__e[\"destination.ip\"] || __e[\"dest_ip\"]"},
          {"name": "dest_port", "value": "__e[\"destination.port\"] || __e[\"dest_port\"]"},
          {"name": "user",      "value": "__e[\"user.name\"] || __e[\"user\"]"},
          {"name": "host",      "value": "__e[\"host.name\"] || __e[\"host\"]"},
          {"name": "process",   "value": "__e[\"process.name\"] || __e[\"process\"]"},
          {"name": "CommandLine", "value": "__e[\"process.command_line\"] || __e[\"CommandLine\"]"},
          {"name": "EventCode", "value": "__e[\"event.code\"] || __e[\"EventCode\"]"},
          {"name": "mitre_technique", "value": "__e[\"_simulation\"] && __e[\"_simulation\"][\"technique\"]"}
        ]
      }
    },
    {
      "id": "eval",
      "filter": "true",
      "description": "Tag attack events with high-priority marker",
      "conf": {
        "add": [
          {"name": "lab_event_type", "value": "__e[\"_simulation\"] && __e[\"_simulation\"][\"type\"] == \"attack\" ? \"attack\" : \"baseline\""}
        ]
      }
    }
  ]
}' > /dev/null
log_ok "CIM normalization pipeline created"

# ─── Create Elasticsearch Output ─────────────────────────────────
log_info "Creating Elasticsearch output destination..."
cribl_api POST "/m/default/outputs" "{
  \"id\": \"elastic_out\",
  \"type\": \"elasticsearch\",
  \"hosts\": [\"$ES_URL\"],
  \"index\": \"logs-cribl-{_simulation && _simulation.type == 'attack' ? 'attack' : 'baseline'}\",
  \"authType\": \"basic\",
  \"username\": \"elastic\",
  \"password\": \"changeme\",
  \"rejectUnauthorized\": false,
  \"compress\": false,
  \"description\": \"Elastic SIEM — attack+baseline events after CIM normalization\"
}" > /dev/null
log_ok "Elasticsearch output configured → $ES_URL"

# ─── Create Splunk HEC Output ────────────────────────────────────
log_info "Creating Splunk HEC output destination..."
cribl_api POST "/m/default/outputs" "{
  \"id\": \"splunk_out\",
  \"type\": \"splunk_hec\",
  \"url\": \"$SPLUNK_HEC_URL\",
  \"authType\": \"splunkAuthToken\",
  \"hecToken\": \"$SPLUNK_HEC_TOKEN\",
  \"index\": \"sysmon\",
  \"sourcetype\": \"simulation\",
  \"rejectUnauthorized\": false,
  \"description\": \"Splunk SIEM — HEC output after CIM normalization\"
}" > /dev/null
log_ok "Splunk HEC output configured → $SPLUNK_HEC_URL"

# ─── Create Routing Rules ─────────────────────────────────────────
log_info "Creating routing rules..."
cribl_api POST "/m/default/routes" '{
  "id": "lab_routes",
  "routes": [
    {
      "id": "attack_both_siems",
      "name": "Attack Events → Elastic + Splunk",
      "filter": "__e[\"_simulation\"] && __e[\"_simulation\"][\"type\"] == \"attack\"",
      "pipeline": "cim_normalize",
      "output": "elastic_out",
      "final": false,
      "description": "High-fidelity attack telemetry goes to both SIEMs"
    },
    {
      "id": "attack_splunk",
      "name": "Attack Events → Splunk",
      "filter": "__e[\"_simulation\"] && __e[\"_simulation\"][\"type\"] == \"attack\"",
      "pipeline": "cim_normalize",
      "output": "splunk_out",
      "final": true,
      "description": "Same attack events cloned to Splunk"
    },
    {
      "id": "baseline_elastic",
      "name": "Baseline Events → Elastic only",
      "filter": "true",
      "pipeline": "cim_normalize",
      "output": "elastic_out",
      "final": true,
      "description": "Baseline telemetry goes only to Elastic (reduce Splunk ingest)"
    }
  ]
}' > /dev/null
log_ok "Routing rules created (attack → both SIEMs, baseline → Elastic only)"

echo ""
echo -e "${GREEN}Cribl Stream configured!${NC}"
echo ""
echo -e "  ${CYAN}Cribl Web UI${NC}:  http://localhost:9000"
echo -e "  ${CYAN}Login${NC}:         admin / CriblLab1!"
echo ""
echo -e "  ${CYAN}Data flow:${NC}"
echo "    Simulator → Cribl HEC (8088)"
echo "    ├── Attack events  → Elastic (9200) + Splunk HEC (8088)"
echo "    └── Baseline events → Elastic (9200) only"
echo ""
echo -e "  ${CYAN}Pipeline:${NC} cim_normalize"
echo "    - ECS → CIM field aliasing (src_ip, dest_ip, user, host, process)"
echo "    - Attack event tagging (lab_event_type, mitre_technique)"
echo "    - Log reduction: 70% of svchost baseline events dropped"
echo ""
echo -e "  ${YELLOW}Agent tasks to demonstrate Cribl lifecycle:${NC}"
echo "    1. Review Cribl's Live Data capture for field normalization gaps"
echo "    2. Suggest additional field mappings based on detection requirements"
echo "    3. Tune log reduction rules based on FP analysis"
echo "    4. Validate that reduced logs still contain all detection-relevant fields"
echo ""
