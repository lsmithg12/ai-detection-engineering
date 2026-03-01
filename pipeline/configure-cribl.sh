#!/usr/bin/env bash
# =============================================================================
# Cribl Stream — Auto-Configure for Blue Team Lab
#
# Sets up Cribl Stream as a log pipeline between the simulator and SIEMs:
#   Simulator → Cribl HEC (port 8088) → Elastic (9200) + Splunk (8088)
#
# Cribl pipeline features configured:
#   1. HEC input enabled (built-in in_splunk_hec on port 8088)
#   2. CIM normalization pipeline (ECS → Splunk CIM field mapping)
#   3. Elasticsearch output destination
#   4. Splunk HEC output destination
#   5. Routing rules (all events → both SIEMs via CIM pipeline)
#
# Usage: ./pipeline/configure-cribl.sh
# Run AFTER Cribl is healthy (setup.sh calls this automatically)
# =============================================================================

set -euo pipefail

CRIBL_URL="${CRIBL_URL:-http://localhost:9000}"
CRIBL_USER="${CRIBL_USER:-admin}"
CRIBL_PASS="${CRIBL_PASS:-admin}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "  \033[0;34m[*]\033[0m $1"; }
log_ok()    { echo -e "  ${GREEN}[+]${NC} $1"; }
log_warn()  { echo -e "  ${YELLOW}[!]${NC} $1"; }
log_err()   { echo -e "  ${RED}[✗]${NC} $1"; }

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
AUTH_RESPONSE=$(curl -sf -X POST "$CRIBL_URL/api/v1/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"$CRIBL_USER\", \"password\": \"$CRIBL_PASS\"}" 2>/dev/null) || {
    log_err "Failed to authenticate with Cribl at $CRIBL_URL"
    exit 1
}
AUTH_TOKEN=$(echo "$AUTH_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
if [ -z "$AUTH_TOKEN" ]; then
    log_err "Could not get auth token. Check credentials: $CRIBL_USER / $CRIBL_PASS"
    exit 1
fi
log_ok "Authenticated as $CRIBL_USER"

# ─── API Helper ──────────────────────────────────────────────────
# Returns HTTP status code; body goes to stdout
cribl_api() {
    local method="$1"
    local path="$2"
    local data="${3:-}"

    if [ -n "$data" ]; then
        curl -s -X "$method" "$CRIBL_URL/api/v1$path" \
            -H "Authorization: Bearer $AUTH_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$data" 2>/dev/null
    else
        curl -s -X "$method" "$CRIBL_URL/api/v1$path" \
            -H "Authorization: Bearer $AUTH_TOKEN" 2>/dev/null
    fi
}

# ─── 1. Enable HEC Input ─────────────────────────────────────────
# Cribl has a built-in in_splunk_hec input on port 8088 — PATCH to enable it.
# Required fields: type, host, port, splunkHecAPI. authTokens must be objects.
log_info "Enabling HEC input (in_splunk_hec, port 8088)..."
RESULT=$(cribl_api PATCH "/system/inputs/in_splunk_hec" '{
  "type": "splunk_hec",
  "host": "0.0.0.0",
  "port": 8088,
  "disabled": false,
  "tls": {"disabled": true},
  "splunkHecAPI": "/services/collector",
  "splunkHecAcks": false,
  "authTokens": [{"token": "blue-team-lab-hec-token"}],
  "pipeline": "cim_normalize"
}')
if echo "$RESULT" | grep -q '"disabled":false'; then
    log_ok "HEC input enabled on port 8088"
else
    log_err "Failed to enable HEC input: $RESULT"
fi

# ─── 2. Create CIM Normalization Pipeline ────────────────────────
# Pipeline functions must be inside conf.functions wrapper.
log_info "Creating CIM normalization pipeline..."
RESULT=$(cribl_api POST "/pipelines" '{
  "id": "cim_normalize",
  "conf": {
    "functions": [
      {
        "id": "eval",
        "filter": "true",
        "description": "ECS-to-CIM field aliases for Splunk compatibility",
        "conf": {
          "add": [
            {"name": "EventCode",   "value": "__e[\"event.code\"]"},
            {"name": "src_ip",      "value": "__e[\"source.ip\"]"},
            {"name": "dest_ip",     "value": "__e[\"destination.ip\"]"},
            {"name": "dest_port",   "value": "__e[\"destination.port\"]"},
            {"name": "user",        "value": "__e[\"user.name\"]"},
            {"name": "host",        "value": "__e[\"host.name\"]"},
            {"name": "process",     "value": "__e[\"process.name\"]"},
            {"name": "CommandLine", "value": "__e[\"process.command_line\"]"},
            {"name": "Image",       "value": "__e[\"process.executable\"]"},
            {"name": "ParentImage", "value": "__e[\"process.parent.executable\"]"},
            {"name": "TargetObject","value": "__e[\"registry.path\"]"},
            {"name": "Details",     "value": "__e[\"registry.value\"]"}
          ]
        }
      }
    ]
  }
}')
if echo "$RESULT" | grep -q '"cim_normalize"'; then
    log_ok "CIM normalization pipeline created (12 field mappings)"
else
    log_warn "Pipeline may already exist (re-run is idempotent)"
fi

# ─── 3. Create Elasticsearch Outputs ─────────────────────────────
# Type must be "elastic" (not "elasticsearch"). Requires "url" field.
# Two outputs: sim-baseline (normal) and sim-attack (attack scenarios).
log_info "Creating Elasticsearch outputs..."
RESULT=$(cribl_api POST "/system/outputs" '{
  "id": "elastic_out",
  "type": "elastic",
  "url": "http://elasticsearch:9200",
  "index": "sim-baseline",
  "authType": "basic",
  "username": "elastic",
  "password": "changeme",
  "compress": false,
  "description": "Elastic SIEM — baseline events"
}')
if echo "$RESULT" | grep -q '"elastic_out"'; then
    log_ok "Elasticsearch baseline output → sim-baseline"
else
    log_warn "ES baseline output may already exist"
fi

RESULT=$(cribl_api POST "/system/outputs" '{
  "id": "elastic_attack",
  "type": "elastic",
  "url": "http://elasticsearch:9200",
  "index": "sim-attack",
  "authType": "basic",
  "username": "elastic",
  "password": "changeme",
  "compress": false,
  "description": "Elastic SIEM — attack events only"
}')
if echo "$RESULT" | grep -q '"elastic_attack"'; then
    log_ok "Elasticsearch attack output → sim-attack"
else
    log_warn "ES attack output may already exist"
fi

# ─── 4. Create Splunk HEC Output ─────────────────────────────────
# Token field is "token" (not "hecToken" or "authType").
log_info "Creating Splunk HEC output..."
RESULT=$(cribl_api POST "/system/outputs" '{
  "id": "splunk_out",
  "type": "splunk_hec",
  "url": "http://splunk:8088",
  "token": "blue-team-lab-hec-token",
  "index": "sysmon",
  "sourcetype": "sysmon",
  "description": "Splunk SIEM — HEC output after CIM normalization"
}')
if echo "$RESULT" | grep -q '"splunk_out"'; then
    log_ok "Splunk HEC output configured → http://splunk:8088"
else
    log_warn "Splunk output may already exist (re-run is idempotent)"
fi

# ─── 5. Configure Routes ─────────────────────────────────────────
# Routes use PATCH on the default route group (not POST to create new ones).
# Attack events → sim-attack (Elastic) + sysmon (Splunk), non-final so they also hit baseline route.
# Baseline events → sim-baseline (Elastic) + sysmon (Splunk).
log_info "Configuring routing rules..."
RESULT=$(cribl_api PATCH "/routes/default" '{
  "id": "default",
  "routes": [
    {
      "id": "attack_to_elastic",
      "name": "Attack Events → Elastic (sim-attack)",
      "filter": "__e._simulation && __e._simulation.type === \"attack\"",
      "pipeline": "cim_normalize",
      "output": "elastic_attack",
      "final": false,
      "disabled": false
    },
    {
      "id": "attack_to_splunk",
      "name": "Attack Events → Splunk",
      "filter": "__e._simulation && __e._simulation.type === \"attack\"",
      "pipeline": "cim_normalize",
      "output": "splunk_out",
      "final": true,
      "disabled": false
    },
    {
      "id": "baseline_to_elastic",
      "name": "Baseline → Elastic (sim-baseline)",
      "filter": "true",
      "pipeline": "cim_normalize",
      "output": "elastic_out",
      "final": false,
      "disabled": false
    },
    {
      "id": "baseline_to_splunk",
      "name": "Baseline → Splunk",
      "filter": "true",
      "pipeline": "cim_normalize",
      "output": "splunk_out",
      "final": true,
      "disabled": false
    }
  ]
}')
if echo "$RESULT" | grep -q '"attack_to_elastic"'; then
    log_ok "Routes configured (attack → sim-attack, baseline → sim-baseline, both → Splunk)"
else
    log_err "Failed to configure routes: $RESULT"
fi

# ─── 6. Commit Changes ───────────────────────────────────────────
log_info "Committing configuration..."
RESULT=$(cribl_api POST "/version/commit" '{"message": "Lab auto-config: HEC input, CIM pipeline, outputs, routes"}')
if echo "$RESULT" | grep -q '"commit"'; then
    log_ok "Configuration committed to Cribl"
else
    log_warn "Commit may have failed — changes might not persist across restart"
fi

# ─── Summary ─────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}Cribl Stream configured!${NC}"
echo ""
echo -e "  ${CYAN}Cribl Web UI${NC}:  http://localhost:9000"
echo -e "  ${CYAN}Login${NC}:         admin / admin"
echo ""
echo -e "  ${CYAN}Data flow:${NC}"
echo "    Simulator → Cribl HEC (8088)"
echo "    ├── CIM normalize pipeline (ECS → Splunk field aliases)"
echo "    ├── Attack events  → Elastic (sim-attack) + Splunk (sysmon)"
echo "    └── Baseline events → Elastic (sim-baseline) + Splunk (sysmon)"
echo ""
