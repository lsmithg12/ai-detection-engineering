#!/usr/bin/env bash
# =============================================================================
# Splunk Attack Range v5 — BOTS Dataset Fetcher
#
# Downloads Boss of the SOC (BOTS) datasets from Splunk's GitHub releases.
# These provide real attack telemetry (Sysmon, Windows Event, Zeek logs) from
# actual red team exercises — great supplements to the lab's Fawkes simulator.
#
# Dataset options:
#   bots-v3 (2018 APT + cloud attacks)    — ~36 GB Splunk bucket archive
#   bots-v2 (2017 ransomware + web)       — ~30 GB Splunk bucket archive
#   bots-v1 (2016 APT scenario)           — ~40 GB Splunk bucket archive
#
# After ingestion, query in Splunk:
#   index=botsv3 earliest=-30d | head 100
#   index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
#
# Usage:
#   ./pipeline/fetch-attack-range-data.sh bots-v3   # Download BOTSv3
#   ./pipeline/fetch-attack-range-data.sh bots-v2   # Download BOTSv2
#   ./pipeline/fetch-attack-range-data.sh samples   # Download small samples only
#
# Requirements: Splunk container must be running (docker compose --profile splunk up -d)
# Storage: 36-40GB free disk space (or use --samples for small representative set)
# =============================================================================

set -euo pipefail

DATASET="${1:-samples}"
SPLUNK_CONTAINER="${SPLUNK_CONTAINER:-splunk}"
SPLUNK_HOME="/opt/splunk"
DATA_DIR="./pipeline/attack-range-data"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "  \033[0;34m[*]\033[0m $1"; }
log_ok()   { echo -e "  ${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
log_err()  { echo -e "  ${RED}[✗]${NC} $1"; }

mkdir -p "$DATA_DIR"

echo ""
echo -e "${CYAN}━━━ Splunk Attack Range — Dataset Ingestion ━━━${NC}"
echo ""

case "$DATASET" in

# ─── Small Samples Mode ──────────────────────────────────────────
samples)
    echo -e "  Mode: ${YELLOW}samples${NC} (small representative dataset, no large download)"
    echo ""
    log_info "Generating representative Attack Range event samples..."

    # Create small JSON samples representative of Attack Range telemetry
    # These are example events from common Attack Range simulations
    cat > "$DATA_DIR/atomicred-t1059-001.json" << 'EVENTSEOF'
{"@timestamp":"2024-01-15T14:23:01.000Z","event":{"code":"1","category":"process","type":"start"},"process":{"name":"powershell.exe","command_line":"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"IEX ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('BASE64PAYLOAD')))\"","executable":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","parent":{"name":"cmd.exe"}},"host":{"name":"win10-victim"},"user":{"name":"victim","domain":"CORP"},"agent":{"type":"sysmon"},"_dataset":{"source":"attack_range","technique":"T1059.001","tool":"AtomicRedTeam"}}
{"@timestamp":"2024-01-15T14:23:15.000Z","event":{"code":"3","category":"network","type":"connection"},"process":{"name":"powershell.exe"},"destination":{"ip":"192.168.100.50","port":4444},"network":{"direction":"outbound"},"host":{"name":"win10-victim"},"agent":{"type":"sysmon"},"_dataset":{"source":"attack_range","technique":"T1071.001","tool":"AtomicRedTeam"}}
EVENTSEOF

    cat > "$DATA_DIR/atomicred-t1003-001.json" << 'EVENTSEOF'
{"@timestamp":"2024-01-15T14:30:00.000Z","event":{"code":"10","category":"process","type":"access"},"process":{"name":"mimikatz.exe","executable":"C:\\Users\\victim\\Downloads\\mimikatz.exe"},"winlog":{"event_data":{"TargetImage":"C:\\Windows\\System32\\lsass.exe","GrantedAccess":"0x1F3FFF"}},"host":{"name":"win10-victim"},"user":{"name":"victim","domain":"CORP"},"agent":{"type":"sysmon"},"_dataset":{"source":"attack_range","technique":"T1003.001","tool":"AtomicRedTeam"}}
EVENTSEOF

    cat > "$DATA_DIR/atomicred-t1547-001.json" << 'EVENTSEOF'
{"@timestamp":"2024-01-15T14:35:00.000Z","event":{"code":"13","category":"registry","type":"change"},"registry":{"path":"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\MaliciousPersistence","value":"C:\\Users\\victim\\AppData\\Local\\Temp\\payload.exe"},"process":{"name":"reg.exe","command_line":"reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v MaliciousPersistence /d C:\\Users\\victim\\AppData\\Local\\Temp\\payload.exe /f"},"host":{"name":"win10-victim"},"agent":{"type":"sysmon"},"_dataset":{"source":"attack_range","technique":"T1547.001","tool":"AtomicRedTeam"}}
EVENTSEOF

    log_ok "Sample attack events created in $DATA_DIR/"
    log_info "Ingesting into Elasticsearch (index: attack-range-samples)..."

    # Check if ES is running
    if curl -sf -u elastic:changeme http://localhost:9200/_cluster/health 2>/dev/null | grep -qE '"status":"(green|yellow)"'; then
        for f in "$DATA_DIR"/*.json; do
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                curl -sf -u elastic:changeme -X POST "http://localhost:9200/attack-range-samples/_doc" \
                    -H "Content-Type: application/json" \
                    -d "$line" > /dev/null 2>&1 || true
            done < "$f"
        done
        COUNT=$(curl -sf -u elastic:changeme "http://localhost:9200/attack-range-samples/_count" 2>/dev/null | grep -o '"count":[0-9]*' | cut -d: -f2 || echo "?")
        log_ok "Ingested $COUNT events into index 'attack-range-samples'"
    else
        log_warn "Elasticsearch not running — events saved to $DATA_DIR/ for later ingestion"
    fi

    # Also ingest into Splunk if running
    if curl -sf -k https://localhost:8089/services/server/health -u admin:BlueTeamLab1! &>/dev/null; then
        for f in "$DATA_DIR"/*.json; do
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                curl -sf http://localhost:8288/services/collector/event \
                    -H "Authorization: Splunk blue-team-lab-hec-token" \
                    -H "Content-Type: application/json" \
                    -d "{\"event\": $line, \"index\": \"attack_simulation\", \"sourcetype\": \"attack_range\"}" > /dev/null 2>&1 || true
            done < "$f"
        done
        log_ok "Ingested sample events into Splunk index 'attack_simulation'"
    fi
    ;;

# ─── BOTS v3 ─────────────────────────────────────────────────────
bots-v3)
    echo -e "  Dataset: ${YELLOW}BOTS v3${NC} (2018 APT + cloud attack scenario)"
    echo -e "  Size: ~36 GB — ensure sufficient disk space"
    echo ""
    log_warn "BOTS v3 is a large download (~36 GB). This will take significant time."
    echo ""
    read -p "  Continue? [y/N]: " confirm
    [ "$confirm" != "y" ] && { echo "  Aborted."; exit 0; }

    BOTS_URL="https://github.com/splunk/botsv3/releases/download/1.0/botsv3_data_set.tgz"
    BOTS_FILE="$DATA_DIR/botsv3_data_set.tgz"

    log_info "Downloading BOTS v3 from GitHub releases..."
    log_info "URL: $BOTS_URL"
    curl -L -o "$BOTS_FILE" "$BOTS_URL" --progress-bar

    log_info "Extracting to Splunk container..."
    # Copy archive into Splunk container and extract into the index directory
    docker cp "$BOTS_FILE" "$SPLUNK_CONTAINER:/tmp/botsv3.tgz"
    docker exec "$SPLUNK_CONTAINER" bash -c "
        mkdir -p $SPLUNK_HOME/var/lib/splunk
        cd $SPLUNK_HOME/var/lib/splunk
        tar -xzf /tmp/botsv3.tgz
        rm /tmp/botsv3.tgz
        chown -R splunk:splunk botsv3/ 2>/dev/null || true
    "
    log_info "Restarting Splunk to pick up new indexes..."
    docker exec "$SPLUNK_CONTAINER" bash -c "$SPLUNK_HOME/bin/splunk restart" || true
    sleep 30

    log_ok "BOTS v3 ingested!"
    echo ""
    echo "  Query in Splunk:"
    echo "    index=botsv3 | head 50"
    echo "    index=botsv3 sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\""
    ;;

# ─── BOTS v2 ─────────────────────────────────────────────────────
bots-v2)
    echo -e "  Dataset: ${YELLOW}BOTS v2${NC} (2017 ransomware + web attack scenario)"
    echo -e "  Size: ~30 GB"
    echo ""
    log_warn "Large download (~30 GB)"
    read -p "  Continue? [y/N]: " confirm
    [ "$confirm" != "y" ] && { echo "  Aborted."; exit 0; }

    BOTS_URL="https://github.com/splunk/botsv2/releases/download/1.0/botsv2_data_set.tgz"
    BOTS_FILE="$DATA_DIR/botsv2_data_set.tgz"
    curl -L -o "$BOTS_FILE" "$BOTS_URL" --progress-bar
    docker cp "$BOTS_FILE" "$SPLUNK_CONTAINER:/tmp/botsv2.tgz"
    docker exec "$SPLUNK_CONTAINER" bash -c "
        cd $SPLUNK_HOME/var/lib/splunk
        tar -xzf /tmp/botsv2.tgz && rm /tmp/botsv2.tgz
    "
    docker exec "$SPLUNK_CONTAINER" bash -c "$SPLUNK_HOME/bin/splunk restart" || true
    log_ok "BOTS v2 ingested! Query: index=botsv2"
    ;;

*)
    echo "  Usage: $0 [samples|bots-v3|bots-v2]"
    echo ""
    echo "    samples   Small representative events — no large download (recommended for lab)"
    echo "    bots-v3   Full BOTS v3 dataset — 36 GB, real APT scenario"
    echo "    bots-v2   Full BOTS v2 dataset — 30 GB, ransomware scenario"
    exit 1
    ;;
esac

echo ""
echo -e "${GREEN}Done!${NC}"
echo ""
echo -e "${CYAN}Next steps for the agent:${NC}"
echo "  1. Explore the Attack Range data:"
echo "     Elastic: GET /attack-range-samples/_search"
echo "     Splunk: search index=attack_simulation source=attack_range"
echo ""
echo "  2. Compare technique coverage:"
echo "     Are Attack Range TTPs covered by our existing Sigma rules?"
echo ""
echo "  3. Identify gaps and create new detections"
echo ""
