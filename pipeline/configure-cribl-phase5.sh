#!/usr/bin/env bash
# configure-cribl-phase5.sh
# Deploy Phase 5 per-source Cribl pipelines and updated route table to a running Cribl Stream instance.
#
# Usage:
#   ./pipeline/configure-cribl-phase5.sh
#
# Environment variables (all have defaults):
#   CRIBL_URL   - Cribl Stream base URL  (default: http://localhost:9000)
#   CRIBL_USER  - Cribl admin username   (default: admin)
#   CRIBL_PASS  - Cribl admin password   (default: admin)

set -euo pipefail

CRIBL_URL="${CRIBL_URL:-http://localhost:9000}"
CRIBL_USER="${CRIBL_USER:-admin}"
CRIBL_PASS="${CRIBL_PASS:-admin}"

# Resolve script directory so the file can be run from anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PIPELINE_DIR="${REPO_ROOT}/cribl/pipelines"
ROUTES_FILE="${REPO_ROOT}/cribl/routes/phase5_routes.json"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()    { echo "[INFO]  $*"; }
success() { echo "[OK]    $*"; }
warn()    { echo "[WARN]  $*"; }
error()   { echo "[ERROR] $*" >&2; }

# Check a curl response for Cribl API errors.  Prints the error and returns 1
# when the body contains {"message":...} at the top level.
check_response() {
  local label="$1"
  local body="$2"
  if echo "$body" | grep -q '"message"'; then
    error "${label} — API returned an error: ${body}"
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Step 1 — Health check
# ---------------------------------------------------------------------------

info "Checking Cribl Stream health at ${CRIBL_URL} ..."
HEALTH_BODY=$(curl -sf "${CRIBL_URL}/api/v1/health" 2>/dev/null || true)
if [[ -z "$HEALTH_BODY" ]]; then
  error "Cribl Stream is not reachable at ${CRIBL_URL}."
  error "Start Docker Desktop and the lab stack first:"
  error "  docker compose up -d cribl"
  exit 1
fi
success "Cribl Stream is healthy."

# ---------------------------------------------------------------------------
# Step 2 — Authenticate and obtain a bearer token
# ---------------------------------------------------------------------------

info "Authenticating as '${CRIBL_USER}' ..."
AUTH_BODY=$(curl -sf -X POST "${CRIBL_URL}/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"${CRIBL_USER}\", \"password\": \"${CRIBL_PASS}\"}" 2>/dev/null)

if [[ -z "$AUTH_BODY" ]]; then
  error "Authentication request failed — check CRIBL_URL, CRIBL_USER, CRIBL_PASS."
  exit 1
fi

TOKEN=$(echo "$AUTH_BODY" | grep -o '"token":"[^"]*"' | cut -d'"' -f4 || true)
if [[ -z "$TOKEN" ]]; then
  error "Could not extract auth token from response: ${AUTH_BODY}"
  exit 1
fi
success "Authenticated successfully."

# Convenience wrapper for authenticated Cribl API calls.
cribl_request() {
  local method="$1"
  local path="$2"
  shift 2
  curl -sf -X "${method}" "${CRIBL_URL}${path}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    "$@"
}

# ---------------------------------------------------------------------------
# Step 3 — Deploy each pipeline
# ---------------------------------------------------------------------------

PIPELINES=(
  "sysmon_normalize"
  "windows_security_normalize"
  "linux_auditd_normalize"
  "cloudtrail_normalize"
  "zeek_normalize"
)

info "Deploying ${#PIPELINES[@]} pipelines to Cribl (worker group: default) ..."

for PIPELINE_ID in "${PIPELINES[@]}"; do
  PIPELINE_FILE="${PIPELINE_DIR}/${PIPELINE_ID}.json"

  if [[ ! -f "$PIPELINE_FILE" ]]; then
    warn "Pipeline file not found, skipping: ${PIPELINE_FILE}"
    continue
  fi

  info "  Uploading pipeline '${PIPELINE_ID}' ..."
  RESPONSE=$(cribl_request PUT "/api/v1/m/default/pipelines/${PIPELINE_ID}" \
    --data-binary "@${PIPELINE_FILE}" 2>&1 || true)

  if check_response "Pipeline '${PIPELINE_ID}'" "$RESPONSE"; then
    success "  Pipeline '${PIPELINE_ID}' deployed."
  else
    # Non-fatal — log and continue so remaining pipelines are attempted.
    warn "  Pipeline '${PIPELINE_ID}' may not have deployed cleanly. Continuing."
  fi
done

# ---------------------------------------------------------------------------
# Step 4 — Update route table
# ---------------------------------------------------------------------------

if [[ ! -f "$ROUTES_FILE" ]]; then
  error "Routes file not found: ${ROUTES_FILE}"
  exit 1
fi

info "Updating route table from ${ROUTES_FILE} ..."

# Cribl expects the routes endpoint to receive {"routes": [...]}
ROUTES_PAYLOAD=$(python3 -c "
import json, sys
routes = json.load(open('${ROUTES_FILE}'))
print(json.dumps({'routes': routes}))
" 2>/dev/null || python -c "
import json, sys
routes = json.load(open('${ROUTES_FILE}'))
print(json.dumps({'routes': routes}))
" 2>/dev/null || true)

if [[ -z "$ROUTES_PAYLOAD" ]]; then
  error "Failed to build routes payload — ensure python3 or python is available."
  exit 1
fi

RESPONSE=$(cribl_request PUT "/api/v1/m/default/routes" \
  --data "${ROUTES_PAYLOAD}" 2>&1 || true)

if check_response "Route table update" "$RESPONSE"; then
  success "Route table updated (${#PIPELINES[@]} source-specific routes + validation + fallback)."
else
  warn "Route table update may not have completed cleanly. Check Cribl UI."
fi

# ---------------------------------------------------------------------------
# Step 5 — Commit configuration changes
# ---------------------------------------------------------------------------

info "Committing Cribl configuration ..."
COMMIT_PAYLOAD='{"message": "Phase 5: per-source normalization pipelines (sysmon, windows_security, linux_auditd, cloudtrail, zeek)"}'
RESPONSE=$(cribl_request POST "/api/v1/m/default/commit" \
  --data "${COMMIT_PAYLOAD}" 2>&1 || true)

if check_response "Commit" "$RESPONSE"; then
  success "Configuration committed."
else
  warn "Commit may have failed — changes are staged but not yet committed. Check Cribl UI."
fi

# ---------------------------------------------------------------------------
# Step 6 — Deploy committed configuration
# ---------------------------------------------------------------------------

info "Deploying committed configuration to workers ..."
RESPONSE=$(cribl_request POST "/api/v1/m/default/deploy" \
  --data '{}' 2>&1 || true)

if check_response "Deploy" "$RESPONSE"; then
  success "Configuration deployed to worker group 'default'."
else
  warn "Deploy request returned an error. Workers may need a manual deploy from the Cribl UI."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "======================================================================"
echo "  Phase 5 Cribl pipeline deployment complete"
echo "======================================================================"
echo ""
echo "  Pipelines deployed:"
for PIPELINE_ID in "${PIPELINES[@]}"; do
  echo "    - ${PIPELINE_ID}"
done
echo ""
echo "  Route table: ${ROUTES_FILE}"
echo "  Worker group: default"
echo "  Cribl UI: ${CRIBL_URL}"
echo ""
echo "  Next steps:"
echo "    1. Open ${CRIBL_URL} and verify pipelines appear under Pipelines."
echo "    2. Use 'Quick Connect' or the Routes page to confirm routing rules."
echo "    3. Send a sample Sysmon / CloudTrail / Zeek event and use"
echo "       'Live Data Capture' to verify field extraction."
echo "    4. Run a validation: cd autonomous && python3 orchestration/cli.py validate --all"
echo ""
