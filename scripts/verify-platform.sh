#!/bin/bash
# Polls OpenCTI until MITRE ATT&CK import is complete and TAXII 2.1 is live.
# Usage: ./scripts/verify-platform.sh

set -euo pipefail

# Resolve project root relative to script location (not cwd)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Load token from .env (fatal if missing)
if [ ! -f "$PROJECT_ROOT/.env" ]; then
  echo "ERROR: .env not found. Run ./scripts/setup-env.sh first."
  exit 1
fi
# shellcheck source=/dev/null
source "$PROJECT_ROOT/.env"

# Validate token is set
if [ -z "${OPENCTI_ADMIN_TOKEN:-}" ]; then
  echo "ERROR: OPENCTI_ADMIN_TOKEN not set in .env. Run ./scripts/setup-env.sh to regenerate."
  exit 1
fi

OPENCTI_URL="http://localhost:8080"
TIMEOUT=${MITRE_IMPORT_TIMEOUT:-5400}  # First ATT&CK import can take close to an hour.
START_TIME=$(date +%s)
POLL_N=0

# ── Step 1: Wait for OpenCTI /health (5s retry, respect timeout) ─────────────
echo "[verify-platform] Waiting for OpenCTI at ${OPENCTI_URL}/health ..."
until curl -s "${OPENCTI_URL}/health" 2>/dev/null | grep -qE 'unauthorized|ok'; do
  ELAPSED=$(( $(date +%s) - START_TIME ))
  if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "ERROR: Timeout waiting for OpenCTI health after ${TIMEOUT}s."
    echo "  Check logs: docker compose --profile core logs opencti"
    exit 1
  fi
  sleep 5
done
echo "[verify-platform] OpenCTI is up. Waiting for MITRE ATT&CK import..."

# ── Step 2: Wait for a relationship-rich ATT&CK graph (30s interval) ─────────
# Object-only thresholds are insufficient: the broken pilot already had 415
# attack patterns while almost all MITRE `uses` relationships were missing.
while true; do
  ELAPSED=$(( $(date +%s) - START_TIME ))
  if [ $ELAPSED -ge $TIMEOUT ]; then
    echo ""
    echo "ERROR: ${TIMEOUT}s timeout. MITRE import is incomplete."
    echo "  Check logs: docker compose --profile core --profile connectors logs connector-mitre"
    echo "  Check work/graph: ./scripts/check_mitre_relationships.sh"
    echo "  Retry a stale/incomplete run: ./scripts/retry-mitre-import.sh --force"
    echo "  Re-run this script when import completes."
    exit 1
  fi

  POLL_N=$(( POLL_N + 1 ))
  if GRAPH_STATUS=$("$SCRIPT_DIR/check_mitre_relationships.sh" 2>&1); then
    printf '%s\n' "$GRAPH_STATUS"
    echo ""
    echo "[verify-platform] Platform ready. ATT&CK objects and uses relationships imported."
    break
  fi
  printf '[%d] MITRE graph incomplete (%ss elapsed)\n%s\n' "$POLL_N" "$ELAPSED" "$GRAPH_STATUS"

  sleep 30
done

# ── Step 3: Verify TAXII 2.1 endpoint (D-10) ─────────────────────────────────
echo "[verify-platform] Checking TAXII 2.1 endpoint..."
TAXII_HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
  -H "Accept: application/taxii+json;version=2.1" \
  "${OPENCTI_URL}/taxii2/root/collections/")

if [ "$TAXII_HTTP" = "200" ]; then
  echo "[verify-platform] TAXII endpoint: OK (HTTP ${TAXII_HTTP})"
else
  echo "[verify-platform] TAXII endpoint: WARNING (HTTP ${TAXII_HTTP})"
  echo "  TAXII may not be ready. Check: OpenCTI > Data > Data Sharing > TAXII Collections."
fi

echo "[verify-platform] Phase 1 complete."
