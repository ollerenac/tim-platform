#!/usr/bin/env bash
# Force a new MITRE connector cycle without deleting OpenCTI data or volumes.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

if [[ "${1:-}" != "--force" ]]; then
  echo "Usage: ./scripts/retry-mitre-import.sh --force"
  echo "This resets only the MITRE connector last_run and starts a full update import."
  exit 2
fi

if [[ ! -f .env ]]; then
  echo "ERROR: .env not found. Run ./scripts/setup-env.sh first."
  exit 1
fi

# shellcheck source=/dev/null
source .env
if [[ -z "${CONNECTOR_MITRE_ID:-}" ]]; then
  echo "ERROR: CONNECTOR_MITRE_ID is not set in .env."
  exit 1
fi

queue_counts=$(docker compose --profile core exec -T rabbitmq \
  rabbitmqctl -q list_queues name messages_ready messages_unacknowledged --formatter table \
  | awk -v queue="push_${CONNECTOR_MITRE_ID}" '$1 == queue {print $2, $3}')
read -r queue_ready queue_unacked <<<"${queue_counts:-0 0}"
if (( queue_ready > 0 || queue_unacked > 0 )); then
  echo "ERROR: MITRE import is already active (${queue_ready} ready, ${queue_unacked} unacked)."
  echo "Monitor it with: ./scripts/verify-platform.sh"
  exit 3
fi

if "$SCRIPT_DIR/check_mitre_relationships.sh" >/dev/null 2>&1; then
  echo "[retry-mitre-import] ATT&CK graph is already ready; refusing an unnecessary full import."
  exit 0
fi

restart_connector() {
  docker compose --profile core --profile connectors start connector-mitre >/dev/null 2>&1 || true
}
trap restart_connector EXIT

echo "[retry-mitre-import] Stopping only connector-mitre..."
docker compose --profile core --profile connectors stop connector-mitre

echo "[retry-mitre-import] Resetting connector last_run; OpenCTI data is preserved..."
docker compose --profile core exec -T opencti node -e '
const http = require("http");
const connectorId = process.argv[1];
const token = process.env.APP__ADMIN__TOKEN || "";
const query = "mutation Reset($id:ID!,$state:String){pingConnector(id:$id,state:$state){id connector_state}}";
const body = JSON.stringify({query, variables: {id: connectorId, state: JSON.stringify({last_run: 0})}});
const req = http.request({hostname: "127.0.0.1", port: 8080, path: "/graphql", method: "POST", headers: {"Content-Type": "application/json", "Content-Length": Buffer.byteLength(body), "Authorization": "Bearer " + token}}, res => {
  let data = "";
  res.on("data", chunk => data += chunk);
  res.on("end", () => {
    const result = JSON.parse(data);
    if (result.errors || !result.data?.pingConnector) {
      console.error("ERROR: OpenCTI rejected the MITRE state reset.");
      process.exit(1);
    }
    console.log("[retry-mitre-import] Connector state reset accepted.");
  });
});
req.on("error", error => { console.error(error.message); process.exit(1); });
req.write(body);
req.end();
' "$CONNECTOR_MITRE_ID"

echo "[retry-mitre-import] Starting connector-mitre..."
docker compose --profile core --profile connectors start connector-mitre
trap - EXIT

echo "[retry-mitre-import] New cycle requested. Monitor with: ./scripts/verify-platform.sh"
