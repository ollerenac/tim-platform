#!/usr/bin/env bash
# Verifica el grafo ATT&CK en OpenCTI.
#
# Uso: check_mitre_relationships.sh [--steady-state]
#   (sin flag)      arranque inicial: exige además cola MITRE vacía y work
#                   `complete`. Lo usa verify-platform.sh antes de levantar el resto.
#   --steady-state  régimen: solo los umbrales del grafo son fatales. Cada ciclo del
#                   conector reimporta los mismos objetos (upsert) y deja la cola
#                   ocupada durante horas con el grafo ya completo; ahí se avisa.
set -euo pipefail

MODE="bootstrap"
if [[ "${1:-}" == "--steady-state" ]]; then
  MODE="steady-state"
elif [[ -n "${1:-}" ]]; then
  echo "uso: check_mitre_relationships.sh [--steady-state]" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

if [[ ! -f .env ]]; then
  echo "ERROR: .env not found. Run ./scripts/setup-env.sh first." >&2
  exit 1
fi
# shellcheck source=/dev/null
source .env
if [[ -z "${CONNECTOR_MITRE_ID:-}" ]]; then
  echo "ERROR: CONNECTOR_MITRE_ID is not set in .env." >&2
  exit 1
fi

# Query Elasticsearch directly: the equivalent GraphQL fromTypes distribution
# scans more than a million relationships and is too slow for a feedback loop.
entity_json=$(docker compose --profile core exec -T elasticsearch \
  curl -fsS -H 'Content-Type: application/json' \
  http://localhost:9200/opencti_stix_domain_objects-*/_search \
  -d '{"size":0,"aggs":{"types":{"terms":{"field":"entity_type.keyword","size":100}}}}')

uses_json=$(docker compose --profile core exec -T elasticsearch \
  curl -fsS -H 'Content-Type: application/json' \
  http://localhost:9200/opencti_stix_core_relationships-*/_count \
  -d '{"query":{"term":{"relationship_type.keyword":"uses"}}}')

malware_uses_json=$(docker compose --profile core exec -T elasticsearch \
  curl -fsS -H 'Content-Type: application/json' \
  http://localhost:9200/opencti_stix_core_relationships-*/_count \
  -d '{"query":{"bool":{"filter":[{"term":{"relationship_type.keyword":"uses"}},{"nested":{"path":"connections","query":{"bool":{"filter":[{"term":{"connections.role.keyword":"uses_from"}},{"term":{"connections.types.keyword":"malware"}}]}}}}]}}}')

count_type() {
  local entity_type=$1
  jq -r --arg entity_type "$entity_type" \
    '[.aggregations.types.buckets[] | select(.key == $entity_type) | .doc_count][0] // 0' \
    <<<"$entity_json"
}

intrusion_sets=$(count_type intrusion-set)
attack_patterns=$(count_type attack-pattern)
malware=$(count_type malware)
uses=$(jq -r '.count' <<<"$uses_json")
malware_uses=$(jq -r '.count' <<<"$malware_uses_json")

queue_counts=$(docker compose --profile core exec -T rabbitmq \
  rabbitmqctl -q list_queues name messages_ready messages_unacknowledged --formatter table \
  | awk -v queue="push_${CONNECTOR_MITRE_ID}" '$1 == queue {print $2, $3}')
read -r queue_ready queue_unacked <<<"${queue_counts:-missing missing}"

work_json=$(docker compose --profile core exec -T worker python3 -c '
import json
import logging
import os
import sys

from pycti import OpenCTIApiClient

logging.disable(logging.CRITICAL)
api = OpenCTIApiClient(
    os.environ["OPENCTI_URL"],
    os.environ["OPENCTI_TOKEN"],
    ssl_verify=False,
)
works = api.work.get_connector_works(sys.argv[1])
work = works[-1] if works else {}
print(json.dumps({"status": work.get("status", "missing"), "tracking": work.get("tracking") or {}}))
' "$CONNECTOR_MITRE_ID")
work_status=$(jq -r '.status' <<<"$work_json")
work_processed=$(jq -r '.tracking.import_processed_number // 0' <<<"$work_json")
work_expected=$(jq -r '.tracking.import_expected_number // 0' <<<"$work_json")

printf 'intrusion_sets=%s\n' "$intrusion_sets"
printf 'attack_patterns=%s\n' "$attack_patterns"
printf 'malware=%s\n' "$malware"
printf 'uses=%s\n' "$uses"
printf 'malware_uses=%s\n' "$malware_uses"
printf 'mitre_queue=%s ready, %s unacked\n' "$queue_ready" "$queue_unacked"
printf 'mitre_work=%s (%s/%s)\n' "$work_status" "$work_processed" "$work_expected"

failed=()
(( intrusion_sets >= 100 )) || failed+=("intrusion_sets=${intrusion_sets}<100")
(( attack_patterns >= 1000 )) || failed+=("attack_patterns=${attack_patterns}<1000")
(( uses >= 10000 )) || failed+=("uses=${uses}<10000")
(( malware_uses >= 1000 )) || failed+=("malware_uses=${malware_uses}<1000")

# Cola y work acreditan el fin de la carga inicial, no la salud del grafo.
pending=()
[[ "$queue_ready" == "0" ]] || pending+=("queue_ready=${queue_ready}")
[[ "$queue_unacked" == "0" ]] || pending+=("queue_unacked=${queue_unacked}")
[[ "$work_status" == "complete" ]] || pending+=("work_status=${work_status}:${work_processed}/${work_expected}")
if ((${#pending[@]})); then
  if [[ "$MODE" == "steady-state" ]]; then
    printf 'MITRE_IMPORT_IN_PROGRESS (no fatal en régimen): %s\n' "$(IFS=', '; echo "${pending[*]}")"
  else
    failed+=("${pending[@]}")
  fi
fi

if ((${#failed[@]})); then
  printf 'MITRE_GRAPH_NOT_READY: %s\n' "$(IFS=', '; echo "${failed[*]}")" >&2
  exit 1
fi

echo 'MITRE_GRAPH_READY'
