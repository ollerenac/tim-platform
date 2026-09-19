#!/usr/bin/env bash
# Imprime el comando docker compose completo para un objetivo de despliegue.
# Única fuente de verdad en shell; el equivalente Python es
# verify-service-contracts.py::compose_command (test-compose-targets.py los
# mantiene alineados vía render).
#
# Uso:  $(./scripts/compose-target.sh aws) ps
#       $(./scripts/compose-target.sh local-gpu) up -d --wait

set -euo pipefail

TARGET="${1:-}"
FULL_PROFILES=(core connectors feeds extractor briefings dashboard)

case "$TARGET" in
  aws)
    FILES=(-f docker-compose.yml -f docker-compose.aws.yml)
    PROFILES=("${FULL_PROFILES[@]}")
    ;;
  local-gpu)
    FILES=(-f docker-compose.yml -f docker-compose.local-gpu.yml)
    # inference (ollama) solo existe en el piloto local.
    PROFILES=("${FULL_PROFILES[@]}" inference)
    ;;
  core-only)
    FILES=(-f docker-compose.yml)
    PROFILES=(core)
    ;;
  *)
    echo "uso: compose-target.sh <aws|local-gpu|core-only>" >&2
    echo "  aws       — nodo sin GPU: Bedrock genera, sin Ollama" >&2
    echo "  local-gpu — piloto con NVIDIA: ollama genera" >&2
    echo "  core-only — plataforma OpenCTI sin servicios funcionales" >&2
    exit 2
    ;;
esac

CMD=(docker compose "${FILES[@]}")
for p in "${PROFILES[@]}"; do CMD+=(--profile "$p"); done
echo "${CMD[@]}"
