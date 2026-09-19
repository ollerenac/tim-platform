#!/usr/bin/env bash
# Imprime el comando docker compose completo para un objetivo de despliegue.
# Única fuente de verdad en shell; el equivalente Python es
# verify-service-contracts.py::compose_command (test-compose-targets.py los
# mantiene alineados vía render).
#
# Uso:  $(./scripts/compose-target.sh aws) ps
#       $(./scripts/compose-target.sh aws) up -d --wait

set -euo pipefail

TARGET="${1:-}"

case "$TARGET" in
  aws)
    PROFILES=(core connectors feeds extractor briefings dashboard)
    ;;
  core-only)
    PROFILES=(core)
    ;;
  *)
    echo "uso: compose-target.sh <aws|core-only>" >&2
    echo "  aws       — despliegue completo; la generación va a Amazon Bedrock" >&2
    echo "  core-only — plataforma OpenCTI sin servicios funcionales" >&2
    exit 2
    ;;
esac

CMD=(docker compose -f docker-compose.yml)
for p in "${PROFILES[@]}"; do CMD+=(--profile "$p"); done
echo "${CMD[@]}"
