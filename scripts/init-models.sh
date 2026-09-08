#!/bin/bash
# Descarga los modelos Ollama que exige el objetivo de despliegue.
# Ejecutar una sola vez después de levantar el stack.
#
# Uso: ./scripts/init-models.sh <aws|local-gpu>
#   aws       — solo nomic-embed-text (embeddings CPU; Bedrock genera)
#   local-gpu — nomic-embed-text + llama3.2:3b (generación local)

set -euo pipefail

TARGET="${1:-}"
case "$TARGET" in
  aws)       MODELS=(nomic-embed-text) ;;
  local-gpu) MODELS=(nomic-embed-text "llama3.2:3b") ;;
  *)
    echo "uso: init-models.sh <aws|local-gpu>" >&2
    exit 2
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE=$("$SCRIPT_DIR/compose-target.sh" "$TARGET")

echo "[init-models] Esperando que Ollama esté listo..."
until $COMPOSE exec -T ollama ollama list > /dev/null 2>&1; do
  sleep 3
done

for model in "${MODELS[@]}"; do
  echo "[init-models] Descargando $model..."
  $COMPOSE exec -T ollama ollama pull "$model"
done

echo "[init-models] Modelos listos para el objetivo $TARGET."
$COMPOSE exec -T ollama ollama list
