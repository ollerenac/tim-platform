#!/bin/bash
# Descarga el modelo Ollama que exige el objetivo local-gpu.
# Ejecutar una sola vez después de levantar el stack.
#
# Uso: ./scripts/init-models.sh local-gpu
#   local-gpu — llama3.2:3b (generación local)
#   aws       — no aplica: no despliega Ollama, Bedrock genera

set -euo pipefail

TARGET="${1:-}"
case "$TARGET" in
  local-gpu) MODELS=("llama3.2:3b") ;;
  *)
    echo "uso: init-models.sh local-gpu" >&2
    echo "  el objetivo aws no despliega Ollama (Bedrock genera)" >&2
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
