#!/usr/bin/env bash
# Bootstrap ATT&CK in isolation, then start and verify the complete TIM stack
# for one deployment target.
#
# Uso: ./scripts/bootstrap-platform.sh <aws|local-gpu>

# configuracion: da errexit, undefined variables, pipefail
set -euo pipefail # configuracion segura para depuracion/debugging

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

TARGET="${1:-}"
if [ "$TARGET" != "aws" ] && [ "$TARGET" != "local-gpu" ]; then
  echo "uso: bootstrap-platform.sh <aws|local-gpu>" >&2
  exit 2
fi
COMPOSE=$("$SCRIPT_DIR/compose-target.sh" "$TARGET")

echo "[bootstrap-platform] Starting OpenCTI core, worker, and MITRE connector only..."
$COMPOSE up -d elasticsearch minio rabbitmq redis opencti worker connector-mitre

"$SCRIPT_DIR/verify-platform.sh"

echo "[bootstrap-platform] ATT&CK graph ready; starting remaining services for target $TARGET..."
STARTUP_TIMEOUT="${TIM_STARTUP_TIMEOUT:-600}"

if ! $COMPOSE up -d --wait --wait-timeout "$STARTUP_TIMEOUT"; then
  echo "ERROR: the complete TIM stack did not become healthy within ${STARTUP_TIMEOUT}s." >&2
  $COMPOSE ps -a >&2 || true
  exit 1
fi

MODELS="$($COMPOSE exec -T ollama ollama list 2>/dev/null || true)"
NEEDED=(nomic-embed-text)
[ "$TARGET" = "local-gpu" ] && NEEDED+=("llama3.2:3b")
for model in "${NEEDED[@]}"; do
  if ! grep -q "$model" <<<"$MODELS"; then
    echo "[bootstrap-platform] Required Ollama models are missing; initializing them..."
    "$SCRIPT_DIR/init-models.sh" "$TARGET"
    break
  fi
done

echo "[bootstrap-platform] All services are healthy; running functional readiness checks..."
if ! "$SCRIPT_DIR/tim-check.sh" "$TARGET"; then
  echo "ERROR: containers started, but TIM failed functional verification." >&2
  echo "  Inspect: \$($SCRIPT_DIR/compose-target.sh $TARGET) ps -a" >&2
  exit 1
fi

echo "[bootstrap-platform] READY: complete TIM stack ($TARGET) passed functional verification."
