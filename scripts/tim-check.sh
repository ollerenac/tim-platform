#!/usr/bin/env bash
# Functional readiness gate for a TIM deployment target.
#
# Uso: ./scripts/tim-check.sh <aws|local-gpu|core-only>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  echo "uso: tim-check.sh <aws|local-gpu|core-only>" >&2
  echo "  aws       — nodo sin GPU: Bedrock genera, ollama-CPU embebe" >&2
  echo "  local-gpu — piloto con NVIDIA: ollama embebe y genera" >&2
  echo "  core-only — solo inventario de la plataforma base" >&2
  exit 2
fi

if [ ! -f .env ]; then
  echo "ERROR: .env not found. Run ./scripts/setup-env.sh first." >&2
  exit 1
fi

python3 "$SCRIPT_DIR/verify-service-contracts.py" "$TARGET"

if [ "$TARGET" = "core-only" ]; then
  echo "[tim-check] READY (core-only): inventario de la plataforma base verificado."
  exit 0
fi

"$SCRIPT_DIR/check_mitre_relationships.sh"

# La verificación de UI exige node. En un host sin node el fallo debe ser
# explícito — un SKIP silencioso es exactamente la clase de sobreafirmación
# que el gate 17-07 penalizó. TIM_SKIP_UI=1 lo declara a la vista.
if command -v node >/dev/null 2>&1; then
  node "$SCRIPT_DIR/verify-uis.mjs"
  UI_NOTE="SOC Dashboard, and Kibana passed"
elif [ "${TIM_SKIP_UI:-}" = "1" ]; then
  echo "[tim-check] SKIP verify-uis.mjs: node ausente y TIM_SKIP_UI=1 declarado." >&2
  echo "[tim-check]      La UI queda verificada solo por los contratos HTTP del verificador." >&2
  UI_NOTE="UI-JS check SKIPPED (no node)"
else
  echo "ERROR: node no está instalado y la verificación de UI lo requiere." >&2
  echo "  Instala node, o ejecuta el gate desde una máquina con túnel SSH," >&2
  echo "  o declara TIM_SKIP_UI=1 para omitirla de forma explícita." >&2
  exit 1
fi

echo "[tim-check] READY ($TARGET): container inventory, data contracts, $UI_NOTE."
