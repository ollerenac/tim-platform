#!/bin/bash
# Generates .env from .env.example with auto-created UUIDs and passwords.
# Usage: ./scripts/setup-env.sh

# set -eu (not pipefail): password generation intentionally uses a short /dev/urandom
# pipeline where head closes after enough bytes.
set -eu

# Resolve project root relative to script location (not cwd)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Idempotency guard (D-07): exit 0 if .env already exists
if [ -f "$PROJECT_ROOT/.env" ]; then
  echo "[setup-env] .env already exists. Remove it to regenerate."
  exit 0
fi

# NVIDIA GPU check: warn but do not block
# nvidia-container-toolkit may need manual install (see docs/SETUP.md)
if command -v nvidia-smi > /dev/null 2>&1; then
  if ! docker info 2>/dev/null | grep -q nvidia; then
    echo "[setup-env] WARN: NVIDIA GPU detected but nvidia-container-toolkit is not configured."
    echo "            Ollama will fail to start. See docs/SETUP.md for installation steps."
  fi
fi

# Copy template (Plan 01 fixed .env.example permissions)
cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/.env"
# Lock down immediately — .env holds the OpenCTI admin token + RabbitMQ/MinIO secrets.
chmod 600 "$PROJECT_ROOT/.env"

echo "[setup-env] Generating UUIDs and passwords..."

# UUID generation: uuidgen preferred; python3 fallback
_gen_uuid() {
  if command -v uuidgen > /dev/null 2>&1; then uuidgen; else python3 -c "import uuid; print(uuid.uuid4())"; fi
}
OPENCTI_TOKEN=$(_gen_uuid)
CONNECTOR_MITRE_UUID=$(_gen_uuid)
CONNECTOR_IPINFO_UUID=$(_gen_uuid)
CONNECTOR_CVE_UUID=$(_gen_uuid)
CONNECTOR_CISA_KEV_UUID=$(_gen_uuid)
CONNECTOR_MISP_FEED_UUID=$(_gen_uuid)

# Password generation: alphanumeric only — avoids shell quoting issues with sed.
# tr receives SIGPIPE when head has enough bytes; suppress that harmless stderr noise.
_gen_password() {
  tr -dc 'a-zA-Z0-9' < /dev/urandom 2>/dev/null | head -c 24
}
RABBITMQ_PASS=$(_gen_password)
MINIO_SECRET=$(_gen_password)

# Write generated values to .env: sed replaces existing lines; append if the
# template predates the variable (keeps script correct as connectors are added)
_set_var() {
  local key="$1" val="$2"
  if grep -q "^${key}=" "$PROJECT_ROOT/.env"; then
    sed -i "s|^${key}=.*|${key}=${val}|" "$PROJECT_ROOT/.env"
  else
    echo "${key}=${val}" >> "$PROJECT_ROOT/.env"
  fi
}
_set_var OPENCTI_ADMIN_TOKEN "$OPENCTI_TOKEN"
_set_var CONNECTOR_MITRE_ID "$CONNECTOR_MITRE_UUID"
_set_var CONNECTOR_IPINFO_ID "$CONNECTOR_IPINFO_UUID"
_set_var CONNECTOR_CVE_ID "$CONNECTOR_CVE_UUID"
_set_var CONNECTOR_CISA_KEV_ID "$CONNECTOR_CISA_KEV_UUID"
_set_var CONNECTOR_MISP_FEED_ID "$CONNECTOR_MISP_FEED_UUID"
_set_var RABBITMQ_PASSWORD "$RABBITMQ_PASS"
_set_var MINIO_SECRET_KEY "$MINIO_SECRET"

# Dashboard + Kibana share one nginx basic-auth credential. Persist its plaintext only in
# the protected .env so the automated browser verifier can authenticate; nginx gets a hash.
HTPASSWD_FILE="$PROJECT_ROOT/services/dashboard/.kibana.htpasswd"
DASH_USER="analyst"
DASH_PASS=$(_gen_password)
DASH_PASS="${DASH_PASS:0:20}"
_set_var KIBANA_USER "$DASH_USER"
_set_var KIBANA_PASSWORD "$DASH_PASS"
mkdir -p "$(dirname "$HTPASSWD_FILE")"
printf '%s:%s\n' "$DASH_USER" "$(openssl passwd -apr1 "$DASH_PASS")" > "$HTPASSWD_FILE"
chmod 600 "$HTPASSWD_FILE"

# Print only the non-secret connector IDs. The admin token and RabbitMQ/MinIO secrets are
# NOT echoed — that would leave live credentials in terminal scrollback / tmux / CI logs.
echo "[setup-env] Generated .env (chmod 600) with connector IDs:"
echo "  CONNECTOR_MITRE_ID    = ${CONNECTOR_MITRE_UUID}"
echo "  CONNECTOR_IPINFO_ID   = ${CONNECTOR_IPINFO_UUID}"
echo "  CONNECTOR_CVE_ID      = ${CONNECTOR_CVE_UUID}"
echo "  CONNECTOR_CISA_KEV_ID = ${CONNECTOR_CISA_KEV_UUID}"
echo "  CONNECTOR_MISP_FEED_ID= ${CONNECTOR_MISP_FEED_UUID}"
echo "  OPENCTI_ADMIN_TOKEN, RABBITMQ_PASSWORD, MINIO_SECRET_KEY written to .env (not shown)"
echo "  Dashboard + Kibana credentials saved in protected .env (not shown)"
echo ""
echo "[setup-env] Next step: ./scripts/bootstrap-platform.sh"
