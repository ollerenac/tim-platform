#!/usr/bin/env bash
# Verify .env exists and is not world-readable.
set -euo pipefail

ENV_FILE="${1:-.env}"

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found — copy .env.example and fill in secrets" >&2
  exit 1
fi

perms=$(stat -c "%a" "$ENV_FILE")
if [ "$perms" != "600" ]; then
  echo "Fixing $ENV_FILE permissions: $perms → 600"
  chmod 600 "$ENV_FILE"
fi

echo "✓ $ENV_FILE exists and is chmod 600"
