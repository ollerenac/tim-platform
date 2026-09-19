"""
config.py — Environment variable configuration for briefing-generator.

All env vars are read at import time and exposed as module-level constants.
Security: token values are NEVER logged. Only presence is logged via bool().
"""
import logging
import os

logger = logging.getLogger(__name__)

# ── OpenCTI connection ──────────────────────────────────────────────────────
OPENCTI_URL   = os.environ.get("OPENCTI_URL", "http://opencti:8080")
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN", "")

# ── LLM provider ────────────────────────────────────────────────────────────
# Amazon Bedrock es el único proveedor: claude por bedrock-runtime legacy con el rol
# IAM de la instancia. No es variable de entorno: la ruta local con Ollama se retiró
# el 2026-09-19. El nombre se conserva porque el anclaje lo persiste en cada briefing
# y los conductores de evaluación lo leen.
LLM_PROVIDER = "bedrock"
AWS_REGION   = os.environ.get("AWS_REGION", "us-east-1")
# Legacy bedrock-runtime exige inference profile IDs (us.anthropic.<modelo>-<fecha>-v1:0);
# Mantle está 403-gateado para esta cuenta (verificado 2026-08-18).
BEDROCK_MODEL = os.environ.get("BEDROCK_MODEL", "us.anthropic.claude-haiku-4-5-20251001-v1:0")

# ── Provenance allowlist ────────────────────────────────────────────────────
# Only entities authored (createdBy) by these identities feed the briefing.
# Mass commodity publishers (OTX community bots, honeypot feeds) otherwise crowd
# out curated intel in every top-N selection. Empty list = no filtering.
CURATED_AUTHORS = [
    a.strip() for a in os.environ.get("CURATED_AUTHORS", "").split(",") if a.strip()
]

# ── Persistence ─────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", "/data/briefings.db")

# ── Key presence logging (never log key values) ─────────────────────────────
logger.info("OPENCTI_TOKEN configured: %s", bool(OPENCTI_TOKEN))
logger.info("LLM_PROVIDER: %s (%s, %s)", LLM_PROVIDER, BEDROCK_MODEL, AWS_REGION)
