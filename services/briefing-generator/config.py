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

# ── LLM provider selection (sintetizador 2026-08-19) ───────────────────────
# "ollama"  — local llama3.2:3b, path original del pilot (default: tests y GPU local).
# "bedrock" — claude via Amazon Bedrock legacy con rol IAM de instancia (VPS sin GPU).
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "ollama")
AWS_REGION   = os.environ.get("AWS_REGION", "us-east-1")
# Legacy bedrock-runtime exige inference profile IDs (us.anthropic.<modelo>-<fecha>-v1:0);
# Mantle está 403-gateado para esta cuenta (verificado 2026-08-18).
BEDROCK_MODEL = os.environ.get("BEDROCK_MODEL", "us.anthropic.claude-haiku-4-5-20251001-v1:0")

# ── Ollama (local LLM) ──────────────────────────────────────────────────────
OLLAMA_URL     = os.environ.get("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL   = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "60"))  # LLM prose generation: 30-45s on 4GB VRAM

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
logger.info("OLLAMA_URL configured: %s", OLLAMA_URL)
