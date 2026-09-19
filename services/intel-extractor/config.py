"""
config.py — Environment variable configuration for intel-extractor.

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
# Amazon Bedrock is the only provider: whole-document single call, v2.1 prompt
# (entities + relationships + per-object citation). Auth via the EC2 instance
# IAM role — no API key anywhere on disk. Not an env var: the local Ollama path
# and the direct Anthropic API path were retired on 2026-09-19. The name stays
# because the evaluation harnesses assert `extractor.LLM_PROVIDER == "bedrock"`.
LLM_PROVIDER  = "bedrock"
AWS_REGION    = os.environ.get("AWS_REGION", "us-east-1")
# Legacy bedrock-runtime takes cross-region inference profile IDs
# ("us.anthropic.<model>-<date>-v1:0" — copy exact value from Bedrock console →
# Inference profiles). Default = the haiku profile verified live 2026-08-18.
BEDROCK_MODEL = os.environ.get("BEDROCK_MODEL", "us.anthropic.claude-haiku-4-5-20251001-v1:0")

# ── Collector gate (incident 2026-08-10: paid side-effects without a lock) ──
# False by default: the service exposes ONLY the manual /extract API. The RSS
# collector + auto-extraction loop — which turns feed items into paid LLM calls
# with no human in the loop — must be enabled explicitly per deployment.
COLLECTOR_ENABLED = os.environ.get("COLLECTOR_ENABLED", "false").strip().lower() in ("1", "true", "yes")

# ── Key presence logging (never log key values) ─────────────────────────────
logger.info("OPENCTI_TOKEN configured: %s", bool(OPENCTI_TOKEN))
logger.info("LLM_PROVIDER: %s (%s, %s)", LLM_PROVIDER, BEDROCK_MODEL, AWS_REGION)
logger.info("COLLECTOR_ENABLED: %s", COLLECTOR_ENABLED)
