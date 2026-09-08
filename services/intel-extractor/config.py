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

# ── Ollama (local LLM) ──────────────────────────────────────────────────────
OLLAMA_URL   = os.environ.get("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")

# ── LLM provider selection (decision-llm 2026-08-10) ────────────────────────
# "ollama"    — legacy local pilot path (chunked, flat schema). Default so the
#               offline test suite and any GPU deployment keep working untouched.
# "anthropic" — claude-opus-5 via Anthropic API: whole-document single call,
#               v2.1 prompt (entities+relationships+per-object citation).
# "bedrock"   — same claude models and v2.1 path via Amazon Bedrock. Auth via
#               the EC2 instance IAM role (no API key anywhere on disk).
LLM_PROVIDER      = os.environ.get("LLM_PROVIDER", "ollama")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL   = os.environ.get("ANTHROPIC_MODEL", "claude-opus-5")
AWS_REGION        = os.environ.get("AWS_REGION", "us-east-1")
# Legacy bedrock-runtime takes cross-region inference profile IDs
# ("us.anthropic.<model>-<date>-v1:0" — copy exact value from Bedrock console →
# Inference profiles). Default = the haiku profile verified live 2026-08-18;
# quality runs override to the opus profile once the account-tier gate lifts.
BEDROCK_MODEL     = os.environ.get("BEDROCK_MODEL", "us.anthropic.claude-haiku-4-5-20251001-v1:0")

# ── Collector gate (incident 2026-08-10: paid side-effects without a lock) ──
# False by default: the service exposes ONLY the manual /extract API. The RSS
# collector + auto-extraction loop — which turns feed items into paid LLM calls
# with no human in the loop — must be enabled explicitly per deployment.
COLLECTOR_ENABLED = os.environ.get("COLLECTOR_ENABLED", "false").strip().lower() in ("1", "true", "yes")

# ── Key presence logging (never log key values) ─────────────────────────────
logger.info("OPENCTI_TOKEN configured: %s", bool(OPENCTI_TOKEN))
logger.info("OLLAMA_URL configured: %s", bool(OLLAMA_URL))
logger.info("LLM_PROVIDER: %s", LLM_PROVIDER)
logger.info("ANTHROPIC_API_KEY configured: %s", bool(ANTHROPIC_API_KEY))
logger.info("COLLECTOR_ENABLED: %s", COLLECTOR_ENABLED)
