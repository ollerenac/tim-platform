"""
config.py — Environment variable configuration for semantic-engine.

All env vars are read at import time and exposed as module-level constants.
Security: token values are NEVER logged. Only presence is logged via bool().
"""
import logging
import os

logger = logging.getLogger(__name__)

# ── OpenCTI connection ──────────────────────────────────────────────────────
OPENCTI_URL      = os.environ.get("OPENCTI_URL", "http://opencti:8080")
OPENCTI_TOKEN    = os.environ.get("OPENCTI_TOKEN", "")
# OPENCTI_BASE_URL: external-facing URL for deep-link generation (AISEM-04)
# Not the internal http://opencti:8080 — this is what analysts open in a browser
OPENCTI_BASE_URL = os.environ.get("OPENCTI_BASE_URL", "http://localhost:8080")
OPENCTI_PAGE_SIZE = int(os.environ.get("OPENCTI_PAGE_SIZE", "100"))
if not 1 <= OPENCTI_PAGE_SIZE <= 100:
    raise ValueError("OPENCTI_PAGE_SIZE must be between 1 and 100")

# ── Ollama (local embeddings) ───────────────────────────────────────────────
OLLAMA_URL         = os.environ.get("OLLAMA_URL", "http://ollama:11434")
OLLAMA_EMBED_MODEL = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")
OLLAMA_SEARCH_TIMEOUT_SECONDS = int(
    os.environ.get("OLLAMA_SEARCH_TIMEOUT_SECONDS", "90")
)
OLLAMA_KEEP_ALIVE = os.environ.get("OLLAMA_KEEP_ALIVE", "5m")
EMBED_BATCH_SIZE = int(os.environ.get("EMBED_BATCH_SIZE", "32"))
if not 1 <= EMBED_BATCH_SIZE <= 100:
    raise ValueError("EMBED_BATCH_SIZE must be between 1 and 100")
SEMANTIC_WARMUP_RETRY_SECONDS = int(
    os.environ.get("SEMANTIC_WARMUP_RETRY_SECONDS", "5")
)

# ── ChromaDB (vector store) ─────────────────────────────────────────────────
CHROMADB_URL = os.environ.get("CHROMADB_URL", "http://chromadb:8000")

# ── Provenance allowlist ────────────────────────────────────────────────────
# Only indicators authored (createdBy) by these identities are indexed for
# semantic search. Mass commodity feeds (GreyNoise, OTX community publishers)
# drowned the vector space — provenance is the quality signal, not content.
# Empty list = no filtering (index everything), preserving pre-allowlist behavior.
CURATED_AUTHORS = [
    a.strip() for a in os.environ.get("CURATED_AUTHORS", "").split(",") if a.strip()
]

# ── Semantic search tuning ──────────────────────────────────────────────────
# D-07: similarity threshold — drop results below this score to avoid noise
SIMILARITY_THRESHOLD  = float(os.environ.get("SIMILARITY_THRESHOLD", "0.3"))
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "300"))

# ── Key presence logging (never log key values) ─────────────────────────────
logger.info("OPENCTI_TOKEN configured: %s", bool(OPENCTI_TOKEN))
