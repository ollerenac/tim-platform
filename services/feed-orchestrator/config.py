"""
config.py — Environment variable configuration for feed-orchestrator.

All env vars are read at import time and exposed as module-level constants.
Security: API key values are NEVER logged. Only presence is logged via bool().
"""
import logging
import os

logger = logging.getLogger(__name__)

# ── OpenCTI connection ──────────────────────────────────────────────────────
OPENCTI_URL = os.environ.get("OPENCTI_URL", "http://opencti:8080")
OPENCTI_TOKEN = os.environ.get("OPENCTI_TOKEN", "")

# ── Redis connection ────────────────────────────────────────────────────────
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379")

# ── Feed API Keys (all optional — feeds are disabled if key is absent) ──────
MALWAREBAZAAR_AUTH_KEY = os.environ.get("MALWAREBAZAAR_AUTH_KEY", "")
THREATFOX_AUTH_KEY = os.environ.get("THREATFOX_AUTH_KEY", "")
# abuse.ch SSLBL static CSVs still download unauthenticated (verified 2026-07-07);
# the Auth-Key header is sent when present, feeds stay enabled when absent.
ABUSECH_AUTH_KEY = os.environ.get("ABUSECH_AUTH_KEY", "")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")

# ── Feed cadences (hours) ───────────────────────────────────────────────────
FEED_INTERVALS = {
    "urlhaus": 1,
    "malwarebazaar": 2,
    "threatfox": 2,
    "feodo": 4,
    "sslbl_cert": 2,   # regenerates every 5 min upstream; 2h is polite and fresh
    "sslbl_ja3": 24,   # frozen list since 2021-08-03 — daily no-op
    "openphish": 6,    # upstream refreshes ~12h; 6h halves worst-case staleness
    "et_compromised": 12,  # daily upstream
    "spamhaus_drop": 12,  # daily re-eval upstream; max 1 fetch/hour policy honored
    "dshield": 4,         # ~daily upstream; poll <=1/hour allowed — 4h fine for ~20 rows
    "cins": 4,            # high-volume feed; 24h dedup TTL limits full-cost cycles
    "abuseipdb": 24,      # free tier 5 req/day (x-ratelimit-limit: 5) — daily is the ceiling
}

# ── Per-source quality weights (D-09) ──────────────────────────────────────
# score = min(100, feed_count * 25 + recency_bonus + quality_weight)
QUALITY_WEIGHTS = {
    "feodo": 30,        # manually curated C2 blocklist — highest signal
    "threatfox": 20,    # community + analyst-reviewed
    "urlhaus": 15,      # automated with community validation
    "malwarebazaar": 15, # automated with community validation
    "sslbl_cert": 25,    # abuse.ch-curated C2 certificates — high signal
    "sslbl_ja3": 10,     # frozen + FP-prone per abuse.ch's own warning
    "openphish": 20,      # phishing-specific curated URL feed
    "et_compromised": 20, # compromised-host list from Emerging Threats
    "spamhaus_drop": 30,  # Spamhaus-curated hijacked netblocks — highest signal of new set
    "dshield": 20,        # attack-volume derived, community sensors
    "cins": 15,            # large automated bad-IP list, lower influence
    "abuseipdb": 25,       # every free-tier entry is confidence-100 confirmed abuse — curated tier
}

# ── SIEM / Elasticsearch ────────────────────────────────────────────────────
ES_URL = os.environ.get("ES_URL", "http://elasticsearch:9200")

# ── Alerting ────────────────────────────────────────────────────────────────
# Max reachable score with seen_in_feeds=1: feodo fresh = 65.
ALERT_THRESHOLD = int(os.environ.get("ALERT_THRESHOLD", "55"))

# ── Key presence logging (never log key values) ─────────────────────────────
logger.info("OPENCTI_TOKEN configured: %s", bool(OPENCTI_TOKEN))
logger.info("MALWAREBAZAAR_AUTH_KEY configured: %s", bool(MALWAREBAZAAR_AUTH_KEY))
logger.info("THREATFOX_AUTH_KEY configured: %s", bool(THREATFOX_AUTH_KEY))
logger.info("ABUSECH_AUTH_KEY configured: %s", bool(ABUSECH_AUTH_KEY))
logger.info("ABUSEIPDB_API_KEY configured: %s", bool(ABUSEIPDB_API_KEY))
