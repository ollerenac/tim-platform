"""
api.py — FastAPI application for feed-orchestrator HTTP endpoints.

Endpoints:
  GET /feeds/status  — per-feed run history from Redis (DASH-01)
  GET /feeds/recent  — last N IOCs from ES tim-iocs index (MON-01)
  GET /health        — liveness probe

CORS: allow_origins includes https://localhost (dashboard :443) per T-06-01-01.
"""
import json
import logging
import re
import time
import uuid
from datetime import datetime, timezone

import requests
import stix2
from dateutil.parser import parse as parse_dt
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from redis import from_url as redis_from_url

from config import ALERT_THRESHOLD, ES_URL, OPENCTI_TOKEN, OPENCTI_URL, REDIS_URL
from status import get_status

logger = logging.getLogger(__name__)

app = FastAPI(title="feed-orchestrator", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://localhost"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

# One shared Redis client (connection pool) reused across requests — building a fresh
# client per request churned connections/FDs under the dashboard's 30s polling.
_redis = redis_from_url(REDIS_URL, decode_responses=True)

# Confirmed .name attribute values from each feed class (build_enabled_feeds order)
# "otx" retirado 2026-07-22: la fuente OTX ahora entra SOLO por el conector oficial
# connector-alienvault (P0.1 — doble ingesta del mismo origen).
# "digitalside" retirado 2026-07-25: host osint.digitalside.it caído desde 2026-07-07
# (nunca ingirió; DNS resuelve pero HTTP timeout). Reactivar si el sitio revive.
FEED_NAMES = ["urlhaus", "malwarebazaar", "threatfox", "feodo", "sslbl_cert", "sslbl_ja3", "openphish", "et_compromised", "spamhaus_drop", "dshield", "abuseipdb", "cins"]

# T-08-02: compiled once at module level; never raises on malformed/null input
_STIX_TYPE_RE = re.compile(r"^\[([a-z0-9-]+):")

_STIX_TYPE_MAP = {
    "ipv4-addr": "IPv4",
    "domain-name": "Domain",
    "url": "URL",
    "email-addr": "Email",
}


def _parse_type_from_pattern(pattern: str) -> str:
    """Map a STIX pattern string to a human-readable IOC type label.

    T-08-02 guard: never raises — malformed or empty patterns return 'Unknown'.
    """
    m = _STIX_TYPE_RE.match(pattern or "")
    if not m:
        return "Unknown"
    sco = m.group(1)
    if sco == "file":
        if "SHA-256" in pattern:
            return "SHA-256"
        if "SHA-1" in pattern:
            return "SHA-1"
        return "MD5"
    return _STIX_TYPE_MAP.get(sco, sco)


@app.get("/feeds/status")
def feeds_status():
    """Return per-feed status from Redis. Missing keys return safe defaults."""
    feeds = []
    for name in FEED_NAMES:
        h = get_status(_redis, name)
        feeds.append({
            "name": name,
            "last_run": h.get("last_run"),
            "ioc_count": int(h.get("ioc_count", 0)),
            "status": h.get("status", "never_run"),
            "error_msg": h.get("error_msg", ""),
        })
    return {"feeds": feeds}


@app.get("/feeds/alerts")
def feeds_alerts():
    """Return the 100 most recent high-confidence IOC alerts from Redis."""
    raw = _redis.lrange("tim:alerts", 0, -1)
    alerts = [json.loads(e) for e in raw]
    return {"threshold": ALERT_THRESHOLD, "alerts": list(reversed(alerts))}


@app.get("/feeds/recent")
def feeds_recent(limit: int = 200):
    """Return the most recent IOCs from ES tim-iocs index (MON-01).

    T-08-01: limit capped at 500 server-side — client cannot force a 99999-size ES request.
    """
    capped = min(limit, 500)
    try:
        resp = requests.get(
            f"{ES_URL}/tim-iocs/_search",
            json={"size": capped, "sort": [{"ts": {"order": "desc"}}]},
            timeout=10,
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"ES unavailable: {exc}")

    iocs = []
    for h in hits:
        src = h.get("_source", {})
        # Skip malformed docs rather than 500 the whole endpoint on one bad row.
        if "ts" not in src or "value" not in src:
            continue
        iocs.append({
            "ts": src["ts"],
            "ingested_at": src.get("ingested_at", src["ts"]),
            "value": src["value"],
            "type": _parse_type_from_pattern(src.get("pattern", "")),
            "feed": src.get("feed", "unknown"),
            "confidence": src.get("confidence", 0),
            "stix_id": src.get("stix_id"),
            "opencti_standard_id": src.get("opencti_standard_id", src.get("stix_id")),
            "stix_id_source": src.get("stix_id_source"),
            "valid_from": src.get("valid_from"),
            "opencti_created_at": src.get("opencti_created_at"),
        })
    return {"iocs": iocs}


@app.get("/feeds/export/stix")
def export_stix():
    """Return a STIX 2.1 bundle of all high-confidence IOCs indexed in Elasticsearch."""
    try:
        resp = requests.get(
            f"{ES_URL}/tim-iocs/_search",
            json={"size": 1000, "sort": [{"ts": {"order": "desc"}}]},
            timeout=10,
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"ES unavailable: {exc}")

    indicators = []
    for hit in hits:
        src = hit.get("_source", {})
        try:
            indicators.append(stix2.Indicator(
                id=src.get("stix_id", f"indicator--{uuid.uuid4()}"),
                name=src["value"],
                pattern=src["pattern"],
                pattern_type="stix",
                valid_from=parse_dt(src["ts"]),
                confidence=src["confidence"],
                labels=[src.get("feed", "unknown")],
            ))
        except Exception as exc:  # skip one bad doc, don't 500 the whole bundle
            logger.warning("[export] skipping malformed IOC doc: %s", exc)
            continue

    bundle = stix2.Bundle(*indicators, allow_custom=True)
    return Response(content=bundle.serialize(), media_type="application/stix+json")


# 30s in-memory cache — dashboard polls every 30s per tab; one OpenCTI query per TTL.
_connectors_cache = {"ts": 0.0, "data": None}
_CONNECTORS_TTL = 30.0

_CONNECTORS_QUERY = "{ connectors { id name active auto connector_state connector_type } }"


def _parse_last_run(connector_state):
    """Extract last_run_timestamp from connector_state (JSON string) as ISO-8601 UTC.

    connector_state may be null/empty/malformed → None. Never raises.
    """
    try:
        state = json.loads(connector_state or "null") or {}
        # OpenCTI 7 connectors use heterogeneous keys (verified live 2026-07-10):
        # greynoise: last_run_timestamp (ms); mitre/cve/misp: last_run; cisa-kev: last_update
        ts = next((state[k] for k in ("last_run_timestamp", "last_run", "last_update") if state.get(k) is not None), None)
        if ts is None:
            return None
        if isinstance(ts, str):
            return ts
        ts = float(ts)
        if ts > 1e12:  # epoch milliseconds
            ts /= 1000.0
        return datetime.fromtimestamp(ts, timezone.utc).isoformat()
    except (ValueError, TypeError, AttributeError):
        return None


@app.get("/connectors/status")
def connectors_status():
    """Return OpenCTI connector list (name/active/type/last_run). Token stays server-side."""
    now = time.monotonic()
    if _connectors_cache["data"] is not None and now - _connectors_cache["ts"] < _CONNECTORS_TTL:
        return _connectors_cache["data"]

    try:
        resp = requests.post(
            f"{OPENCTI_URL}/graphql",
            json={"query": _CONNECTORS_QUERY},
            headers={"Authorization": f"Bearer {OPENCTI_TOKEN}"},
            timeout=10,
        )
        resp.raise_for_status()
        raw = resp.json()["data"]["connectors"]
    except Exception:
        # Never echo the exception — it may carry request headers (token).
        if _connectors_cache["data"] is not None:
            logger.warning("[connectors] OpenCTI unavailable — serving stale cache")
            return _connectors_cache["data"]
        raise HTTPException(status_code=503, detail="OpenCTI unavailable")

    data = {"connectors": [
        {
            "name": c.get("name"),
            "active": c.get("active"),
            "connector_type": c.get("connector_type"),
            "last_run": _parse_last_run(c.get("connector_state")),
        }
        for c in raw
    ]}
    _connectors_cache["ts"] = now
    _connectors_cache["data"] = data
    return data


@app.get("/health")
def health():
    return {"status": "ok"}
