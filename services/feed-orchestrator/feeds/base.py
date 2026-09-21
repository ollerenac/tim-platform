"""
feeds/base.py — Abstract base class for all feed implementations.

BaseFeed defines the contract that all 5 feed subclasses (urlhaus, malwarebazaar,
threatfox, feodo, otx) must implement: fetch() and normalize().

The run() method orchestrates the full feed cycle:
  1. Write status=running to Redis (D-02 fields, D-01 key namespace)
  2. _fetch_with_retry(): download with 3x backoff [30, 60, 120]s (D-04)
  3. normalize(): transform raw data to pycti create_indicator() kwargs dicts
  4. _insert_deduplicated(): dedup via Redis SETNX, insert via pycti (D-05 retry)
  5. Write status=ok or status=error to Redis

All Redis writes use hset(mapping={...}) — NOT hmset() (removed in redis-py 4.x).
"""
import json
import logging
import re
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

import requests

from config import ALERT_THRESHOLD, ES_URL
from deduplicator import clear_seen, is_duplicate
from opencti_client import create_indicator

logger = logging.getLogger(__name__)

# Escape-aware: a value may legitimately contain an escaped quote (\') — match the whole
# escaped literal, then unescape, instead of stopping at the first raw quote.
_IOC_VALUE_RE = re.compile(r"= '((?:[^'\\]|\\.)*)'")
_STIX_INDICATOR_ID_RE = re.compile(
    r"^indicator--[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def stix_escape(value: str) -> str:
    """Escape a value for safe interpolation into a STIX single-quoted string literal.

    Backslash MUST be escaped before the single quote: otherwise a value ending in '\'
    produces '...\'' where the backslash escapes the closing quote, letting the remainder
    inject additional STIX pattern expressions pushed to OpenCTI (T-02-04-01).
    """
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _pattern_value(pattern: str) -> str:
    """Recover the original IOC value from a STIX pattern, undoing stix_escape()."""
    m = _IOC_VALUE_RE.search(pattern)
    if not m:
        return pattern
    return m.group(1).replace("\\'", "'").replace("\\\\", "\\")


def _indicator_stix_id(opencti_indicator: dict, pattern: str) -> tuple[str, bool]:
    """Return the real OpenCTI/STIX Indicator ID when pycti exposes it.

    pycti normally returns `standard_id`; older or mocked clients may only return
    `id`. Only values already shaped as STIX Indicator IDs are treated as real.
    The deterministic fallback is for export continuity, not for OpenCTI lookup.
    """
    for key in ("standard_id", "standardId", "id"):
        value = opencti_indicator.get(key)
        if isinstance(value, str) and _STIX_INDICATOR_ID_RE.match(value):
            return value, True
    return f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, pattern)}", False


def _index_ioc(
    redis_client: Any,
    pattern: str,
    confidence: int,
    feed: str,
    ioc_type: str,
    opencti_indicator: dict,
    submitted_valid_from: str,
) -> None:
    """Index every inserted IOC into ES tim-iocs, and additionally push to the alert list
    when it clears ALERT_THRESHOLD.

    Previously only alert-level IOCs were indexed, so /feeds/recent and /feeds/export/stix
    (which read solely from ES) never saw sub-threshold feeds like URLhaus/MalwareBazaar.
    """
    ingested_at = datetime.now(timezone.utc).isoformat()
    stix_id, has_opencti_standard_id = _indicator_stix_id(opencti_indicator, pattern)
    doc = {
        "ts": ingested_at,
        "ingested_at": ingested_at,
        "value": _pattern_value(pattern),
        "confidence": confidence,
        "feed": feed,
        "type": ioc_type,
        "pattern": pattern,
        "stix_id": stix_id,
        "opencti_standard_id": stix_id if has_opencti_standard_id else None,
        "stix_id_source": "opencti" if has_opencti_standard_id else "deterministic-fallback",
        "opencti_id": opencti_indicator.get("id"),
        "valid_from": opencti_indicator.get("valid_from") or submitted_valid_from,
        "opencti_created_at": opencti_indicator.get("created_at"),
        "opencti_updated_at": opencti_indicator.get("updated_at"),
    }
    try:
        requests.post(f"{ES_URL}/tim-iocs/_doc/{stix_id}", json=doc, timeout=5)
    except Exception as exc:
        logger.warning("[index] ES index failed: %s", exc)
    if confidence >= ALERT_THRESHOLD:
        redis_client.rpush("tim:alerts", json.dumps(doc))
        redis_client.ltrim("tim:alerts", -100, -1)  # keep newest 100


class BaseFeed(ABC):
    """Abstract base class for all threat intelligence feed implementations."""

    name: str        # Feed identifier used in Redis keys and log messages
    quality_weight: int   # D-09 confidence formula weight
    interval_hours: int   # Scheduled cadence for APScheduler

    @abstractmethod
    def fetch(self) -> list[dict]:
        """Download and parse raw feed data. Returns list of raw row dicts."""
        raise NotImplementedError

    @abstractmethod
    def normalize(self, raw: list[dict]) -> list[dict]:
        """
        Transform raw feed rows to pycti create_indicator() kwargs dicts.

        Each returned dict must contain keys:
          name, pattern, observable_type, confidence, labels, source_name
        Optional: valid_from (ISO-8601 string)

        Returns list of dicts — one per indicator to insert.
        """
        raise NotImplementedError

    def run(self, redis_client: Any, pycti_client: Any) -> None:
        """
        Execute a full feed cycle: status=running → fetch → normalize →
        insert → status=ok/error.

        Called by APScheduler on the configured interval, and once immediately
        on container startup (D-06).
        """
        redis_client.hset(
            f"tim:feed_status:{self.name}",
            mapping={
                "status": "running",
                "last_run": datetime.now(timezone.utc).isoformat(),
                "ioc_count": "0",
                # Reset here so a failed run never shows the previous run's funnel.
                "fetched_count": "0",
                "normalized_count": "0",
                "error_msg": "",
            },
        )
        try:
            raw = self._fetch_with_retry()
            indicators = self.normalize(raw)
            count = self._insert_deduplicated(indicators, redis_client, pycti_client)
            redis_client.hset(
                f"tim:feed_status:{self.name}",
                mapping={
                    "status": "ok",
                    "last_run": datetime.now(timezone.utc).isoformat(),
                    "ioc_count": str(count),
                    "fetched_count": str(len(raw)),
                    "normalized_count": str(len(indicators)),
                    "error_msg": "",
                },
            )
            logger.info(
                "[%s] run complete: %d indicators inserted (%d fetched, %d normalized)",
                self.name, count, len(raw), len(indicators),
            )
        except Exception as exc:
            logger.error("[%s] run failed: %s", self.name, exc)
            redis_client.hset(
                f"tim:feed_status:{self.name}",
                mapping={
                    "status": "error",
                    "last_run": datetime.now(timezone.utc).isoformat(),
                    "ioc_count": "0",
                    "error_msg": str(exc)[:500],
                },
            )

    def _fetch_with_retry(self) -> list[dict]:
        """
        Call self.fetch() with D-04 retry: 3 attempts, delays [30, 60, 120]s.

        On each failure before the last attempt, logs a warning and sleeps.
        On final failure, re-raises the exception so run()'s except block
        can write status=error.
        """
        delays = [30, 60, 120]
        last_exc: Exception | None = None
        for attempt, delay in enumerate(delays):
            try:
                return self.fetch()
            except Exception as exc:
                last_exc = exc
                if attempt < len(delays) - 1:
                    logger.warning(
                        "[%s] fetch attempt %d failed, retrying in %ds: %s",
                        self.name,
                        attempt + 1,
                        delay,
                        exc,
                    )
                    time.sleep(delay)
        raise last_exc  # type: ignore[misc]

    def _insert_deduplicated(
        self,
        indicators: list[dict],
        redis_client: Any,
        pycti_client: Any,
    ) -> int:
        """
        Insert indicators into OpenCTI, skipping duplicates via Redis SETNX.

        Loops over normalized indicator dicts. For each:
          - If is_duplicate() returns True: skip (already inserted this cycle)
          - Else: compute D-09 confidence, call create_indicator() with D-05 retry

        Returns count of indicators actually submitted to pycti (not skipped).
        """
        # Lazy import avoids circular-import risk at module load time
        from normalizer import compute_confidence, parse_first_seen

        count = 0
        for ind in indicators:
            pattern = ind.get("pattern", "")
            if not pattern:
                continue
            if is_duplicate(redis_client, pattern):
                continue
            first_seen_dt = parse_first_seen(ind.get("valid_from", ""))
            confidence = compute_confidence(self.name, first_seen_dt)
            ind["confidence"] = confidence
            result = create_indicator(
                client=pycti_client,
                name=ind.get("name", f"{self.name} indicator"),
                pattern=pattern,
                observable_type=ind.get("observable_type", ""),
                confidence=confidence,
                labels=ind.get("labels", []),
                source_name=ind.get("source_name", self.name),
                valid_from=first_seen_dt.isoformat(),  # ISO 8601 required by OpenCTI GraphQL
                description=ind.get("description"),
            )
            if result is not None:
                count += 1
                # Index every successfully-inserted IOC (not just alerts) so the ES-backed
                # /feeds/recent and /feeds/export/stix endpoints see all feeds.
                _index_ioc(
                    redis_client,
                    pattern,
                    confidence,
                    self.name,
                    ind.get("observable_type", ""),
                    result,
                    first_seen_dt.isoformat(),
                )
            else:
                # H3: insert failed — un-mark the dedup key so the next scheduled run retries
                # this IOC instead of suppressing it for the full 24h TTL.
                clear_seen(redis_client, pattern)
        return count
