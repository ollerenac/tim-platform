"""
normalizer.py — Confidence scoring and type mapping for feed-orchestrator.

Provides:
  compute_confidence()   — D-09 formula: seen_in_feeds * 25 + recency_bonus + quality_weight
  parse_first_seen()     — parse ISO-8601 and common feed date strings to aware datetime
  OBSERVABLE_TYPE_MAP    — STIX observable type → OpenCTI x_opencti_main_observable_type

D-09 Formula (LOCKED DECISION):
  score = min(100, seen_in_feeds * 25 + recency_bonus + quality_weight)
  recency_bonus = max(0, 10 - days_old)   # linear decay, floor at 0
  quality_weight = QUALITY_WEIGHTS.get(feed_name, 10)  # default 10 for unknown feeds
"""
from datetime import datetime, timezone

from config import QUALITY_WEIGHTS

# STIX observable type → OpenCTI x_opencti_main_observable_type
OBSERVABLE_TYPE_MAP = {
    "url":          "Url",
    "domain-name":  "Domain-Name",
    "ipv4-addr":    "IPv4-Addr",
    "file":         "StixFile",
}


def compute_confidence(feed_name: str, first_seen_dt: datetime, seen_in_feeds: int = 1) -> int:
    """
    Compute a 0-100 confidence score for an IOC using the D-09 formula.

    Args:
        feed_name:      Feed identifier key in QUALITY_WEIGHTS (e.g. "feodo")
        first_seen_dt:  Datetime the IOC was first observed (aware or naive; naive → UTC)
        seen_in_feeds:  Number of feeds that reported this IOC (default 1)

    Returns:
        int in range [0, 100]
    """
    quality_weight = QUALITY_WEIGHTS.get(feed_name, 10)

    # Normalise naive datetime to UTC-aware
    if first_seen_dt.tzinfo is None:
        first_seen_dt = first_seen_dt.replace(tzinfo=timezone.utc)

    days_old = max(0, (datetime.now(timezone.utc) - first_seen_dt).days)
    recency_bonus = max(0, 10 - days_old)
    score = seen_in_feeds * 25 + recency_bonus + quality_weight
    return min(100, score)


def parse_first_seen(date_str: str) -> datetime:
    """
    Parse a date string from a feed into a timezone-aware datetime.

    Accepts ISO-8601 with Z suffix, with +00:00 offset, or bare date (YYYY-MM-DD).
    Falls back to datetime.now(UTC) if the string is empty or unparseable.
    """
    if not date_str:
        return datetime.now(timezone.utc)

    # Normalise Z suffix
    date_str = date_str.strip().replace("Z", "+00:00")

    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f+00:00",
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    # Last resort: try fromisoformat (Python 3.7+)
    try:
        dt = datetime.fromisoformat(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return datetime.now(timezone.utc)
