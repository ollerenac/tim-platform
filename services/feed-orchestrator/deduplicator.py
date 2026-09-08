"""
deduplicator.py — Redis-based IOC deduplication using SETNX.

Key pattern: tim:ioc_seen:{sha256(pattern)}
TTL: 86400 seconds (24 hours) — longer than any feed cadence (max 6h)

Uses sha256 of the full STIX pattern string (not raw IOC value) as the
dedup key. The same IP can be a legitimate IOC under different pattern
types; the STIX pattern string is the canonical dedup unit.

Namespace tim:ioc_seen: avoids collision with OpenCTI's own Redis keys (D-01).
"""
import hashlib
from typing import Any


def is_duplicate(redis_client: Any, ioc_pattern: str) -> bool:
    """
    Check whether this STIX pattern has already been inserted in this cycle.

    Returns False when the key was newly set (not a duplicate — proceed with insert).
    Returns True when the key already existed (duplicate — skip insert).

    redis_client.set(key, "1", nx=True, ex=86400):
      - Returns True  => key was set (new)
      - Returns None  => key already existed (duplicate)
    """
    key = "tim:ioc_seen:" + hashlib.sha256(ioc_pattern.encode()).hexdigest()
    was_new = redis_client.set(key, "1", nx=True, ex=86400)
    return not was_new  # True = duplicate = skip


def clear_seen(redis_client: Any, ioc_pattern: str) -> None:
    """Remove the dedup key for a pattern.

    Called when an insert fails after is_duplicate() already set the key, so the IOC
    is retried on the next run instead of being suppressed for the full 24h TTL.
    """
    key = "tim:ioc_seen:" + hashlib.sha256(ioc_pattern.encode()).hexdigest()
    redis_client.delete(key)
