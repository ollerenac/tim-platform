"""
status.py — Feed status writer/reader for Redis.

Writes all 4 D-02 fields atomically via hset(mapping={...}).
Key pattern: tim:feed_status:{feed_name}

D-02 fields:
  last_run   — ISO-8601 UTC timestamp of the run that wrote this status
  ioc_count  — integer count of IOCs inserted in that run (stored as str)
  status     — one of: ok | error | running | never_run | disabled
  error_msg  — error description truncated to 500 chars, or empty string

Note: hmset() was removed in redis-py 4.x. Use hset(mapping={...}) only.
"""
from datetime import datetime, timezone


def set_status(
    redis_client,
    feed_name: str,
    status: str,
    ioc_count: int = 0,
    error_msg: str = "",
) -> None:
    """Write all 4 D-02 fields atomically for the given feed."""
    redis_client.hset(
        f"tim:feed_status:{feed_name}",
        mapping={
            "last_run": datetime.now(timezone.utc).isoformat(),
            "ioc_count": str(ioc_count),
            "status": status,
            "error_msg": error_msg[:500],
        },
    )


def get_status(redis_client, feed_name: str) -> dict:
    """Return the current status hash for the given feed (may be empty dict)."""
    return redis_client.hgetall(f"tim:feed_status:{feed_name}")
