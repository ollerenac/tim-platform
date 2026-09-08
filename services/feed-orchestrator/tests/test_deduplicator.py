"""
test_deduplicator.py — RED phase tests for deduplicator.is_duplicate() (FEED-04).

These tests will raise ImportError until deduplicator.py is implemented (Wave 2, Plan 02/03).
That is expected and correct.

Redis SETNX semantics:
  - r.set(key, "1", nx=True, ex=86400) returns True  => key was set (new key, not duplicate)
  - r.set(key, "1", nx=True, ex=86400) returns None  => key already existed (duplicate)

Key format (D-01 namespace): "tim:ioc_seen:" + sha256(pattern)
"""
import hashlib
import pytest
from unittest.mock import MagicMock

# RED: This import will fail until Plan 02/03 creates deduplicator.py
from deduplicator import clear_seen, is_duplicate
from feeds.base import _pattern_value, stix_escape

PATTERN = "[url:value = 'http://x.com']"


def test_clear_seen_deletes_key():
    """H3: clear_seen() deletes the dedup key so a failed insert is retried next run."""
    r = MagicMock()
    clear_seen(r, PATTERN)
    r.delete.assert_called_once()
    key = r.delete.call_args[0][0]
    assert key == "tim:ioc_seen:" + hashlib.sha256(PATTERN.encode()).hexdigest()


def test_stix_escape_backslash_before_quote():
    """H1: backslash is doubled before the quote is escaped, so a trailing '\\' can't
    escape the closing quote and inject extra pattern expressions."""
    assert stix_escape("http://x/\\") == "http://x/\\\\"
    assert stix_escape("a'b") == "a\\'b"
    # round-trip: a value escaped into a pattern is recovered intact
    val = "weird\\'value"
    pattern = f"[url:value = '{stix_escape(val)}']"
    assert _pattern_value(pattern) == val


def test_first_call_not_duplicate(mock_redis):
    """FEED-04: is_duplicate() returns False when Redis.set returns True (new key)."""
    # mock_redis.set.return_value = True already set in conftest.py
    result = is_duplicate(mock_redis, PATTERN)
    assert result is False


def test_second_call_is_duplicate():
    """FEED-04: is_duplicate() returns True when Redis.set returns None (key existed)."""
    r = MagicMock()
    # Simulate key already existing: SETNX returns None (did not set)
    r.set.return_value = None
    result = is_duplicate(r, PATTERN)
    assert result is True


def test_key_uses_sha256_of_pattern(mock_redis):
    """FEED-04: Redis key is prefixed with 'tim:ioc_seen:' followed by sha256 of pattern."""
    is_duplicate(mock_redis, PATTERN)
    # Verify the call was made
    mock_redis.set.assert_called_once()
    call_args = mock_redis.set.call_args
    # First positional argument is the key
    key = call_args[0][0]
    assert key.startswith("tim:ioc_seen:"), (
        f"Expected key to start with 'tim:ioc_seen:', got: {key!r}"
    )
    expected_hash = hashlib.sha256(PATTERN.encode()).hexdigest()
    expected_key = "tim:ioc_seen:" + expected_hash
    assert key == expected_key, (
        f"Expected key {expected_key!r}, got {key!r}"
    )


def test_uses_nx_and_ttl(mock_redis):
    """FEED-04: Redis.set is called with nx=True and ex=86400 (24h TTL)."""
    is_duplicate(mock_redis, PATTERN)
    mock_redis.set.assert_called_once()
    call_kwargs = mock_redis.set.call_args[1]
    assert call_kwargs.get("nx") is True, "Expected nx=True for SETNX semantics"
    assert call_kwargs.get("ex") == 86400, "Expected ex=86400 (24h TTL)"
