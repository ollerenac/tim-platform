"""
test_urlhaus.py — RED phase tests for URLhausFeed (FEED-01).

These tests will raise ImportError until feeds/urlhaus.py is implemented (Wave 2, Plan 04).
That is expected and correct — this file defines the contract the implementation must satisfy.
"""
import pytest

# RED: This import will fail until Plan 04 creates feeds/urlhaus.py
from feeds.urlhaus import URLhausFeed


def test_normalize_url_pattern(sample_urlhaus_rows):
    """FEED-01: URLhaus row normalizes to a STIX url:value pattern."""
    feed = URLhausFeed()
    result = feed.normalize(sample_urlhaus_rows)
    assert len(result) == 1
    assert result[0]["pattern"] == "[url:value = 'http://evil.example.com/malware.exe']"


def test_normalize_includes_tags(sample_urlhaus_rows):
    """FEED-01: Tags from the 'tags' column appear in the 'labels' list."""
    feed = URLhausFeed()
    result = feed.normalize(sample_urlhaus_rows)
    assert len(result) == 1
    assert "Mozi" in result[0]["labels"]


def test_normalize_skips_empty_url():
    """FEED-01: Rows with empty url value are excluded from output."""
    feed = URLhausFeed()
    result = feed.normalize([{"url": "", "tags": "", "dateadded": ""}])
    assert result == []
