"""
test_feodo.py — RED phase tests for FeodoFeed (FEED-02c).

These tests will raise ImportError until feeds/feodo.py is implemented (Wave 2, Plan 04).
That is expected and correct.

Feodo Tracker is the highest-quality feed (quality_weight=30) and always represents
confirmed Botnet C2 servers. Every normalized indicator MUST include the "c2" label.
"""
import pytest

# RED: This import will fail until Plan 04 creates feeds/feodo.py
from feeds.feodo import FeodoFeed


def test_normalize_dst_ip_pattern(sample_feodo_rows):
    """FEED-02c: dst_ip column maps to STIX ipv4-addr:value pattern."""
    feed = FeodoFeed()
    result = feed.normalize(sample_feodo_rows)
    assert len(result) == 1
    assert result[0]["pattern"] == "[ipv4-addr:value = '185.220.101.47']"


def test_normalize_c2_label_always_present(sample_feodo_rows):
    """FEED-02c: Every Feodo indicator must include 'c2' in labels (all entries are C2 servers)."""
    feed = FeodoFeed()
    result = feed.normalize(sample_feodo_rows)
    assert len(result) == 1
    assert "c2" in result[0]["labels"]


def test_normalize_includes_malware_family(sample_feodo_rows):
    """FEED-02c: Malware family name from 'malware' column appears in labels."""
    feed = FeodoFeed()
    result = feed.normalize(sample_feodo_rows)
    assert len(result) == 1
    assert "Emotet" in result[0]["labels"]
