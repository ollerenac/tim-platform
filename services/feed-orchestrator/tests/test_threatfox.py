"""
test_threatfox.py — RED phase tests for ThreatFoxFeed (FEED-02b).

These tests will raise ImportError until feeds/threatfox.py is implemented (Wave 2, Plan 05).
That is expected and correct.

Critical Pitfall 2 (RESEARCH.md): ThreatFox ip:port IOC type
  - ioc = "185.220.101.47:4444" with ioc_type = "ip:port"
  - WRONG: [ipv4-addr:value = '185.220.101.47:4444']  — invalid STIX (port in value)
  - CORRECT: [ipv4-addr:value = '185.220.101.47']     — split on ':' and use IP only
"""
import pytest

# RED: This import will fail until Plan 05 creates feeds/threatfox.py
from feeds.threatfox import ThreatFoxFeed


def test_normalize_ip_port_split(sample_threatfox_rows):
    """FEED-02b: ip:port IOC type splits on ':' and produces ipv4-addr pattern (Pitfall 2)."""
    feed = ThreatFoxFeed()
    # sample_threatfox_rows[1] has ioc_type="ip:port", ioc="185.220.101.47:4444"
    ip_port_rows = [sample_threatfox_rows[1]]
    result = feed.normalize(ip_port_rows)
    assert len(result) == 1
    assert result[0]["pattern"] == "[ipv4-addr:value = '185.220.101.47']"


def test_normalize_domain(sample_threatfox_rows):
    """FEED-02b: domain ioc_type produces domain-name:value STIX pattern."""
    feed = ThreatFoxFeed()
    # sample_threatfox_rows[0] has ioc_type="domain", ioc="evil.example.com"
    domain_rows = [sample_threatfox_rows[0]]
    result = feed.normalize(domain_rows)
    assert len(result) == 1
    assert result[0]["pattern"] == "[domain-name:value = 'evil.example.com']"


def test_normalize_sha256_hash(sample_threatfox_rows):
    """FEED-02b: sha256_hash ioc_type produces file:hashes.'SHA-256' pattern (Pitfall 3)."""
    feed = ThreatFoxFeed()
    # sample_threatfox_rows[4] has ioc_type="sha256_hash"
    sha256_rows = [sample_threatfox_rows[4]]
    result = feed.normalize(sha256_rows)
    assert len(result) == 1
    expected_pattern = (
        "[file:hashes.'SHA-256' = "
        "'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']"
    )
    assert result[0]["pattern"] == expected_pattern


def test_normalize_skips_unknown_type():
    """FEED-02b: Unknown ioc_type (e.g., 'email') is excluded from output."""
    feed = ThreatFoxFeed()
    rows = [
        {
            "ioc": "attacker@evil.example.com",
            "ioc_type": "email",
            "malware_printable": "Emotet",
            "first_seen": "2026-06-25 00:00:00 UTC",
            "tags": [],
        }
    ]
    result = feed.normalize(rows)
    assert result == []
