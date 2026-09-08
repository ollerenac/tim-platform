"""
Shared pytest fixtures for feed-orchestrator test suite.

All fixtures use MagicMock objects with no real Redis or OpenCTI connections.
No real API keys or credentials are used — hardcoded dummy values only.
"""
import pytest
from unittest.mock import MagicMock


@pytest.fixture
def mock_redis():
    """
    Mock Redis client for deduplicator and status tests.

    r.set(key, val, nx=True, ex=86400) returns True  => new key (not duplicate)
    r.hset() returns None
    r.hgetall() returns {}
    """
    r = MagicMock()
    r.set.return_value = True   # simulates new key: SETNX succeeds
    r.hset.return_value = None
    r.hgetall.return_value = {}
    return r


@pytest.fixture
def mock_pycti():
    """
    Mock pycti OpenCTIApiClient.

    client.indicator.create() returns a dict with a deterministic indicator ID.
    """
    client = MagicMock()
    client.indicator.create.return_value = {"id": "indicator--test-uuid"}
    return client


@pytest.fixture
def sample_urlhaus_rows():
    """
    One-element list of URLhaus CSV row dicts (FEED-01).

    Fields per RESEARCH.md URLhaus field table:
      id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
    """
    return [
        {
            "id": "1234567",
            "dateadded": "2026-06-25 00:00:00",
            "url": "http://evil.example.com/malware.exe",
            "url_status": "online",
            "last_online": "2026-06-25 00:00:00",
            "threat": "malware_download",
            "tags": "Mozi,exe",
            "urlhaus_link": "https://urlhaus.abuse.ch/url/1234567/",
            "reporter": "anonymous",
        }
    ]


@pytest.fixture
def sample_malwarebazaar_rows():
    """
    One-element list of MalwareBazaar API response entry dicts (FEED-02a).

    Fields per RESEARCH.md MalwareBazaar field table:
      sha256_hash, md5_hash, sha1_hash, first_seen, signature, tags, file_type, file_name, file_size
    """
    return [
        {
            "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "md5_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "sha1_hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "first_seen": "2026-06-25 00:00:00",
            "signature": "Emotet",
            "tags": ["banking", "emotet"],
            "file_type": "exe",
            "file_name": "evil.exe",
            "file_size": 12345,
        }
    ]


@pytest.fixture
def sample_threatfox_rows():
    """
    Five-element list of ThreatFox API IOC dicts covering all ioc_types (FEED-02b).

    Types covered: domain, ip:port, url, md5_hash, sha256_hash
    Fields per RESEARCH.md ThreatFox field table:
      ioc, ioc_type, threat_type, malware, malware_printable, confidence_level,
      first_seen, last_seen, tags, reporter
    """
    return [
        {
            "ioc": "evil.example.com",
            "ioc_type": "domain",
            "threat_type": "botnet_cc",
            "malware": "win.emotet",
            "malware_printable": "Emotet",
            "confidence_level": 75,
            "first_seen": "2026-06-25 00:00:00 UTC",
            "last_seen": "2026-06-25 00:00:00 UTC",
            "tags": ["emotet"],
            "reporter": "abuse_ch",
        },
        {
            "ioc": "185.220.101.47:4444",
            "ioc_type": "ip:port",
            "threat_type": "botnet_cc",
            "malware": "win.cobalt_strike",
            "malware_printable": "CobaltStrike",
            "confidence_level": 90,
            "first_seen": "2026-06-25 00:00:00 UTC",
            "last_seen": "2026-06-25 00:00:00 UTC",
            "tags": ["cobalt_strike"],
            "reporter": "abuse_ch",
        },
        {
            "ioc": "http://evil.example.com/payload.bin",
            "ioc_type": "url",
            "threat_type": "malware_download",
            "malware": "win.qakbot",
            "malware_printable": "QakBot",
            "confidence_level": 80,
            "first_seen": "2026-06-25 00:00:00 UTC",
            "last_seen": "2026-06-25 00:00:00 UTC",
            "tags": ["qakbot"],
            "reporter": "abuse_ch",
        },
        {
            "ioc": "d41d8cd98f00b204e9800998ecf8427e",
            "ioc_type": "md5_hash",
            "threat_type": "payload_delivery",
            "malware": "win.emotet",
            "malware_printable": "Emotet",
            "confidence_level": 70,
            "first_seen": "2026-06-25 00:00:00 UTC",
            "last_seen": "2026-06-25 00:00:00 UTC",
            "tags": ["emotet"],
            "reporter": "abuse_ch",
        },
        {
            "ioc": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "ioc_type": "sha256_hash",
            "threat_type": "payload_delivery",
            "malware": "win.dridex",
            "malware_printable": "Dridex",
            "confidence_level": 85,
            "first_seen": "2026-06-25 00:00:00 UTC",
            "last_seen": "2026-06-25 00:00:00 UTC",
            "tags": ["dridex"],
            "reporter": "abuse_ch",
        },
    ]


@pytest.fixture
def sample_feodo_rows():
    """
    One-element list of Feodo Tracker CSV row dicts (FEED-02c).

    Fields per RESEARCH.md Feodo field table:
      first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware
    """
    return [
        {
            "first_seen_utc": "2026-06-25 00:00:00 UTC",
            "dst_ip": "185.220.101.47",
            "dst_port": "4444",
            "c2_status": "online",
            "last_online": "2026-06-25",
            "malware": "Emotet",
        }
    ]


