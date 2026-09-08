"""
test_abuseipdb.py — offline tests for AbuseipdbFeed (quick-260710-4dc).

AbuseIPDB blacklist: GET api.abuseipdb.com/api/v2/blacklist with Key +
Accept: application/json headers and limit=10000 param. Body shape:
{"meta": {...}, "data": [{"ipAddress", "countryCode", "abuseConfidenceScore",
"lastReportedAt"}]}. Mixed IPv4 + IPv6, all abuseConfidenceScore=100.

Inline sample data — do NOT move to conftest.py (cross-plan file conflict risk).
Tests use fake key strings only — no real API key anywhere.
"""
from unittest.mock import MagicMock

import pytest

from feeds.abuseipdb import AbuseipdbFeed

SAMPLE_BODY = {
    "meta": {"generatedAt": "2026-07-10T08:00:00+00:00"},
    "data": [
        {
            "ipAddress": "185.220.101.42",
            "countryCode": "DE",
            "abuseConfidenceScore": 100,
            "lastReportedAt": "2026-07-10T07:55:00+00:00",
        },
        {
            "ipAddress": "45.148.10.99",
            "countryCode": "NL",
            "abuseConfidenceScore": 100,
            "lastReportedAt": "2026-07-10T07:50:00+00:00",
        },
        {
            "ipAddress": "2001:db8::bad:1",
            "countryCode": "US",
            "abuseConfidenceScore": 100,
            "lastReportedAt": "2026-07-10T07:45:00+00:00",
        },
    ],
}


class _FakeResponse:
    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body

    def raise_for_status(self):
        pass


def test_fetch_parses_json_data_rows(monkeypatch):
    """fetch() returns the data rows from the JSON body."""
    monkeypatch.setattr("feeds.abuseipdb.ABUSEIPDB_API_KEY", "fake-test-key")
    monkeypatch.setattr(
        "feeds.abuseipdb.requests.get", lambda *a, **k: _FakeResponse(SAMPLE_BODY)
    )
    rows = AbuseipdbFeed().fetch()
    assert len(rows) == 3
    assert rows[0]["ipAddress"] == "185.220.101.42"
    assert rows[2]["ipAddress"] == "2001:db8::bad:1"


def test_fetch_sends_key_accept_and_limit(monkeypatch):
    """fetch() sends Key + Accept: application/json headers and limit=10000."""
    monkeypatch.setattr("feeds.abuseipdb.ABUSEIPDB_API_KEY", "fake-test-key")
    captured = {}

    def fake_get(*args, **kwargs):
        captured["headers"] = kwargs.get("headers", {})
        captured["params"] = kwargs.get("params", {})
        return _FakeResponse(SAMPLE_BODY)

    monkeypatch.setattr("feeds.abuseipdb.requests.get", fake_get)
    AbuseipdbFeed().fetch()
    assert captured["headers"]["Key"] == "fake-test-key"
    assert captured["headers"]["Accept"] == "application/json"
    assert captured["params"]["limit"] == 10000


def test_fetch_empty_data_raises(monkeypatch):
    """Pitfall 6: {"data": []} body must raise instead of status=ok with 0 IOCs."""
    monkeypatch.setattr(
        "feeds.abuseipdb.requests.get",
        lambda *a, **k: _FakeResponse({"meta": {}, "data": []}),
    )
    with pytest.raises(ValueError):
        AbuseipdbFeed().fetch()


def test_fetch_malformed_body_raises(monkeypatch):
    """Malformed bodies ({} or rows without ipAddress) must raise ValueError."""
    for body in ({}, {"data": [{"countryCode": "DE"}]}, {"data": [{"ipAddress": "  "}]}):
        monkeypatch.setattr(
            "feeds.abuseipdb.requests.get", lambda *a, _b=body, **k: _FakeResponse(_b)
        )
        with pytest.raises(ValueError):
            AbuseipdbFeed().fetch()


def test_normalize_ipv4_and_ipv6():
    """IPv4/IPv6 rows map to the right STIX pattern family with full metadata."""
    result = AbuseipdbFeed().normalize(SAMPLE_BODY["data"])
    assert len(result) == 3

    v4 = result[0]
    assert v4["pattern"] == "[ipv4-addr:value = '185.220.101.42']"
    assert v4["observable_type"] == "IPv4-Addr"
    assert v4["name"] == "AbuseIPDB blacklist 185.220.101.42"
    assert "abuseipdb" in v4["labels"]
    assert "abuse-reputation" in v4["labels"]
    assert v4["source_name"] == "AbuseIPDB"
    assert "DE" in v4["description"]
    assert v4["valid_from"] == "2026-07-10T07:55:00+00:00"

    v6 = result[2]
    assert v6["pattern"] == "[ipv6-addr:value = '2001:db8::bad:1']"
    assert v6["observable_type"] == "IPv6-Addr"
    assert "US" in v6["description"]


def test_run_disabled_without_key(monkeypatch):
    """Without ABUSEIPDB_API_KEY: status=disabled in Redis, pycti never touched."""
    monkeypatch.setattr("feeds.abuseipdb.ABUSEIPDB_API_KEY", "")
    redis_client = MagicMock()
    pycti_client = MagicMock()

    AbuseipdbFeed().run(redis_client, pycti_client)

    redis_client.hset.assert_called_once()
    _, kwargs = redis_client.hset.call_args
    assert kwargs["mapping"]["status"] == "disabled"
    assert not pycti_client.method_calls
