"""
test_transport.py — Unit tests for transport.py (ROB-01 tier escalation, ROB-02 conditional GET).

ROB-01: per-host tier escalation plain-requests → curl_cffi on 403, winning tier cached per host.
ROB-02: conditional GET (If-None-Match / If-Modified-Since), 304 = no work (no raise).

No network: the two low-level fetchers inside transport (`_fetch_plain`, `_fetch_cffi`) are
monkeypatched with fakes returning objects carrying status_code / headers / a streamable body.
Import-guard pattern mirrors test_collector.py: tests SKIP if transport absent (Wave-0 RED state).
"""
from unittest.mock import MagicMock

import pytest

try:
    import transport
    _IMPORT_OK = True
except ImportError:
    _IMPORT_OK = False

_skip = pytest.mark.skipif(not _IMPORT_OK, reason="transport not yet implemented")


# ── Helpers ───────────────────────────────────────────────────────────────────

class _FakeResp:
    """Minimal stand-in for a requests/curl_cffi streamed response."""

    def __init__(self, status_code, body=b"", headers=None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.closed = False

    def iter_content(self, chunk_size=65536):
        yield self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def close(self):
        self.closed = True


def _fetcher(resp, calls, name):
    """Build a fake fetcher recording every call's kwargs; returns `resp`."""
    def _f(url, *, headers, timeout, allow_redirects):
        calls.append(
            {"name": name, "url": url, "headers": headers,
             "timeout": timeout, "allow_redirects": allow_redirects}
        )
        return resp
    return _f


# ── ROB-01: tier escalation + per-host cache ────────────────────────────────────

@_skip
def test_escalates_on_403(monkeypatch):
    calls = []
    plain = _FakeResp(403)
    cffi = _FakeResp(200, body=b"cffi-body", headers={"Content-Type": "application/xml"})
    monkeypatch.setattr(transport, "_fetch_plain", _fetcher(plain, calls, "plain"))
    monkeypatch.setattr(transport, "_fetch_cffi", _fetcher(cffi, calls, "cffi"))

    res = transport.fetch_conditional("https://waf.example.com/feed.xml", check_ssrf=False)

    assert res.status == 200
    assert res.body == b"cffi-body"
    assert res.tier == "cffi"


@_skip
def test_tier_cache_reused(monkeypatch):
    calls = []
    plain = _FakeResp(200, body=b"plain")
    cffi = _FakeResp(200, body=b"cffi-body")
    monkeypatch.setattr(transport, "_fetch_plain", _fetcher(plain, calls, "plain"))
    monkeypatch.setattr(transport, "_fetch_cffi", _fetcher(cffi, calls, "cffi"))

    host_tier = {"waf.example.com": "cffi"}
    res = transport.fetch_conditional(
        "https://waf.example.com/feed.xml", check_ssrf=False, host_tier=host_tier
    )

    assert res.body == b"cffi-body"
    assert [c["name"] for c in calls] == ["cffi"]  # plain never probed
    assert sum(1 for c in calls if c["name"] == "plain") == 0


@_skip
def test_escalation_persists_tier(monkeypatch):
    calls = []
    plain = _FakeResp(403)
    cffi = _FakeResp(200, body=b"cffi-body")
    monkeypatch.setattr(transport, "_fetch_plain", _fetcher(plain, calls, "plain"))
    monkeypatch.setattr(transport, "_fetch_cffi", _fetcher(cffi, calls, "cffi"))

    host_tier = {}
    transport.fetch_conditional(
        "https://waf.example.com/feed.xml", check_ssrf=False, host_tier=host_tier
    )

    assert host_tier.get("waf.example.com") == "cffi"


# ── ROB-02: conditional GET + 304 ───────────────────────────────────────────────

@_skip
def test_304_returns_not_modified(monkeypatch):
    calls = []
    plain = _FakeResp(304)
    monkeypatch.setattr(transport, "_fetch_plain", _fetcher(plain, calls, "plain"))
    monkeypatch.setattr(transport, "_fetch_cffi", _fetcher(_FakeResp(200), calls, "cffi"))

    res = transport.fetch_conditional(
        "https://ok.example.com/feed.xml", etag='"abc"', modified="Wed, 01 Jan 2025 00:00:00 GMT",
        check_ssrf=False,
    )

    assert res.status == 304
    assert res.body is None


@_skip
def test_conditional_headers_sent(monkeypatch):
    calls = []
    plain = _FakeResp(200, body=b"x")
    monkeypatch.setattr(transport, "_fetch_plain", _fetcher(plain, calls, "plain"))
    monkeypatch.setattr(transport, "_fetch_cffi", _fetcher(_FakeResp(200), calls, "cffi"))

    transport.fetch_conditional(
        "https://ok.example.com/feed.xml",
        etag='"abc"', modified="Wed, 01 Jan 2025 00:00:00 GMT", check_ssrf=False,
    )

    sent = calls[0]["headers"]
    assert sent.get("If-None-Match") == '"abc"'
    assert sent.get("If-Modified-Since") == "Wed, 01 Jan 2025 00:00:00 GMT"


# ── Security: SSRF + redirects on both tiers ─────────────────────────────────────

@_skip
def test_ssrf_enforced_on_cffi_tier(monkeypatch):
    calls = []
    monkeypatch.setattr(transport, "_fetch_plain", _fetcher(_FakeResp(200), calls, "plain"))
    monkeypatch.setattr(transport, "_fetch_cffi", _fetcher(_FakeResp(200), calls, "cffi"))

    # host_tier preseeds the cffi tier; SSRF guard must still fire BEFORE any fetch.
    with pytest.raises(ValueError):
        transport.fetch_conditional(
            "http://localhost/feed.xml", host_tier={"localhost": "cffi"}
        )

    assert calls == []  # no network call happened


@_skip
def test_redirects_disabled_both_tiers(monkeypatch):
    calls = []
    plain = _FakeResp(403)
    cffi = _FakeResp(200, body=b"cffi-body")
    monkeypatch.setattr(transport, "_fetch_plain", _fetcher(plain, calls, "plain"))
    monkeypatch.setattr(transport, "_fetch_cffi", _fetcher(cffi, calls, "cffi"))

    transport.fetch_conditional("https://waf.example.com/feed.xml", check_ssrf=False)

    # Escalation exercises both tiers; both must be redirect-disabled.
    assert {c["name"] for c in calls} == {"plain", "cffi"}
    assert all(c["allow_redirects"] is False for c in calls)
