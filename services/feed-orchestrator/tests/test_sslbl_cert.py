"""
test_sslbl_cert.py — RED phase tests for SslblCertFeed (SRC-01, Phase 12 Plan 01).

SSLBL certificate blacklist: comment-prefixed CSV with positional columns
Listingdate,SHA1,Listingreason. Column headers live INSIDE comments, so the
parser must use positional csv.reader, not DictReader.

Inline sample data — do NOT move to conftest.py (cross-plan file conflict risk).
"""
import pytest

from feeds.sslbl_cert import SslblCertFeed

SAMPLE_CSV = (
    "# abuse.ch SSLBL SSL Certificate Blacklist\n"
    "# Last updated: 2026-07-07 14:20:28 UTC\n"
    "#\n"
    "# Listingdate,SHA1,Listingreason\n"
    "2026-07-07 14:20:28,bca627eabc0123456789abcdef0123456789abcd,MSDuckStealer C&C\n"
)

COMMENTS_ONLY_CSV = (
    "# abuse.ch SSLBL SSL Certificate Blacklist\n"
    "# Listingdate,SHA1,Listingreason\n"
)

INVALID_SHA1_CSV = (
    "# Listingdate,SHA1,Listingreason\n"
    "2026-07-07 14:20:28,notsha,MSDuckStealer C&C\n"
)


class _FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def test_fetch_parses_csv_and_skips_comments(monkeypatch):
    """Comment lines are skipped; data rows yield the three positional columns."""
    monkeypatch.setattr(
        "feeds.sslbl_cert.requests.get", lambda *a, **k: _FakeResponse(SAMPLE_CSV)
    )
    rows = SslblCertFeed().fetch()
    assert len(rows) == 1
    assert rows[0]["listing_date"] == "2026-07-07 14:20:28"
    assert rows[0]["sha1"] == "bca627eabc0123456789abcdef0123456789abcd"
    assert rows[0]["reason"] == "MSDuckStealer C&C"


def test_fetch_empty_body_raises(monkeypatch):
    """Pitfall 6: comments-only body must raise instead of yielding ioc_count=0 status=ok."""
    monkeypatch.setattr(
        "feeds.sslbl_cert.requests.get",
        lambda *a, **k: _FakeResponse(COMMENTS_ONLY_CSV),
    )
    with pytest.raises(ValueError):
        SslblCertFeed().fetch()


def test_fetch_all_invalid_sha1_raises(monkeypatch):
    """Non-empty SSLBL cert rows with malformed SHA-1 values are rejected."""
    monkeypatch.setattr(
        "feeds.sslbl_cert.requests.get",
        lambda *a, **k: _FakeResponse(INVALID_SHA1_CSV),
    )
    with pytest.raises(ValueError):
        SslblCertFeed().fetch()


def test_fetch_sends_auth_key_when_configured(monkeypatch):
    """Auth-Key header is sent only when ABUSECH_AUTH_KEY is non-empty."""
    captured = {}

    def fake_get(*args, **kwargs):
        captured["headers"] = kwargs.get("headers", {})
        return _FakeResponse(SAMPLE_CSV)

    monkeypatch.setattr("feeds.sslbl_cert.requests.get", fake_get)

    monkeypatch.setattr("feeds.sslbl_cert.ABUSECH_AUTH_KEY", "k")
    SslblCertFeed().fetch()
    assert captured["headers"] == {"Auth-Key": "k"}

    monkeypatch.setattr("feeds.sslbl_cert.ABUSECH_AUTH_KEY", "")
    SslblCertFeed().fetch()
    assert "Auth-Key" not in captured["headers"]


def test_normalize_x509_pattern():
    """SHA-1 maps to a quoted-key x509-certificate hash pattern with c2 + reason labels."""
    feed = SslblCertFeed()
    raw = [{
        "listing_date": "2026-07-07 14:20:28",
        "sha1": "bca627eabc0123456789abcdef0123456789abcd",
        "reason": "MSDuckStealer C&C",
    }]
    result = feed.normalize(raw)
    assert len(result) == 1
    ind = result[0]
    assert ind["pattern"] == (
        "[x509-certificate:hashes.'SHA-1' = "
        "'bca627eabc0123456789abcdef0123456789abcd']"
    )
    assert ind["observable_type"] == "X509-Certificate"
    assert "c2" in ind["labels"]
    assert "MSDuckStealer C&C" in ind["labels"]
    assert ind["source_name"] == "abuse.ch SSLBL"


def test_normalize_valid_from_iso():
    """Space-separated SSLBL timestamp becomes T-separated ISO with explicit UTC offset
    (normalization convention for cross-feed consistency — corrected Pitfall 7)."""
    feed = SslblCertFeed()
    raw = [{
        "listing_date": "2026-07-07 14:20:28",
        "sha1": "bca627eabc0123456789abcdef0123456789abcd",
        "reason": "",
    }]
    result = feed.normalize(raw)
    assert result[0]["valid_from"] == "2026-07-07T14:20:28+00:00"
