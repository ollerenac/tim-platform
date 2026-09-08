"""
test_cins.py - RED phase tests for CinsFeed (SRC-01, Phase 12 Plan 04).

CINS Army ci-badguys.txt is a high-volume plain text IPv4 list. Non-IP lines
are skipped; empty parsed bodies raise so format drift cannot look like a
successful zero-IOC run.
"""
import pytest

from feeds.cins import CinsFeed

SAMPLE_IPS = (
    "# CINS Army badguys\n"
    "203.0.113.10\n"
    "not-an-ip\n"
    "2001:db8::10\n"
    "\n"
)

COMMENTS_ONLY = "# empty\n\n"


class _FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def test_cins_fetch_and_normalize(monkeypatch):
    """Only IPv4 lines survive; rows normalize to attacker-ip indicators."""
    monkeypatch.setattr(
        "feeds.cins.requests.get",
        lambda *a, **k: _FakeResponse(SAMPLE_IPS),
    )
    rows = CinsFeed().fetch()
    assert rows == [{"ip": "203.0.113.10"}]

    ind = CinsFeed().normalize(rows)[0]
    assert ind["pattern"] == "[ipv4-addr:value = '203.0.113.10']"
    assert ind["observable_type"] == "IPv4-Addr"
    assert ind["name"] == "203.0.113.10"
    assert "attacker-ip" in ind["labels"]
    assert ind["source_name"] == "CINS Army"


def test_cins_empty_body_raises(monkeypatch):
    """Pitfall 6: comment-only body must surface as status=error."""
    monkeypatch.setattr(
        "feeds.cins.requests.get",
        lambda *a, **k: _FakeResponse(COMMENTS_ONLY),
    )
    with pytest.raises(ValueError):
        CinsFeed().fetch()
