"""
test_et_compromised.py - RED phase tests for EtCompromisedFeed (SRC-01, Phase 12 Plan 04).

Emerging Threats compromised-IPs is a plain text IPv4 list. Garbage, comments,
and non-IPv4-shaped lines are skipped before any STIX pattern interpolation.
"""
import pytest

from feeds.et_compromised import EtCompromisedFeed

SAMPLE_IPS = (
    "# Emerging Threats compromised IPs\n"
    "1.2.3.4\n"
    "not-an-ip\n"
    "2001:db8::1\n"
    "\n"
)

COMMENTS_ONLY = "# no data today\n\n"


class _FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def test_et_fetch_skips_non_ip_lines(monkeypatch):
    """Only IPv4-shaped non-comment lines survive."""
    monkeypatch.setattr(
        "feeds.et_compromised.requests.get",
        lambda *a, **k: _FakeResponse(SAMPLE_IPS),
    )
    rows = EtCompromisedFeed().fetch()
    assert rows == [{"ip": "1.2.3.4"}]


def test_et_fetch_empty_body_raises(monkeypatch):
    """Pitfall 6: comment-only body must surface as status=error."""
    monkeypatch.setattr(
        "feeds.et_compromised.requests.get",
        lambda *a, **k: _FakeResponse(COMMENTS_ONLY),
    )
    with pytest.raises(ValueError):
        EtCompromisedFeed().fetch()


def test_et_normalize_ip_pattern():
    """Rows become compromised-host ipv4-addr indicators."""
    result = EtCompromisedFeed().normalize([{"ip": "1.2.3.4"}])
    assert len(result) == 1
    ind = result[0]
    assert ind["pattern"] == "[ipv4-addr:value = '1.2.3.4']"
    assert ind["observable_type"] == "IPv4-Addr"
    assert ind["name"] == "1.2.3.4"
    assert "compromised-host" in ind["labels"]
    assert ind["source_name"] == "Emerging Threats"
