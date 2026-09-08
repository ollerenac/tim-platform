"""
test_dshield.py — RED phase tests for DshieldFeed (SRC-01, Phase 12 Plan 03).

DShield block.txt is tab-separated: start_ip, end_ip, netmask, attacks, name,
country, email — with '#' comment lines. The /24 CIDR is derived from the
start-ip + netmask column. The endpoint 403s some proxies/UAs, so fetch must
send an explicit tim-feed-orchestrator/1.0 User-Agent (live-probed).

Inline sample data — do NOT move to conftest.py (cross-plan file conflict risk).
"""
import pytest

from feeds.dshield import DshieldFeed

SAMPLE_TSV = (
    "# DShield.org Recommended Block List\n"
    "# creation date and other commentary\n"
    "#\n"
    "45.33.41.0\t45.33.41.255\t24\t579\tAKAMAI-LINODE-AP\tSG\temail@example.com\n"
)

SHORT_ROW_TSV = (
    "# comment\n"
    "1.2.3.0\t1.2.3.255\n"
    "45.33.41.0\t45.33.41.255\t24\t579\tAKAMAI-LINODE-AP\tSG\temail@example.com\n"
)

COMMENTS_ONLY_TSV = (
    "# DShield.org Recommended Block List\n"
    "#\n"
)

INVALID_CIDR_TSV = (
    "# comment\n"
    "45.33.41.0\t45.33.41.255\tbadmask\t579\tAKAMAI-LINODE-AP\tSG\temail@example.com\n"
)


class _FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def test_fetch_parses_tsv_and_derives_cidr(monkeypatch):
    """Comment lines skipped; data row yields cidr derived from start-ip + netmask."""
    monkeypatch.setattr(
        "feeds.dshield.requests.get", lambda *a, **k: _FakeResponse(SAMPLE_TSV)
    )
    rows = DshieldFeed().fetch()
    assert len(rows) == 1
    assert rows[0]["cidr"] == "45.33.41.0/24"


def test_fetch_sets_user_agent(monkeypatch):
    """fetch() sends the explicit tim-feed-orchestrator/1.0 User-Agent (403 avoidance)."""
    captured = {}

    def fake_get(*args, **kwargs):
        captured["headers"] = kwargs.get("headers", {})
        return _FakeResponse(SAMPLE_TSV)

    monkeypatch.setattr("feeds.dshield.requests.get", fake_get)
    DshieldFeed().fetch()
    assert captured["headers"]["User-Agent"] == "tim-feed-orchestrator/1.0"


def test_fetch_short_rows_skipped(monkeypatch):
    """A line with fewer than 3 tab-separated fields is skipped."""
    monkeypatch.setattr(
        "feeds.dshield.requests.get", lambda *a, **k: _FakeResponse(SHORT_ROW_TSV)
    )
    rows = DshieldFeed().fetch()
    assert [r["cidr"] for r in rows] == ["45.33.41.0/24"]


def test_fetch_empty_body_raises(monkeypatch):
    """Pitfall 6: comments-only body must raise instead of status=ok with 0 IOCs."""
    monkeypatch.setattr(
        "feeds.dshield.requests.get",
        lambda *a, **k: _FakeResponse(COMMENTS_ONLY_TSV),
    )
    with pytest.raises(ValueError):
        DshieldFeed().fetch()


def test_fetch_all_invalid_cidr_raises(monkeypatch):
    """Rows with invalid start IP/prefix data are skipped and all-invalid bodies raise."""
    monkeypatch.setattr(
        "feeds.dshield.requests.get",
        lambda *a, **k: _FakeResponse(INVALID_CIDR_TSV),
    )
    with pytest.raises(ValueError):
        DshieldFeed().fetch()


def test_normalize_cidr_pattern():
    """CIDR rides inside a normal ipv4-addr pattern — never expanded per-IP."""
    feed = DshieldFeed()
    result = feed.normalize([{"cidr": "45.33.41.0/24"}])
    assert len(result) == 1
    ind = result[0]
    assert ind["pattern"] == "[ipv4-addr:value = '45.33.41.0/24']"
    assert ind["observable_type"] == "IPv4-Addr"
    assert ind["name"] == "DShield block 45.33.41.0/24"
    assert "attacker-netblock" in ind["labels"]
    assert ind["source_name"] == "DShield"
