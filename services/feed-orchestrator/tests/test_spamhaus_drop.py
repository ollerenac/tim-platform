"""
test_spamhaus_drop.py — RED phase tests for SpamhausDropFeed (SRC-01, Phase 12 Plan 03).

Spamhaus DROP v4 is NDJSON (one JSON object per line) — resp.json() raises
(Pitfall 5). The final line is a metadata record without a "cidr" key and must
be skipped. CIDR values ride inside normal [ipv4-addr:value] patterns (official
OpenCTI DShield-connector representation) — never expanded to per-IP indicators.

Inline sample data — do NOT move to conftest.py (cross-plan file conflict risk).
"""
import pytest

from feeds.spamhaus_drop import SpamhausDropFeed

SAMPLE_NDJSON = (
    '{"cidr":"224.0.0.0/3","sblid":"SBL230","rir":"iana"}\n'
    "\n"
    '{"type":"metadata","timestamp":123}\n'
)

MALFORMED_LINE_NDJSON = (
    '{"cidr":"224.0.0.0/3","sblid":"SBL230","rir":"iana"}\n'
    "this is not json at all {{{\n"
    '{"cidr":"198.51.100.0/24","sblid":"SBL231","rir":"arin"}\n'
    '{"type":"metadata","timestamp":123}\n'
)

METADATA_ONLY_NDJSON = '{"type":"metadata","timestamp":123}\n'

INVALID_CIDR_NDJSON = (
    '{"cidr":"not-a-cidr","sblid":"SBLBAD","rir":"iana"}\n'
    '{"type":"metadata","timestamp":123}\n'
)


class _FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def test_fetch_parses_ndjson_lines(monkeypatch):
    """Only lines with a cidr key survive; metadata record and blank line skipped."""
    monkeypatch.setattr(
        "feeds.spamhaus_drop.requests.get",
        lambda *a, **k: _FakeResponse(SAMPLE_NDJSON),
    )
    rows = SpamhausDropFeed().fetch()
    assert len(rows) == 1
    assert rows[0]["cidr"] == "224.0.0.0/3"
    assert rows[0]["sblid"] == "SBL230"


def test_fetch_malformed_line_skipped(monkeypatch):
    """A non-JSON garbage line among valid lines is skipped, not fatal."""
    monkeypatch.setattr(
        "feeds.spamhaus_drop.requests.get",
        lambda *a, **k: _FakeResponse(MALFORMED_LINE_NDJSON),
    )
    rows = SpamhausDropFeed().fetch()
    assert [r["cidr"] for r in rows] == ["224.0.0.0/3", "198.51.100.0/24"]


def test_fetch_empty_body_raises(monkeypatch):
    """Pitfall 6: body with only the metadata line must raise instead of status=ok 0 IOCs."""
    monkeypatch.setattr(
        "feeds.spamhaus_drop.requests.get",
        lambda *a, **k: _FakeResponse(METADATA_ONLY_NDJSON),
    )
    with pytest.raises(ValueError):
        SpamhausDropFeed().fetch()


def test_fetch_all_invalid_cidr_raises(monkeypatch):
    """Non-empty DROP data with malformed CIDR values must surface as format drift."""
    monkeypatch.setattr(
        "feeds.spamhaus_drop.requests.get",
        lambda *a, **k: _FakeResponse(INVALID_CIDR_NDJSON),
    )
    with pytest.raises(ValueError):
        SpamhausDropFeed().fetch()


def test_normalize_cidr_pattern():
    """CIDR rides inside a normal ipv4-addr pattern — never expanded per-IP."""
    feed = SpamhausDropFeed()
    result = feed.normalize([{"cidr": "224.0.0.0/3", "sblid": "SBL230", "rir": "iana"}])
    assert len(result) == 1
    ind = result[0]
    assert ind["pattern"] == "[ipv4-addr:value = '224.0.0.0/3']"
    assert ind["observable_type"] == "IPv4-Addr"
    assert ind["name"] == "Spamhaus DROP 224.0.0.0/3"
    assert "hijacked-netblock" in ind["labels"]
    assert "SBL230" in ind["labels"]
    assert ind["source_name"] == "Spamhaus DROP"


def test_normalize_missing_sblid_label_omitted():
    """A row without sblid must not yield an empty-string label entry."""
    feed = SpamhausDropFeed()
    result = feed.normalize([{"cidr": "198.51.100.0/24", "rir": "arin"}])
    assert result[0]["labels"] == ["hijacked-netblock"]
    assert "" not in result[0]["labels"]
