"""
test_sslbl_ja3.py — RED phase tests for SslblJa3Feed (SRC-01, Phase 12 Plan 01).

JA3 fingerprint blacklist: comment-prefixed CSV with positional columns
ja3_md5,Firstseen,Lastseen,Listingreason. The list is frozen upstream since
2021-08-03 (~97 rows) and abuse.ch warns it is FP-prone — hence weight 10.

Adopted decision (research Open Question 1): JA3 MD5s are represented as
[text:value = '<md5>'] with observable_type "Text" — STIX 2.1 has no JA3 SCO.

Inline sample data — do NOT move to conftest.py (cross-plan file conflict risk).
"""
import pytest

from feeds.sslbl_ja3 import SslblJa3Feed

SAMPLE_CSV = (
    "# abuse.ch SSLBL JA3 fingerprint blacklist\n"
    "# Last updated: 2021-08-03\n"
    "# ja3_md5,Firstseen,Lastseen,Listingreason\n"
    "e7d705a3286e19ea42f587b344ee6865,2017-07-14 18:08:15,2019-07-27 20:42:54,Tofsee\n"
)

COMMENTS_ONLY_CSV = (
    "# abuse.ch SSLBL JA3 fingerprint blacklist\n"
    "# ja3_md5,Firstseen,Lastseen,Listingreason\n"
)

INVALID_MD5_CSV = (
    "# ja3_md5,Firstseen,Lastseen,Listingreason\n"
    "notmd5,2017-07-14 18:08:15,2019-07-27 20:42:54,Tofsee\n"
)


class _FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


SAMPLE_ROW = {
    "ja3_md5": "e7d705a3286e19ea42f587b344ee6865",
    "first_seen": "2017-07-14 18:08:15",
    "last_seen": "2019-07-27 20:42:54",
    "reason": "Tofsee",
}


def test_fetch_parses_ja3_rows(monkeypatch):
    """Comment lines skipped; data rows yield the four positional columns."""
    monkeypatch.setattr(
        "feeds.sslbl_ja3.requests.get", lambda *a, **k: _FakeResponse(SAMPLE_CSV)
    )
    rows = SslblJa3Feed().fetch()
    assert len(rows) == 1
    assert rows[0] == SAMPLE_ROW


def test_normalize_text_pattern():
    """JA3 MD5 maps to a text:value pattern with ja3/c2/fp-prone + reason labels."""
    result = SslblJa3Feed().normalize([dict(SAMPLE_ROW)])
    assert len(result) == 1
    ind = result[0]
    assert ind["pattern"] == "[text:value = 'e7d705a3286e19ea42f587b344ee6865']"
    assert ind["observable_type"] == "Text"
    assert "ja3" in ind["labels"]
    assert "c2" in ind["labels"]
    assert "fp-prone" in ind["labels"]
    assert "Tofsee" in ind["labels"]
    assert ind["source_name"] == "abuse.ch SSLBL JA3"


def test_normalize_valid_from_iso():
    """first_seen space separator converted to T + explicit +00:00 offset."""
    result = SslblJa3Feed().normalize([dict(SAMPLE_ROW)])
    assert result[0]["valid_from"] == "2017-07-14T18:08:15+00:00"


def test_fetch_empty_body_raises(monkeypatch):
    """Pitfall 6: comments-only body must raise instead of quiet ioc_count=0."""
    monkeypatch.setattr(
        "feeds.sslbl_ja3.requests.get",
        lambda *a, **k: _FakeResponse(COMMENTS_ONLY_CSV),
    )
    with pytest.raises(ValueError):
        SslblJa3Feed().fetch()


def test_fetch_all_invalid_md5_raises(monkeypatch):
    """Non-empty JA3 rows with malformed MD5 values are rejected."""
    monkeypatch.setattr(
        "feeds.sslbl_ja3.requests.get",
        lambda *a, **k: _FakeResponse(INVALID_MD5_CSV),
    )
    with pytest.raises(ValueError):
        SslblJa3Feed().fetch()
