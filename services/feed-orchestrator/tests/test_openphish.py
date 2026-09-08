"""
test_openphish.py - RED phase tests for OpenphishFeed (SRC-01, Phase 12 Plan 04).

OpenPhish is a plain text URL list. Requests follows the upstream 302 to GitHub
raw by default, so the parser only needs one non-empty URL per line plus the
Pitfall 6 empty-body guard.
"""
import pytest

from feeds.openphish import OpenphishFeed

SAMPLE_URLS = (
    "http://evil.example/login\n"
    "\n"
    "https://phish.example/path\n"
)

EMPTY_BODY = "\n\n"

HTML_BODY = "<html>not a feed</html>\nservice unavailable\n"


class _FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def test_openphish_fetch_lines(monkeypatch):
    """Blank lines skipped; each remaining line is one URL row."""
    monkeypatch.setattr(
        "feeds.openphish.requests.get",
        lambda *a, **k: _FakeResponse(SAMPLE_URLS),
    )
    rows = OpenphishFeed().fetch()
    assert [r["url"] for r in rows] == [
        "http://evil.example/login",
        "https://phish.example/path",
    ]


def test_openphish_fetch_empty_body_raises(monkeypatch):
    """Pitfall 6: empty parsed body must surface as status=error."""
    monkeypatch.setattr(
        "feeds.openphish.requests.get",
        lambda *a, **k: _FakeResponse(EMPTY_BODY),
    )
    with pytest.raises(ValueError):
        OpenphishFeed().fetch()


def test_openphish_fetch_rejects_non_url_body(monkeypatch):
    """Non-empty upstream error/html bodies must not become phishing URL indicators."""
    monkeypatch.setattr(
        "feeds.openphish.requests.get",
        lambda *a, **k: _FakeResponse(HTML_BODY),
    )
    with pytest.raises(ValueError):
        OpenphishFeed().fetch()


def test_openphish_normalize_url_pattern():
    """OpenPhish rows become phishing-labeled url:value indicators."""
    result = OpenphishFeed().normalize([{"url": "http://evil.example/login"}])
    assert len(result) == 1
    ind = result[0]
    assert ind["pattern"] == "[url:value = 'http://evil.example/login']"
    assert ind["observable_type"] == "Url"
    assert ind["name"] == "http://evil.example/login"
    assert "phishing" in ind["labels"]
    assert ind["source_name"] == "OpenPhish"


def test_openphish_escape():
    """A single quote in the URL is escaped before STIX literal interpolation."""
    result = OpenphishFeed().normalize([{"url": "http://evil.example/a'b"}])
    assert result[0]["pattern"] == "[url:value = 'http://evil.example/a\\'b']"
