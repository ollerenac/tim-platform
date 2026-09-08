"""
test_collector.py — Unit tests for collector.py (DOC-01..DOC-03, ROB-01/ROB-02).

All tests use monkeypatch/tmp_path — no Docker or live network required.
Feed fetches are stubbed at the transport seam (collector.fetch_conditional);
per-entry fetches at collector.fetch. Import-guard mirrors test_extractor.py.
"""
import asyncio
import copy
import json
import sys
import types
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

try:
    import collector
    _IMPORT_OK = True
except ImportError:
    _IMPORT_OK = False

_skip = pytest.mark.skipif(not _IMPORT_OK, reason="collector not yet implemented")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fake_feed(entries=None, bozo=False):
    """Build a minimal feedparser-like feed object."""
    feed = types.SimpleNamespace()
    feed.bozo = bozo
    feed.bozo_exception = Exception("bad xml") if bozo else None
    feed.entries = entries or []
    return feed


def _fake_entry(link: str) -> dict:
    """feedparser entries are FeedParserDict (dict subclass) — use dict to match."""
    return {"link": link}


def _fake_result(status=200, body=b"<rss/>", etag=None, last_modified=None, tier="plain"):
    """transport.FetchResult stand-in (SimpleNamespace — no live transport needed)."""
    return types.SimpleNamespace(
        status=status, body=body, content_type="application/rss+xml",
        etag=etag, last_modified=last_modified, tier=tier,
    )


def _one_source():
    """Single always-due rss source, decoupled from the real sources.yaml."""
    return [{"name": "src", "type": "rss", "url": "https://feeds.example.com/rss",
             "poll_interval_hours": 0}]


# ── Tests ─────────────────────────────────────────────────────────────────────

@_skip
def test_load_sources():
    """Phase 13: sources.yaml carries the curated direct RSS/CSAF source catalog."""
    sources = collector._load_sources()
    assert isinstance(sources, list)

    expected = {
        "NCSC UK": ("rss", "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", "advisory"),
        "CERT-EU Threat Intelligence": (
            "rss",
            "https://cert.europa.eu/publications/threat-intelligence-rss",
            "report",
        ),
        "CISA CSAF": ("csaf_github", None, "advisory"),
        "CERT-FR IOC": ("rss", "https://www.cert.ssi.gouv.fr/ioc/feed/", "advisory"),
        "CERT-PL EN": ("rss", "https://cert.pl/en/rss.xml", "advisory"),
        "JPCERT/CC English": (
            "rss",
            "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf",
            "advisory",
        ),
        "ACSC Advisories": ("rss", "https://www.cyber.gov.au/rss/advisories", "advisory"),
        "CCCS Canada": (
            "rss",
            "https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&lang=en",
            "advisory",
        ),
        "The DFIR Report": ("rss", "https://thedfirreport.com/feed/", "blog"),
        "Unit 42": ("rss", "https://unit42.paloaltonetworks.com/feed/", "blog"),
        "Cisco Talos": ("rss", "http://feeds.feedburner.com/feedburner/Talos", "blog"),
        "SentinelLabs": ("rss", "https://www.sentinelone.com/labs/feed/", "blog"),
        "Kaspersky Securelist": ("rss", "https://securelist.com/feed/", "blog"),
        "Check Point Research": ("rss", "https://research.checkpoint.com/feed/", "blog"),
        "ESET WeLiveSecurity": ("rss", "https://www.welivesecurity.com/en/rss/feed/", "blog"),
        "Google Mandiant Threat Intelligence": (
            "rss",
            "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v",
            "blog",
        ),
        "Volexity": ("rss", "https://www.volexity.com/feed/", "blog"),
        "CNSD Integrated Digital Security Alerts": (
            "html_collection",
            CNSD_COLLECTION_URL,
            "bulletin",
        ),
        "ColCERT Boletines": (
            "html_collection",
            "https://www.colcert.gov.co/800/w3-propertyvalue-412601.html",
            "bulletin",
        ),
        "MITRE ATT&CK Groups": (
            "html_index",
            "https://attack.mitre.org/groups/",
            "report",
        ),
    }

    assert len(sources) == len(expected)
    by_name = {s["name"]: s for s in sources}
    assert set(by_name) == set(expected)

    for s in sources:
        assert "name" in s
        assert "type" in s
        assert "source_type" in s
        assert "poll_interval_hours" in s
        assert s["poll_interval_hours"] >= 24
        expected_type, expected_url, expected_source_type = expected[s["name"]]
        assert s["type"] == expected_type
        assert s["source_type"] == expected_source_type
        if s["type"] == "rss":
            assert "url" in s
            assert s["url"] == expected_url
        elif s["type"] == "csaf_github":
            assert "repo" in s
            assert "path" in s
            assert s["repo"] == "cisagov/CSAF"
        elif s["type"] == "html_collection":
            assert s["url"] == expected_url
        elif s["type"] == "html_index":
            assert s["url"] == expected_url
        else:
            pytest.fail(f"unexpected source type: {s['type']}")

    configured_urls = {s.get("url") for s in sources if s["type"] == "rss"}
    assert "https://cert.pl/en/posts/feed/" not in configured_urls
    assert "https://cert.pl/en/feed/" not in configured_urls
    assert "https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en" not in configured_urls
    assert "https://isc.sans.edu/rssfeed.xml" not in configured_urls
    assert "https://cloud.google.com/blog/topics/threat-intelligence/rss" not in configured_urls
    assert "https://www.volexity.com/blog/feed/" not in configured_urls


@_skip
def test_skip_known_url(monkeypatch, tmp_path):
    """DOC-01 dedup / DOC-03: run_extraction must NOT be called for already-processed URLs."""
    known_url = "https://example.com/known.html"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [known_url], "sources": {}}))

    monkeypatch.setattr(collector, "STATE_PATH", state_file)

    feed = _fake_feed(entries=[_fake_entry(known_url)])
    monkeypatch.setattr("collector.fetch_conditional", lambda *a, **kw: _fake_result())
    monkeypatch.setattr("collector.feedparser.parse", lambda data: feed)

    collector._run_poll_cycle()


@_skip
def test_dispatch_new_url(monkeypatch, tmp_path):
    """DOC-01 dispatch / D-06: run_extraction IS called once with mode='url' for a new URL."""
    new_url = "https://example.com/advisory.html"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))

    monkeypatch.setattr(collector, "STATE_PATH", state_file)

    feed = _fake_feed(entries=[_fake_entry(new_url)])
    monkeypatch.setattr("collector.fetch_conditional", lambda *a, **kw: _fake_result())
    monkeypatch.setattr("collector.feedparser.parse", lambda data: feed)
    # per-entry fetch returns HTML → routed as mode='url'
    monkeypatch.setattr("collector.fetch", lambda *a, **kw: (b"<html>advisory</html>", "text/html"))

    pending = collector._run_poll_cycle()

    # pending list should have one entry; actual dispatch happens in run_collector_loop
    assert len(pending) == 1
    mode, content, url, _source_type = pending[0]
    assert mode == "url"
    assert url == new_url


@_skip
def test_pending_entry_carries_configured_source_type(monkeypatch, tmp_path):
    """Phase 13 D-13-13: configured source_type must travel with queued work."""
    new_url = "https://example.com/report.html"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "_collector_state", {"sources_meta": {}, "last_run": None})
    monkeypatch.setattr(collector, "_load_sources", lambda: [{
        "name": "src",
        "type": "rss",
        "url": "https://feeds.example.com/rss",
        "source_type": "report",
        "poll_interval_hours": 0,
    }])
    monkeypatch.setattr("collector.fetch_conditional", lambda *a, **kw: _fake_result())
    monkeypatch.setattr(
        "collector.feedparser.parse", lambda data: _fake_feed(entries=[_fake_entry(new_url)])
    )
    monkeypatch.setattr("collector.fetch", lambda *a, **kw: (b"<html>report</html>", "text/html"))

    pending = collector._run_poll_cycle()

    assert pending == [("url", None, new_url, "report")]


@_skip
def test_pdf_detected_by_content_type(monkeypatch, tmp_path):
    """P1/P3: a URL with no .pdf suffix but application/pdf content-type is ingested as PDF."""
    new_url = "https://example.com/download?docid=42"  # no .pdf suffix
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)

    feed = _fake_feed(entries=[_fake_entry(new_url)])
    monkeypatch.setattr("collector.fetch_conditional", lambda *a, **kw: _fake_result())
    monkeypatch.setattr("collector.feedparser.parse", lambda data: feed)
    monkeypatch.setattr("collector.fetch", lambda *a, **kw: (b"%PDF-1.7 ...", "application/pdf"))

    pending = collector._run_poll_cycle()
    assert len(pending) == 1
    mode, content, url, _source_type = pending[0]
    assert mode == "pdf"
    assert content == b"%PDF-1.7 ..."


@_skip
def test_entry_url_prefers_pdf_enclosure():
    """P4: an application/pdf enclosure/link wins over the HTML <link>."""
    entry = {
        "link": "https://site/report-landing.html",
        "links": [{"href": "https://site/report.pdf", "type": "application/pdf"}],
    }
    assert collector._entry_url(entry) == "https://site/report.pdf"
    # no pdf link → falls back to <link>
    assert collector._entry_url({"link": "https://site/x.html"}) == "https://site/x.html"


@_skip
def test_state_persistence(tmp_path):
    """DOC-03: save/load round-trip for collector_state.json."""
    state_file = tmp_path / "state.json"
    monkeypatch_obj = type("MP", (), {})()

    # Directly patch STATE_PATH on the module
    original = collector.STATE_PATH
    collector.STATE_PATH = state_file
    try:
        collector._save_state({"processed_urls": ["https://example.com/a"], "sources": {}})
        loaded = collector._load_state()
        assert loaded["processed_urls"] == ["https://example.com/a"]
    finally:
        collector.STATE_PATH = original


@_skip
def test_error_increments_counter(monkeypatch, tmp_path):
    """D-03: bozo feed with no entries must not raise — skip-and-continue behavior."""
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)

    bozo_feed = _fake_feed(bozo=True, entries=[])
    monkeypatch.setattr("collector.fetch_conditional", lambda *a, **kw: _fake_result())
    monkeypatch.setattr("collector.feedparser.parse", lambda data: bozo_feed)

    # Must not raise
    try:
        collector._run_poll_cycle()
    except Exception as exc:
        pytest.fail(f"_run_poll_cycle raised unexpectedly: {exc}")


@_skip
def test_304_no_work(monkeypatch, tmp_path):
    """ROB-02: a 304 yields no work, stamps last_polled, and does NOT count as an error."""
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "_collector_state", {"sources_meta": {}, "last_run": None})
    monkeypatch.setattr(collector, "_load_sources", _one_source)
    monkeypatch.setattr(
        "collector.fetch_conditional", lambda *a, **kw: _fake_result(status=304, body=None)
    )

    pending = collector._run_poll_cycle()

    assert pending == []
    assert collector._collector_state["sources_meta"]["src"]["errors"] == 0
    assert collector._collector_state["sources_meta"]["src"]["new_found"] == 0
    saved = json.loads(state_file.read_text())
    assert saved["sources"]["src"]["last_polled"] is not None


@_skip
def test_conditional_persisted(monkeypatch, tmp_path):
    """ROB-02: ETag/Last-Modified from a 200 persist to disk and are sent back on the next poll."""
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "_collector_state", {"sources_meta": {}, "last_run": None})
    monkeypatch.setattr(collector, "_load_sources", _one_source)

    calls = []

    def fake_fc(url, **kw):
        calls.append(kw)
        return _fake_result(etag='W/"abc123"', last_modified="Wed, 01 Jan 2026 00:00:00 GMT")

    monkeypatch.setattr("collector.fetch_conditional", fake_fc)
    monkeypatch.setattr("collector.feedparser.parse", lambda data: _fake_feed(entries=[]))

    collector._run_poll_cycle()

    saved = json.loads(state_file.read_text())
    assert saved["sources"]["src"]["etag"] == 'W/"abc123"'
    assert saved["sources"]["src"]["last_modified"] == "Wed, 01 Jan 2026 00:00:00 GMT"

    # Second poll (interval 0 → due again) reads the persisted validators back off disk
    collector._run_poll_cycle()
    assert calls[1]["etag"] == 'W/"abc123"'
    assert calls[1]["modified"] == "Wed, 01 Jan 2026 00:00:00 GMT"


@_skip
def test_tier_persisted(monkeypatch, tmp_path):
    """ROB-01: a host escalated to cffi lands in state['host_tier'] and survives _load_state."""
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "_collector_state", {"sources_meta": {}, "last_run": None})
    monkeypatch.setattr(collector, "_load_sources", _one_source)

    def fake_fc(url, **kw):
        # Mirror what transport.fetch_conditional does when the cffi tier wins a 403 probe
        kw["host_tier"]["feeds.example.com"] = "cffi"
        return _fake_result()

    monkeypatch.setattr("collector.fetch_conditional", fake_fc)
    monkeypatch.setattr("collector.feedparser.parse", lambda data: _fake_feed(entries=[]))

    collector._run_poll_cycle()

    saved = json.loads(state_file.read_text())
    assert saved["host_tier"]["feeds.example.com"] == "cffi"
    assert collector._load_state()["host_tier"]["feeds.example.com"] == "cffi"


def _landing_setup(monkeypatch, tmp_path, landing_url, landing_html, pdf_url=None):
    """Common ROB-03 scaffolding: one due source, feed with one landing-page entry,
    per-entry fetch returns HTML for the landing URL and PDF bytes for the candidate."""
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "_collector_state", {"sources_meta": {}, "last_run": None})
    monkeypatch.setattr(collector, "_load_sources", _one_source)
    monkeypatch.setattr("collector.fetch_conditional", lambda *a, **kw: _fake_result())
    monkeypatch.setattr(
        "collector.feedparser.parse", lambda data: _fake_feed(entries=[_fake_entry(landing_url)])
    )

    def fake_fetch(url, **kw):
        if url == landing_url:
            return (landing_html, "text/html")
        if pdf_url is not None and url == pdf_url:
            return (b"%PDF-1.7 fake", "application/pdf")
        raise AssertionError(f"unexpected fetch: {url}")

    monkeypatch.setattr("collector.fetch", fake_fetch)
    return state_file


@_skip
def test_poll_save_does_not_clobber_concurrent_dispatch_write(monkeypatch, tmp_path):
    """P0.5 race repro (deterministic): while the poll cycle sits in network I/O
    holding its in-memory state snapshot, an async dispatch finishes and records
    its URL via the locked fresh-load path. The poll's subsequent per-entry save
    must NOT overwrite the file with its stale snapshot — the dispatched URL has
    to survive on disk, or the next cycle re-ingests that document."""
    entry_url = "https://example.com/new-post.html"
    dispatched_url = "https://example.com/docs/finished-by-dispatch.pdf"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "_collector_state", {"sources_meta": {}, "last_run": None})
    monkeypatch.setattr(collector, "_load_sources", _one_source)
    monkeypatch.setattr("collector.fetch_conditional", lambda *a, **kw: _fake_result())
    monkeypatch.setattr(
        "collector.feedparser.parse", lambda data: _fake_feed(entries=[_fake_entry(entry_url)])
    )

    def fetch_with_concurrent_dispatch(url, **kw):
        # The "other thread": a dispatch completing mid-fetch, using the same
        # locked read-modify-write pattern as _record_collection_dispatch.
        with collector._state_write_lock:
            fresh = collector._load_state()
            fresh.setdefault("processed_urls", []).append(dispatched_url)
            collector._save_state(fresh)
        return (b"<html><body>plain page</body></html>", "text/html")

    monkeypatch.setattr("collector.fetch", fetch_with_concurrent_dispatch)

    collector._run_poll_cycle()

    saved = json.loads(state_file.read_text())
    assert entry_url in saved["processed_urls"]
    assert dispatched_url in saved["processed_urls"], (
        "poll cycle's stale-snapshot save erased a URL recorded concurrently "
        "by a finished dispatch (lost update)"
    )


@_skip
def test_same_cycle_duplicate_entry_queued_once(monkeypatch, tmp_path):
    """P0.5 guard for the fix's own risk: with delta-writes to fresh state, the
    poll loop's LOCAL dedup view must stay in sync — a URL repeated within one
    feed cycle is still queued exactly once."""
    entry_url = "https://example.com/docs/dup.pdf"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "_collector_state", {"sources_meta": {}, "last_run": None})
    monkeypatch.setattr(collector, "_load_sources", _one_source)
    monkeypatch.setattr("collector.fetch_conditional", lambda *a, **kw: _fake_result())
    monkeypatch.setattr(
        "collector.feedparser.parse",
        lambda data: _fake_feed(entries=[_fake_entry(entry_url), _fake_entry(entry_url)]),
    )
    monkeypatch.setattr(
        "collector.fetch", lambda url, **kw: (b"%PDF-1.7 fake", "application/pdf")
    )

    pending = collector._run_poll_cycle()

    assert pending == [("pdf", b"%PDF-1.7 fake", entry_url, None)]


@_skip
def test_delta_write_refuses_to_persist_reset_registry(monkeypatch, tmp_path):
    """P0.5 blast-radius guard: if the state file is corrupt mid-cycle (fresh load
    resets to empty), a delta write must NOT persist the near-empty registry —
    that would trigger a mass re-ingest next cycle. It logs and skips instead."""
    entry_url = "https://example.com/new-post.html"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps(
        {"processed_urls": [f"https://old.example/{i}" for i in range(12)], "sources": {}}
    ))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "_collector_state", {"sources_meta": {}, "last_run": None})
    monkeypatch.setattr(collector, "_load_sources", _one_source)
    monkeypatch.setattr("collector.fetch_conditional", lambda *a, **kw: _fake_result())
    monkeypatch.setattr(
        "collector.feedparser.parse", lambda data: _fake_feed(entries=[_fake_entry(entry_url)])
    )

    def fetch_then_corrupt(url, **kw):
        state_file.write_text("{corrupt json!!")  # disk goes bad mid-cycle
        return (b"<html><body>page</body></html>", "text/html")

    monkeypatch.setattr("collector.fetch", fetch_then_corrupt)

    collector._run_poll_cycle()

    raw = state_file.read_text()
    if raw.startswith("{corrupt"):
        return  # nothing persisted over the corrupt file — acceptable outcome
    saved = json.loads(raw)
    assert len(saved.get("processed_urls", [])) >= 12, (
        "delta write persisted a reset registry over a previously populated one"
    )


@_skip
def test_is_transient_error_classification():
    """Transient (network/infra) vs permanent failure — drives whether a URL retries."""
    for msg in [
        "Cannot resolve 'cyber.gc.ca': [Errno -3] Temporary failure in name resolution",
        "OpenCTI client init failed: OpenCTI API is not reachable.",
        "HTTPSConnectionPool(...): Max retries exceeded ... connect timeout=30",
        "503 Service Unavailable",
    ]:
        assert collector._is_transient_error(msg), msg
    for msg in ["404 Not Found", "Unknown mode: 'foo'", "malformed_response", "", None]:
        assert not collector._is_transient_error(msg), msg


@_skip
def test_transient_dispatch_failure_unpersists_url_for_retry(monkeypatch, tmp_path):
    """P0.x regression (audit 2026-07-25): a URL that failed extraction on a transient
    error must be REMOVED from processed_urls so the next poll retries it. Before the
    fix, the optimistic persist made one DNS blip a permanent silent loss (14 advisories
    lost in a single bad cycle)."""
    import asyncio

    url = "https://cyber.gc.ca/en/alerts-advisories/example"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [url], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)

    class _FakeExtractor:
        jobs = {}
        def register_job(self, jid): self.jobs[jid] = {}
        def run_extraction(self, jid, *a, **kw):
            self.jobs[jid] = {"status": "failed",
                              "error": "Cannot resolve 'cyber.gc.ca': Temporary failure in name resolution"}
    monkeypatch.setattr(collector, "_load_extractor_module", lambda: _FakeExtractor())

    item = collector.PendingDocument("url", None, url, "advisory")
    asyncio.run(collector._dispatch_pending(item))

    saved = json.loads(state_file.read_text())
    assert url not in saved["processed_urls"], "transient failure left URL burned — never retried"


@_skip
def test_permanent_dispatch_failure_keeps_url_processed(monkeypatch, tmp_path):
    """Counterpart: a PERMANENT failure (parse error) must NOT un-persist — retrying a
    genuinely bad document every cycle forever is wrong."""
    import asyncio

    url = "https://example.com/not-a-document"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [url], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)

    class _FakeExtractor:
        jobs = {}
        def register_job(self, jid): self.jobs[jid] = {}
        def run_extraction(self, jid, *a, **kw):
            self.jobs[jid] = {"status": "failed", "error": "Unknown mode / malformed_response"}
    monkeypatch.setattr(collector, "_load_extractor_module", lambda: _FakeExtractor())

    item = collector.PendingDocument("url", None, url, "advisory")
    asyncio.run(collector._dispatch_pending(item))

    saved = json.loads(state_file.read_text())
    assert url in saved["processed_urls"], "permanent failure un-persisted — would retry forever"


@_skip
def test_discover_pdf_links_respects_pdf_pattern():
    """Phase 13: pdf_pattern constrains which PDF anchors a source recipe admits."""
    html = b"""
    <html><body>
      <a href="/docs/noisy.pdf">Generic PDF link</a>
      <a class="approved" href="/reports/threat-landscape.pdf">Approved report</a>
      <a class="approved" href="https://cdn.example.net/reports/annex.pdf">Approved annex</a>
    </body></html>
    """

    links = collector.discover_pdf_links(
        html,
        "https://example.com/publications/threat-intelligence",
        pdf_pattern="a.approved[href$='.pdf']",
    )

    assert links == [
        "https://example.com/reports/threat-landscape.pdf",
        "https://cdn.example.net/reports/annex.pdf",
    ]


@_skip
def test_discover_pdf_links_without_pattern_keeps_generic_fallback():
    """Existing ROB-03 behavior remains available when a source has no recipe."""
    html = b"""
    <html><body>
      <a href="/docs/report-one.pdf">Report one</a>
      <a href="/docs/report-two.PDF?download=1">Report two</a>
      <a href="/docs/readme.txt">Readme</a>
    </body></html>
    """

    links = collector.discover_pdf_links(html, "https://example.com/reports/index.html")

    assert links == [
        "https://example.com/docs/report-one.pdf",
        "https://example.com/docs/report-two.PDF?download=1",
    ]


@_skip
def test_pdf_in_landing(monkeypatch, tmp_path):
    """ROB-03: an HTML landing page's linked PDF is discovered, Content-Type-confirmed,
    and ingested as mode='pdf' — the landing URL is NOT also queued as mode='url'.
    P0.4: the tuple carries the discovered PDF's own URL — url=None starved
    run_extraction of provenance and silently discarded all targeting."""
    landing_url = "https://example.com/advisory-landing.html"
    pdf_url = "https://example.com/docs/report.pdf"
    landing_html = b'<html><body><a href="/docs/report.pdf">Download report</a></body></html>'
    _landing_setup(monkeypatch, tmp_path, landing_url, landing_html, pdf_url)

    pending = collector._run_poll_cycle()

    assert pending == [("pdf", b"%PDF-1.7 fake", pdf_url, None)]
    assert not any(mode == "url" for mode, _, _, _ in pending), (
        "landing page must not also be queued as mode='url' when its PDF is ingested"
    )


@_skip
def test_direct_pdf_entry_carries_its_url(monkeypatch, tmp_path):
    """P0.4 regression: an RSS entry that IS a PDF must keep its URL in the pending
    tuple — provenance feeds the Report name, the external reference, and Step 9
    targeting (which fails closed on a missing source_url)."""
    entry_url = "https://example.com/docs/bulletin.pdf"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "_collector_state", {"sources_meta": {}, "last_run": None})
    monkeypatch.setattr(collector, "_load_sources", _one_source)
    monkeypatch.setattr("collector.fetch_conditional", lambda *a, **kw: _fake_result())
    monkeypatch.setattr(
        "collector.feedparser.parse", lambda data: _fake_feed(entries=[_fake_entry(entry_url)])
    )
    monkeypatch.setattr(
        "collector.fetch", lambda url, **kw: (b"%PDF-1.7 fake", "application/pdf")
    )

    pending = collector._run_poll_cycle()

    assert pending == [("pdf", b"%PDF-1.7 fake", entry_url, None)]


@_skip
def test_rss_pdf_pattern_prevents_unmatched_landing_pdf_ingest(monkeypatch, tmp_path):
    """Phase 13: RSS landing-page discovery must honor the configured source recipe."""
    landing_url = "https://example.com/advisory-landing.html"
    pdf_url = "https://example.com/docs/report.pdf"
    landing_html = b"""
    <html><body>
      <a class="generic" href="/docs/report.pdf">Generic PDF</a>
    </body></html>
    """
    _landing_setup(monkeypatch, tmp_path, landing_url, landing_html, pdf_url)
    monkeypatch.setattr(collector, "_load_sources", lambda: [{
        "name": "src",
        "type": "rss",
        "url": "https://feeds.example.com/rss",
        "pdf_pattern": "a.approved[href$='.pdf']",
        "poll_interval_hours": 0,
    }])

    pending = collector._run_poll_cycle()

    assert pending == [("url", None, landing_url, None)]


@_skip
def test_landing_pdf_dedup(monkeypatch, tmp_path):
    """ROB-03 / Pitfall 3: the discovered PDF URL is recorded in processed_urls, so a
    second poll of the same feed queues zero new work; error counter unchanged."""
    landing_url = "https://example.com/advisory-landing.html"
    pdf_url = "https://example.com/docs/report.pdf"
    landing_html = b'<html><body><a href="/docs/report.pdf">Download report</a></body></html>'
    state_file = _landing_setup(monkeypatch, tmp_path, landing_url, landing_html, pdf_url)

    first = collector._run_poll_cycle()
    assert len(first) == 1 and first[0][0] == "pdf"

    saved = json.loads(state_file.read_text())
    assert landing_url in saved["processed_urls"]
    assert pdf_url in saved["processed_urls"], (
        "discovered PDF URL must be persisted to processed_urls (Pitfall 3)"
    )

    second = collector._run_poll_cycle()
    assert second == [], "second poll must queue zero new work"
    assert collector._collector_state["sources_meta"]["src"]["errors"] == 0


@_skip
def test_landing_no_pdf_falls_back(monkeypatch, tmp_path):
    """ROB-03: an HTML page with no confirmable PDF link falls back to mode='url'
    page-text extraction — unchanged pre-ROB-03 behavior."""
    landing_url = "https://example.com/plain-advisory.html"
    landing_html = b'<html><body><a href="/about.html">About</a><p>advisory text</p></body></html>'
    _landing_setup(monkeypatch, tmp_path, landing_url, landing_html)

    pending = collector._run_poll_cycle()

    assert pending == [("url", None, landing_url, None)]


def _csaf_source(max_advisories=10, poll_interval_hours=0):
    """Single csaf_github source, decoupled from the real sources.yaml."""
    return [{"name": "csaf", "type": "csaf_github", "repo": "cisagov/CSAF",
             "branch": "develop", "path": "csaf_files/OT/white",
             "max_advisories": max_advisories,
             "poll_interval_hours": poll_interval_hours}]


def _csaf_listing(names):
    """GitHub contents-API JSON body listing the given file names."""
    return json.dumps([
        {"name": n, "type": "file",
         "download_url": f"https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/{n}"}
        for n in names
    ]).encode()


def _csaf_setup(monkeypatch, tmp_path, listing_body, sources=None):
    """Common ROB-04 scaffolding: one csaf_github source, mocked contents-API fetch."""
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "_collector_state", {"sources_meta": {}, "last_run": None})
    monkeypatch.setattr(collector, "_load_sources", lambda: sources or _csaf_source())

    def fake_fetch(url, **kw):
        assert url.startswith("https://api.github.com/repos/cisagov/CSAF/contents/"), url
        return (listing_body, "application/json")

    monkeypatch.setattr("collector.fetch", fake_fetch)
    return state_file


@_skip
def test_csaf_dispatch_dedup(monkeypatch, tmp_path):
    """ROB-04: 3 advisory JSONs listed → 3 ("url", None, download_url) queued once,
    all recorded in processed_urls; a second poll over the same listing queues 0."""
    names = ["icsa-26-001-01.json", "icsa-26-002-01.json", "icsa-26-003-01.json"]
    # .asc/.sha512 siblings must be filtered out, never dispatched
    listing = _csaf_listing(names + ["icsa-26-001-01.json.sha512", "icsa-26-001-01.json.asc"])
    state_file = _csaf_setup(monkeypatch, tmp_path, listing)

    first = collector._run_poll_cycle()

    assert len(first) == 3
    for mode, content, url, _source_type in first:
        assert mode == "url"
        assert content is None
        assert url.startswith("https://raw.githubusercontent.com/cisagov/CSAF/")
        assert url.endswith(".json")

    saved = json.loads(state_file.read_text())
    assert len(saved["processed_urls"]) == 3
    assert saved["sources"]["csaf"]["last_polled"] is not None

    second = collector._run_poll_cycle()
    assert second == [], "second poll over the same listing must queue zero new work"
    assert collector._collector_state["sources_meta"]["csaf"]["errors"] == 0


@_skip
def test_csaf_max_advisories_cap(monkeypatch, tmp_path):
    """ROB-04 / T-10-03: never queue more than max_advisories per poll; newest names win."""
    names = [f"icsa-26-00{i}-01.json" for i in range(1, 6)]  # 5 files listed
    _csaf_setup(monkeypatch, tmp_path, _csaf_listing(names),
                sources=_csaf_source(max_advisories=2))

    pending = collector._run_poll_cycle()

    assert len(pending) == 2
    queued = {url for _, _, url, _source_type in pending}
    assert all(n in u for n, u in zip(["icsa-26-005-01.json", "icsa-26-004-01.json"],
                                      sorted(queued, reverse=True)))


@_skip
def test_csaf_not_due(monkeypatch, tmp_path):
    """D-02: a csaf_github source polled within its interval queues nothing."""
    state_file = tmp_path / "state.json"
    from datetime import datetime, timezone
    state_file.write_text(json.dumps({
        "processed_urls": [],
        "sources": {"csaf": {"last_polled": datetime.now(timezone.utc).isoformat()}},
    }))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "_collector_state", {"sources_meta": {}, "last_run": None})
    monkeypatch.setattr(collector, "_load_sources", lambda: _csaf_source(poll_interval_hours=24))
    monkeypatch.setattr("collector.fetch",
                        lambda *a, **kw: pytest.fail("not-due source must not fetch"))

    assert collector._run_poll_cycle() == []


@_skip
def test_validate_flags_dead(monkeypatch, tmp_path):
    """ROB-05: a source whose fetch raises is reported reachable/parseable False with
    an error string; a healthy rss source reports reachable+parseable True; one dead
    source never aborts the sweep."""
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "_load_sources", lambda: [
        {"name": "dead", "type": "rss", "url": "https://dead.example.com/rss",
         "poll_interval_hours": 24},
        {"name": "healthy", "type": "rss", "url": "https://ok.example.com/rss",
         "poll_interval_hours": 24},
    ])

    def fake_fc(url, **kw):
        if "dead" in url:
            raise ConnectionError("connection refused")
        return _fake_result(body=b"<rss>...</rss>")

    monkeypatch.setattr("collector.fetch_conditional", fake_fc)
    monkeypatch.setattr(
        "collector.feedparser.parse",
        lambda data: _fake_feed(entries=[_fake_entry("https://ok.example.com/a")]),
    )

    results = collector.validate_sources()

    assert len(results) == 2
    by_name = {r["name"]: r for r in results}
    dead, healthy = by_name["dead"], by_name["healthy"]
    assert dead["reachable"] is False
    assert dead["parseable"] is False
    assert dead["error"], "dead source must carry an error string"
    assert healthy["reachable"] is True
    assert healthy["parseable"] is True
    assert healthy["error"] is None
    for r in results:
        assert set(r) >= {"name", "type", "reachable", "parseable", "tier", "error"}


@_skip
def test_validate_csaf(monkeypatch, tmp_path):
    """ROB-05: a csaf_github source validates as reachable+parseable when the contents
    API lists >=1 advisory JSON; an empty listing is reachable but NOT parseable."""
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "_load_sources", lambda: _csaf_source())

    listing = {"body": _csaf_listing(["icsa-26-001-01.json"])}
    monkeypatch.setattr("collector.fetch", lambda url, **kw: (listing["body"], "application/json"))

    ok = collector.validate_sources()[0]
    assert ok["reachable"] is True
    assert ok["parseable"] is True
    assert ok["error"] is None

    listing["body"] = b"[]"  # reachable, but zero advisories listed
    empty = collector.validate_sources()[0]
    assert empty["reachable"] is True
    assert empty["parseable"] is False


@_skip
def test_validate_landing_source_pdf_pattern_success(monkeypatch, tmp_path):
    """Phase 13: a landing recipe is parseable only after one candidate confirms as PDF."""
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    landing_url = "https://example.com/reports"
    pdf_url = "https://example.com/reports/threat-landscape.pdf"
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "_load_sources", lambda: [{
        "name": "landing",
        "type": "landing",
        "url": landing_url,
        "pdf_pattern": "a.approved[href$='.pdf']",
        "poll_interval_hours": 168,
    }])

    def fake_fetch(url, **kw):
        if url == landing_url:
            return (
                b'<html><body><a class="approved" href="/reports/threat-landscape.pdf">'
                b"Download</a></body></html>",
                "text/html",
            )
        if url == pdf_url:
            return (b"%PDF-1.7 fake", "application/pdf")
        raise AssertionError(f"unexpected fetch: {url}")

    monkeypatch.setattr("collector.fetch", fake_fetch)

    row = collector.validate_sources()[0]

    assert row["reachable"] is True
    assert row["parseable"] is True
    assert row["error"] is None
    assert row["matched_url"] == pdf_url


@_skip
def test_validate_landing_source_pdf_pattern_miss(monkeypatch, tmp_path):
    """Phase 13: selector misses are explicit validation failures, not silent success."""
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    landing_url = "https://example.com/reports"
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "_load_sources", lambda: [{
        "name": "landing",
        "type": "landing",
        "url": landing_url,
        "pdf_pattern": "a.approved[href$='.pdf']",
        "poll_interval_hours": 168,
    }])
    monkeypatch.setattr(
        "collector.fetch",
        lambda url, **kw: (
            b'<html><body><a class="generic" href="/reports/other.pdf">Other</a></body></html>',
            "text/html",
        ),
    )

    row = collector.validate_sources()[0]

    assert row["reachable"] is True
    assert row["parseable"] is False
    assert "pdf_pattern" in row["error"]
    assert "matched no PDF links" in row["error"]


@_skip
def test_get_status_shape():
    """DOC-04 shape: get_status() returns sources list, registry_size int, last_run."""
    result = collector.get_status()
    assert isinstance(result, dict)
    assert "sources" in result
    assert "registry_size" in result
    assert "last_run" in result
    assert isinstance(result["sources"], list)
    assert isinstance(result["registry_size"], int)


# ── html_collection adapter ──────────────────────────────────────────────────

CNSD_COLLECTION_URL = (
    "https://www.gob.pe/institucion/pcm/colecciones/"
    "791-alerta-integrada-de-seguridad-digital-del-cnsd"
)

SEED_DOCUMENTS = [
    {
        "landing_url": f"https://www.gob.pe/institucion/pcm/informes-publicaciones/{number}-alerta-integrada-de-seguridad-digital-n-{number}-2026-cnsd",
        "document_url": f"https://cdn.www.gob.pe/uploads/document/file/{number}/{number}-alerta-integrada-de-seguridad-digital-{number}-2026-cnsd.pdf",
    }
    for number in (117, 116, 115)
]


def _html_collection_source(**overrides):
    source = {
        "name": "CNSD Integrated Digital Security Alerts",
        "type": "html_collection",
        "url": CNSD_COLLECTION_URL,
        "source_type": "bulletin",
        "collection_item_selector": "a.leading-6.font-bold[href]",
        "landing_allowed_hosts": ["www.gob.pe"],
        "landing_path_pattern": r"^/institucion/pcm/informes-publicaciones/.*cnsd$",
        "document_link_selector": "a.track-ga-click[href]",
        "document_allowed_hosts": ["cdn.www.gob.pe"],
        "document_path_pattern": r"^/uploads/document/file/.*\.pdf$",
        "max_candidates": 3,
        "max_new_per_cycle": 1,
        "automatic_dispatch": True,
        "dispatch_pipeline": "cnsd_strict",
        "processed_seed_documents": copy.deepcopy(SEED_DOCUMENTS),
        "poll_interval_hours": 0,
    }
    source.update(overrides)
    return source


@_skip
def test_cnsd_periodic_recipe_is_canonical_bounded_and_strict():
    # Exactly one strict-pipeline html_collection recipe (CNSD); other
    # html_collection sources are pipeline-less (quick-260717-col).
    recipes = [
        source
        for source in collector._load_sources()
        if source["type"] == "html_collection"
        and source.get("dispatch_pipeline") == "cnsd_strict"
    ]

    assert len(recipes) == 1
    source = recipes[0]
    assert source["url"] == CNSD_COLLECTION_URL
    assert source["automatic_dispatch"] is True
    assert source["poll_interval_hours"] == 24
    assert source["max_candidates"] == 3
    assert source["max_new_per_cycle"] == 1
    assert source["dispatch_pipeline"] == "cnsd_strict"
    assert len(source["processed_seed_documents"]) == 3
    assert "controlled_documents" not in source


@_skip
def test_html_collection_traversal_is_ordered_confined_and_capped(monkeypatch):
    landing_one = "https://www.gob.pe/institucion/pcm/informes-publicaciones/900-one-cnsd"
    landing_two = "https://www.gob.pe/institucion/pcm/informes-publicaciones/899-two-cnsd"
    landing_three = "https://www.gob.pe/institucion/pcm/informes-publicaciones/898-three-cnsd"
    pdf_one = "https://cdn.www.gob.pe/uploads/document/file/900/alert-one.pdf?download=1"
    pdf_two = "https://cdn.www.gob.pe/uploads/document/file/899/alert-two.pdf"
    collection_html = f"""
      <a class="leading-6 font-bold" href="{landing_one}#heading">one</a>
      <a class="leading-6 font-bold" href="{landing_one}">one</a>
      <a class="leading-6 font-bold" href="https://www.gob.pe.evil.test/institucion/pcm/informes-publicaciones/bad-cnsd">evil</a>
      <a class="leading-6 font-bold" href="{landing_two}">two</a>
      <a class="leading-6 font-bold" href="{landing_three}">three</a>
    """.encode()
    landing_html = {
        landing_one: f"""
          <main><h1>one</h1><time datetime="2026-07-11"></time>
            <a class="track-ga-click" href="{pdf_one}#download">pdf</a>
            <a class="track-ga-click" href="{pdf_one}">duplicate pdf</a>
            <a class="track-ga-click" href="https://cdn.www.gob.pe.evil.test/uploads/document/file/bad.pdf">evil</a>
          </main>
        """.encode(),
        landing_two: (
            f'<main><h1>two</h1><time datetime="2026-07-10"></time>'
            f'<a class="track-ga-click" href="{pdf_two}">pdf</a></main>'
        ).encode(),
    }
    calls = []

    def fake_fetch(url, **kwargs):
        calls.append(url)
        if url == CNSD_COLLECTION_URL:
            return collection_html, "text/html"
        if url in landing_html:
            return landing_html[url], "text/html"
        if url in {pdf_one, pdf_two}:
            return b"%PDF-1.7 fake", "application/pdf"
        raise AssertionError(f"unsafe or over-cap fetch: {url}")

    monkeypatch.setattr(collector, "fetch", fake_fetch)
    result = collector.discover_html_collection(
        _html_collection_source(max_candidates=2), state={"processed_urls": []}
    )

    assert [(d.landing_dedup_key, d.document_dedup_key) for d in result.documents] == [
        (landing_one, pdf_one),
        (landing_two, pdf_two),
    ]
    assert result.collection_candidates == 3
    assert result.landing_fetches == 2
    assert result.document_fetches == 2
    assert landing_three not in calls
    assert all("evil.test" not in url for url in calls)


@_skip
def test_html_collection_provenance_is_confirmed_and_enumerated(monkeypatch):
    landing = "https://www.gob.pe/institucion/pcm/informes-publicaciones/900-one-cnsd"
    document = "https://cdn.www.gob.pe/uploads/document/file/900/one.pdf"
    collection_html = f"""
      <main><article><time datetime="2026-07-11">11 de julio de 2026</time>
        <a class="leading-6 font-bold" href="{landing}"> Alerta Integrada 117 </a>
      </article></main>
    """.encode()
    landing_html = f"""
      <main><h1>Alerta Integrada 117</h1><time datetime="2026-07-11"></time>
        <a class="track-ga-click" href="{document}">PDF</a>
      </main>
    """.encode()

    def fake_fetch(url, **kwargs):
        if url == CNSD_COLLECTION_URL:
            return collection_html, "text/html"
        if url == landing:
            return landing_html, "text/html"
        if url == document:
            return b"%PDF-1.7 fake", "application/pdf"
        raise AssertionError(url)

    monkeypatch.setattr(collector, "fetch", fake_fetch)

    result = collector.discover_html_collection(_html_collection_source(), state={})

    assert result.errors == []
    assert len(result.documents) == 1
    pending = result.documents[0]
    assert pending.title == "Alerta Integrada 117"
    assert pending.publication_date == "2026-07-11"
    assert pending.title_source == "collection_anchor+landing_confirmed"
    assert pending.publication_date_source == "collection_card_time+landing_confirmed"


@_skip
def test_html_collection_provenance_conflict_fails_closed(monkeypatch):
    landing = "https://www.gob.pe/institucion/pcm/informes-publicaciones/900-one-cnsd"
    document = "https://cdn.www.gob.pe/uploads/document/file/900/one.pdf"
    collection_html = f"""
      <article><time datetime="2026-07-11"></time>
        <a class="leading-6 font-bold" href="{landing}">Alerta Integrada 117</a>
      </article>
    """.encode()
    landing_html = f"""
      <main><h1>Different bulletin</h1><time datetime="2026-07-11"></time>
        <a class="track-ga-click" href="{document}">PDF</a>
      </main>
    """.encode()

    monkeypatch.setattr(
        collector,
        "fetch",
        lambda url, **kwargs: (
            (collection_html, "text/html")
            if url == CNSD_COLLECTION_URL
            else (landing_html, "text/html")
            if url == landing
            else (b"%PDF-1.7 fake", "application/pdf")
        ),
    )

    result = collector.discover_html_collection(_html_collection_source(), state={})

    assert result.documents == []
    assert any("title" in error and "conflict" in error for error in result.errors)


@_skip
def test_html_collection_provenance_confirms_card_title_against_document_h2(monkeypatch):
    """gob.pe uses main h1 for the institution and h2 for the report title."""
    landing = "https://www.gob.pe/institucion/pcm/informes-publicaciones/900-one-cnsd"
    document = "https://cdn.www.gob.pe/uploads/document/file/900/one.pdf"
    title = "Alerta integrada de seguridad digital N° 117-2026-CNSD"
    collection_html = (
        f'<meta charset="utf-8"><article><div>9 de julio de 2026</div>'
        f'<a class="leading-6 font-bold" href="{landing}">{title}</a></article>'
    ).encode()
    landing_html = (
        f'<meta charset="utf-8"><main><h1><a>Presidencia del Consejo de Ministros</a></h1>'
        f'<h2>{title}</h2><p>9 de julio de 2026</p>'
        f'<a class="track-ga-click" href="{document}">PDF</a></main>'
    ).encode()

    def fake_fetch(url, **kwargs):
        if url == CNSD_COLLECTION_URL:
            return collection_html, "text/html"
        if url == landing:
            return landing_html, "text/html"
        return b"%PDF-1.7 fake", "application/pdf"

    monkeypatch.setattr(collector, "fetch", fake_fetch)

    result = collector.discover_html_collection(_html_collection_source(), state={})

    assert result.errors == []
    assert result.documents[0].title == title
    assert result.documents[0].title_source == "collection_anchor+landing_confirmed"


@_skip
def test_html_collection_requires_confirmed_pdf_and_deduplicates_shared_document(monkeypatch):
    landing_one = "https://www.gob.pe/institucion/pcm/informes-publicaciones/900-one-cnsd"
    landing_two = "https://www.gob.pe/institucion/pcm/informes-publicaciones/899-two-cnsd"
    pdf_url = "https://cdn.www.gob.pe/uploads/document/file/900/shared.pdf"
    collection_html = f"""
      <article><time datetime="2026-07-11"></time><a class="leading-6 font-bold" href="{landing_one}">one</a></article>
      <article><time datetime="2026-07-10"></time><a class="leading-6 font-bold" href="{landing_two}">two</a></article>
    """.encode()

    def landing_page(url):
        title, date = ("one", "2026-07-11") if url == landing_one else ("two", "2026-07-10")
        return (
            f'<main><h1>{title}</h1><time datetime="{date}"></time>'
            f'<a class="track-ga-click" href="{pdf_url}">pdf</a></main>'
        ).encode()

    def fake_fetch(url, **kwargs):
        if url == CNSD_COLLECTION_URL:
            return collection_html, "text/html"
        if url in {landing_one, landing_two}:
            return landing_page(url), "text/html"
        if url == pdf_url:
            return b"not a pdf", "text/plain"
        raise AssertionError(url)

    monkeypatch.setattr(collector, "fetch", fake_fetch)
    rejected = collector.discover_html_collection(_html_collection_source(), state={})
    assert rejected.documents == []

    monkeypatch.setattr(
        collector,
        "fetch",
        lambda url, **kwargs: (
            (collection_html, "text/html") if url == CNSD_COLLECTION_URL
            else (landing_page(url), "text/html")
            if url in {landing_one, landing_two}
            else (b"%PDF-1.7 fake", "application/pdf")
        ),
    )
    admitted = collector.discover_html_collection(_html_collection_source(), state={})
    assert len(admitted.documents) == 1
    assert admitted.documents[0].landing_dedup_key == landing_one
    assert admitted.documents[0].document_dedup_key == pdf_url


@_skip
@pytest.mark.parametrize(
    ("selector_key", "selector"),
    [
        ("collection_item_selector", "a["),
        ("document_link_selector", "a["),
    ],
)
def test_html_collection_validation_reports_invalid_selectors(
    monkeypatch, tmp_path, selector_key, selector
):
    source = _html_collection_source(**{selector_key: selector})
    landing = "https://www.gob.pe/institucion/pcm/informes-publicaciones/900-one-cnsd"
    monkeypatch.setattr(collector, "STATE_PATH", tmp_path / "state.json")
    monkeypatch.setattr(collector, "_load_sources", lambda: [source])
    def fake_fetch(url, **kwargs):
        if url == CNSD_COLLECTION_URL:
            return (
                f'<article><time datetime="2026-07-11"></time>'
                f'<a class="leading-6 font-bold" href="{landing}">one</a></article>'
            ).encode(), "text/html"
        return (
            b'<main><h1>one</h1><time datetime="2026-07-11"></time></main>',
            "text/html",
        )

    monkeypatch.setattr(collector, "fetch", fake_fetch)

    row = collector.validate_sources()[0]

    assert row["reachable"] is True
    assert row["parseable"] is False
    assert selector_key in row["error"]
    assert "invalid" in row["error"]


@_skip
def test_html_collection_validation_reports_selector_allowlist_miss(monkeypatch, tmp_path):
    monkeypatch.setattr(collector, "STATE_PATH", tmp_path / "state.json")
    monkeypatch.setattr(collector, "_load_sources", lambda: [_html_collection_source()])
    monkeypatch.setattr(
        collector,
        "fetch",
        lambda url, **kwargs: (
            b'<a class="leading-6 font-bold" href="https://attacker.test/bad">bad</a>',
            "text/html",
        ),
    )

    row = collector.validate_sources()[0]

    assert row["reachable"] is True
    assert row["parseable"] is False
    assert "collection_item_selector" in row["error"]
    assert "allowlist" in row["error"]


def _single_html_document_fetch(monkeypatch, landing_url, document_url):
    collection_html = (
        f'<article><time datetime="2026-07-11"></time>'
        f'<a class="leading-6 font-bold" href="{landing_url}">one</a></article>'
    ).encode()
    landing_html = (
        f'<main><h1>one</h1><time datetime="2026-07-11"></time>'
        f'<a class="track-ga-click" href="{document_url}">pdf</a></main>'
    )
    landing_html = landing_html.encode()

    def fake_fetch(url, **kwargs):
        if url == CNSD_COLLECTION_URL:
            return collection_html, "text/html"
        if url == landing_url:
            return landing_html, "text/html"
        if url == document_url:
            return b"%PDF-1.7 fake", "application/pdf"
        raise AssertionError(url)

    monkeypatch.setattr(collector, "fetch", fake_fetch)


@_skip
def test_html_collection_inflight_then_zero_ioc_report_acknowledges_both_keys(
    monkeypatch, tmp_path
):
    landing = "https://www.gob.pe/institucion/pcm/informes-publicaciones/900-one-cnsd"
    document = "https://cdn.www.gob.pe/uploads/document/file/900/one.pdf"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    collector._html_collection_inflight.clear()
    _single_html_document_fetch(monkeypatch, landing, document)

    first = collector.discover_html_collection(
        _html_collection_source(), state=collector._load_state(), operational=True
    )
    assert len(first.documents) == 1
    assert collector._html_collection_inflight == {landing, document}
    assert collector.discover_html_collection(
        _html_collection_source(), state=collector._load_state(), operational=True
    ).documents == []

    monkeypatch.setattr(
        collector,
        "_load_extractor_module",
        lambda: pytest.fail("CNSD must not load the generic extractor"),
    )

    assert asyncio.run(
        collector._dispatch_pending(
            first.documents[0], dispatchers={"cnsd_strict": lambda item: {"ok": True}}
        )
    ) is True

    assert collector._html_collection_inflight == set()
    assert set(json.loads(state_file.read_text())["processed_urls"]) == {landing, document}
    assert collector.discover_html_collection(
        _html_collection_source(), state=collector._load_state(), operational=True
    ).documents == []


@_skip
@pytest.mark.parametrize("outcome", ["exception", "failed", "missing_report"])
def test_html_collection_failed_dispatch_clears_inflight_and_remains_retryable(
    monkeypatch, tmp_path, outcome
):
    landing = "https://www.gob.pe/institucion/pcm/informes-publicaciones/900-one-cnsd"
    document = "https://cdn.www.gob.pe/uploads/document/file/900/one.pdf"
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    collector._html_collection_inflight.clear()
    _single_html_document_fetch(monkeypatch, landing, document)
    item = collector.discover_html_collection(
        _html_collection_source(), state=collector._load_state(), operational=True
    ).documents[0]

    def strict_handler(item):
        if outcome == "exception":
            raise RuntimeError("boom")
        return {"ok": outcome not in {"failed", "missing_report"}}

    monkeypatch.setattr(
        collector,
        "_load_extractor_module",
        lambda: pytest.fail("CNSD must not load the generic extractor"),
    )

    assert asyncio.run(
        collector._dispatch_pending(
            item, dispatchers={"cnsd_strict": strict_handler}
        )
    ) is False

    assert collector._html_collection_inflight == set()
    assert json.loads(state_file.read_text())["processed_urls"] == []
    assert len(collector.discover_html_collection(
        _html_collection_source(), state=collector._load_state(), operational=True
    ).documents) == 1
    collector._html_collection_inflight.clear()


@_skip
def test_html_collection_automatic_dispatch_false_never_discovers(monkeypatch, tmp_path):
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(
        collector,
        "discover_html_collection",
        lambda *args, **kwargs: pytest.fail("disabled source must not discover operationally"),
    )

    pending = collector._poll_source(
        _html_collection_source(automatic_dispatch=False), collector._load_state()
    )

    assert pending == []


@_skip
def test_html_collection_canary_is_measured_read_only_and_lazy(monkeypatch, tmp_path):
    landing = "https://www.gob.pe/institucion/pcm/informes-publicaciones/900-one-cnsd"
    document = "https://cdn.www.gob.pe/uploads/document/file/900/one.pdf"
    state_file = tmp_path / "sentinel-state.json"
    db_file = tmp_path / "sentinel-stats.db"
    state_file.write_bytes(b"state-sentinel")
    db_file.write_bytes(b"db-sentinel")
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(collector, "DB_PATH", db_file)
    monkeypatch.setattr(collector, "_load_sources", lambda: [_html_collection_source()])
    monkeypatch.setattr(
        collector,
        "_load_extractor_module",
        lambda: pytest.fail("canary must not load the operational extractor"),
    )
    monkeypatch.setenv("OPENCTI_TOKEN", "")
    monkeypatch.setenv("OPENCTI_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("OLLAMA_URL", "http://127.0.0.1:9")
    _single_html_document_fetch(monkeypatch, landing, document)
    before_state = collector._snapshot_path(state_file)
    before_db = collector._snapshot_path(db_file)
    modules_before = set(sys.modules)

    result = collector.run_collection_canary(CNSD_COLLECTION_URL, 3)

    after_state = collector._snapshot_path(state_file)
    after_db = collector._snapshot_path(db_file)
    measured = before_state != after_state or before_db != after_db
    assert result["documents"] == [{"landing_url": landing, "document_url": document}]
    assert result["credentials_present"] is False
    assert result["operational_imports_loaded"] is False
    assert result["write_attempts"] == 0
    assert result["state_before"] == before_state
    assert result["state_after"] == after_state
    assert result["db_before"] == before_db
    assert result["db_after"] == after_db
    assert result["state_mutated"] is measured is False
    assert not any(
        name in sys.modules and name not in modules_before
        for name in ("extractor", "opencti_client", "ollama", "stats_store")
    )


@_skip
def test_cnsd_due_attempt_failure_enforces_periodic_cadence(monkeypatch, tmp_path):
    state_path = tmp_path / "state.json"
    monkeypatch.setattr(collector, "STATE_PATH", state_path)
    source = _html_collection_source(poll_interval_hours=24)
    calls = []

    def fail_discovery(*args, **kwargs):
        calls.append("discovery")
        raise RuntimeError("collection unavailable")

    monkeypatch.setattr(collector, "discover_html_collection", fail_discovery)
    now = datetime(2026, 7, 12, 12, tzinfo=timezone.utc)
    state = {"processed_urls": ["sentinel"], "sources": {}}

    assert collector._poll_html_collection(source, state, now=now) == []
    assert collector._poll_html_collection(
        source, state, now=now + timedelta(minutes=1)
    ) == []

    persisted = json.loads(state_path.read_text())
    row = persisted["sources"][source["name"]]
    assert calls == ["discovery"]
    assert row["last_attempt"] == now.isoformat()
    assert row["last_outcome"] == "not_due"
    assert row["counters"]["due"] == 1
    assert row["counters"]["not_due"] == 1
    assert row["counters"]["failed"] == 1
    assert "sentinel" in persisted["processed_urls"]
    assert all(
        pair[key] in persisted["processed_urls"]
        for pair in SEED_DOCUMENTS
        for key in ("landing_url", "document_url")
    )


@_skip
def test_cnsd_periodic_dry_run_is_due_then_not_due_without_extra_fetches(
    monkeypatch, tmp_path
):
    state_path = tmp_path / "state.json"
    monkeypatch.setattr(collector, "STATE_PATH", state_path)
    source = _html_collection_source(poll_interval_hours=24)
    monkeypatch.setattr(collector, "_load_sources", lambda: [source])
    calls = []
    collection = "".join(
        f'<article><a class="leading-6 font-bold" href="{item["landing_url"]}">seed</a></article>'
        for item in SEED_DOCUMENTS
    ).encode()

    def fake_fetch(url, **kwargs):
        calls.append(url)
        if url == CNSD_COLLECTION_URL:
            return collection, "text/html"
        raise AssertionError(f"known seed must not fetch downstream: {url}")

    monkeypatch.setattr(collector, "fetch", fake_fetch)
    now = datetime(2026, 7, 12, 12, tzinfo=timezone.utc)

    first = collector.run_collection_poll_once(
        CNSD_COLLECTION_URL, now=now, dry_run=True
    )
    second = collector.run_collection_poll_once(
        CNSD_COLLECTION_URL, now=now + timedelta(minutes=1), dry_run=True
    )

    assert first == {
        **first,
        "outcome": "due",
        "known": 3,
        "new": 0,
        "selected": 0,
        "processed": 0,
        "failed": 0,
        "collection_fetches": 1,
        "landing_fetches": 0,
        "document_fetches": 0,
        "write_attempts": 0,
    }
    assert second == {
        **second,
        "outcome": "not_due",
        "collection_fetches": 0,
        "landing_fetches": 0,
        "document_fetches": 0,
        "processed": 0,
        "write_attempts": 0,
    }
    assert calls == [CNSD_COLLECTION_URL]


@_skip
def test_cnsd_dispatcher_is_strictly_injected_and_has_no_generic_fallback(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(collector, "STATE_PATH", tmp_path / "state.json")
    item = collector.PendingDocument(
        mode="pdf",
        content=b"%PDF-1.7 future",
        url=None,
        source_type="bulletin",
        source_name="CNSD Integrated Digital Security Alerts",
        landing_dedup_key=SEED_DOCUMENTS[0]["landing_url"],
        document_dedup_key=SEED_DOCUMENTS[0]["document_url"],
        dispatch_pipeline="cnsd_strict",
        source_config=_html_collection_source(),
    )
    collector._html_collection_inflight.update(
        {item.landing_dedup_key, item.document_dedup_key}
    )
    generic = MagicMock(side_effect=AssertionError("generic fallback forbidden"))
    monkeypatch.setattr(collector, "_load_extractor_module", generic)

    assert asyncio.run(collector._dispatch_pending(item, dispatchers={})) is False
    handler = MagicMock(return_value={"ok": True})
    assert asyncio.run(
        collector._dispatch_pending(item, dispatchers={"cnsd_strict": handler})
    ) is True

    generic.assert_not_called()
    handler.assert_called_once_with(item)
    assert collector._html_collection_inflight == set()
    status = collector.get_status()
    row = next(source for source in status["sources"] if source["name"] == item.source_name)
    assert {"last_outcome", "cycle", "counters"} <= set(row)
    assert {"due", "not_due", "new", "known", "processed", "failed"} <= set(
        row["counters"]
    )


# ── html_index source type (quick-260716-m2g) ────────────────────────────────

MITRE_INDEX_URL = "https://attack.mitre.org/groups/"
MITRE_IDENTITY = {"name": "The MITRE Corporation", "type": "Organization"}

# 8 anchors: 3 valid group links (G0001 duplicated — ID and Name columns both
# link), 1 cross-host, 1 non-matching short ID, 1 index path itself, 1 javascript:
MITRE_INDEX_HTML = b"""
<html><body><table>
  <tr><td><a href="/groups/G0001">G0001</a></td><td><a href="/groups/G0001">Axiom</a></td></tr>
  <tr><td><a href="/groups/G0002">G0002</a></td></tr>
  <tr><td><a href="/groups/G0003">G0003</a></td></tr>
  <a href="https://evil.example.com/groups/G0004">cross-host</a>
  <a href="/groups/G001">short id</a>
  <a href="/groups/">index itself</a>
  <a href="javascript:alert(1)">js</a>
</table></body></html>
"""


def _html_index_source(**overrides):
    source = {
        "name": "MITRE ATT&CK Groups",
        "type": "html_index",
        "url": MITRE_INDEX_URL,
        "source_type": "report",
        "item_selector": "a[href]",
        "allowed_hosts": ["attack.mitre.org"],
        "path_pattern": r"^/groups/G\d{4}$",
        "max_new_per_cycle": 5,
        "identity": dict(MITRE_IDENTITY),
        "poll_interval_hours": 0,
    }
    source.update(overrides)
    return source


def _html_index_setup(monkeypatch, tmp_path, state=None):
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps(state or {"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    monkeypatch.setattr(
        collector, "_collector_state", {"sources_meta": {}, "last_run": None}
    )
    return state_file


@_skip
@pytest.mark.parametrize("overrides", [
    {"item_selector": None},
    {"item_selector": "   "},
    {"allowed_hosts": []},
    {"allowed_hosts": ["https://attack.mitre.org"]},
    {"path_pattern": "["},
    {"path_pattern": "   "},
    {"max_new_per_cycle": 0},
    {"append_slash": "yes"},
])
def test_html_index_invalid_recipe_errors_and_never_fetches(
    monkeypatch, tmp_path, overrides
):
    """An invalid html_index recipe is a recorded config error that never fetches."""
    _html_index_setup(monkeypatch, tmp_path)
    monkeypatch.setattr(
        collector, "fetch",
        lambda *a, **kw: pytest.fail("invalid recipe must never fetch"),
    )

    pending = collector._poll_html_index(
        _html_index_source(**overrides), collector._load_state()
    )

    assert pending == []
    meta = collector._collector_state["sources_meta"]["MITRE ATT&CK Groups"]
    assert meta["errors"] == 1


@_skip
def test_html_index_discovery_is_confined_capped_and_persisted(monkeypatch, tmp_path):
    """Confined group links dispatch as mode='url' PendingDocuments, capped and persisted."""
    state_file = _html_index_setup(monkeypatch, tmp_path)
    fetched = []

    def fake_fetch(url, **kw):
        fetched.append(url)
        assert url == MITRE_INDEX_URL
        return MITRE_INDEX_HTML, "text/html"

    monkeypatch.setattr(collector, "fetch", fake_fetch)
    source = _html_index_source(max_new_per_cycle=2)

    pending = collector._poll_source(source, collector._load_state())

    assert fetched == [MITRE_INDEX_URL]
    assert [p.url for p in pending] == [
        "https://attack.mitre.org/groups/G0001",
        "https://attack.mitre.org/groups/G0002",
    ]
    for p in pending:
        assert isinstance(p, collector.PendingDocument)
        assert p.mode == "url"
        assert p.content is None
        assert p.source_type == "report"
        assert p.source_name == "MITRE ATT&CK Groups"
        assert p.dispatch_pipeline is None
        assert p.source_config["identity"] == MITRE_IDENTITY

    saved = json.loads(state_file.read_text())
    assert set(saved["processed_urls"]) == {
        "https://attack.mitre.org/groups/G0001",
        "https://attack.mitre.org/groups/G0002",
    }
    assert saved["sources"]["MITRE ATT&CK Groups"]["last_polled"] is not None
    assert collector._collector_state["sources_meta"]["MITRE ATT&CK Groups"][
        "new_found"
    ] == 2


@_skip
def test_html_index_append_slash_dispatches_canonical_urls(monkeypatch, tmp_path):
    """append_slash normalizes slashless hrefs to the canonical trailing-slash URL.

    attack.mitre.org 301-redirects /groups/GXXXX -> /groups/GXXXX/ and the
    extractor's fetch path never follows redirects (SSRF guard) — dispatching
    the slashless URL extracts '301 Moved Permanently' instead of the page.
    """
    _html_index_setup(monkeypatch, tmp_path)
    monkeypatch.setattr(
        collector, "fetch", lambda *a, **kw: (MITRE_INDEX_HTML, "text/html")
    )
    source = _html_index_source(append_slash=True, max_new_per_cycle=2)

    pending = collector._poll_html_index(source, collector._load_state())

    assert [p.url for p in pending] == [
        "https://attack.mitre.org/groups/G0001/",
        "https://attack.mitre.org/groups/G0002/",
    ]

    monkeypatch.setattr(collector, "_load_sources", lambda: [source])
    row = collector.validate_sources()[0]
    assert row["parseable"] is True
    assert row["matched_url"] == "https://attack.mitre.org/groups/G0001/"


@_skip
def test_html_index_dedup_across_polls(monkeypatch, tmp_path):
    """Optimistic dedup: later polls only dispatch the remaining unprocessed URLs."""
    _html_index_setup(monkeypatch, tmp_path)
    monkeypatch.setattr(
        collector, "fetch", lambda *a, **kw: (MITRE_INDEX_HTML, "text/html")
    )
    source = _html_index_source(max_new_per_cycle=2)

    first = collector._poll_html_index(source, collector._load_state())
    assert [p.url for p in first] == [
        "https://attack.mitre.org/groups/G0001",
        "https://attack.mitre.org/groups/G0002",
    ]

    second = collector._poll_html_index(source, collector._load_state())
    assert [p.url for p in second] == ["https://attack.mitre.org/groups/G0003"]

    third = collector._poll_html_index(source, collector._load_state())
    assert third == []


@_skip
def test_html_index_not_due_skips_fetch_and_resets_new_found(monkeypatch, tmp_path):
    """D-02: an html_index source polled within its interval never fetches."""
    _html_index_setup(monkeypatch, tmp_path, state={
        "processed_urls": [],
        "sources": {
            "MITRE ATT&CK Groups": {
                "last_polled": datetime.now(timezone.utc).isoformat()
            }
        },
    })
    collector._collector_state["sources_meta"]["MITRE ATT&CK Groups"] = {
        "new_found": 3, "errors": 0,
    }
    monkeypatch.setattr(
        collector, "fetch",
        lambda *a, **kw: pytest.fail("not-due source must not fetch"),
    )
    source = _html_index_source(poll_interval_hours=24)

    assert collector._poll_html_index(source, collector._load_state()) == []
    assert collector._collector_state["sources_meta"]["MITRE ATT&CK Groups"][
        "new_found"
    ] == 0


@_skip
def test_validate_html_index_confined_match_and_miss(monkeypatch, tmp_path):
    """ROB-05: html_index validates on a confined link; misses carry an error string."""
    _html_index_setup(monkeypatch, tmp_path)
    monkeypatch.setattr(collector, "_load_sources", lambda: [_html_index_source()])
    monkeypatch.setattr(
        collector, "fetch", lambda *a, **kw: (MITRE_INDEX_HTML, "text/html")
    )

    row = collector.validate_sources()[0]
    assert row["reachable"] is True
    assert row["parseable"] is True
    assert row["matched_url"] == "https://attack.mitre.org/groups/G0001"
    assert row["error"] is None

    monkeypatch.setattr(
        collector, "fetch",
        lambda *a, **kw: (b'<html><a href="/other/page">x</a></html>', "text/html"),
    )
    miss = collector.validate_sources()[0]
    assert miss["reachable"] is True
    assert miss["parseable"] is False
    assert "item_selector" in miss["error"]


@_skip
def test_dispatch_pending_forwards_source_identity_as_created_by(monkeypatch, tmp_path):
    """The generic dispatch branch forwards source_config identity as created_by."""
    monkeypatch.setattr(collector, "STATE_PATH", tmp_path / "state.json")
    run_extraction = MagicMock()
    fake_extractor = types.SimpleNamespace(
        register_job=lambda job_id: None,
        run_extraction=run_extraction,
        jobs={},
    )
    monkeypatch.setattr(collector, "_load_extractor_module", lambda: fake_extractor)

    item = collector.PendingDocument(
        mode="url",
        content=None,
        url="https://attack.mitre.org/groups/G0001",
        source_type="report",
        source_name="MITRE ATT&CK Groups",
        source_config=_html_index_source(),
    )
    asyncio.run(collector._dispatch_pending(item))
    assert run_extraction.call_args.kwargs["created_by"] == MITRE_IDENTITY
    assert run_extraction.call_args.kwargs["source_type"] == "report"

    run_extraction.reset_mock()
    legacy = ("url", None, "https://example.com/advisory.html", "advisory")
    asyncio.run(collector._dispatch_pending(legacy))
    assert run_extraction.call_args.kwargs["created_by"] is None


@_skip
def test_mitre_groups_recipe_is_canonical_and_bounded():
    """quick-260716-m2g: exactly one html_index source, exact recipe, cap <= 10."""
    recipes = [s for s in collector._load_sources() if s["type"] == "html_index"]

    assert len(recipes) == 1
    source = recipes[0]
    assert source["name"] == "MITRE ATT&CK Groups"
    assert source["url"] == MITRE_INDEX_URL
    assert source["source_type"] == "report"
    assert source["item_selector"] == "a[href]"
    assert source["allowed_hosts"] == ["attack.mitre.org"]
    assert source["path_pattern"] == r"^/groups/G\d{4}$"
    assert source["append_slash"] is True
    assert source["max_new_per_cycle"] == 10  # raised with the 6 GiB Ollama limit (3b0f233)
    assert source["max_new_per_cycle"] <= 10
    assert source["identity"] == MITRE_IDENTITY
    assert source["poll_interval_hours"] == 24
    assert "dispatch_pipeline" not in source


# ── Pipeline-optional automatic html_collection (quick-260717-col) ────────────

COLCERT_IDENTITY = {
    "name": "Grupo de Respuesta a Emergencias Ciberneticas de Colombia (ColCERT)",
    "type": "Organization",
}


def _pipelineless_collection_source(**overrides):
    """html_collection recipe with NO dispatch_pipeline but a valid identity."""
    source = _html_collection_source(identity=dict(COLCERT_IDENTITY))
    source.pop("dispatch_pipeline")
    source.update(overrides)
    return source


def _fake_generic_extractor(status="complete", report_id="r1"):
    """Fake extractor module whose jobs report a fixed terminal status."""
    jobs = {}

    def register_job(job_id):
        jobs[job_id] = {"status": status, "report_id": report_id}

    return types.SimpleNamespace(
        register_job=register_job, run_extraction=MagicMock(), jobs=jobs
    )


@_skip
def test_automatic_html_collection_valid_without_pipeline_when_identity_present():
    """automatic + no dispatch_pipeline + identity{name,type} must validate."""
    compiled = collector._validated_collection_recipe(_pipelineless_collection_source())
    assert isinstance(compiled, tuple) and len(compiled) == 5


@_skip
@pytest.mark.parametrize(
    "identity",
    [
        None,  # key absent entirely
        "not a dict",
        {"name": "", "type": "Organization"},
        {"name": "ColCERT", "type": ""},
        {"type": "Organization"},
        {"name": "ColCERT"},
        {"name": 5, "type": "Organization"},
    ],
)
def test_automatic_html_collection_without_pipeline_fails_closed_on_identity(identity):
    """automatic + no pipeline + broken identity raises mentioning identity."""
    source = _pipelineless_collection_source()
    if identity is None:
        source.pop("identity")
    else:
        source["identity"] = identity
    with pytest.raises(collector.CollectionConfigError, match="identity"):
        collector._validated_collection_recipe(source)


@_skip
def test_automatic_html_collection_pipeline_path_validation_unchanged():
    """Declared pipelines keep the existing non-empty-str requirement."""
    collector._validated_collection_recipe(
        _html_collection_source(dispatch_pipeline="cnsd_strict")
    )
    for bad in ("", "   ", 5):
        with pytest.raises(collector.CollectionConfigError):
            collector._validated_collection_recipe(
                _html_collection_source(dispatch_pipeline=bad)
            )


@_skip
def test_pipelineless_dispatch_threads_document_url_and_acknowledges(
    monkeypatch, tmp_path
):
    """Pipeline-less html_collection item: run_extraction gets created_by=identity,
    source_type, and positional url == document_dedup_key (http(s), NOT None — pins
    Report naming + External Reference + Step 9 targeting eligibility); success
    acknowledges both dedup keys into processed_urls."""
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    collector._html_collection_inflight.clear()
    fake = _fake_generic_extractor(status="complete", report_id="r1")
    monkeypatch.setattr(collector, "_load_extractor_module", lambda: fake)

    source = _pipelineless_collection_source(name="ColCERT Boletines")
    landing = "https://www.colcert.gov.co/800/w3-article-439553.html"
    document = (
        "https://www.colcert.gov.co/800/articles-439553_"
        "COLCERT_IN20260629033_Informe_de_apreciacion_Sector_Industria.pdf"
    )
    item = collector.PendingDocument(
        mode="pdf",
        content=b"%PDF-1.7 fake",
        url=None,
        source_type="bulletin",
        source_name=source["name"],
        landing_dedup_key=landing,
        document_dedup_key=document,
        dispatch_pipeline=None,
        source_config=source,
    )
    collector._html_collection_inflight.update({landing, document})

    assert asyncio.run(collector._dispatch_pending(item)) is True

    call = fake.run_extraction.call_args
    assert call.kwargs["created_by"] == COLCERT_IDENTITY
    assert call.kwargs["source_type"] == "bulletin"
    assert call.args[3] == document
    assert call.args[3].startswith("https://")
    assert collector._html_collection_inflight == set()
    assert set(json.loads(state_file.read_text())["processed_urls"]) == {
        landing,
        document,
    }


@_skip
def test_pipelineless_dispatch_failure_remains_retryable(monkeypatch, tmp_path):
    """Failed pipeline-less dispatch: keys NOT persisted, failed counter bumped,
    inflight cleared so the item is retryable next cycle."""
    state_file = tmp_path / "state.json"
    state_file.write_text(json.dumps({"processed_urls": [], "sources": {}}))
    monkeypatch.setattr(collector, "STATE_PATH", state_file)
    collector._html_collection_inflight.clear()
    fake = _fake_generic_extractor(status="failed", report_id=None)
    monkeypatch.setattr(collector, "_load_extractor_module", lambda: fake)

    source = _pipelineless_collection_source(name="ColCERT Boletines")
    landing = "https://www.colcert.gov.co/800/w3-article-439553.html"
    document = "https://www.colcert.gov.co/800/articles-439553_Informe.pdf"
    item = collector.PendingDocument(
        mode="pdf",
        content=b"%PDF-1.7 fake",
        url=None,
        source_type="bulletin",
        source_name=source["name"],
        landing_dedup_key=landing,
        document_dedup_key=document,
        dispatch_pipeline=None,
        source_config=source,
    )
    collector._html_collection_inflight.update({landing, document})

    assert asyncio.run(collector._dispatch_pending(item)) is False

    state = json.loads(state_file.read_text())
    assert state["processed_urls"] == []
    assert state["sources"]["ColCERT Boletines"]["counters"]["failed"] == 1
    assert collector._html_collection_inflight == set()


@_skip
def test_pipelineless_dispatch_without_dedup_keys_keeps_url_none(monkeypatch, tmp_path):
    """Genuine uploads / legacy items (no dedup keys) still reach run_extraction
    with url=None — URL threading only fires when a document_dedup_key exists."""
    monkeypatch.setattr(collector, "STATE_PATH", tmp_path / "state.json")
    fake = _fake_generic_extractor(status="complete", report_id="r1")
    monkeypatch.setattr(collector, "_load_extractor_module", lambda: fake)

    item = collector.PendingDocument(
        mode="pdf",
        content=b"%PDF-1.7 fake",
        url=None,
        source_type="bulletin",
    )
    asyncio.run(collector._dispatch_pending(item))

    assert fake.run_extraction.call_args.args[3] is None


# ── ColCERT Boletines recipe (quick-260717-col) ───────────────────────────────

COLCERT_COLLECTION_URL = "https://www.colcert.gov.co/800/w3-propertyvalue-412601.html"

COLCERT_SEED_DOCUMENTS = [
    {
        "landing_url": "https://www.colcert.gov.co/800/w3-article-439644.html",
        "document_url": (
            "https://www.colcert.gov.co/800/articles-439644_COLCERT_AL__20260710__102_"
            "Alerta_Red_de_Retransmision_Operativa_CHARLIE."
        ),
    },
    {
        "landing_url": "https://www.colcert.gov.co/800/w3-article-439567.html",
        "document_url": (
            "https://www.colcert.gov.co/800/articles-439567_COLCERT_IN20260703034_"
            "Informe_de_apreciacion_Sector_Salud_.pdf"
        ),
    },
]


def _colcert_shaped_source(**overrides):
    source = {
        "name": "ColCERT Boletines",
        "type": "html_collection",
        "url": COLCERT_COLLECTION_URL,
        "source_type": "bulletin",
        "collection_item_selector": "div.h5.font-weight-bold > a[href]",
        "landing_allowed_hosts": ["www.colcert.gov.co"],
        "landing_path_pattern": r"^/800/w3-article-\d+\.html$",
        "document_link_selector": 'div[class*="binary-"] > a[href]',
        "document_allowed_hosts": ["www.colcert.gov.co"],
        "document_path_pattern": r"^/800/articles-\d+_",
        "max_candidates": 3,
        "max_new_per_cycle": 1,
        "automatic_dispatch": True,
        "identity": dict(COLCERT_IDENTITY),
        "processed_seed_documents": [],
        "poll_interval_hours": 0,
    }
    source.update(overrides)
    return source


@_skip
def test_colcert_recipe_is_canonical_and_bounded():
    """quick-260717-col: exactly one ColCERT html_collection recipe, exact fields,
    pipeline-less with identity, two exact seeds, bounded to 1 new per 24h cycle."""
    recipes = [
        s for s in collector._load_sources()
        if s["type"] == "html_collection" and "ColCERT" in s["name"]
    ]

    assert len(recipes) == 1
    source = recipes[0]
    assert source["name"] == "ColCERT Boletines"
    assert source["url"] == COLCERT_COLLECTION_URL
    assert source["source_type"] == "bulletin"
    assert source["collection_item_selector"] == "div.h5.font-weight-bold > a[href]"
    assert source["landing_allowed_hosts"] == ["www.colcert.gov.co"]
    assert source["landing_path_pattern"] == r"^/800/w3-article-\d+\.html$"
    assert source["document_link_selector"] == 'div[class*="binary-"] > a[href]'
    assert source["document_allowed_hosts"] == ["www.colcert.gov.co"]
    assert source["document_path_pattern"] == r"^/800/articles-\d+_"
    assert source["max_candidates"] == 3
    assert source["max_new_per_cycle"] == 1
    assert source["automatic_dispatch"] is True
    assert "dispatch_pipeline" not in source
    assert source["identity"] == COLCERT_IDENTITY
    assert source["processed_seed_documents"] == COLCERT_SEED_DOCUMENTS
    assert source["poll_interval_hours"] == 24
    # Proves the pipeline-optional relaxation covers the recipe and the seeds
    # round-trip host/pattern confinement exactly.
    collector._validated_collection_recipe(source)


@_skip
def test_colcert_extensionless_pdf_gated_by_content_sniffing(monkeypatch):
    """A bare-dot document href (no .pdf extension) IS selected when it serves
    %PDF magic, and rejected with a per-landing error when it serves HTML —
    the recipe gate is looks_like_pdf content sniffing, not the path pattern."""
    landing = "https://www.colcert.gov.co/800/w3-article-439644.html"
    document = (
        "https://www.colcert.gov.co/800/articles-439644_COLCERT_AL__20260710__102_"
        "Alerta_Red_de_Retransmision_Operativa_CHARLIE."
    )
    title = "COLCERT AL - 20260710 - 102 Alerta Red de Retransmision Operativa CHARLIE"
    collection_html = (
        f'<div class="h5 font-weight-bold">'
        f'<a href="w3-article-439644.html">{title}</a></div>'
    ).encode()
    landing_html = (
        f'<main><h1>{title}</h1><p>10 de julio de 2026</p>'
        f'<div class="binary-CHARLIE format-"><a href="{document}">Descargar</a></div>'
        f"</main>"
    ).encode()

    def fetch_pdf(url, **kwargs):
        if url == COLCERT_COLLECTION_URL:
            return collection_html, "text/html"
        if url == landing:
            return landing_html, "text/html"
        if url == document:
            return b"%PDF-1.7 fake", "application/pdf"
        raise AssertionError(url)

    monkeypatch.setattr(collector, "fetch", fetch_pdf)
    admitted = collector.discover_html_collection(_colcert_shaped_source(), state={})
    assert admitted.errors == []
    assert [d.document_dedup_key for d in admitted.documents] == [document]
    assert admitted.documents[0].landing_dedup_key == landing

    def fetch_html_body(url, **kwargs):
        if url == document:
            return b"<html>not a pdf</html>", "text/html"
        return fetch_pdf(url)

    monkeypatch.setattr(collector, "fetch", fetch_html_body)
    rejected = collector.discover_html_collection(_colcert_shaped_source(), state={})
    assert rejected.documents == []
    assert any("not confirmed as PDF" in error for error in rejected.errors)
