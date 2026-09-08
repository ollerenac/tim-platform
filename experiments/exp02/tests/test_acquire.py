"""Offline behavioral contracts for read-only EXP-02 acquisition."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

import exp02.acquire as acquire_module
from exp02.acquire import (
    AcquisitionError,
    Candidate,
    InspectorDecision,
    SourceConfig,
    acquire_one,
    acquire_selection,
    configured_sources,
    discover_candidates,
    inspect_candidate,
    inspect_selection,
)
from exp02.jsonio import MAX_JSON_BYTES, sha256_file


FIXTURES = Path(__file__).parent / "fixtures"
POLICY = Path(__file__).parents[1] / "config" / "source-policy.v1.json"
SOURCE_NAMES = {
    "ncsc-uk": "NCSC UK",
    "cert-eu": "CERT-EU Threat Intelligence",
    "cert-pl-en": "CERT-PL EN",
    "acsc-advisories": "ACSC Advisories",
    "unit-42": "Unit 42",
    "eset-welivesecurity": "ESET WeLiveSecurity",
    "volexity": "Volexity",
}
FROZEN_FEED_URLS = {
    "ncsc-uk": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
    "cert-eu": "https://cert.europa.eu/publications/threat-intelligence-rss",
    "cert-pl-en": "https://cert.pl/en/rss.xml",
    "acsc-advisories": "https://www.cyber.gov.au/rss/advisories",
    "unit-42": "https://unit42.paloaltonetworks.com/feed/",
    "eset-welivesecurity": "https://www.welivesecurity.com/en/rss/feed/",
    "volexity": "https://www.volexity.com/feed/",
}


class FakeTransport:
    """A closed response inventory that raises if acquisition reaches the network."""

    def __init__(self, responses: dict[str, tuple[bytes, str]]) -> None:
        self.responses = responses
        self.requests: list[str] = []

    def fetch(self, url: str) -> tuple[bytes, str]:
        self.requests.append(url)
        try:
            return self.responses[url]
        except KeyError as error:
            raise AssertionError(f"unexpected network request: {url}") from error


@pytest.fixture
def fake_transport() -> FakeTransport:
    return FakeTransport(
        {
            FROZEN_FEED_URLS["ncsc-uk"]: (
                (FIXTURES / "source-feed.xml").read_bytes(),
                "application/rss+xml",
            )
        }
    )


def source_config() -> SourceConfig:
    return SourceConfig(
        source_id="ncsc-uk",
        source_name="NCSC UK",
        source_class="institutional",
        feed_url=FROZEN_FEED_URLS["ncsc-uk"],
        publisher="NCSC UK",
    )


def _source_config_for(
    source_id: str,
    source_class: str,
    feed_url: str,
) -> SourceConfig:
    source_name = SOURCE_NAMES[source_id]
    return SourceConfig(
        source_id=source_id,
        source_name=source_name,
        source_class=source_class,  # type: ignore[arg-type]
        feed_url=feed_url,
        publisher=source_name,
    )


def test_discovery_uses_exact_source_publisher_when_feed_author_is_blank() -> None:
    """Dropping publisher fallback would exclude official organizational reports."""
    feed = b"""<?xml version='1.0'?><rss version='2.0'><channel>
    <item><title>Official report</title><link>https://example.test/report</link>
    <author></author><pubDate>03 Jun 2025 12:00:00 +0000</pubDate></item>
    </channel></rss>"""
    transport = FakeTransport(
        {FROZEN_FEED_URLS["ncsc-uk"]: (feed, "application/rss+xml")}
    )

    found = discover_candidates(source_config(), transport)

    assert [(item.author, item.author_basis) for item in found] == [
        ("NCSC UK", "source_publisher")
    ]


def test_discovery_preserves_explicit_feed_author_and_records_basis(
    fake_transport: FakeTransport,
) -> None:
    """Replacing an explicit byline with the publisher would corrupt provenance."""
    found = discover_candidates(source_config(), fake_transport)

    assert found[0].author == "New Author"
    assert found[0].author_basis == "feed_author"


@pytest.mark.parametrize("publisher", ["", "Different Organization"])
def test_discovery_rejects_missing_or_unfrozen_publisher(publisher: str) -> None:
    """An arbitrary fallback string must never become an experiment author."""
    source = SourceConfig(
        source_id="ncsc-uk",
        source_name="NCSC UK",
        source_class="institutional",
        feed_url=FROZEN_FEED_URLS["ncsc-uk"],
        publisher=publisher,
    )
    transport = FakeTransport(
        {FROZEN_FEED_URLS["ncsc-uk"]: (b"<rss><channel/></rss>", "application/rss+xml")}
    )

    with pytest.raises(AcquisitionError, match="publisher"):
        discover_candidates(source, transport)

    assert transport.requests == []


def test_discovery_rejects_substituted_feed_url_before_transport() -> None:
    """A public HTTPS substitute must not impersonate a frozen source registry row."""
    source = SourceConfig(
        source_id="ncsc-uk",
        source_name="NCSC UK",
        source_class="institutional",
        feed_url="https://substitute.example.test/feed",
        publisher="NCSC UK",
    )
    transport = FakeTransport(
        {
            "https://substitute.example.test/feed": (
                b"<rss><channel/></rss>",
                "application/rss+xml",
            )
        }
    )

    with pytest.raises(AcquisitionError, match="feed URL"):
        discover_candidates(source, transport)

    assert transport.requests == []


def test_configured_sources_rejects_substituted_frozen_feed_url(
    tmp_path: Path,
) -> None:
    """The live TIM registry must not redirect a frozen source to another feed."""
    registry_path = Path(__file__).parents[3] / "services" / "intel-extractor" / "sources.yaml"
    payload = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    for row in payload["sources"]:
        if row.get("name") == "NCSC UK":
            row["url"] = "https://substitute.example.test/feed"
            break
    else:  # pragma: no cover - the real registry contract catches this first
        raise AssertionError("NCSC UK missing from registry fixture")
    substituted = tmp_path / "sources.yaml"
    substituted.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(AcquisitionError, match="feed URL"):
        configured_sources(substituted)


def test_discovery_orders_by_publication_date_and_deduplicates_urls(
    fake_transport: FakeTransport,
) -> None:
    """A later duplicate feed entry must not replace the first canonical URL record."""
    found = discover_candidates(source_config(), fake_transport)

    assert [item.origin_url for item in found] == [
        "https://example.test/new",
        "https://example.test/old",
    ]
    assert found[0].title == "Newest incident report"
    assert found[0].published_at == "2025-06-03T12:00:00Z"


def test_acquisition_rejects_private_host(tmp_path: Path, fake_transport: FakeTransport) -> None:
    """Removing the public HTTPS gate would allow SSRF targets into frozen evidence."""
    candidate = Candidate(
        source_id="ncsc-uk",
        source_class="institutional",
        origin_url="http://127.0.0.1/x",
        title="Private target",
        author="Analyst",
        author_basis="feed_author",
        published_at="2025-06-03T12:00:00Z",
    )

    with pytest.raises(AcquisitionError, match="HTTPS public origin required"):
        acquire_one(candidate, tmp_path, fake_transport)


def test_html_response_at_pdf_suffix_routes_as_html(fake_transport: FakeTransport) -> None:
    """Passing the URL to TIM's suffix-aware helper would send HTML to the PDF parser."""
    url = "https://example.test/report.pdf"
    fake_transport.responses[url] = ((FIXTURES / "article.html").read_bytes(), "text/html")
    candidate = Candidate(
        source_id="ncsc-uk",
        source_class="institutional",
        origin_url=url,
        title="Threat report",
        author="Analyst",
        author_basis="feed_author",
        published_at="2025-06-03T12:00:00Z",
    )

    acquired = acquire_one(candidate, transport=fake_transport)

    assert acquired.media_type == "html"
    assert "Threat actors used" in acquired.converted_text


def test_inspection_requires_explicit_human_decision(fake_transport: FakeTransport) -> None:
    """Keyword-based inspection would silently replace the required human gate."""
    url = "https://example.test/inspection"
    fake_transport.responses[url] = ((FIXTURES / "article.html").read_bytes(), "text/html")
    candidate = Candidate(
        source_id="ncsc-uk",
        source_class="institutional",
        origin_url=url,
        title="Unrelated title",
        author="Analyst",
        author_basis="feed_author",
        published_at="2025-06-03T12:00:00Z",
    )
    acquired = acquire_one(candidate, transport=fake_transport)

    with pytest.raises(AcquisitionError, match="missing inspector decision"):
        inspect_candidate(acquired, None)
    assert inspect_candidate(
        acquired,
        InspectorDecision(
            threat_focused=False,
            has_narrative_section=True,
            language="en",
            translation_duplicate=False,
        ),
    ).reason == "not_threat_focused"


def test_inspection_fails_closed_for_language_and_translation_duplicates(
    fake_transport: FakeTransport,
) -> None:
    url = "https://example.test/inspection"
    fake_transport.responses[url] = ((FIXTURES / "article.html").read_bytes(), "text/html")
    acquired = acquire_one(
        Candidate(
            source_id="ncsc-uk",
            source_class="institutional",
            origin_url=url,
            title="Threat report",
            author="Analyst",
            author_basis="feed_author",
            published_at="2025-06-03T12:00:00Z",
        ),
        transport=fake_transport,
    )

    assert inspect_candidate(
        acquired, InspectorDecision(True, True, "other", False)
    ).reason == "unsupported_language"
    assert inspect_candidate(
        acquired, InspectorDecision(True, True, "es", True)
    ).reason == "translation_duplicate"
    with pytest.raises(AcquisitionError, match="language"):
        inspect_candidate(acquired, InspectorDecision(True, True, "", False))


def _feed(source_id: str) -> bytes:
    items = [
        f"""
        <item><title>Earlier excluded {source_id}</title><link>https://{source_id}.test/skip</link>
        <author></author><pubDate>Fri, 01 Aug 2025 12:00:00 +0000</pubDate></item>
        """
    ]
    for number in range(1, 7):
        items.append(
            f"""
            <item><title>{source_id} threat report {number}</title>
            <link>https://{source_id}.test/article-{number}</link>
            <author>{source_id} analyst</author>
            <pubDate>{number:02d} Aug 2025 12:00:00 +0000</pubDate></item>
            """
        )
    return (
        "<?xml version='1.0'?><rss version='2.0'><channel><title>fixture</title>"
        + "".join(items)
        + "</channel></rss>"
    ).encode("utf-8")


def _article(source_id: str, number: int) -> bytes:
    words = " ".join(f"evidence{word}" for word in range(500))
    return (
        f"<html><body><article><h1>{source_id} {number}</h1>"
        f"<h2>Incident narrative</h2><p>{words}</p></article></body></html>"
    ).encode("utf-8")


def _source_registry() -> list[SourceConfig]:
    return [
        _source_config_for("ncsc-uk", "institutional", FROZEN_FEED_URLS["ncsc-uk"]),
        _source_config_for("cert-eu", "institutional", FROZEN_FEED_URLS["cert-eu"]),
        _source_config_for("cert-pl-en", "institutional", FROZEN_FEED_URLS["cert-pl-en"]),
        _source_config_for(
            "acsc-advisories",
            "institutional",
            FROZEN_FEED_URLS["acsc-advisories"],
        ),
        _source_config_for("unit-42", "technical-research", FROZEN_FEED_URLS["unit-42"]),
        _source_config_for(
            "eset-welivesecurity",
            "technical-research",
            FROZEN_FEED_URLS["eset-welivesecurity"],
        ),
        _source_config_for("volexity", "technical-research", FROZEN_FEED_URLS["volexity"]),
    ]


def _selection_transport(
    sources: list[SourceConfig], *, available_ids: set[str] | None = None
) -> FakeTransport:
    available = available_ids or {
        "ncsc-uk",
        "cert-eu",
        "unit-42",
        "eset-welivesecurity",
    }
    responses: dict[str, tuple[bytes, str]] = {}
    for source in sources:
        if source.source_id not in available:
            continue
        responses[source.feed_url] = (_feed(source.source_id), "application/rss+xml")
        responses[f"https://{source.source_id}.test/skip"] = (
            _article(source.source_id, 0),
            "text/html",
        )
        for number in range(1, 7):
            responses[f"https://{source.source_id}.test/article-{number}"] = (
                _article(source.source_id, number),
                "text/html",
            )
    return FakeTransport(responses)


def _approved_decisions(sources: list[SourceConfig]) -> dict[str, InspectorDecision]:
    decisions: dict[str, InspectorDecision] = {}
    for source in sources:
        decisions[f"https://{source.source_id}.test/skip"] = InspectorDecision(
            True, True, "en", False
        )
        for number in range(1, 7):
            decisions[f"https://{source.source_id}.test/article-{number}"] = InspectorDecision(
                True, True, "en", False
            )
    return decisions


def _write_decisions(
    root: Path,
    *,
    overrides: dict[str, InspectorDecision] | None = None,
    omit: set[str] | None = None,
    output_path: Path | None = None,
) -> Path:
    inspection_path = root / "inspection-manifest.v1.json"
    inspection = json.loads(inspection_path.read_text(encoding="utf-8"))
    decisions = []
    for candidate in inspection["candidates"]:
        if "snapshot_original_path" not in candidate or candidate["origin_url"] in (omit or set()):
            continue
        decision = (overrides or {}).get(
            candidate["origin_url"], InspectorDecision(True, True, "en", False)
        )
        decisions.append(
            {
                "origin_url": candidate["origin_url"],
                "original_sha256": candidate["original_sha256"],
                "text_sha256": candidate["text_sha256"],
                "threat_focused": decision.threat_focused,
                "has_narrative_section": decision.has_narrative_section,
                "language": decision.language,
                "translation_duplicate": decision.translation_duplicate,
            }
        )
    path = output_path or root / "inspector-decisions.v1.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "inspection_manifest_digest": sha256_file(inspection_path),
                "decisions": decisions,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_complete_selection_is_closed_offline_and_writes_a_16_document_manifest(
    tmp_path: Path,
) -> None:
    """Wrong source order, role counts, or an external write invalidates the frozen sample."""
    sources = _source_registry()
    transport = _selection_transport(sources)
    output = tmp_path / "evidence"

    inspection_path = inspect_selection(
        POLICY,
        output,
        sources=sources,
        transport=transport,
    )
    requests_after_inspection = tuple(transport.requests)
    inspection = json.loads(inspection_path.read_text(encoding="utf-8"))
    assert inspection_path == output / "inspection-manifest.v1.json"
    assert not (output / "input-manifest.v1.json").exists()
    assert all("inspection" not in candidate for candidate in inspection["candidates"])

    manifest_path = acquire_selection(
        POLICY,
        output,
        decisions_path=_write_decisions(output),
        acquired_at="2026-08-30T13:00:00Z",
    )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    records = manifest["documents"]
    assert manifest_path == output / "input-manifest.v1.json"
    assert manifest["policy_digest"] == "012121b694667565d0f17d29eb7f78801e9d0f379c796f0fe013cbf10cd7440b"
    assert manifest["inspection_manifest_digest"] == sha256_file(inspection_path)
    assert manifest["inspector_decisions_digest"] == sha256_file(
        output / "inspector-decisions.v1.json"
    )
    assert [source["source_id"] for source in manifest["sources"]] == [
        "ncsc-uk",
        "cert-eu",
        "unit-42",
        "eset-welivesecurity",
    ]
    assert manifest["sources"][0] == {
        "feed_url": FROZEN_FEED_URLS["ncsc-uk"],
        "publisher": "NCSC UK",
        "source_class": "institutional",
        "source_id": "ncsc-uk",
        "source_name": "NCSC UK",
    }
    assert len(records) == 16
    assert {record["role"] for record in records} == {"primary"}
    assert records[0]["document_id"] == "ncsc-uk-2025-08-06-a16ffd5771"
    assert records[0]["origin_url"] == "https://ncsc-uk.test/article-6"
    assert records[0]["author"] == "ncsc-uk analyst"
    assert records[0]["author_basis"] == "feed_author"
    candidate_ledger = json.loads(
        (output / "candidate-ledger.v1.json").read_text(encoding="utf-8")
    )
    selected_decision = next(
        candidate
        for candidate in candidate_ledger["candidates"]
        if candidate.get("origin_url") == records[0]["origin_url"]
    )
    assert selected_decision["text_sha256"] == records[0]["text_sha256"]
    assert selected_decision["author"] == "ncsc-uk analyst"
    assert selected_decision["author_basis"] == "feed_author"
    selected_decision = selected_decision["inspection"]
    assert selected_decision == {
        "decision": "eligible",
        "has_narrative_section": True,
        "language": "en",
        "reason": None,
        "section_headings": ["ncsc-uk 6", "Incident narrative"],
        "threat_focused": True,
        "title": "ncsc-uk threat report 6",
        "translation_duplicate": False,
    }
    assert "entities" not in candidate_ledger
    assert "model_output" not in candidate_ledger
    assert not (tmp_path / "inputs").exists()
    assert tuple(transport.requests) == requests_after_inspection
    assert all(path.is_relative_to(output) for path in output.rglob("*"))


def test_selection_fails_closed_without_human_inspector_decisions(tmp_path: Path) -> None:
    """Acquisition without recorded review decisions must not freeze a manifest."""
    sources = _source_registry()

    root = tmp_path / "evidence"
    inspect_selection(POLICY, root, sources=sources, transport=_selection_transport(sources))
    inspection = json.loads((root / "inspection-manifest.v1.json").read_text(encoding="utf-8"))
    omitted = {inspection["candidates"][0]["origin_url"]}

    with pytest.raises(AcquisitionError, match="every inspected candidate"):
        acquire_selection(POLICY, root, decisions_path=_write_decisions(root, omit=omitted))
    assert not (root / "input-manifest.v1.json").exists()


def test_selection_refuses_symlinked_inputs_directory_without_outside_write(tmp_path: Path) -> None:
    """Following an existing inputs symlink would write frozen originals outside the root."""
    sources = _source_registry()
    output = tmp_path / "evidence"
    outside = tmp_path / "outside"
    output.mkdir()
    outside.mkdir()
    (output / "inputs").symlink_to(outside, target_is_directory=True)

    inspect_selection(
        POLICY,
        output,
        sources=sources,
        transport=_selection_transport(sources),
    )
    with pytest.raises(AcquisitionError, match="refusing symlink"):
        acquire_selection(POLICY, output, decisions_path=_write_decisions(output))
    assert list(outside.iterdir()) == []


def test_source_failure_and_exact_duplicate_are_recorded_before_shortfall(
    tmp_path: Path,
) -> None:
    sources = _source_registry()
    transport = _selection_transport(
        sources,
        available_ids={
            "ncsc-uk",
            "cert-eu",
            "cert-pl-en",
            "unit-42",
            "eset-welivesecurity",
        },
    )
    del transport.responses[FROZEN_FEED_URLS["ncsc-uk"]]
    for number in range(1, 5):
        transport.responses[f"https://cert-pl-en.test/article-{number}"] = (
            transport.responses[f"https://cert-eu.test/article-{number}"]
        )
    output = tmp_path / "evidence"

    inspect_selection(
        POLICY,
        output,
        sources=sources,
        transport=transport,
    )
    with pytest.raises(ValueError, match="insufficient eligible sources"):
        acquire_selection(
            POLICY,
            output,
            decisions_path=_write_decisions(output),
            acquired_at="2026-08-30T13:00:00Z",
        )

    ledger = json.loads((output / "candidate-ledger.v1.json").read_text(encoding="utf-8"))
    assert ledger["source_failures"] == [
        {"reason": "inaccessible", "source_id": "ncsc-uk"},
        {"reason": "inaccessible", "source_id": "acsc-advisories"},
        {"reason": "inaccessible", "source_id": "volexity"},
    ]
    assert any(
        candidate.get("reasons") == ["duplicate"]
        for candidate in ledger["candidates"]
    )


def test_source_feed_failure_continues_to_next_frozen_source(tmp_path: Path) -> None:
    sources = _source_registry()
    transport = _selection_transport(
        sources,
        available_ids={
            "ncsc-uk",
            "cert-eu",
            "cert-pl-en",
            "unit-42",
            "eset-welivesecurity",
        },
    )
    del transport.responses[FROZEN_FEED_URLS["ncsc-uk"]]
    output = tmp_path / "evidence"

    inspect_selection(
        POLICY,
        output,
        sources=sources,
        transport=transport,
    )
    manifest_path = acquire_selection(
        POLICY,
        output,
        decisions_path=_write_decisions(output),
        acquired_at="2026-08-30T13:00:00Z",
    )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert [source["source_id"] for source in manifest["sources"]] == [
        "cert-eu", "cert-pl-en", "unit-42", "eset-welivesecurity"
    ]
    candidate_ledger = json.loads(
        (output / "candidate-ledger.v1.json").read_text(encoding="utf-8")
    )
    assert candidate_ledger["source_failures"] == [
        {"reason": "inaccessible", "source_id": "ncsc-uk"},
        {"reason": "inaccessible", "source_id": "acsc-advisories"},
        {"reason": "inaccessible", "source_id": "volexity"},
    ]


def test_selection_takes_four_newest_when_sources_have_more_eligible_documents(
    tmp_path: Path,
) -> None:
    sources = _source_registry()
    transport = _selection_transport(sources)
    decisions = _approved_decisions(sources)
    for source in sources:
        if source.feed_url not in transport.responses:
            continue
        extra_url = f"https://{source.source_id}.test/article-7"
        feed = transport.responses[source.feed_url][0].decode("utf-8").replace(
            "</channel></rss>",
            (
                f"<item><title>{source.source_id} threat report 7</title>"
                f"<link>{extra_url}</link><author>{source.source_id} analyst</author>"
                "<pubDate>07 Aug 2025 12:00:00 +0000</pubDate></item>"
                "</channel></rss>"
            ),
        )
        transport.responses[source.feed_url] = (feed.encode("utf-8"), "application/rss+xml")
        transport.responses[extra_url] = (_article(source.source_id, 7), "text/html")
        decisions[extra_url] = InspectorDecision(True, True, "en", False)

    inspect_selection(
        POLICY,
        tmp_path / "evidence",
        sources=sources,
        transport=transport,
    )
    manifest_path = acquire_selection(
        POLICY,
        tmp_path / "evidence",
        decisions_path=_write_decisions(tmp_path / "evidence", overrides=decisions),
        acquired_at="2026-08-30T13:00:00Z",
    )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert len(manifest["documents"]) == 16
    assert all(
        not record["origin_url"].endswith(("article-1", "article-2", "article-3"))
        for record in manifest["documents"]
    )


def test_acquisition_rejects_changed_inspection_snapshot_without_network_request(
    tmp_path: Path,
) -> None:
    sources = _source_registry()
    transport = _selection_transport(sources)
    root = tmp_path / "evidence"
    inspect_selection(POLICY, root, sources=sources, transport=transport)
    decisions = _write_decisions(root)
    request_count = len(transport.requests)
    snapshot = next((root / "inspection").glob("*/original.html"))
    original = snapshot.read_bytes()
    snapshot.write_bytes(bytes([original[0] ^ 1]) + original[1:])

    with pytest.raises(AcquisitionError, match="inspection snapshot digest mismatch"):
        acquire_selection(POLICY, root, decisions_path=decisions)

    assert len(transport.requests) == request_count
    assert not (root / "input-manifest.v1.json").exists()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("author", "Different Organization"),
        ("author_basis", "guessed"),
    ],
)
def test_acquisition_rejects_invalid_publisher_author_provenance_on_unselected_candidate(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    """Unselected rows must not carry unauditable author provenance into ledgers."""
    sources = _source_registry()
    root = tmp_path / "evidence"
    inspect_selection(POLICY, root, sources=sources, transport=_selection_transport(sources))
    inspection_path = root / "inspection-manifest.v1.json"
    inspection = json.loads(inspection_path.read_text(encoding="utf-8"))
    candidate = next(
        item
        for item in inspection["candidates"]
        if item.get("source_id") == "ncsc-uk"
        and item.get("author_basis") == "source_publisher"
    )
    candidate[field] = replacement
    inspection_path.write_text(json.dumps(inspection), encoding="utf-8")

    with pytest.raises(AcquisitionError, match="author provenance"):
        acquire_selection(
            POLICY,
            root,
            decisions_path=_write_decisions(root),
            acquired_at="2026-08-30T13:00:00Z",
        )

    assert not (root / "candidate-ledger.v1.json").exists()


def test_acquisition_rejects_invalid_author_basis_on_failed_candidate(
    tmp_path: Path,
) -> None:
    sources = _source_registry()
    transport = _selection_transport(sources)
    del transport.responses["https://ncsc-uk.test/article-1"]
    root = tmp_path / "evidence"
    inspect_selection(POLICY, root, sources=sources, transport=transport)
    inspection_path = root / "inspection-manifest.v1.json"
    inspection = json.loads(inspection_path.read_text(encoding="utf-8"))
    failed = next(item for item in inspection["candidates"] if item.get("reason") == "inaccessible")
    failed["author_basis"] = "guessed"
    inspection_path.write_text(json.dumps(inspection), encoding="utf-8")

    with pytest.raises(AcquisitionError, match="author provenance"):
        acquire_selection(
            POLICY,
            root,
            decisions_path=_write_decisions(root),
            acquired_at="2026-08-30T13:00:00Z",
        )


def test_inspection_rejects_a_registry_that_omits_an_earlier_approved_source(
    tmp_path: Path,
) -> None:
    incomplete_registry = _source_registry()[1:]
    transport = _selection_transport(incomplete_registry)

    with pytest.raises(AcquisitionError, match="complete frozen source registry"):
        inspect_selection(
            POLICY,
            tmp_path / "evidence",
            sources=incomplete_registry,
            transport=transport,
        )

    assert transport.requests == []
    assert not (tmp_path / "evidence").exists()


def test_invalid_external_decisions_do_not_poison_a_corrected_retry(
    tmp_path: Path,
) -> None:
    sources = _source_registry()
    transport = _selection_transport(sources)
    root = tmp_path / "evidence"
    inspect_selection(POLICY, root, sources=sources, transport=transport)
    requests_after_inspection = tuple(transport.requests)
    external = _write_decisions(
        root, output_path=tmp_path / "external-decisions.v1.json"
    )
    invalid = json.loads(external.read_text(encoding="utf-8"))
    invalid["decisions"][0]["original_sha256"] = "0" * 64
    external.write_text(json.dumps(invalid), encoding="utf-8")

    with pytest.raises(AcquisitionError, match="binding mismatch"):
        acquire_selection(POLICY, root, decisions_path=external)

    canonical = root / "inspector-decisions.v1.json"
    assert not canonical.exists()
    corrected = _write_decisions(root, output_path=external)
    corrected_bytes = corrected.read_bytes()

    manifest = acquire_selection(
        POLICY,
        root,
        decisions_path=corrected,
        acquired_at="2026-08-30T13:00:00Z",
    )

    assert manifest == root / "input-manifest.v1.json"
    assert canonical.read_bytes() == corrected_bytes
    assert tuple(transport.requests) == requests_after_inspection


class _ReadProbe:
    def __init__(self, handle, sizes: list[int]) -> None:  # type: ignore[no-untyped-def]
        self._handle = handle
        self._sizes = sizes

    def __enter__(self):  # type: ignore[no-untyped-def]
        self._handle.__enter__()
        return self

    def __exit__(self, *args):  # type: ignore[no-untyped-def]
        return self._handle.__exit__(*args)

    def read(self, size: int = -1) -> bytes:
        self._sizes.append(size)
        return self._handle.read(size)

    def __getattr__(self, name: str):  # type: ignore[no-untyped-def]
        return getattr(self._handle, name)


def _probe_decision_reads(
    monkeypatch: pytest.MonkeyPatch,
    decision_path: Path,
    *,
    grow_before_read: bool,
) -> list[int]:
    original_fdopen = acquire_module.os.fdopen
    read_sizes: list[int] = []
    grown = False

    def probed_fdopen(descriptor: int, *args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal grown
        descriptor_path = Path(acquire_module.os.readlink(f"/proc/self/fd/{descriptor}"))
        handle = original_fdopen(descriptor, *args, **kwargs)
        if descriptor_path != decision_path:
            return handle
        if grow_before_read and not grown:
            with decision_path.open("ab") as destination:
                destination.write(b" " * (MAX_JSON_BYTES + 1))
            grown = True
        return _ReadProbe(handle, read_sizes)

    monkeypatch.setattr(acquire_module.os, "fdopen", probed_fdopen)
    return read_sizes


def test_oversized_external_decisions_are_rejected_before_any_file_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources = _source_registry()
    root = tmp_path / "evidence"
    inspect_selection(
        POLICY, root, sources=sources, transport=_selection_transport(sources)
    )
    external = tmp_path / "oversized-decisions.v1.json"
    with external.open("wb") as handle:
        handle.seek(MAX_JSON_BYTES)
        handle.write(b"x")
    read_sizes = _probe_decision_reads(
        monkeypatch, external, grow_before_read=False
    )

    with pytest.raises(AcquisitionError, match="exceeds 20 MiB"):
        acquire_selection(POLICY, root, decisions_path=external)

    assert read_sizes == []
    assert not (root / "inspector-decisions.v1.json").exists()


def test_external_decisions_that_grow_during_read_are_bounded_and_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources = _source_registry()
    root = tmp_path / "evidence"
    inspect_selection(
        POLICY, root, sources=sources, transport=_selection_transport(sources)
    )
    external = _write_decisions(
        root, output_path=tmp_path / "growing-decisions.v1.json"
    )
    read_sizes = _probe_decision_reads(
        monkeypatch, external, grow_before_read=True
    )

    with pytest.raises(AcquisitionError, match="exceeds 20 MiB"):
        acquire_selection(POLICY, root, decisions_path=external)

    assert read_sizes == [MAX_JSON_BYTES + 1]
    assert not (root / "inspector-decisions.v1.json").exists()
