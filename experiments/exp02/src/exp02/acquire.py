"""Read-only, model-blind discovery and freezing of EXP-02 document inputs."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from typing import Literal, Protocol
from urllib.parse import urlsplit
import warnings

from bs4 import BeautifulSoup
import feedparser
import trafilatura
import yaml

# TIM currently imports PyPDF2, whose package-level deprecation warning is not
# actionable for this acquisition module. Keep the filter narrow and install it
# before importing the TIM parser.
warnings.filterwarnings(
    "ignore",
    message=r"PyPDF2 is deprecated\. Please move to the pypdf library instead\.",
    category=DeprecationWarning,
    module=r"PyPDF2",
)
import parser as tim_parser

from .jsonio import (
    MAX_JSON_BYTES,
    _open_existing_file,
    _open_new_file,
    load_json,
    sha256_file,
    write_new_json,
)
from .records import DocumentRecord
from .source_policy import SourcePolicy, assign_roles, select_sources


_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_TIM_SOURCES = _REPOSITORY_ROOT / "services" / "intel-extractor" / "sources.yaml"
_EXCLUSIONS = _REPOSITORY_ROOT / "experiments" / "exp02" / "config" / "exclusions.v1.json"
INSPECTOR_DECISIONS = "inspector-decisions.v1.json"


class AcquisitionError(ValueError):
    """Raised when a candidate cannot be safely acquired or converted."""


class Transport(Protocol):
    """The only network boundary used by this module."""

    def fetch(self, url: str) -> tuple[bytes, str]:
        """Return response bytes and lower-cased media type without redirects."""


@dataclass(frozen=True)
class SourceConfig:
    """One policy source bound to its already configured RSS endpoint."""

    source_id: str
    source_name: str
    source_class: Literal["institutional", "technical-research"]
    feed_url: str
    publisher: str


@dataclass(frozen=True)
class Candidate:
    """Metadata discovered from one RSS entry; never contains TIM output."""

    source_id: str
    source_class: Literal["institutional", "technical-research"]
    origin_url: str
    title: str
    author: str
    author_basis: Literal["feed_author", "source_publisher"]
    published_at: str
    sha256: str = ""

    @property
    def url(self) -> str:
        """Compatibility name for the closed eligibility rule."""
        return self.origin_url


@dataclass(frozen=True)
class Exclusions:
    """Previously processed source URLs and bytes, kept as a closed set."""

    urls: frozenset[str]
    hashes: frozenset[str]
    entries: tuple[dict[str, object], ...]


@dataclass(frozen=True)
class Eligibility:
    eligible: bool
    reasons: tuple[str, ...]
    word_count: int


@dataclass(frozen=True)
class InspectorDecision:
    """A human reviewer decision required before a candidate can be selected."""

    threat_focused: bool
    has_narrative_section: bool
    language: Literal["en", "es", "other"]
    translation_duplicate: bool


@dataclass(frozen=True)
class Inspection:
    """A narrow human-review-ready decision without entities or model output."""

    title: str
    section_headings: tuple[str, ...]
    threat_focused: bool
    has_narrative_section: bool
    language: Literal["en", "es", "other"]
    translation_duplicate: bool
    decision: Literal["eligible", "excluded"]
    reason: str | None


@dataclass(frozen=True)
class AcquiredDocument:
    candidate: Candidate
    original: bytes
    converted_text: str
    media_type: Literal["html", "pdf"]
    headings: tuple[str, ...]


_SOURCE_BINDINGS: dict[
    str,
    tuple[
        str,
        Literal["institutional", "technical-research"],
        str,
        str,
    ],
] = {
    "ncsc-uk": (
        "NCSC UK",
        "institutional",
        "NCSC UK",
        "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
    ),
    "cert-eu": (
        "CERT-EU Threat Intelligence",
        "institutional",
        "CERT-EU Threat Intelligence",
        "https://cert.europa.eu/publications/threat-intelligence-rss",
    ),
    "cert-pl-en": (
        "CERT-PL EN",
        "institutional",
        "CERT-PL EN",
        "https://cert.pl/en/rss.xml",
    ),
    "acsc-advisories": (
        "ACSC Advisories",
        "institutional",
        "ACSC Advisories",
        "https://www.cyber.gov.au/rss/advisories",
    ),
    "unit-42": (
        "Unit 42",
        "technical-research",
        "Unit 42",
        "https://unit42.paloaltonetworks.com/feed/",
    ),
    "eset-welivesecurity": (
        "ESET WeLiveSecurity",
        "technical-research",
        "ESET WeLiveSecurity",
        "https://www.welivesecurity.com/en/rss/feed/",
    ),
    "volexity": (
        "Volexity",
        "technical-research",
        "Volexity",
        "https://www.volexity.com/feed/",
    ),
}


def _validate_source_identity(source: SourceConfig) -> None:
    expected = _SOURCE_BINDINGS.get(source.source_id)
    if expected is None:
        raise AcquisitionError("source identity is not frozen")
    source_name, source_class, publisher, feed_url = expected
    if source.source_name != source_name or source.source_class != source_class:
        raise AcquisitionError("source identity conflicts with frozen registry")
    if not source.publisher or source.publisher != publisher:
        raise AcquisitionError("source publisher conflicts with frozen registry")
    if source.feed_url != feed_url:
        raise AcquisitionError("source feed URL conflicts with frozen registry")


def _validate_candidate_author_provenance(
    candidate: Candidate,
    source: SourceConfig,
) -> None:
    if not candidate.author:
        raise AcquisitionError("candidate author provenance is invalid")
    if candidate.author_basis == "feed_author":
        return
    if (
        candidate.author_basis == "source_publisher"
        and candidate.author == source.publisher
    ):
        return
    raise AcquisitionError("candidate author provenance is invalid")


def configured_sources(path: Path = _TIM_SOURCES) -> list[SourceConfig]:
    """Read the TIM registry without importing or invoking collector code."""
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    source_rows = loaded.get("sources", []) if isinstance(loaded, Mapping) else []
    by_name = {
        row.get("name"): row
        for row in source_rows
        if isinstance(row, Mapping) and isinstance(row.get("name"), str)
    }
    configured: list[SourceConfig] = []
    for source_id, (name, source_class, publisher, feed_url) in _SOURCE_BINDINGS.items():
        row = by_name.get(name)
        if not isinstance(row, Mapping) or row.get("type") != "rss":
            raise AcquisitionError(f"configured RSS source missing: {name}")
        url = row.get("url")
        if not isinstance(url, str):
            raise AcquisitionError(f"configured RSS URL missing: {name}")
        source = SourceConfig(source_id, name, source_class, url, publisher)
        _validate_source_identity(source)
        configured.append(source)
    return configured


def _fetch(transport: Transport | None, url: str) -> tuple[bytes, str]:
    try:
        response = tim_parser.fetch(url) if transport is None else transport.fetch(url)
    except Exception as error:
        raise AcquisitionError("fetch failed") from error
    if (
        not isinstance(response, tuple)
        or len(response) != 2
        or not isinstance(response[0], bytes)
        or not isinstance(response[1], str)
    ):
        raise AcquisitionError("invalid fetch response")
    return response


def _utc_from_entry(entry: Mapping[str, object]) -> str:
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if not isinstance(parsed, tuple) or len(parsed) < 6:
        return ""
    try:
        value = datetime(*parsed[:6], tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return ""
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def discover_candidates(source: SourceConfig, transport: Transport | None = None) -> list[Candidate]:
    """Parse one RSS response into deduplicated immutable candidates, newest first."""
    _validate_source_identity(source)
    feed_bytes, _content_type = _fetch(transport, source.feed_url)
    try:
        feed = feedparser.parse(feed_bytes)
    except Exception as error:
        raise AcquisitionError("source feed parse failed") from error
    candidates: list[Candidate] = []
    seen_urls: set[str] = set()
    for raw_entry in feed.entries:
        entry = dict(raw_entry)
        url = str(entry.get("link") or "").strip()
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        feed_author = str(entry.get("author") or "").strip()
        candidate = Candidate(
            source_id=source.source_id,
            source_class=source.source_class,
            origin_url=url,
            title=str(entry.get("title") or "").strip(),
            author=feed_author or source.publisher,
            author_basis="feed_author" if feed_author else "source_publisher",
            published_at=_utc_from_entry(entry),
        )
        _validate_candidate_author_provenance(candidate, source)
        candidates.append(candidate)
    return sorted(candidates, key=lambda candidate: candidate.published_at, reverse=True)


def _require_public_https(url: str) -> None:
    parsed = urlsplit(url)
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise AcquisitionError("HTTPS public origin required")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if not address.is_global:
        raise AcquisitionError("HTTPS public origin required")


def _html_headings(data: bytes) -> tuple[str, ...]:
    soup = BeautifulSoup(data.decode("utf-8", errors="replace"), "html.parser")
    return tuple(
        heading.get_text(" ", strip=True)
        for heading in soup.find_all(re.compile(r"^h[1-6]$"))
        if heading.get_text(" ", strip=True)
    )


def _extract_html_text(data: bytes) -> str:
    """Mirror TIM's ``extract_url_text`` extraction after this module's single fetch."""
    html = data.decode("utf-8", errors="replace")
    result = trafilatura.extract(html)
    if result:
        return result[: tim_parser.MAX_TEXT_CHARS]
    soup = BeautifulSoup(html, "html.parser")
    return soup.get_text(separator="\n", strip=True)[: tim_parser.MAX_TEXT_CHARS]


def acquire_one(
    candidate: Candidate, output_root: Path | str | None = None, transport: Transport | None = None
) -> AcquiredDocument:
    """Fetch exactly once through TIM transport and convert without model execution.

    ``output_root`` is accepted for the command-level acquisition interface; material
    is deliberately deferred until the document is selected as eligible.
    """
    del output_root
    _require_public_https(candidate.origin_url)
    try:
        original, content_type = _fetch(transport, candidate.origin_url)
        # Omit the URL on purpose: TIM's helper otherwise uses a `.pdf` suffix as
        # a last-resort hint, while EXP-02 accepts only a PDF media type or magic.
        if tim_parser.looks_like_pdf(content_type, original):
            converted = tim_parser.extract_pdf_text(original)
            media_type: Literal["html", "pdf"] = "pdf"
            headings: tuple[str, ...] = ()
        else:
            converted = _extract_html_text(original)
            media_type = "html"
            headings = _html_headings(original)
    except Exception as error:
        if isinstance(error, AcquisitionError):
            raise
        raise AcquisitionError("candidate fetch or parse failed") from error
    if not converted.strip():
        raise AcquisitionError("unreadable converted text")
    return AcquiredDocument(
        candidate=replace(candidate, sha256=hashlib.sha256(original).hexdigest()),
        original=original,
        converted_text=converted,
        media_type=media_type,
        headings=headings,
    )


def load_exclusions(path: Path = _EXCLUSIONS) -> Exclusions:
    """Load only URL and digest exclusion keys; unknown entry fields remain inert evidence."""
    loaded = load_json(path)
    entries = loaded.get("entries", [])
    if not isinstance(entries, list):
        raise AcquisitionError("exclusion ledger entries must be a list")
    normalized = tuple(dict(item) for item in entries if isinstance(item, Mapping))
    return Exclusions(
        urls=frozenset(
            str(item["source_url"]) for item in normalized if isinstance(item.get("source_url"), str)
        ),
        hashes=frozenset(
            str(item["sha256"]) for item in normalized if isinstance(item.get("sha256"), str)
        ),
        entries=normalized,
    )


def evaluate_candidate(
    candidate: Candidate, converted_text: str, exclusions: Exclusions, policy: SourcePolicy
) -> Eligibility:
    """Apply deterministic, closed eligibility rules before any material is frozen."""
    reasons: list[str] = []
    words = len(converted_text.split())
    if words < policy.min_words or words > policy.max_words:
        reasons.append("out_of_length_range")
    if candidate.url in exclusions.urls or candidate.sha256 in exclusions.hashes:
        reasons.append("previously_processed")
    if not candidate.author or not candidate.published_at:
        reasons.append("missing_author_or_date")
    return Eligibility(eligible=not reasons, reasons=tuple(reasons), word_count=words)


def inspect_candidate(
    acquired: AcquiredDocument, decision: InspectorDecision | None
) -> Inspection:
    """Record a supplied human threat/narrative decision without model output."""
    if decision is None:
        raise AcquisitionError(
            f"missing inspector decision for {acquired.candidate.origin_url}"
        )
    if not isinstance(decision, InspectorDecision):
        raise AcquisitionError("inspector decision must contain closed human decisions")
    if (
        type(decision.threat_focused) is not bool
        or type(decision.has_narrative_section) is not bool
        or type(decision.translation_duplicate) is not bool
    ):
        raise AcquisitionError("inspector decision must contain boolean human decisions")
    if decision.language not in {"en", "es", "other"}:
        raise AcquisitionError("inspector decision language must be en, es, or other")
    title = acquired.candidate.title
    prefix = (
        title,
        acquired.headings,
        decision.threat_focused,
        decision.has_narrative_section,
        decision.language,
        decision.translation_duplicate,
    )
    if decision.language == "other":
        return Inspection(*prefix, "excluded", "unsupported_language")
    if decision.translation_duplicate:
        return Inspection(*prefix, "excluded", "translation_duplicate")
    if not decision.threat_focused:
        return Inspection(*prefix, "excluded", "not_threat_focused")
    if not decision.has_narrative_section:
        return Inspection(*prefix, "excluded", "no_narrative_section")
    return Inspection(*prefix, "eligible", None)


def _document_id(candidate: Candidate) -> str:
    date = candidate.published_at[:10]
    url_digest = hashlib.sha256(candidate.origin_url.encode("utf-8")).hexdigest()[:10]
    return f"{candidate.source_id}-{date}-{url_digest}"


def _record_for(acquired: AcquiredDocument, word_count: int) -> DocumentRecord:
    document_id = _document_id(acquired.candidate)
    relative = f"experiments/exp02/evidence/inputs/{document_id}"
    return DocumentRecord.from_dict(
        {
            "document_id": document_id,
            "source_id": acquired.candidate.source_id,
            "source_class": acquired.candidate.source_class,
            "role": "primary",
            "title": acquired.candidate.title,
            "author": acquired.candidate.author,
            "author_basis": acquired.candidate.author_basis,
            "published_at": acquired.candidate.published_at,
            "origin_url": acquired.candidate.origin_url,
            "original_path": f"{relative}/original.{acquired.media_type}",
            "text_path": f"{relative}/converted.txt",
            "media_type": acquired.media_type,
            "word_count": word_count,
            "original_sha256": acquired.candidate.sha256,
            "text_sha256": hashlib.sha256(acquired.converted_text.encode("utf-8")).hexdigest(),
            "acquired_at": "1970-01-01T00:00:00Z",
        }
    )


def _write_new_bytes(path: Path, data: bytes) -> None:
    file_descriptor = _open_new_file(path)
    with os.fdopen(file_descriptor, "xb") as handle:
        handle.write(data)


def _materialize_snapshot(
    output_root: Path,
    record: DocumentRecord,
    original: bytes,
    converted_text: bytes,
) -> None:
    root = output_root / "inputs" / record.document_id
    try:
        _write_new_bytes(root / f"original.{record.media_type}", original)
        _write_new_bytes(root / "converted.txt", converted_text)
    except ValueError as error:
        raise AcquisitionError(str(error)) from error


def _read_regular_bytes(path: Path) -> bytes:
    try:
        descriptor = _open_existing_file(path)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise AcquisitionError("inspection snapshot must be a regular file")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            return handle.read()
    except AcquisitionError:
        raise
    except (OSError, ValueError) as error:
        raise AcquisitionError("inspection snapshot is unavailable") from error
    finally:
        if "descriptor" in locals() and descriptor != -1:
            os.close(descriptor)


def _entry_payload(
    candidate: Candidate,
    text_sha256: str,
    eligibility: Eligibility,
    inspection: Inspection,
) -> dict[str, object]:
    return {
        "source_id": candidate.source_id,
        "source_class": candidate.source_class,
        "origin_url": candidate.origin_url,
        "title": candidate.title,
        "author": candidate.author,
        "author_basis": candidate.author_basis,
        "published_at": candidate.published_at,
        "original_sha256": candidate.sha256,
        "text_sha256": text_sha256,
        "eligibility": asdict(eligibility),
        "inspection": asdict(inspection),
    }


def _validated_source_configs(
    policy: SourcePolicy,
    sources: Iterable[SourceConfig] | None,
) -> list[SourceConfig]:
    supplied = list(sources) if sources is not None else configured_sources()
    frozen_order = list(
        policy.institutional_order + policy.technical_research_order
    )
    if [source.source_id for source in supplied] != frozen_order:
        raise AcquisitionError(
            "inspection requires the complete frozen source registry in policy order"
        )
    for source in supplied:
        _validate_source_identity(source)
        expected_class = (
            "institutional"
            if source.source_id in policy.institutional_order
            else "technical-research"
        )
        if source.source_class != expected_class:
            raise AcquisitionError("acquisition source class conflicts with frozen policy")
        _require_public_https(source.feed_url)
    return supplied


def _mechanical_checks(eligibility: Eligibility) -> dict[str, bool]:
    reasons = set(eligibility.reasons)
    return {
        "length_in_range": "out_of_length_range" not in reasons,
        "not_previously_processed": "previously_processed" not in reasons,
        "author_and_date_present": "missing_author_or_date" not in reasons,
        "readable": True,
    }


def inspect_selection(
    policy_path: Path | str,
    output_root: Path | str,
    *,
    sources: Iterable[SourceConfig] | None = None,
    transport: Transport | None = None,
    exclusions_path: Path | str = _EXCLUSIONS,
) -> Path:
    """Snapshot and mechanically inspect candidates without human decisions.

    Every successful fetch is converted once and written beneath ``inspection``.
    The exclusive manifest binds the exact original bytes and UTF-8 text that a
    later, network-free acquisition may promote.
    """
    policy_file = Path(policy_path)
    exclusions_file = Path(exclusions_path)
    root = Path(output_root)
    policy = SourcePolicy.load(policy_file)
    exclusions = load_exclusions(exclusions_file)
    selected_configs = _validated_source_configs(policy, sources)
    source_failures: list[dict[str, str]] = []
    candidates: list[dict[str, object]] = []
    seen_document_ids: set[str] = set()
    for source in selected_configs:
        try:
            discovered = discover_candidates(source, transport)
        except AcquisitionError:
            source_failures.append(
                {"source_id": source.source_id, "reason": "inaccessible"}
            )
            continue
        if not discovered:
            source_failures.append(
                {"source_id": source.source_id, "reason": "inaccessible"}
            )
            continue
        for candidate in discovered:
            try:
                acquired = acquire_one(candidate, transport=transport)
            except AcquisitionError as error:
                candidates.append(
                    {
                        "source_id": candidate.source_id,
                        "source_class": candidate.source_class,
                        "origin_url": candidate.origin_url,
                        "title": candidate.title,
                        "author": candidate.author,
                        "author_basis": candidate.author_basis,
                        "published_at": candidate.published_at,
                        "reason": "inaccessible",
                        "error": str(error),
                    }
                )
                continue
            document_id = _document_id(acquired.candidate)
            if document_id in seen_document_ids:
                raise AcquisitionError("inspection contains duplicate document IDs")
            seen_document_ids.add(document_id)
            eligibility = evaluate_candidate(
                acquired.candidate, acquired.converted_text, exclusions, policy
            )
            relative = Path("inspection") / document_id
            original_relative = relative / f"original.{acquired.media_type}"
            text_relative = relative / "converted.txt"
            try:
                _write_new_bytes(root / original_relative, acquired.original)
                _write_new_bytes(
                    root / text_relative, acquired.converted_text.encode("utf-8")
                )
            except (OSError, ValueError) as error:
                raise AcquisitionError(str(error)) from error
            candidates.append(
                {
                    "document_id": document_id,
                    "source_id": acquired.candidate.source_id,
                    "source_class": acquired.candidate.source_class,
                    "origin_url": acquired.candidate.origin_url,
                    "title": acquired.candidate.title,
                    "author": acquired.candidate.author,
                    "author_basis": acquired.candidate.author_basis,
                    "published_at": acquired.candidate.published_at,
                    "media_type": acquired.media_type,
                    "word_count": eligibility.word_count,
                    "original_sha256": acquired.candidate.sha256,
                    "text_sha256": hashlib.sha256(
                        acquired.converted_text.encode("utf-8")
                    ).hexdigest(),
                    "section_headings": list(acquired.headings),
                    "snapshot_original_path": original_relative.as_posix(),
                    "snapshot_text_path": text_relative.as_posix(),
                    "mechanical_checks": _mechanical_checks(eligibility),
                    "mechanical_reasons": list(eligibility.reasons),
                }
            )
    manifest_path = root / "inspection-manifest.v1.json"
    write_new_json(
        manifest_path,
        {
            "schema_version": 1,
            "policy_digest": sha256_file(policy_file),
            "exclusions_digest": sha256_file(exclusions_file),
            "sources": [asdict(source) for source in selected_configs],
            "source_failures": source_failures,
            "candidates": candidates,
        },
    )
    return manifest_path


_SNAPSHOT_CANDIDATE_FIELDS = {
    "document_id",
    "source_id",
    "source_class",
    "origin_url",
    "title",
    "author",
    "author_basis",
    "published_at",
    "media_type",
    "word_count",
    "original_sha256",
    "text_sha256",
    "section_headings",
    "snapshot_original_path",
    "snapshot_text_path",
    "mechanical_checks",
    "mechanical_reasons",
}
_FAILED_CANDIDATE_FIELDS = {
    "source_id",
    "source_class",
    "origin_url",
    "title",
    "author",
    "author_basis",
    "published_at",
    "reason",
    "error",
}
_DECISION_FIELDS = {
    "origin_url",
    "original_sha256",
    "text_sha256",
    "threat_focused",
    "has_narrative_section",
    "language",
    "translation_duplicate",
}


def _inspection_sources(value: object, policy: SourcePolicy) -> list[SourceConfig]:
    if not isinstance(value, list):
        raise AcquisitionError("inspection manifest is invalid")
    try:
        sources = [SourceConfig(**dict(item)) for item in value]
    except (TypeError, ValueError):
        raise AcquisitionError("inspection manifest is invalid") from None
    if any(
        not isinstance(item, Mapping)
        or set(item)
        != {"source_id", "source_name", "source_class", "feed_url", "publisher"}
        or any(
            not isinstance(item.get(field), str)
            for field in (
                "source_id",
                "source_name",
                "source_class",
                "feed_url",
                "publisher",
            )
        )
        for item in value
    ):
        raise AcquisitionError("inspection manifest is invalid")
    return _validated_source_configs(policy, sources)


def _decision_map_value(
    value: Mapping[str, object],
    inspection_digest: str,
    candidates: list[Mapping[str, object]],
) -> dict[str, InspectorDecision]:
    if (
        set(value) != {"schema_version", "inspection_manifest_digest", "decisions"}
        or value.get("schema_version") != 1
        or value.get("inspection_manifest_digest") != inspection_digest
        or not isinstance(value.get("decisions"), list)
    ):
        raise AcquisitionError("inspection decisions are invalid")
    expected = [
        candidate
        for candidate in candidates
        if set(candidate) == _SNAPSHOT_CANDIDATE_FIELDS
    ]
    supplied = value["decisions"]
    if len(supplied) != len(expected):
        raise AcquisitionError("decisions must bind every inspected candidate")
    result: dict[str, InspectorDecision] = {}
    for candidate, raw in zip(expected, supplied):
        if not isinstance(raw, Mapping) or set(raw) != _DECISION_FIELDS:
            raise AcquisitionError("inspection decisions are invalid")
        url = raw.get("origin_url")
        if (
            not isinstance(url, str)
            or url in result
            or url != candidate.get("origin_url")
            or raw.get("original_sha256") != candidate.get("original_sha256")
            or raw.get("text_sha256") != candidate.get("text_sha256")
        ):
            raise AcquisitionError("inspection decision URL/digest binding mismatch")
        decision = InspectorDecision(
            raw.get("threat_focused"),  # type: ignore[arg-type]
            raw.get("has_narrative_section"),  # type: ignore[arg-type]
            raw.get("language"),  # type: ignore[arg-type]
            raw.get("translation_duplicate"),  # type: ignore[arg-type]
        )
        if (
            type(decision.threat_focused) is not bool
            or type(decision.has_narrative_section) is not bool
            or decision.language not in {"en", "es", "other"}
            or type(decision.translation_duplicate) is not bool
        ):
            raise AcquisitionError("inspection decisions are invalid")
        result[url] = decision
    return result


def _decision_map(
    decisions_path: Path | str,
    inspection_digest: str,
    candidates: list[Mapping[str, object]],
) -> dict[str, InspectorDecision]:
    return _decision_map_value(
        load_json(decisions_path), inspection_digest, candidates
    )


def _load_decision_snapshot(data: bytes) -> dict[str, object]:
    if len(data) > MAX_JSON_BYTES:
        raise AcquisitionError("inspection decisions are invalid")

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise AcquisitionError("inspection decisions are invalid")
            result[key] = value
        return result

    def reject_non_finite(_value: str) -> None:
        raise AcquisitionError("inspection decisions are invalid")

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_non_finite,
        )
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise AcquisitionError("inspection decisions are invalid") from None
    if not isinstance(value, dict):
        raise AcquisitionError("inspection decisions are invalid")
    return value


def _read_bounded_decision_snapshot(path: Path) -> bytes:
    """Read one regular no-follow file without allocating beyond the JSON cap."""
    try:
        descriptor = _open_existing_file(path)
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode):
            raise AcquisitionError("inspection decisions must be a regular file")
        if status.st_size > MAX_JSON_BYTES:
            raise AcquisitionError("inspection decisions file exceeds 20 MiB")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            snapshot = handle.read(MAX_JSON_BYTES + 1)
            final_size = os.fstat(handle.fileno()).st_size
        if len(snapshot) > MAX_JSON_BYTES or final_size > MAX_JSON_BYTES:
            raise AcquisitionError("inspection decisions file exceeds 20 MiB")
        return snapshot
    except AcquisitionError:
        raise
    except (OSError, ValueError) as error:
        raise AcquisitionError("inspection decisions are unavailable") from error
    finally:
        if "descriptor" in locals() and descriptor != -1:
            os.close(descriptor)


def _freeze_inspector_decisions(
    output_root: Path,
    decisions_path: Path | str,
    inspection_digest: str,
    candidates: list[Mapping[str, object]],
) -> tuple[Path, str, dict[str, InspectorDecision]]:
    """Validate one exact decision snapshot before retaining those same bytes."""
    supplied = Path(decisions_path)
    frozen = output_root / INSPECTOR_DECISIONS
    decision_bytes = _read_bounded_decision_snapshot(supplied)
    decisions = _decision_map_value(
        _load_decision_snapshot(decision_bytes), inspection_digest, candidates
    )
    decision_digest = hashlib.sha256(decision_bytes).hexdigest()
    supplied_absolute = Path(os.path.abspath(os.path.normpath(os.fspath(supplied))))
    frozen_absolute = Path(os.path.abspath(os.path.normpath(os.fspath(frozen))))
    if supplied_absolute != frozen_absolute:
        try:
            _write_new_bytes(frozen, decision_bytes)
        except (OSError, ValueError) as error:
            raise AcquisitionError(str(error)) from error
    if sha256_file(frozen) != decision_digest:
        raise AcquisitionError("inspector decisions changed while being frozen")
    return frozen, decision_digest, decisions


def acquire_selection(
    policy_path: Path | str,
    output_root: Path | str,
    *,
    decisions_path: Path | str,
    exclusions_path: Path | str = _EXCLUSIONS,
    acquired_at: str | None = None,
) -> Path:
    """Promote a fixed 16-document collection without another network request."""
    policy_file = Path(policy_path)
    root = Path(output_root)
    policy = SourcePolicy.load(policy_file)
    exclusions_file = Path(exclusions_path)
    exclusions = load_exclusions(exclusions_file)
    inspection_path = root / "inspection-manifest.v1.json"
    inspection_digest = sha256_file(inspection_path)
    inspection_manifest = load_json(inspection_path)
    if (
        set(inspection_manifest)
        != {
            "schema_version",
            "policy_digest",
            "exclusions_digest",
            "sources",
            "source_failures",
            "candidates",
        }
        or inspection_manifest.get("schema_version") != 1
        or inspection_manifest.get("policy_digest") != sha256_file(policy_file)
        or inspection_manifest.get("exclusions_digest") != sha256_file(exclusions_file)
        or not isinstance(inspection_manifest.get("source_failures"), list)
        or not isinstance(inspection_manifest.get("candidates"), list)
    ):
        raise AcquisitionError("inspection manifest is invalid")
    selected_configs = _inspection_sources(inspection_manifest["sources"], policy)
    source_ids = {source.source_id for source in selected_configs}
    if any(
        not isinstance(failure, Mapping)
        or set(failure) != {"source_id", "reason"}
        or failure.get("source_id") not in source_ids
        or failure.get("reason") != "inaccessible"
        for failure in inspection_manifest["source_failures"]
    ):
        raise AcquisitionError("inspection manifest is invalid")
    raw_candidates = inspection_manifest["candidates"]
    if any(not isinstance(candidate, Mapping) for candidate in raw_candidates):
        raise AcquisitionError("inspection manifest is invalid")
    candidate_rows = [dict(candidate) for candidate in raw_candidates]
    (
        _frozen_decisions_path,
        inspector_decisions_digest,
        decisions,
    ) = _freeze_inspector_decisions(
        root, decisions_path, inspection_digest, candidate_rows
    )
    by_source = {source.source_id: source for source in selected_configs}
    acquisition_time = acquired_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    snapshots_by_id: dict[str, tuple[bytes, bytes]] = {}
    inventories: dict[str, list[DocumentRecord]] = {}
    candidate_payloads: list[dict[str, object]] = []
    excluded_payloads: list[dict[str, object]] = []
    seen_content_hashes: set[str] = set()
    for source in selected_configs:
        inventories[source.source_id] = []
    for raw in candidate_rows:
        if set(raw) == _FAILED_CANDIDATE_FIELDS:
            if (
                raw.get("reason") != "inaccessible"
                or raw.get("source_id") not in source_ids
                or raw.get("source_class")
                not in {"institutional", "technical-research"}
                or any(
                    not isinstance(raw.get(field), str)
                    for field in (
                        "source_id",
                        "origin_url",
                        "title",
                        "author",
                        "published_at",
                        "error",
                    )
                )
            ):
                raise AcquisitionError("inspection manifest is invalid")
            failed_candidate = Candidate(
                source_id=raw["source_id"],
                source_class=raw["source_class"],  # type: ignore[arg-type]
                origin_url=raw["origin_url"],
                title=raw["title"],
                author=raw["author"],
                author_basis=raw["author_basis"],  # type: ignore[arg-type]
                published_at=raw["published_at"],
            )
            _validate_candidate_author_provenance(
                failed_candidate, by_source[failed_candidate.source_id]
            )
            payload = {
                "source_id": raw["source_id"],
                "origin_url": raw["origin_url"],
                "title": raw["title"],
                "author": raw["author"],
                "author_basis": raw["author_basis"],
                "reason": "inaccessible",
                "error": raw["error"],
            }
            candidate_payloads.append(payload)
            excluded_payloads.append(payload)
            continue
        if set(raw) != _SNAPSHOT_CANDIDATE_FIELDS:
            raise AcquisitionError("inspection manifest is invalid")
        try:
            text_fields = (
                "document_id",
                "source_id",
                "origin_url",
                "title",
                "author",
                "author_basis",
                "published_at",
                "original_sha256",
                "text_sha256",
                "snapshot_original_path",
                "snapshot_text_path",
            )
            checks = raw["mechanical_checks"]
            reasons = raw["mechanical_reasons"]
            if (
                any(not isinstance(raw[field], str) for field in text_fields)
                or raw["source_id"] not in source_ids
                or raw["source_class"]
                not in {"institutional", "technical-research"}
                or isinstance(raw["word_count"], bool)
                or not isinstance(raw["word_count"], int)
                or not isinstance(checks, Mapping)
                or set(checks)
                != {
                    "length_in_range",
                    "not_previously_processed",
                    "author_and_date_present",
                    "readable",
                }
                or any(type(value) is not bool for value in checks.values())
                or not isinstance(reasons, list)
                or any(not isinstance(reason, str) for reason in reasons)
            ):
                raise AcquisitionError("inspection manifest is invalid")
            candidate = Candidate(
                source_id=raw["source_id"],
                source_class=raw["source_class"],  # type: ignore[arg-type]
                origin_url=raw["origin_url"],
                title=raw["title"],
                author=raw["author"],
                author_basis=raw["author_basis"],  # type: ignore[arg-type]
                published_at=raw["published_at"],
                sha256=raw["original_sha256"],
            )
            if candidate.source_class != by_source[candidate.source_id].source_class:
                raise AcquisitionError("inspection manifest is invalid")
            _validate_candidate_author_provenance(
                candidate, by_source[candidate.source_id]
            )
            document_id = _document_id(candidate)
            if document_id != raw["document_id"]:
                raise AcquisitionError("inspection manifest is invalid")
            media_type = raw["media_type"]
            if media_type not in {"html", "pdf"}:
                raise AcquisitionError("inspection manifest is invalid")
            expected_original = f"inspection/{document_id}/original.{media_type}"
            expected_text = f"inspection/{document_id}/converted.txt"
            if (
                raw["snapshot_original_path"] != expected_original
                or raw["snapshot_text_path"] != expected_text
            ):
                raise AcquisitionError("inspection manifest is invalid")
            original = _read_regular_bytes(root / expected_original)
            text_bytes = _read_regular_bytes(root / expected_text)
            if (
                hashlib.sha256(original).hexdigest() != raw["original_sha256"]
                or hashlib.sha256(text_bytes).hexdigest() != raw["text_sha256"]
            ):
                raise AcquisitionError("inspection snapshot digest mismatch")
            converted_text = text_bytes.decode("utf-8")
            headings = raw["section_headings"]
            if not isinstance(headings, list) or any(
                not isinstance(value, str) for value in headings
            ):
                raise AcquisitionError("inspection manifest is invalid")
            acquired = AcquiredDocument(
                candidate=candidate,
                original=original,
                converted_text=converted_text,
                media_type=media_type,
                headings=tuple(headings),
            )
            eligibility = evaluate_candidate(acquired.candidate, acquired.converted_text, exclusions, policy)
            if (
                raw["word_count"] != eligibility.word_count
                or raw["mechanical_checks"] != _mechanical_checks(eligibility)
                or raw["mechanical_reasons"] != list(eligibility.reasons)
            ):
                raise AcquisitionError("inspection mechanical checks mismatch")
            human_inspection = inspect_candidate(
                acquired, decisions[acquired.candidate.origin_url]
            )
            duplicate_reason = (
                ("duplicate",)
                if acquired.candidate.sha256 in seen_content_hashes
                else ()
            )
            seen_content_hashes.add(acquired.candidate.sha256)
            reasons = eligibility.reasons + duplicate_reason + (
                () if human_inspection.reason is None else (human_inspection.reason,)
            )
            payload = _entry_payload(
                acquired.candidate,
                raw["text_sha256"],
                eligibility,
                human_inspection,
            )
            if reasons:
                payload = {**payload, "reasons": list(reasons)}
            candidate_payloads.append(payload)
            if reasons:
                excluded_payloads.append(payload)
                continue
            record = _record_for(acquired, eligibility.word_count)
            snapshots_by_id[record.document_id] = (original, text_bytes)
            if record.source_id not in inventories:
                raise AcquisitionError("inspection manifest is invalid")
            inventories[record.source_id].append(record)
        except (KeyError, TypeError, UnicodeDecodeError) as error:
            raise AcquisitionError("inspection manifest is invalid") from error

    candidate_digest = write_new_json(
        root / "candidate-ledger.v1.json",
        {
            "schema_version": 1,
            "source_failures": inspection_manifest["source_failures"],
            "candidates": candidate_payloads,
        },
    )
    exclusion_digest = write_new_json(
        root / "exclusion-ledger.v1.json",
        {
            "schema_version": 1,
            "configured_exclusions": list(exclusions.entries),
            "excluded_candidates": excluded_payloads,
        },
    )

    chosen_source_ids = select_sources(policy, inventories)
    records: list[DocumentRecord] = []
    for source_id in chosen_source_ids:
        newest_four = inventories[source_id][: policy.documents_per_source]
        for selected in assign_roles(newest_four):
            record = replace(selected.entry, role=selected.role, acquired_at=acquisition_time)
            original, converted_text = snapshots_by_id[record.document_id]
            _materialize_snapshot(root, record, original, converted_text)
            records.append(record)

    manifest_path = root / "input-manifest.v1.json"
    write_new_json(
        manifest_path,
        {
            "schema_version": 1,
            "policy_digest": sha256_file(policy_file),
            "inspection_manifest_digest": inspection_digest,
            "inspector_decisions_digest": inspector_decisions_digest,
            "candidate_ledger_digest": candidate_digest,
            "exclusion_ledger_digest": exclusion_digest,
            "sources": [asdict(by_source[source_id]) for source_id in chosen_source_ids],
            "documents": [asdict(record) for record in records],
        },
    )
    return manifest_path
