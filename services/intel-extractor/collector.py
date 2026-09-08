"""
collector.py — RSS feed polling loop for intel-extractor.

Polls CISA, NCSC UK, and CERT-EU RSS feeds, discovers new document URLs,
fetches PDFs inline, dispatches new docs through run_extraction(), and persists
processed URLs to /data/collector_state.json (DOC-03).

D-01: poll immediately on startup, then every 3600s (each source checks its own interval).
D-02: per-source interval check via last_polled timestamp in collector_state.json.
D-03: bozo feed and per-entry errors are WARNING-logged, never crash the loop.
D-06: PDF URLs fetched inline; HTML/other URLs dispatched as mode="url".
D-07: non-rss source types skipped with a WARNING log.
T-09-03: only yaml.safe_load is used — never the unsafe yaml.load variant.
ROB-01: all fetches route through transport (plain → curl_cffi escalation on 403);
        the winning tier per host persists in collector_state.json["host_tier"].
ROB-02: feed fetches are conditional GETs (If-None-Match/If-Modified-Since from
        per-source etag/last_modified in state); a 304 is a success path — stamp
        last_polled, return no work, never touch the error counter.
ROB-03: HTML landing pages are scanned for a linked PDF (bounded, one primary
        doc per entry); confirmed PDFs are ingested and their URL deduped into
        processed_urls so they are never re-ingested on later polls.
ROB-04: csaf_github source type lists recent CSAF advisory JSONs from a GitHub
        repo path (contents API) and dispatches each once as mode='url', capped
        per poll. KEV stays with the native connector-cisa-kev — never here.
ROB-05: validate_sources() sweeps every configured source per type (reachable +
        parseable + error), exposed off-loop via GET /collector/validate so a
        dead URL is caught at config time, not by silent zero-ingest.
"""
import argparse
import asyncio
import hashlib
import importlib
import json
import logging
import os
import re
import sys
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit

import feedparser
import yaml
from bs4 import BeautifulSoup

from parser import looks_like_pdf
from transport import fetch, fetch_conditional

logger = logging.getLogger(__name__)

STATE_PATH = Path(os.environ.get("STATE_PATH", "/data/collector_state.json"))
DB_PATH = Path(os.environ.get("DB_PATH", "/data/stats.db"))
SOURCES_PATH = Path(__file__).parent / "sources.yaml"

# In-memory runtime state — reset on restart; disk state is authoritative for dedup
_collector_state: dict = {
    "sources_meta": {},  # name -> {new_found: int, errors: int}
    "last_run": None,
}

# Keeps strong references to extraction tasks so the GC can't collect them mid-flight
_background_tasks: set = set()

# html_collection keys are reserved only while extraction is outstanding. Disk
# persistence happens after the extractor reports a completed Report.
_html_collection_inflight: set[str] = set()
_state_write_lock = threading.RLock()

# Canary instrumentation. _save_state is the collector's only state writer, so
# counting calls while a canary is active proves the discovery path stayed read-only.
_canary_active = False
_canary_write_attempts = 0


@dataclass(frozen=True)
class PendingDocument:
    """One document ready for extraction, including acknowledgement metadata."""

    mode: str
    content: bytes | None
    url: str | None
    source_type: str | None
    source_name: str | None = None
    landing_dedup_key: str | None = None
    document_dedup_key: str | None = None
    title: str | None = None
    publication_date: str | None = None
    title_source: str | None = None
    publication_date_source: str | None = None
    dispatch_pipeline: str | None = None
    source_config: dict | None = None


@dataclass
class CollectionDiscovery:
    """Measured result of one bounded collection traversal."""

    documents: list[PendingDocument] = field(default_factory=list)
    collection_fetches: int = 0
    collection_candidates: int = 0
    limited_candidates: int = 0
    landing_fetches: int = 0
    document_fetches: int = 0
    known: int = 0
    new: int = 0
    selected: int = 0
    errors: list[str] = field(default_factory=list)


class CollectionConfigError(ValueError):
    """Invalid html_collection recipe, annotated with fetch progress."""

    def __init__(self, message: str, *, collection_fetched: bool = False):
        super().__init__(message)
        self.collection_fetched = collection_fetched


# ── Synchronous helpers (called from within asyncio.to_thread) ────────────────

def _load_sources() -> list[dict]:
    """Read sources.yaml. Uses yaml.safe_load to prevent arbitrary code execution (T-09-03)."""
    with open(SOURCES_PATH) as f:
        data = yaml.safe_load(f)
    return data["sources"]


def _load_state() -> dict:
    """Load persisted URL registry from disk. Returns empty registry when file absent or corrupt."""
    if not STATE_PATH.exists():
        return {"processed_urls": [], "sources": {}}
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        logger.warning("[collector] state file corrupt or unreadable — resetting (URLs will be re-checked)")
        return {"processed_urls": [], "sources": {}}


def _save_state(state: dict) -> None:
    """Persist URL registry to disk atomically (write-then-replace prevents corrupt state on SIGKILL).

    P0.5: processed_urls is merged (union) with the on-disk registry under the
    lock. The poll cycle holds its state snapshot across minutes of network I/O
    while finished dispatches append URLs through their own locked saves — a
    plain overwrite of the stale snapshot erased those URLs (lost update) and
    re-ingested the documents next cycle. The registry is append-only by design,
    so union is always correct; metadata keys stay last-writer-wins (cosmetic).
    The union also rides out a mid-cycle corrupt/reset file: the snapshot still
    carries the full history.
    """
    global _canary_write_attempts
    if _canary_active:
        _canary_write_attempts += 1
    with _state_write_lock:
        on_disk = _load_state() if STATE_PATH.exists() else {}
        state["processed_urls"] = list(dict.fromkeys(
            [*on_disk.get("processed_urls", []), *state.get("processed_urls", [])]
        ))
        tmp = STATE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2))
        tmp.replace(STATE_PATH)  # atomic on POSIX — both paths are under /data


def _utc_now(now: datetime | str | None = None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if isinstance(now, str):
        now = datetime.fromisoformat(now.replace("Z", "+00:00"))
    if now.tzinfo is None:
        raise ValueError("collector clock must be timezone-aware")
    return now.astimezone(timezone.utc)


def _is_source_due(
    name: str,
    state: dict,
    interval_hours: int,
    *,
    now: datetime | str | None = None,
) -> bool:
    """Return True when the last attempted poll is outside the configured interval."""
    source_state = state.get("sources", {}).get(name, {})
    last_attempt = source_state.get("last_attempt") or source_state.get("last_polled")
    if last_attempt is None:
        return True  # fresh deploy — never polled before
    last_dt = _utc_now(last_attempt)
    return _utc_now(now) - last_dt >= timedelta(hours=interval_hours)


def _entry_url(entry) -> str:
    """Best URL for an RSS entry: prefer an application/pdf enclosure/link over the <link>.

    feedparser folds enclosures and alternate links into entry.links[] with a 'type'.
    Report/bulletin feeds often ship the PDF as an enclosure while <link> is only the
    HTML landing page — pick the PDF pointer when the feed gives one (P4).
    """
    for link in (entry.get("links") or []):
        if (link.get("type") or "").lower() == "application/pdf" and link.get("href"):
            return link["href"]
    for enc in (entry.get("enclosures") or []):
        if (enc.get("type") or "").lower() == "application/pdf" and enc.get("href"):
            return enc["href"]
    return entry.get("link", "")


def discover_pdf_links(
    html: bytes,
    base_url: str,
    limit: int = 5,
    pdf_pattern: str | None = None,
) -> list[str]:
    """Find candidate PDF links in a landing page (ROB-03).

    Returns absolute <a href> URLs whose path ends in .pdf (query stripped),
    de-duped preserving order, same-host candidates first, capped at `limit`
    (T-10-03 amplification guard). Candidates are hints only — the caller must
    confirm by Content-Type/magic bytes (looks_like_pdf) before ingesting.
    When `pdf_pattern` is supplied, only anchors matching that BeautifulSoup CSS
    selector are considered (Phase 13 manual source recipes).
    """
    soup = BeautifulSoup(html, "html.parser")
    base_host = urlparse(base_url).hostname
    seen: set = set()
    same_host: list[str] = []
    cross_host: list[str] = []

    anchors = soup.select(pdf_pattern) if pdf_pattern else soup.find_all("a", href=True)
    for a in anchors:
        if a.name != "a" or not a.get("href"):
            continue
        href = urljoin(base_url, a["href"])
        if href in seen or not urlparse(href).path.lower().endswith(".pdf"):
            continue
        seen.add(href)
        (same_host if urlparse(href).hostname == base_host else cross_host).append(href)
    return (same_host + cross_host)[:limit]


_COLLECTION_TEXT_KEYS = (
    "collection_item_selector",
    "landing_path_pattern",
    "document_link_selector",
    "document_path_pattern",
)


def _validated_collection_recipe(source: dict) -> tuple[set[str], re.Pattern, set[str], re.Pattern, int]:
    """Validate and compile one html_collection recipe without performing I/O."""
    for key in _COLLECTION_TEXT_KEYS:
        if not isinstance(source.get(key), str) or not source[key].strip():
            raise CollectionConfigError(f"html_collection requires non-empty {key}")

    def hosts(key: str) -> set[str]:
        values = source.get(key)
        if not isinstance(values, list) or not values:
            raise CollectionConfigError(f"html_collection requires non-empty {key}")
        normalized: set[str] = set()
        for value in values:
            if not isinstance(value, str) or not value.strip():
                raise CollectionConfigError(f"html_collection {key} contains an invalid hostname")
            host = value.strip().lower().rstrip(".")
            if "://" in host or "/" in host or "@" in host or ":" in host:
                raise CollectionConfigError(f"html_collection {key} must contain exact hostnames")
            normalized.add(host)
        return normalized

    try:
        landing_pattern = re.compile(source["landing_path_pattern"])
    except re.error as exc:
        raise CollectionConfigError(f"invalid landing_path_pattern: {exc}") from exc
    try:
        document_pattern = re.compile(source["document_path_pattern"])
    except re.error as exc:
        raise CollectionConfigError(f"invalid document_path_pattern: {exc}") from exc

    max_candidates = source.get("max_candidates")
    if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or max_candidates < 1:
        raise CollectionConfigError("html_collection max_candidates must be a positive integer")
    if not isinstance(source.get("automatic_dispatch"), bool):
        raise CollectionConfigError("html_collection automatic_dispatch must be boolean")

    max_new = source.get("max_new_per_cycle")
    if isinstance(max_new, bool) or not isinstance(max_new, int) or not 1 <= max_new <= max_candidates:
        raise CollectionConfigError(
            "html_collection max_new_per_cycle must be between 1 and max_candidates"
        )
    pipeline = source.get("dispatch_pipeline")
    if source["automatic_dispatch"]:
        if pipeline is None:
            # Pipeline-less recipes ride the generic run_extraction branch;
            # attribution must never silently drop, so require an identity.
            identity = source.get("identity")
            if (
                not isinstance(identity, dict)
                or not isinstance(identity.get("name"), str)
                or not identity["name"].strip()
                or not isinstance(identity.get("type"), str)
                or not identity["type"].strip()
            ):
                raise CollectionConfigError(
                    "automatic html_collection without dispatch_pipeline"
                    " requires an identity with name and type"
                )
        elif not isinstance(pipeline, str) or not pipeline.strip():
            raise CollectionConfigError(
                "automatic html_collection requires a dispatch_pipeline"
            )

    landing_hosts = hosts("landing_allowed_hosts")
    document_hosts = hosts("document_allowed_hosts")
    seeds = source.get("processed_seed_documents")
    if not isinstance(seeds, list):
        raise CollectionConfigError(
            "html_collection processed_seed_documents must be a list"
        )
    for seed in seeds:
        if not isinstance(seed, dict) or set(seed) != {"landing_url", "document_url"}:
            raise CollectionConfigError("html_collection seed document is malformed")
        landing_url = _confined_url(
            source["url"], seed["landing_url"], landing_hosts, landing_pattern
        )
        document_url = _confined_url(
            seed["landing_url"], seed["document_url"], document_hosts, document_pattern
        )
        if (
            landing_url != seed["landing_url"]
            or document_url != seed["document_url"]
            or urlsplit(landing_url).query
            or urlsplit(document_url).query
        ):
            raise CollectionConfigError(
                "html_collection seed URLs must be exact confined canonical URLs"
            )

    return (
        landing_hosts,
        landing_pattern,
        document_hosts,
        document_pattern,
        max_candidates,
    )


_CYCLE_COUNTER_KEYS = ("due", "not_due", "new", "known", "processed", "failed")
_CYCLE_FETCH_KEYS = ("collection_fetches", "landing_fetches", "document_fetches")


def _collection_source_state(state: dict, name: str) -> dict:
    source_state = state.setdefault("sources", {}).setdefault(name, {})
    counters = source_state.setdefault("counters", {})
    for key in _CYCLE_COUNTER_KEYS:
        counters.setdefault(key, 0)
    return source_state


def _empty_collection_cycle() -> dict:
    return {
        **{key: 0 for key in _CYCLE_COUNTER_KEYS},
        "selected": 0,
        **{key: 0 for key in _CYCLE_FETCH_KEYS},
    }


def _merge_collection_seeds(source: dict, state: dict) -> bool:
    processed = state.setdefault("processed_urls", [])
    seen = set(processed)
    changed = False
    for seed in source.get("processed_seed_documents", []):
        for key in ("landing_url", "document_url"):
            value = seed[key]
            if value not in seen:
                processed.append(value)
                seen.add(value)
                changed = True
    return changed


def _confined_url(base_url: str, href: str, allowed_hosts: set[str], path_pattern: re.Pattern) -> str | None:
    """Resolve an href and return a fragment-free, exact-host/path-confined URL."""
    try:
        parts = urlsplit(urljoin(base_url, href))
        hostname = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if parts.scheme.lower() not in {"http", "https"}:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if hostname not in allowed_hosts or not path_pattern.search(parts.path):
        return None
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path, parts.query, ""))


def _select_anchors(html: bytes, selector: str, selector_key: str, *, collection_fetched: bool) -> list:
    """Apply a configured CSS selector with an explicit configuration error."""
    try:
        return list(BeautifulSoup(html, "html.parser").select(selector))
    except Exception as exc:
        raise CollectionConfigError(
            f"invalid {selector_key} '{selector}': {exc}",
            collection_fetched=collection_fetched,
        ) from exc


_SPANISH_MONTHS = {
    "enero": 1,
    "febrero": 2,
    "marzo": 3,
    "abril": 4,
    "mayo": 5,
    "junio": 6,
    "julio": 7,
    "agosto": 8,
    "septiembre": 9,
    "setiembre": 9,
    "octubre": 10,
    "noviembre": 11,
    "diciembre": 12,
}
_SPANISH_DATE_RE = re.compile(
    r"(?<!\d)([0-9]{1,2})\s+de\s+(" + "|".join(_SPANISH_MONTHS) + r")\s+de\s+([0-9]{4})(?!\d)",
    re.IGNORECASE,
)


def _normalized_text(node) -> str:
    return " ".join(node.get_text(" ", strip=True).split()) if node is not None else ""


def _iso_datetime(value: str) -> str:
    """Parse an HTML datetime value and return its ISO calendar date."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("malformed datetime")
    candidate = value.strip()
    try:
        parsed = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.strptime(candidate, "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError(f"malformed datetime '{candidate}'") from exc
    return parsed.date().isoformat()


def _distinct_or_error(values: list[str], label: str) -> str | None:
    distinct = list(dict.fromkeys(value for value in values if value))
    if len(distinct) > 1:
        raise ValueError(f"conflicting {label}")
    return distinct[0] if distinct else None


def _title_or_error(values: list[str], label: str) -> str | None:
    by_folded: dict[str, str] = {}
    for value in values:
        normalized = " ".join(value.split())
        if normalized:
            by_folded.setdefault(normalized.casefold(), normalized)
    if len(by_folded) > 1:
        raise ValueError(f"conflicting {label}")
    return next(iter(by_folded.values()), None)


def _dates_from_scope(scope) -> tuple[str | None, str | None]:
    """Return preferred date and its local source (time or visible text)."""
    time_values = [_iso_datetime(tag.get("datetime")) for tag in scope.select("time[datetime]")]
    time_date = _distinct_or_error(time_values, "datetime values")

    visible_scope = BeautifulSoup(str(scope), "html.parser")
    for excluded in visible_scope.select("nav, footer, script"):
        excluded.decompose()
    text_dates: list[str] = []
    for day, month, year in _SPANISH_DATE_RE.findall(visible_scope.get_text(" ", strip=True)):
        try:
            text_dates.append(
                datetime(int(year), _SPANISH_MONTHS[month.lower()], int(day)).date().isoformat()
            )
        except ValueError as exc:
            raise ValueError("malformed visible Spanish date") from exc
    text_date = _distinct_or_error(text_dates, "visible dates")
    if time_date and text_date and time_date != text_date:
        raise ValueError("conflicting time and visible dates")
    if time_date:
        return time_date, "time"
    if text_date:
        return text_date, "text"
    return None, None


def _collection_anchor_date(anchor, selector: str) -> tuple[str | None, str | None]:
    """Find a date in the nearest confined card, climbing at most four parents."""
    container = anchor
    for _ in range(4):
        container = getattr(container, "parent", None)
        if container is None or getattr(container, "name", None) in {None, "[document]"}:
            break
        if container.name == "main":
            break
        if len(container.select(selector)) != 1:
            continue
        date_value, date_kind = _dates_from_scope(container)
        if date_value:
            return date_value, date_kind
    return None, None


def _landing_provenance(
    landing_body: bytes,
) -> tuple[str | None, str | None, str | None, str | None]:
    soup = BeautifulSoup(landing_body, "html.parser")
    mains = soup.select("main")
    if len(mains) != 1:
        raise ValueError("landing must contain exactly one main element")
    main = mains[0]
    h1_title = _title_or_error(
        [_normalized_text(node) for node in main.select("h1")], "landing h1 titles"
    )
    h2_title = _title_or_error(
        [_normalized_text(node) for node in main.select("h2")], "landing h2 titles"
    )
    date_value, date_kind = _dates_from_scope(main)
    date_source = "landing_main_time" if date_kind == "time" else "landing_main_text" if date_kind else None
    return h1_title, h2_title, date_value, date_source


def discover_html_collection(
    source: dict,
    *,
    state: dict | None = None,
    limit: int | None = None,
    operational: bool = False,
) -> CollectionDiscovery:
    """Traverse collection HTML -> landing HTML -> confirmed PDF deterministically.

    Configuration confinement is applied before each downstream fetch. Discovery
    never writes collector state; operational callers reserve dedup keys in memory
    only when a confirmed document is queued.
    """
    (landing_hosts, landing_pattern, document_hosts,
     document_pattern, configured_cap) = _validated_collection_recipe(source)
    effective_cap = configured_cap if limit is None else min(configured_cap, max(0, int(limit)))
    result = CollectionDiscovery()
    state = state or {}
    host_tier = state.setdefault("host_tier", {})
    processed = set(state.get("processed_urls", []))
    selection_cap = source.get("max_new_per_cycle", configured_cap)

    collection_body, _ = fetch(source["url"], timeout=30, host_tier=host_tier)
    result.collection_fetches = 1
    collection_anchors = _select_anchors(
        collection_body,
        source["collection_item_selector"],
        "collection_item_selector",
        collection_fetched=True,
    )
    landing_urls: list[str] = []
    landing_records: dict[str, dict] = {}
    for anchor in collection_anchors:
        href = anchor.get("href") if getattr(anchor, "name", None) == "a" else None
        if not href:
            continue
        landing_url = _confined_url(source["url"], href, landing_hosts, landing_pattern)
        if not landing_url:
            continue
        if landing_url not in landing_records:
            landing_urls.append(landing_url)
            landing_records[landing_url] = {
                "titles": [],
                "dates": [],
                "date_kinds": [],
                "errors": [],
            }
        record = landing_records[landing_url]
        record["titles"].append(_normalized_text(anchor))
        try:
            collection_date, collection_date_kind = _collection_anchor_date(
                anchor, source["collection_item_selector"]
            )
            if collection_date:
                record["dates"].append(collection_date)
                record["date_kinds"].append(collection_date_kind)
        except ValueError as exc:
            record["errors"].append(str(exc))

    result.collection_candidates = len(landing_urls)
    limited_landings = landing_urls[:effective_cap]
    result.limited_candidates = len(limited_landings)
    if not limited_landings:
        result.errors.append(
            f"collection_item_selector '{source['collection_item_selector']}' matched no allowlist-confined landing links"
        )
        return result

    seen_documents: set[str] = set()
    for landing_url in limited_landings:
        if operational and (landing_url in processed or landing_url in _html_collection_inflight):
            result.known += 1
            continue
        try:
            landing_body, _ = fetch(landing_url, timeout=30, host_tier=host_tier)
            result.landing_fetches += 1
            record = landing_records[landing_url]
            if record["errors"]:
                raise ValueError(record["errors"][0])
            collection_title = _title_or_error(record["titles"], "collection titles")
            collection_date = _distinct_or_error(record["dates"], "collection dates")
            collection_date_kind = _distinct_or_error(
                record["date_kinds"], "collection date sources"
            )
            landing_h1, landing_h2, landing_date, landing_date_source = (
                _landing_provenance(landing_body)
            )
            if collection_title:
                landing_titles = [title for title in (landing_h1, landing_h2) if title]
                if not landing_titles:
                    raise ValueError("missing landing title confirmation")
                if collection_title.casefold() not in {
                    title.casefold() for title in landing_titles
                }:
                    raise ValueError("title conflict between collection and landing")
                title = collection_title
                title_source = "collection_anchor+landing_confirmed"
            else:
                title = landing_h1 or landing_h2
                title_source = (
                    "landing_main_h1" if landing_h1 else "landing_main_h2" if landing_h2 else None
                )
                if not title or not title_source:
                    raise ValueError("missing title provenance")

            if collection_date:
                if not landing_date:
                    raise ValueError("missing landing publication date confirmation")
                if collection_date != landing_date:
                    raise ValueError("publication date conflict between collection and landing")
                publication_date = collection_date
                publication_date_source = (
                    "collection_card_time+landing_confirmed"
                    if collection_date_kind == "time"
                    else "collection_card_text+landing_confirmed"
                )
            else:
                if not landing_date or not landing_date_source:
                    raise ValueError("missing publication date provenance")
                publication_date = landing_date
                publication_date_source = landing_date_source
            document_anchors = _select_anchors(
                landing_body,
                source["document_link_selector"],
                "document_link_selector",
                collection_fetched=True,
            )
        except CollectionConfigError:
            raise
        except ValueError as exc:
            result.errors.append(f"provenance error for {landing_url}: {exc}")
            continue
        except Exception as exc:
            result.errors.append(f"landing fetch failed for {landing_url}: {exc}")
            continue

        confined_documents: list[str] = []
        seen_on_landing: set[str] = set()
        for anchor in document_anchors:
            href = anchor.get("href") if getattr(anchor, "name", None) == "a" else None
            if not href:
                continue
            document_url = _confined_url(landing_url, href, document_hosts, document_pattern)
            if document_url and document_url not in seen_on_landing:
                seen_on_landing.add(document_url)
                confined_documents.append(document_url)
        if not confined_documents:
            result.errors.append(
                f"document_link_selector '{source['document_link_selector']}' matched no allowlist-confined document links on {landing_url}"
            )
            continue

        for document_url in confined_documents:
            if document_url in seen_documents:
                continue
            seen_documents.add(document_url)
            if operational and (
                document_url in processed or document_url in _html_collection_inflight
            ):
                result.known += 1
                continue
            try:
                document_body, document_ctype = fetch(
                    document_url, timeout=30, host_tier=host_tier
                )
                result.document_fetches += 1
            except Exception as exc:
                result.errors.append(f"document fetch failed for {document_url}: {exc}")
                continue
            if not looks_like_pdf(document_ctype, document_body):
                result.errors.append(f"document candidate was not confirmed as PDF: {document_url}")
                continue

            result.new += 1
            if operational and len(result.documents) >= selection_cap:
                break
            if operational:
                _html_collection_inflight.update({landing_url, document_url})
            result.documents.append(PendingDocument(
                mode="pdf",
                content=document_body,
                url=None,
                source_type=source.get("source_type"),
                source_name=source.get("name"),
                landing_dedup_key=landing_url,
                document_dedup_key=document_url,
                title=title,
                publication_date=publication_date,
                title_source=title_source,
                publication_date_source=publication_date_source,
                dispatch_pipeline=source.get("dispatch_pipeline"),
                source_config=source,
            ))
            result.selected = len(result.documents)
            break  # one primary confirmed document per landing

    return result


def _poll_csaf_github(source: dict, state: dict) -> list[tuple]:
    """Poll a csaf_github source (ROB-04): list recent CSAF advisory JSONs from a
    GitHub repo path via the contents API and dispatch each once as mode='url'.

    The advisory JSON rides the existing mode='url' extraction path (extract_url_text's
    fallback yields the JSON text → LLM extracts CVEs/IOCs) — no new extractor mode.
    Same optimistic dedup/persist pattern as the rss entry path.
    """
    name = source["name"]

    if not _is_source_due(name, state, source.get("poll_interval_hours", 24)):
        _collector_state["sources_meta"].setdefault(name, {})["new_found"] = 0
        return []

    if name not in _collector_state["sources_meta"]:
        _collector_state["sources_meta"][name] = {"new_found": 0, "errors": 0}

    meta = state.setdefault("sources", {}).setdefault(name, {})
    host_tier = state.setdefault("host_tier", {})

    repo = source["repo"]
    # {year} resolves at poll time — cisagov/CSAF shards advisories into per-year dirs,
    # so a hardcoded year would go silently stale at rollover (the exact ROB-05 failure).
    path = source["path"].format(year=datetime.now(timezone.utc).year)
    api_url = f"https://api.github.com/repos/{repo}/contents/{path}?ref={source.get('branch', 'develop')}"

    try:
        body, _ = fetch(api_url, timeout=30, host_tier=host_tier)
        listing = json.loads(body)
    except Exception as exc:
        logger.warning("[collector] csaf source '%s' listing error: %s", name, exc)
        _collector_state["sources_meta"][name]["errors"] += 1
        return []

    # Keep only advisory JSONs (drops .json.asc/.json.sha512 signature siblings), sort
    # by name descending (advisories are date/id-named), cap per poll (T-10-03).
    # ponytail: contents API truncates dirs at 1000 entries ascending — switch to the
    # git trees API if a year dir outgrows that mid-year.
    files = sorted(
        (e for e in listing
         if e.get("name", "").endswith(".json") and e.get("download_url")),
        key=lambda e: e["name"],
        reverse=True,
    )[: source.get("max_advisories", 10)]

    # T-10-04: download_url must stay confined to the configured repo's raw namespace
    allowed_prefix = f"https://raw.githubusercontent.com/{repo}/"

    processed_urls = set(state.get("processed_urls", []))
    pending: list[tuple] = []
    new_found = 0
    source_type = source.get("source_type")

    for entry in files:
        url = entry["download_url"]
        if url in processed_urls:
            continue
        if not url.startswith(allowed_prefix):
            logger.warning("[collector] csaf source '%s': download_url outside repo — skipped: %s", name, url)
            continue
        # Optimistic dedup/persist — same pattern as the rss entry path
        pending.append(("url", None, url, source_type))
        processed_urls.add(url)
        state.setdefault("processed_urls", []).append(url)
        new_found += 1
        _save_state(state)

    meta["last_polled"] = datetime.now(timezone.utc).isoformat()
    _save_state(state)

    _collector_state["sources_meta"][name]["new_found"] = new_found
    logger.info("[collector] source '%s': %d new advisory doc(s) queued", name, new_found)
    return pending


def _validated_html_index_recipe(source: dict) -> tuple[set[str], re.Pattern, int]:
    """Validate one html_index recipe without performing I/O (quick-260716-m2g)."""
    selector = source.get("item_selector")
    if not isinstance(selector, str) or not selector.strip():
        raise CollectionConfigError("html_index requires non-empty item_selector")

    hosts_raw = source.get("allowed_hosts")
    if not isinstance(hosts_raw, list) or not hosts_raw:
        raise CollectionConfigError("html_index requires non-empty allowed_hosts")
    hosts: set[str] = set()
    for value in hosts_raw:
        if not isinstance(value, str) or not value.strip():
            raise CollectionConfigError("html_index allowed_hosts contains an invalid hostname")
        host = value.strip().lower().rstrip(".")
        if "://" in host or "/" in host or "@" in host or ":" in host:
            raise CollectionConfigError("html_index allowed_hosts must contain exact hostnames")
        hosts.add(host)

    pattern_raw = source.get("path_pattern")
    if not isinstance(pattern_raw, str) or not pattern_raw.strip():
        raise CollectionConfigError("html_index requires non-empty path_pattern")
    try:
        pattern = re.compile(pattern_raw)
    except re.error as exc:
        raise CollectionConfigError(f"invalid path_pattern: {exc}") from exc

    max_new = source.get("max_new_per_cycle")
    if isinstance(max_new, bool) or not isinstance(max_new, int) or max_new < 1:
        raise CollectionConfigError("html_index max_new_per_cycle must be a positive integer")

    if not isinstance(source.get("append_slash", False), bool):
        raise CollectionConfigError("html_index append_slash must be boolean")

    return hosts, pattern, max_new


def _confined_index_urls(
    body: bytes, source: dict, allowed_hosts: set[str], path_pattern: re.Pattern
) -> list[str]:
    """Select anchors on an index page and return confined URLs, deduped in order.

    _select_anchors raises CollectionConfigError on a malformed CSS selector
    (surfaces at .select() time, not recipe-validation time) — callers must
    catch it to honor the WARNING+return-[] contract.
    """
    anchors = _select_anchors(
        body, source["item_selector"], "item_selector", collection_fetched=True
    )
    append_slash = source.get("append_slash", False)
    urls: list[str] = []
    seen: set[str] = set()
    for anchor in anchors:
        href = anchor.get("href") if getattr(anchor, "name", None) == "a" else None
        if not href:
            continue
        url = _confined_url(source["url"], href, allowed_hosts, path_pattern)
        if url and append_slash:
            # Dispatch the canonical trailing-slash URL: hosts like attack.mitre.org
            # 301 slashless paths, and the extractor's fetch never follows redirects.
            parts = urlsplit(url)
            if not parts.path.endswith("/"):
                url = urlunsplit(
                    (parts.scheme, parts.netloc, parts.path + "/", parts.query, "")
                )
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def _poll_html_index(source: dict, state: dict) -> list[PendingDocument]:
    """Poll an html_index source (quick-260716-m2g): fetch one index page, confine
    links by host+path, dispatch each new URL once as mode='url' through the
    generic extraction path.

    Same optimistic dedup/persist semantics as the rss/csaf paths: a dispatched
    URL is persisted immediately and a failed extraction is not retried.
    """
    name = source["name"]
    meta_mem = _collector_state["sources_meta"].setdefault(
        name, {"new_found": 0, "errors": 0}
    )

    try:
        allowed_hosts, path_pattern, max_new = _validated_html_index_recipe(source)
    except CollectionConfigError as exc:
        logger.warning("[collector] html_index '%s' configuration error: %s", name, exc)
        meta_mem["errors"] = meta_mem.get("errors", 0) + 1
        return []

    if not _is_source_due(name, state, source.get("poll_interval_hours", 24)):
        meta_mem["new_found"] = 0
        return []

    meta = state.setdefault("sources", {}).setdefault(name, {})
    host_tier = state.setdefault("host_tier", {})

    try:
        body, _ = fetch(source["url"], timeout=30, host_tier=host_tier)
        candidates = _confined_index_urls(body, source, allowed_hosts, path_pattern)
    except Exception as exc:
        logger.warning("[collector] html_index '%s' index error: %s", name, exc)
        meta_mem["errors"] = meta_mem.get("errors", 0) + 1
        return []

    processed_urls = set(state.get("processed_urls", []))
    pending: list[PendingDocument] = []
    new_found = 0
    for url in candidates:
        if url in processed_urls:
            continue
        if new_found >= max_new:
            break
        # Optimistic dedup/persist — same pattern as the rss/csaf entry paths
        pending.append(PendingDocument(
            mode="url",
            content=None,
            url=url,
            source_type=source.get("source_type"),
            source_name=name,
            source_config=source,
        ))
        processed_urls.add(url)
        state.setdefault("processed_urls", []).append(url)
        new_found += 1
        _save_state(state)

    meta["last_polled"] = datetime.now(timezone.utc).isoformat()
    _save_state(state)

    meta_mem["new_found"] = new_found
    logger.info("[collector] source '%s': %d new index page(s) queued", name, new_found)
    return pending


def _poll_html_collection(
    source: dict,
    state: dict,
    *,
    now: datetime | str | None = None,
    force: bool = False,
) -> list[PendingDocument]:
    """Poll one collection and persist cadence/outcomes before returning work."""
    name = source["name"]
    current = _utc_now(now)
    source_meta = _collector_state["sources_meta"].setdefault(
        name, {"new_found": 0, "errors": 0}
    )
    cycle = _empty_collection_cycle()
    pending: list[PendingDocument] = []

    try:
        _validated_collection_recipe(source)
        _merge_collection_seeds(source, state)
        persisted_meta = _collection_source_state(state, name)
    except Exception as exc:
        source_meta["errors"] += 1
        logger.warning("[collector] html_collection '%s' configuration error: %s", name, exc)
        raise

    if not force and not _is_source_due(
        name, state, source.get("poll_interval_hours", 24), now=current
    ):
        cycle["not_due"] = 1
        persisted_meta["counters"]["not_due"] += 1
        persisted_meta["cycle"] = cycle
        persisted_meta["last_outcome"] = "not_due"
        source_meta["new_found"] = 0
        _save_state(state)
        return []

    cycle["due"] = 1
    persisted_meta["counters"]["due"] += 1
    persisted_meta["last_outcome"] = "due"
    try:
        if source["automatic_dispatch"] is not False:
            discovery = discover_html_collection(
                source, state=state, operational=True
            )
            pending = discovery.documents
            cycle.update(
                {
                    "known": discovery.known,
                    "new": discovery.new,
                    "selected": discovery.selected,
                    "collection_fetches": discovery.collection_fetches,
                    "landing_fetches": discovery.landing_fetches,
                    "document_fetches": discovery.document_fetches,
                }
            )
            persisted_meta["counters"]["known"] += discovery.known
            persisted_meta["counters"]["new"] += discovery.new
            if discovery.errors:
                persisted_meta["last_errors"] = discovery.errors[:3]
        else:
            persisted_meta.pop("last_errors", None)
    except Exception as exc:
        logger.warning("[collector] html_collection '%s' discovery error: %s", name, exc)
        source_meta["errors"] += 1
        cycle["failed"] = 1
        persisted_meta["counters"]["failed"] += 1
        persisted_meta["last_error"] = str(exc)[:500]
    finally:
        attempted_at = current.isoformat()
        persisted_meta["last_attempt"] = attempted_at
        persisted_meta["last_polled"] = attempted_at
        persisted_meta["cycle"] = cycle
        _save_state(state)

    source_meta["new_found"] = cycle["new"]
    logger.info(
        "[collector] source '%s': %d new, %d selected, %d known",
        name,
        cycle["new"],
        cycle["selected"],
        cycle["known"],
    )
    return pending


def _poll_source(
    source: dict,
    state: dict,
    *,
    now: datetime | str | None = None,
    force: bool = False,
) -> list[tuple]:
    """
    Poll one source (rss or csaf_github). Returns (mode, content, url, source_type) pending tuples.

    Saves processed URLs to disk immediately (optimistic — prevents re-dispatch on
    restart even if extraction ultimately fails, acceptable for demo scope).
    """
    name = source["name"]
    src_type = source.get("type", "")
    source_type = source.get("source_type")

    if src_type == "csaf_github":
        return _poll_csaf_github(source, state)

    if src_type == "html_collection":
        return _poll_html_collection(source, state, now=now, force=force)

    if src_type == "html_index":
        return _poll_html_index(source, state)

    if src_type != "rss":
        # D-07: skip and warn on unsupported source types
        logger.warning("[collector] skipping source '%s' — type '%s' not supported", name, src_type)
        return []

    if not _is_source_due(name, state, source.get("poll_interval_hours", 24)):
        # Reset new_found so the pill shows 0 between polls, not a stale count
        _collector_state["sources_meta"].setdefault(name, {})["new_found"] = 0
        return []

    if name not in _collector_state["sources_meta"]:
        _collector_state["sources_meta"][name] = {"new_found": 0, "errors": 0}

    meta = state.setdefault("sources", {}).setdefault(name, {})
    host_tier = state.setdefault("host_tier", {})  # ROB-01: tier cache persists to disk

    try:
        # Conditional GET through the transport (ROB-01 + ROB-02): timeout + size cap +
        # 403 tier escalation + If-None-Match/If-Modified-Since from persisted state.
        # check_ssrf=False: feed hosts are operator-configured in sources.yaml (trusted).
        result = fetch_conditional(
            source["url"],
            etag=meta.get("etag"),
            modified=meta.get("last_modified"),
            check_ssrf=False,
            host_tier=host_tier,
        )
    except Exception as exc:
        logger.warning("[collector] feed '%s' fetch error: %s", name, exc)
        _collector_state["sources_meta"][name]["errors"] += 1
        return []

    if result.status == 304:
        # ROB-02: 304 is a success path — no work, NOT an error (Pitfall 4)
        logger.info("[collector] source '%s': 304 not modified — no work", name)
        meta["last_polled"] = datetime.now(timezone.utc).isoformat()
        _save_state(state)
        _collector_state["sources_meta"][name]["new_found"] = 0
        return []

    feed = feedparser.parse(result.body)
    if feed.bozo and not feed.entries:
        # D-03: parse error with no recoverable entries — log and skip
        logger.warning(
            "[collector] feed '%s' parse error: %s",
            name,
            getattr(feed, "bozo_exception", "unknown"),
        )
        _collector_state["sources_meta"][name]["errors"] += 1
        return []

    # Parse succeeded — persist the validators for the next conditional GET (ROB-02).
    # Reaches disk via the _save_state calls below.
    if result.etag:
        meta["etag"] = result.etag
    if result.last_modified:
        meta["last_modified"] = result.last_modified

    processed_urls = set(state.get("processed_urls", []))
    pending: list[tuple] = []
    new_found = 0

    for entry in feed.entries:
        url = _entry_url(entry)
        if not url or url in processed_urls:
            continue

        try:
            # Fetch once, then route by what actually arrived — not the URL suffix, which
            # lies for query-string (report.pdf?token=) and extension-less PDF endpoints
            # (P1/P3). transport.fetch keeps the SSRF/redirect/size guards and adds the
            # 403 → cffi tier escalation for document hosts too (ROB-01).
            data, ctype = fetch(url, timeout=30, host_tier=host_tier)
            if looks_like_pdf(ctype, data, url):
                # P0.4: thread the document URL — url=None starved run_extraction
                # of provenance, so Step 9 targeting failed closed and every
                # actor/sector/country from RSS PDFs was silently discarded.
                pending.append(("pdf", data, url, source_type))
            else:
                # ROB-03: HTML landing page — scan for a linked PDF one hop away.
                # Candidates go through transport.fetch (SSRF + no-redirect + size
                # guards, T-10-01) and are confirmed by Content-Type/magic bytes
                # only (url deliberately omitted from looks_like_pdf — the .pdf
                # suffix that nominated the candidate must not also confirm it).
                # One primary doc per entry (break) caps amplification (T-10-03).
                ingested_pdf = None
                for cand in discover_pdf_links(data, url, pdf_pattern=source.get("pdf_pattern")):
                    if cand in processed_urls:
                        continue
                    try:
                        cand_data, cand_ctype = fetch(cand, timeout=30, host_tier=host_tier)
                    except Exception as exc:
                        logger.warning("[collector] candidate PDF '%s' fetch error: %s", cand, exc)
                        continue
                    if looks_like_pdf(cand_ctype, cand_data):
                        # P0.4: cand is the discovered PDF's own URL — provenance
                        # for the Report/external reference/targeting.
                        pending.append(("pdf", cand_data, cand, source_type))
                        # Pitfall 3 / T-10-07: dedup the discovered PDF URL too, or
                        # every poll re-ingests it. Persisted by _save_state below.
                        processed_urls.add(cand)
                        state.setdefault("processed_urls", []).append(cand)
                        ingested_pdf = cand
                        break
                if ingested_pdf is None:
                    # No confirmable PDF → dispatch as URL, unchanged behavior.
                    # ponytail: one extra GET per HTML entry; poll runs hourly on few sources.
                    pending.append(("url", None, url, source_type))

            # Optimistic persistence: persist before async extraction so restarts skip this URL
            processed_urls.add(url)
            state.setdefault("processed_urls", []).append(url)
            new_found += 1
            _save_state(state)

        except Exception as exc:
            # D-03/D-04: per-entry errors must not stop the loop
            logger.warning("[collector] error preparing '%s': %s", url, exc)
            _collector_state["sources_meta"][name]["errors"] += 1

    # Stamp last_polled regardless of how many new entries were found; this save also
    # persists host_tier and the per-source etag/last_modified set above (ROB-01/ROB-02).
    meta["last_polled"] = datetime.now(timezone.utc).isoformat()
    _save_state(state)

    _collector_state["sources_meta"][name]["new_found"] = new_found
    logger.info("[collector] source '%s': %d new doc(s) queued", name, new_found)
    return pending


def _run_poll_cycle(
    *,
    now: datetime | str | None = None,
    sources: list[dict] | None = None,
) -> list[tuple]:
    """
    Run one full poll cycle across all configured sources.
    Returns combined (mode, content, url, source_type) list for run_collector_loop to dispatch.
    Blocking — always called via asyncio.to_thread(_run_poll_cycle).
    """
    state = _load_state()
    sources = sources or _load_sources()
    pending: list[tuple] = []
    for source in sources:
        pending.extend(_poll_source(source, state, now=now))
    _collector_state["last_run"] = _utc_now(now).isoformat()
    return pending


def get_status() -> dict:
    """Return collector status dict for the /collector/status endpoint (plan 09-02)."""
    state = _load_state()
    sources = _load_sources()
    return {
        "sources": [_status_row(s, state) for s in sources],
        "registry_size": len(state.get("processed_urls", [])),
        "last_run": _collector_state.get("last_run"),
    }


def _status_row(source: dict, state: dict) -> dict:
    persisted = state.get("sources", {}).get(source["name"], {})
    row = {
        "name": source["name"],
        "last_polled": persisted.get("last_polled"),
        "new_found": _collector_state["sources_meta"].get(source["name"], {}).get(
            "new_found", 0
        ),
        "errors": _collector_state["sources_meta"].get(source["name"], {}).get(
            "errors", 0
        ),
        "poll_interval_hours": source.get("poll_interval_hours", 24),
    }
    if source.get("type") == "html_collection":
        row.update(
            {
                "last_attempt": persisted.get("last_attempt"),
                "last_outcome": persisted.get("last_outcome"),
                "cycle": {
                    **_empty_collection_cycle(),
                    **persisted.get("cycle", {}),
                },
                "counters": {
                    **{key: 0 for key in _CYCLE_COUNTER_KEYS},
                    **persisted.get("counters", {}),
                },
            }
        )
    return row


def _confirm_pdf_recipe(
    source: dict,
    landing_url: str,
    landing_html: bytes,
    host_tier: dict,
) -> tuple[bool, str | None, str | None]:
    """Validate a Phase 13 landing-page PDF recipe without running extraction."""
    pdf_pattern = source.get("pdf_pattern")
    if not pdf_pattern:
        return False, None, "landing source requires pdf_pattern"

    try:
        candidates = discover_pdf_links(
            landing_html,
            landing_url,
            limit=source.get("validation_limit", 5),
            pdf_pattern=pdf_pattern,
        )
    except Exception as exc:
        return False, None, f"invalid pdf_pattern '{pdf_pattern}': {exc}"

    if not candidates:
        return False, None, f"pdf_pattern '{pdf_pattern}' matched no PDF links"

    candidate_errors = []
    for candidate_url in candidates:
        try:
            candidate_body, candidate_ctype = fetch(candidate_url, timeout=30, host_tier=host_tier)
        except Exception as exc:
            candidate_errors.append(f"{candidate_url}: {exc}")
            continue
        if looks_like_pdf(candidate_ctype, candidate_body):
            return True, candidate_url, None
        candidate_errors.append(f"{candidate_url}: not a PDF ({candidate_ctype or 'unknown content type'})")

    detail = "; ".join(candidate_errors[:3]) or "no candidates fetched"
    return False, None, f"pdf_pattern '{pdf_pattern}' found candidates but none confirmed as PDF: {detail}"


def validate_sources() -> list[dict]:
    """Config-time source-health sweep (ROB-05) for the /collector/validate endpoint.

    Per source, per type: rss → fetch_conditional + feedparser (reachable = 200/304,
    parseable = non-bozo with >=1 entry); csaf_github → contents API (reachable = 2xx,
    parseable = listing with >=1 advisory .json). Exceptions are caught per source into
    an `error` string so one dead source never aborts the sweep. Blocking — call via
    asyncio.to_thread; /collector/status stays network-free.
    """
    state = _load_state()
    host_tier = state.get("host_tier", {})
    results: list[dict] = []

    for source in _load_sources():
        src_type = source.get("type", "")
        row = {"name": source["name"], "type": src_type,
               "reachable": False, "parseable": False, "tier": None, "error": None,
               "matched_url": None, "matched_landing_url": None}
        try:
            if src_type == "rss":
                # check_ssrf=False: feed hosts are operator-configured (same as _poll_source)
                result = fetch_conditional(source["url"], check_ssrf=False, host_tier=host_tier)
                row["tier"] = result.tier
                row["reachable"] = result.status in (200, 304)
                feed = feedparser.parse(result.body)
                row["parseable"] = (not (feed.bozo and not feed.entries)
                                    and len(feed.entries) > 0)
                if row["parseable"] and source.get("pdf_pattern"):
                    recipe_ok = False
                    recipe_error = "pdf_pattern source has no RSS entry URL to inspect"
                    for entry in feed.entries[: source.get("validation_entries", 3)]:
                        entry_url = _entry_url(entry)
                        if not entry_url:
                            continue
                        try:
                            landing_body, _ = fetch(entry_url, timeout=30, host_tier=host_tier)
                        except Exception as exc:
                            recipe_error = f"entry landing fetch failed for {entry_url}: {exc}"
                            continue
                        recipe_ok, matched_url, recipe_error = _confirm_pdf_recipe(
                            source, entry_url, landing_body, host_tier
                        )
                        if recipe_ok:
                            row["matched_url"] = matched_url
                            break
                    row["parseable"] = recipe_ok
                    row["error"] = None if recipe_ok else recipe_error
            elif src_type == "csaf_github":
                path = source["path"].format(year=datetime.now(timezone.utc).year)
                api_url = (f"https://api.github.com/repos/{source['repo']}"
                           f"/contents/{path}?ref={source.get('branch', 'develop')}")
                body, _ = fetch(api_url, timeout=30, host_tier=host_tier)
                row["reachable"] = True  # fetch raises on any non-2xx/304 status
                row["tier"] = host_tier.get(urlparse(api_url).hostname, "plain")
                listing = json.loads(body)
                row["parseable"] = isinstance(listing, list) and any(
                    e.get("name", "").endswith(".json") for e in listing)
            elif src_type == "landing":
                body, _ = fetch(source["url"], timeout=30, host_tier=host_tier)
                row["reachable"] = True  # fetch raises on any non-2xx/304 status
                row["tier"] = host_tier.get(urlparse(source["url"]).hostname, "plain")
                row["parseable"], row["matched_url"], row["error"] = _confirm_pdf_recipe(
                    source, source["url"], body, host_tier
                )
            elif src_type == "html_index":
                # Recipe validated before any fetch — a config error never fetches
                allowed_hosts, path_pattern, _ = _validated_html_index_recipe(source)
                body, _ = fetch(source["url"], timeout=30, host_tier=host_tier)
                row["reachable"] = True  # fetch raises on any non-2xx/304 status
                row["tier"] = host_tier.get(urlparse(source["url"]).hostname, "plain")
                matched = _confined_index_urls(body, source, allowed_hosts, path_pattern)
                row["parseable"] = bool(matched)
                if matched:
                    row["matched_url"] = matched[0]
                else:
                    row["error"] = (
                        f"item_selector '{source['item_selector']}' matched no "
                        "allowlist-confined index links"
                    )
            elif src_type == "html_collection":
                try:
                    discovery = discover_html_collection(
                        source,
                        state={"processed_urls": [], "host_tier": host_tier},
                        operational=False,
                    )
                except CollectionConfigError as exc:
                    row["reachable"] = exc.collection_fetched
                    row["error"] = str(exc)
                else:
                    row["reachable"] = discovery.collection_fetches == 1
                    row["parseable"] = bool(discovery.documents)
                    if discovery.documents:
                        first = discovery.documents[0]
                        row["matched_url"] = first.document_dedup_key
                        row["matched_landing_url"] = first.landing_dedup_key
                    else:
                        row["error"] = "; ".join(discovery.errors[:3]) or "no safe document matched"
                row["tier"] = host_tier.get(urlparse(source["url"]).hostname, "plain")
            else:
                row["error"] = f"unsupported type '{src_type}'"
        except Exception as exc:
            row["error"] = str(exc)
        results.append(row)

    return results


def _normalize_pending(item: PendingDocument | tuple) -> PendingDocument:
    """Normalize legacy RSS/CSAF tuples for the common dispatch path."""
    if isinstance(item, PendingDocument):
        return item
    mode, content, url, source_type = item
    return PendingDocument(mode, content, url, source_type)


def _load_extractor_module():
    """Lazy import keeps validation/canary paths independent of operational clients."""
    return importlib.import_module("extractor")


def _acknowledge_html_document(item: PendingDocument) -> None:
    """Persist both html_collection keys after a successful Report completes."""
    keys = [item.landing_dedup_key, item.document_dedup_key]
    if not all(keys):
        return
    with _state_write_lock:
        state = _load_state()
        processed = state.setdefault("processed_urls", [])
        seen = set(processed)
        for key in keys:
            if key not in seen:
                processed.append(key)
                seen.add(key)
        _save_state(state)


async def _dispatch_pending(
    raw_item: PendingDocument | tuple,
    *,
    dispatchers: dict[str, object] | None = None,
) -> bool:
    """Dispatch one item, failing closed for configured source-specific pipelines."""
    item = _normalize_pending(raw_item)
    dedup_keys = {key for key in (
        item.landing_dedup_key, item.document_dedup_key
    ) if key}
    succeeded = False
    try:
        if item.dispatch_pipeline:
            handler = (dispatchers or {}).get(item.dispatch_pipeline)
            if handler is None:
                raise RuntimeError(
                    f"missing required dispatcher: {item.dispatch_pipeline}"
                )
            result = await asyncio.to_thread(handler, item)
            succeeded = isinstance(result, dict) and result.get("ok") is True
            if not succeeded:
                raise RuntimeError(
                    f"dispatcher {item.dispatch_pipeline} returned non-ok"
                )
        else:
            extractor = _load_extractor_module()
            job_id = str(uuid.uuid4())
            extractor.register_job(job_id)
            await asyncio.to_thread(
                extractor.run_extraction,
                job_id,
                item.mode,
                item.content,
                # html_collection items carry url=None (content already fetched);
                # thread the document URL so the Report is named after the source
                # document, gets its PDF External Reference, and stays eligible
                # for Step 9 targeting (fails closed on non-http source_url).
                # Uploads/legacy items have no dedup keys -> still None.
                item.url or item.document_dedup_key,
                source_type=item.source_type,
                created_by=(item.source_config or {}).get("identity"),
            )
            job = extractor.jobs.get(job_id, {})
            succeeded = job.get("status") == "complete" and bool(job.get("report_id"))
            # Un-burn the optimistic persist on a transient failure so the URL is
            # retried next cycle (audit 2026-07-25). Only for url-path items: the
            # poll added item.url to processed_urls; html_collection items dedup via
            # keys in _record_collection_dispatch, which already skips on failure.
            # ponytail: narrow race — a dispatch finishing during the NEXT cycle's
            # poll could see its snapshot re-union the URL; worst case it retries one
            # cycle later, never data loss. Not worth per-URL locking across cycles.
            if not succeeded and not dedup_keys and item.url and \
                    _is_transient_error(job.get("error")):
                _unpersist_url(item.url)
    except Exception as exc:
        logger.warning("[collector] extraction dispatch failed: %s", exc)
    finally:
        if dedup_keys:
            _record_collection_dispatch(item, succeeded)
        _html_collection_inflight.difference_update(dedup_keys)
    return succeeded


# Transient failures (network/infra) must NOT burn a URL's one-and-only attempt:
# the optimistic persist marks it processed at poll time, so without this a DNS
# blip or an OpenCTI-still-booting error becomes permanent silent loss (audit
# 2026-07-25: 14 advisories lost to one bad DNS cycle). Permanent failures
# (404, parse error, non-document) correctly stay processed and are not retried.
_TRANSIENT_ERROR_RE = re.compile(
    r"name resolution|cannot resolve|temporary failure|not reachable|"
    r"timed out|timeout|connection (refused|reset|aborted|error)|"
    r"max retries|502|503|504|bad gateway|service unavailable|gateway time",
    re.IGNORECASE,
)


def _is_transient_error(message) -> bool:
    """True if the failure is infrastructure/network and the URL should be retried."""
    return bool(_TRANSIENT_ERROR_RE.search(str(message or "")))


def _unpersist_url(url: str) -> None:
    """Remove one URL from the on-disk processed registry so the next poll retries it."""
    if not url:
        return
    with _state_write_lock:
        state = _load_state()
        urls = state.get("processed_urls", [])
        if url in urls:
            state["processed_urls"] = [u for u in urls if u != url]
            # _save_state unions with disk; write the pruned set directly to bypass it.
            tmp = STATE_PATH.with_suffix(".tmp")
            tmp.write_text(json.dumps(state, indent=2))
            tmp.replace(STATE_PATH)
            logger.info("[collector] transient failure — URL un-persisted for retry: %s", url)


def _record_collection_dispatch(item: PendingDocument, succeeded: bool) -> None:
    if not item.source_name:
        return
    with _state_write_lock:
        state = _load_state()
        source_state = _collection_source_state(state, item.source_name)
        cycle = {**_empty_collection_cycle(), **source_state.get("cycle", {})}
        key = "processed" if succeeded else "failed"
        cycle[key] += 1
        source_state["cycle"] = cycle
        source_state["counters"][key] += 1
        if succeeded:
            processed = state.setdefault("processed_urls", [])
            seen = set(processed)
            for value in (item.landing_dedup_key, item.document_dedup_key):
                if value and value not in seen:
                    processed.append(value)
                    seen.add(value)
        _save_state(state)


def run_collection_poll_once(
    collection_url: str,
    *,
    now: datetime | str | None = None,
    force: bool = False,
    dry_run: bool = False,
    dispatchers: dict[str, object] | None = None,
) -> dict:
    """Run the production collection cadence/dedup path once for CLI recovery."""
    matches = [
        source
        for source in _load_sources()
        if source.get("type") == "html_collection"
        and source.get("url") == collection_url
    ]
    if len(matches) != 1:
        raise ValueError(
            "poll-once collection URL must exactly match one configured html_collection"
        )
    source = matches[0]
    state = _load_state()
    pending = _poll_html_collection(source, state, now=now, force=force)
    write_attempts = 0
    if dry_run:
        for item in pending:
            _html_collection_inflight.difference_update(
                {
                    key
                    for key in (item.landing_dedup_key, item.document_dedup_key)
                    if key
                }
            )
    else:
        for item in pending:
            write_attempts += 1
            asyncio.run(_dispatch_pending(item, dispatchers=dispatchers))

    persisted = _load_state().get("sources", {}).get(source["name"], {})
    cycle = {**_empty_collection_cycle(), **persisted.get("cycle", {})}
    return {
        "ok": cycle["failed"] == 0,
        "collection_url": collection_url,
        "outcome": persisted.get("last_outcome"),
        "known": cycle["known"],
        "new": cycle["new"],
        "selected": cycle["selected"],
        "processed": cycle["processed"],
        "failed": cycle["failed"],
        "collection_fetches": cycle["collection_fetches"],
        "landing_fetches": cycle["landing_fetches"],
        "document_fetches": cycle["document_fetches"],
        "write_attempts": write_attempts,
        "counters": {
            **{key: 0 for key in _CYCLE_COUNTER_KEYS},
            **persisted.get("counters", {}),
        },
    }


def _snapshot_path(path: Path) -> dict:
    """Return existence/size/SHA256 evidence without creating the path."""
    if not path.exists():
        return {"exists": False, "size": 0, "sha256": None}
    data = path.read_bytes()
    return {
        "exists": True,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def run_collection_canary(collection_url: str, limit: int) -> dict:
    """Run isolated collection discovery and return measured no-write evidence."""
    global _canary_active, _canary_write_attempts
    matching = [
        source for source in _load_sources()
        if source.get("type") == "html_collection" and source.get("url") == collection_url
    ]
    if len(matching) != 1:
        raise ValueError("canary collection URL must exactly match one configured html_collection")
    source = matching[0]
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("canary limit must be a positive integer")

    effective_limit = min(limit, source["max_candidates"])
    modules_before = set(sys.modules)
    state_before = _snapshot_path(STATE_PATH)
    db_before = _snapshot_path(DB_PATH)
    _canary_write_attempts = 0
    _canary_active = True
    try:
        discovery = discover_html_collection(
            source,
            state={"processed_urls": [], "host_tier": {}},
            limit=effective_limit,
            operational=False,
        )
    finally:
        _canary_active = False
    state_after = _snapshot_path(STATE_PATH)
    db_after = _snapshot_path(DB_PATH)
    operational_modules = {"extractor", "opencti_client", "ollama", "stats_store"}
    operational_imports_loaded = any(
        name in sys.modules and name not in modules_before for name in operational_modules
    )
    result = {
        "collection_url": collection_url,
        "documents": [
            {
                "landing_url": item.landing_dedup_key,
                "document_url": item.document_dedup_key,
            }
            for item in discovery.documents
        ],
        "requested_limit": limit,
        "effective_limit": effective_limit,
        "collection_fetches": discovery.collection_fetches,
        "collection_candidates": discovery.collection_candidates,
        "limited_candidates": discovery.limited_candidates,
        "landing_fetches": discovery.landing_fetches,
        "document_fetches": discovery.document_fetches,
        "opencti_url": os.environ.get("OPENCTI_URL", ""),
        "ollama_url": os.environ.get("OLLAMA_URL", ""),
        "state_path": str(STATE_PATH),
        "db_path": str(DB_PATH),
        "credentials_present": bool(os.environ.get("OPENCTI_TOKEN")),
        "operational_imports_loaded": operational_imports_loaded,
        "write_attempts": _canary_write_attempts,
        "state_before": state_before,
        "state_after": state_after,
        "db_before": db_before,
        "db_after": db_after,
    }
    result["state_mutated"] = (
        result["state_before"] != result["state_after"]
        or result["db_before"] != result["db_after"]
    )
    if not result["documents"]:
        detail = "; ".join(discovery.errors[:3]) or "no safe collection documents"
        raise RuntimeError(detail)
    return result


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Intel document collector")
    parser.add_argument("--canary-collection-url")
    parser.add_argument("--limit", type=int, default=3)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if not args.canary_collection_url:
        raise SystemExit("--canary-collection-url is required")
    try:
        result = run_collection_canary(args.canary_collection_url, args.limit)
    except Exception as exc:
        print(json.dumps({"collection_url": args.canary_collection_url, "error": str(exc)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


async def run_collector_loop(
    *, dispatchers: dict[str, object] | None = None
) -> None:
    """
    Async poll coroutine started by main.py lifespan (D-01).

    Polls immediately on startup (no initial sleep). Runs _run_poll_cycle in a
    thread so feedparser.parse and requests.get don't block the event loop.
    Each discovered doc is dispatched via asyncio.to_thread(run_extraction, ...)
    so extraction also runs off-loop without blocking incoming requests.

    jobs[job_id] is pre-initialized immediately before each dispatch (KeyError
    landmine prevention — mirrors main.py lines 55-63 exactly).
    """
    while True:
        try:
            pending = await asyncio.to_thread(_run_poll_cycle)
            for item in pending:
                t = asyncio.create_task(
                    _dispatch_pending(item, dispatchers=dispatchers)
                )
                _background_tasks.add(t)
                t.add_done_callback(_background_tasks.discard)
        except Exception as exc:
            logger.warning("[collector] poll cycle error: %s", exc)
        try:
            # Fase B: retry quarantined candidates against the grown catalog —
            # no-op (one SQLite read) while the queue is empty.
            import queue_worker
            summary = await asyncio.to_thread(queue_worker.rematch_pending)
            if summary.get("auto_matched"):
                logger.info("[collector] queue re-match: %s", summary)
        except Exception as exc:
            logger.warning("[collector] queue re-match error: %s", exc)
        await asyncio.sleep(3600)  # hourly wakeup; each source checks its own interval


if __name__ == "__main__":
    raise SystemExit(main())
