"""
opencti_client.py — pycti wrapper for OpenCTI indicator creation in intel-extractor.

Provides:
  build_pycti_client()       — construct and return an OpenCTIApiClient
  create_indicator()         — submit a STIX indicator with D-05 retry (3x, 30/60/120s)
  lookup_attack_pattern()    — query OpenCTI for ATT&CK pattern by keyword; returns internal UUID
  create_report()            — create a threat-report object with D-05 retry
  create_relationship()      — create a STIX relationship (indicates) with D-05 retry

D-05: On pycti write failure, retry 3× with delays [30, 60, 120].
After all retries exhausted, log warning and return None (do not raise).

D-08: lookup_attack_pattern returns internal OpenCTI UUID (results[0]["id"]), not x_mitre_id.
D-09: ATT&CK no-match logs at INFO level with prefix "[extractor]".

Assumption A2: pycti.indicator.create() parameter name for labels is
'objectLabel' per RESEARCH.md Pattern 3 and docs.opencti.io.
Assumption A4: 'confidence' and 'x_opencti_score' are independent fields.
Setting both to the same value is safe per RESEARCH.md Pattern 3.
"""
import logging
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from pycti import OpenCTIApiClient

import entity_resolver
import queue_store
from config import OPENCTI_TOKEN, OPENCTI_URL

logger = logging.getLogger(__name__)

# D-05 retry delays: 30s → 60s → 120s
_RETRY_DELAYS = [30, 60, 120]

# In-process value→id cache. Label values repeat across a run, so resolve each once.
_label_id_cache: dict = {}


def _resolve_label_ids(client: OpenCTIApiClient, labels: list) -> list:
    """Resolve label value strings to OpenCTI label IDs (get-or-create), cached.

    indicator.create(objectLabel=...) attaches only label IDs — passing raw value
    strings silently dropped every label. label.create() is get-or-create by value.
    """
    ids = []
    for value in labels:
        if not value:
            continue
        lid = _label_id_cache.get(value)
        if lid is None:
            try:
                lid = client.label.create(value=value)["id"]
                _label_id_cache[value] = lid
            except Exception as exc:
                logger.warning("[opencti_client] label resolve failed for %r: %s", value, exc)
                continue
        ids.append(lid)
    return ids


def build_pycti_client() -> OpenCTIApiClient:
    """Build and return an OpenCTIApiClient connected to OPENCTI_URL."""
    return OpenCTIApiClient(
        url=OPENCTI_URL,
        token=OPENCTI_TOKEN,
        log_level="error",  # suppress INFO spam from pycti internals
    )


def create_indicator(
    client: OpenCTIApiClient,
    name: str,
    pattern: str,
    observable_type: str,
    confidence: int,
    labels: list,
    source_name: str,
    valid_from: Optional[str] = None,
) -> Optional[dict]:
    """
    Submit a STIX indicator to OpenCTI with idempotent upsert (update=True).

    Wraps client.indicator.create() in D-05 retry: 3x with [30, 60, 120]s delays.
    Logs a warning on each failure. Returns None after all retries exhausted.

    Args:
        client:           OpenCTIApiClient instance from build_pycti_client()
        name:             Human-readable indicator name
        pattern:          STIX 2.1 pattern string e.g. "[url:value = 'http://...']"
        observable_type:  x_opencti_main_observable_type value e.g. "IPv4-Addr"
        confidence:       0-100 confidence score (D-09 formula)
        labels:           List of label strings (malware families, tags)
        source_name:      Feed source name for externalReferences
        valid_from:       ISO-8601 UTC string; defaults to now if None

    Returns:
        dict with indicator data on success, None on failure after all retries.
    """
    if valid_from is None:
        valid_from = datetime.now(timezone.utc).isoformat()

    # objectLabel attaches by ID, not by value string — resolve once before the retry loop.
    label_ids = _resolve_label_ids(client, labels)

    last_exc: Optional[Exception] = None
    for attempt, delay in enumerate(_RETRY_DELAYS):
        try:
            return client.indicator.create(
                name=name,
                pattern_type="stix",
                pattern=pattern,
                x_opencti_main_observable_type=observable_type,
                valid_from=valid_from,
                confidence=confidence,
                x_opencti_score=confidence,  # A4: same value as confidence
                objectLabel=label_ids,        # label IDs (raw strings do not attach)
                indicator_types=["malicious-activity"],
                update=True,                 # idempotent upsert — safety net beyond Redis dedup
            )
        except Exception as exc:
            last_exc = exc
            if attempt < len(_RETRY_DELAYS) - 1:
                logger.warning(
                    "[opencti_client] indicator create attempt %d failed, retrying in %ds: %s",
                    attempt + 1,
                    delay,
                    exc,
                )
                time.sleep(delay)
            else:
                logger.warning(
                    "[opencti_client] indicator create failed after %d attempts, skipping: %s",
                    len(_RETRY_DELAYS),
                    exc,
                )

    return None


def lookup_attack_pattern(client: OpenCTIApiClient, keyword: str) -> Optional[str]:
    """
    Query OpenCTI for an ATT&CK pattern matching keyword.

    No retry — this is a read-only query. Returns the internal OpenCTI UUID
    (results[0]["id"]), NOT the x_mitre_id Txxxx string (D-08).

    Args:
        client:   OpenCTIApiClient instance
        keyword:  Technique name or keyword to search (e.g. "phishing")

    Returns:
        Internal OpenCTI UUID string on match, None if no match found (D-09).
    """
    results = client.attack_pattern.list(search=keyword, first=5)
    if not results:
        logger.info("[extractor] ATT&CK no match for: '%s' — skipping", keyword)
        return None
    return results[0]["id"]


def create_report(
    client: OpenCTIApiClient,
    name: str,
    published: str,
    description: str,
    indicator_ids: list[str],
    labels: list[str] = [],
    external_reference_ids: Optional[list[str]] = None,
    created_by_id: Optional[str] = None,
) -> Optional[dict]:
    """
    Create a threat-report in OpenCTI with all indicator objects linked.

    Uses D-05 retry: 3x with [30, 60, 120]s delays. Call only after all
    create_indicator() calls are complete (Pitfall 1 — collect all IDs first).

    Args:
        client:         OpenCTIApiClient instance
        name:           Report title
        published:      ISO-8601 UTC string (e.g. "2026-06-25T00:00:00Z")
        description:    Report summary text
        indicator_ids:  List of internal OpenCTI indicator UUIDs to attach
        external_reference_ids: Source references to attach to the Report
        created_by_id:  Optional Organization identity UUID set as the Report's createdBy

    Returns:
        dict with report data on success, None on failure after all retries.
    """
    kwargs = {
        "name": name,
        "published": published,
        "description": description,
        "objects": indicator_ids,
        "report_types": ["threat-report"],
        "objectLabel": labels if labels else [],
        "externalReferences": external_reference_ids or [],
        "update": True,
    }
    if created_by_id:
        kwargs["createdBy"] = created_by_id

    for attempt, delay in enumerate(_RETRY_DELAYS):
        try:
            return client.report.create(**kwargs)
        except Exception as exc:
            if attempt < len(_RETRY_DELAYS) - 1:
                logger.warning(
                    "[opencti_client] report create attempt %d failed, retrying in %ds: %s",
                    attempt + 1,
                    delay,
                    exc,
                )
                time.sleep(delay)
            else:
                logger.warning(
                    "[opencti_client] report create failed after %d attempts, skipping: %s",
                    len(_RETRY_DELAYS),
                    exc,
                )

    return None


def create_relationship(
    client: OpenCTIApiClient,
    from_id: str,
    to_id: str,
    relationship_type: str = "indicates",
) -> Optional[dict]:
    """
    Create a STIX core relationship between two OpenCTI objects.

    Uses D-05 retry: 3x with [30, 60, 120]s delays. Typically links an
    indicator (from_id) to an attack-pattern (to_id) via "indicates".

    Args:
        client:            OpenCTIApiClient instance
        from_id:           Internal OpenCTI UUID of source object (indicator)
        to_id:             Internal OpenCTI UUID of target object (attack-pattern)
        relationship_type: STIX relationship type (default: "indicates")

    Returns:
        dict with relationship data on success, None on failure after all retries.
    """
    for attempt, delay in enumerate(_RETRY_DELAYS):
        try:
            return client.stix_core_relationship.create(
                fromId=from_id,
                toId=to_id,
                relationship_type=relationship_type,
                update=True,
            )
        except Exception as exc:
            if attempt < len(_RETRY_DELAYS) - 1:
                logger.warning(
                    "[opencti_client] relationship create attempt %d failed, retrying in %ds: %s",
                    attempt + 1,
                    delay,
                    exc,
                )
                time.sleep(delay)
            else:
                logger.warning(
                    "[opencti_client] relationship create failed after %d attempts, skipping: %s",
                    len(_RETRY_DELAYS),
                    exc,
                )

    return None


# quick-260717-t3e: per-document association caps. Grounded names per doc are few
# in practice; caps bound the worst-case cross-product on outlier documents.
_MAX_ACTORS = 5
_MAX_MALWARE = 5
_MAX_SECTORS = 8
_MAX_COUNTRIES = 15
_MAX_CVES = 15


def _capped(names: Optional[list[str]], cap: int, label: str) -> list[str]:
    """Strip, drop empties, dedup, sort deterministically, then slice to cap."""
    cleaned = sorted(dict.fromkeys(name.strip() for name in (names or []) if name.strip()))
    if len(cleaned) > cap:
        logger.info(
            "[opencti_client] %s truncated to %d of %d grounded values",
            label, cap, len(cleaned),
        )
        cleaned = cleaned[:cap]
    return cleaned


def create_targeting_relationships(
    client: OpenCTIApiClient,
    threat_actor_names: list[str],
    sector_names: list[str],
    source_url: str,
    observed_at: str,
    malware_names: Optional[list[str]] = None,
    country_names: Optional[list[str]] = None,
    cve_ids: Optional[list[str]] = None,
) -> dict[str, list[str]]:
    """Persist source-backed targeting knowledge on four axes.

    Axes: IntrusionSet→Sector (original), Malware→Sector, IntrusionSet→Country,
    IntrusionSet→Vulnerability. Sector/country/malware axes are a doc-level
    cross-product of capped lists; the CVE axis fires only when exactly ONE actor
    is grounded (multi-actor advisories make CVE attribution ambiguous).

    The original document URL is attached directly to every created entity and
    relationship. Returned object IDs are intended for Report containment so an
    analyst can navigate from the claim back to its source document.
    """
    parsed_source = urlparse(source_url)
    if parsed_source.scheme not in {"http", "https"} or not parsed_source.hostname:
        return {"object_ids": [], "external_reference_ids": []}

    external_reference = client.external_reference.create(
        source_name=parsed_source.hostname,
        url=source_url,
        update=True,
    )
    if not external_reference or not external_reference.get("id"):
        return {"object_ids": [], "external_reference_ids": []}

    reference_ids = [external_reference["id"]]
    object_ids: list[str] = []
    actors: list[tuple[str, str]] = []
    sectors: list[tuple[str, str]] = []
    malwares: list[tuple[str, str]] = []
    countries: list[tuple[str, str]] = []
    vulnerabilities: list[tuple[str, str]] = []

    actor_names = _capped(threat_actor_names, _MAX_ACTORS, "threat actors")
    capped_sectors = _capped(sector_names, _MAX_SECTORS, "targeted sectors")
    capped_malware = _capped(malware_names, _MAX_MALWARE, "malware families")
    capped_countries = _capped(country_names, _MAX_COUNTRIES, "targeted countries")
    capped_cves = _capped(cve_ids, _MAX_CVES, "exploited CVEs")

    # Fase A (design 260724-fa): closed-world resolution — the extractor links to
    # known entities, it never invents them. Actors/malware resolve against the live
    # OpenCTI catalogs (names + aliases); sectors/countries against fixed taxonomies.
    # Every unmatched candidate is quarantined in entity_queue with its full claim,
    # never silently dropped and never written to the graph.
    actor_names, unmatched_actors = entity_resolver.split_matches(
        actor_names, entity_resolver.fetch_actor_index(client) if actor_names else {}
    )
    capped_malware, unmatched_malware = entity_resolver.split_matches(
        capped_malware,
        entity_resolver.fetch_malware_index(client) if capped_malware else {},
    )
    capped_sectors, unmatched_sectors = entity_resolver.split_taxonomy_matches(
        capped_sectors, entity_resolver.resolve_sector
    )
    capped_countries, unmatched_countries = entity_resolver.split_taxonomy_matches(
        capped_countries, entity_resolver.resolve_country
    )

    unmatched_by_category = {
        "actor": unmatched_actors,
        "malware": unmatched_malware,
        "sector": unmatched_sectors,
        "country": unmatched_countries,
    }
    claim_context = {
        "resolved_actors": actor_names,
        "resolved_malware": capped_malware,
        "resolved_sectors": capped_sectors,
        "resolved_countries": capped_countries,
        "cve_ids": capped_cves,
        "observed_at": observed_at,
    }
    for category, names in unmatched_by_category.items():
        for candidate in names:
            try:
                queue_store.enqueue(
                    category=category,
                    candidate_name=candidate,
                    claim_payload={"candidate": candidate, **claim_context},
                    source_url=source_url,
                )
            except Exception as exc:  # queue failure must not kill the ingest
                logger.warning("[opencti_client] queue insert failed for %r: %s",
                               candidate, exc)
    if any(unmatched_by_category.values()):
        logger.info(
            "[opencti_client] closed-world: quarantined %s",
            {k: v for k, v in unmatched_by_category.items() if v},
        )

    # Single-grounded-actor guard: a multi-actor doc naming CVEs would fabricate
    # N×M attribution claims; skip the axis and say so.
    cve_axis_fires = bool(capped_cves) and len(actor_names) == 1
    if capped_cves and not cve_axis_fires:
        logger.info(
            "[opencti_client] skipping %d CVE claims: %d actors grounded, attribution ambiguous",
            len(capped_cves), len(actor_names),
        )

    # Entity thrift: only upsert an endpoint when its axis can produce a relationship.
    need_actors = bool(actor_names) and (
        bool(capped_sectors) or bool(capped_countries) or cve_axis_fires
    )
    need_sectors = bool(capped_sectors) and (bool(actor_names) or bool(capped_malware))
    need_malware = bool(capped_malware) and bool(capped_sectors)
    need_countries = bool(capped_countries) and bool(actor_names)

    if need_actors:
        for actor_name in actor_names:
            # Intrusion-Set (not Threat-Actor-Group) so name-based STIX ids upsert
            # onto connector-mitre's ATT&CK groups. No description: update=True
            # would clobber MITRE's ATT&CK text on every ingest.
            actor = client.intrusion_set.create(
                name=actor_name,
                externalReferences=reference_ids,
                update=True,
            )
            if actor and actor.get("id"):
                actors.append((actor_name, actor["id"]))
                object_ids.append(actor["id"])

    if need_sectors:
        for sector_name in capped_sectors:
            # Canonical taxonomy name — already cased by entity_resolver.
            sector = client.identity.create(
                type="Sector",
                name=sector_name,
                description=f"Sector reported as targeted by {source_url}.",
                externalReferences=reference_ids,
                update=True,
            )
            if sector and sector.get("id"):
                sectors.append((sector_name, sector["id"]))
                object_ids.append(sector["id"])

    if need_malware:
        for malware_name in capped_malware:
            # Verbatim name, NO description (never clobber ATT&CK text on upsert).
            malware = client.malware.create(
                name=malware_name,
                is_family=True,
                externalReferences=reference_ids,
                update=True,
            )
            if malware and malware.get("id"):
                malwares.append((malware_name, malware["id"]))
                object_ids.append(malware["id"])

    if need_countries:
        for country_name in capped_countries:
            # Canonical name from entity_resolver's country catalog ("US" → "United
            # States") so every mention lands on one Location entity.
            country = client.location.create(
                type="Country",
                name=country_name,
                externalReferences=reference_ids,
                update=True,
            )
            if country and country.get("id"):
                countries.append((country_name, country["id"]))
                object_ids.append(country["id"])

    if cve_axis_fires and actors:
        for cve_id in capped_cves:
            # Name-based uuid5 upserts onto connector-cve's existing entities.
            vulnerability = client.vulnerability.create(
                name=cve_id,
                externalReferences=reference_ids,
                update=True,
            )
            if vulnerability and vulnerability.get("id"):
                vulnerabilities.append((cve_id, vulnerability["id"]))
                object_ids.append(vulnerability["id"])

    def _relate(from_id: str, to_id: str, description: str) -> None:
        relationship = client.stix_core_relationship.create(
            fromId=from_id,
            toId=to_id,
            relationship_type="targets",
            description=description,
            start_time=observed_at,
            externalReferences=reference_ids,
            update=True,
        )
        if relationship and relationship.get("id"):
            object_ids.append(relationship["id"])

    for actor_name, actor_id in actors:
        for sector_name, sector_id in sectors:
            _relate(actor_id, sector_id, f"{actor_name} targets the {sector_name} sector.")

    for malware_name, malware_id in malwares:
        for sector_name, sector_id in sectors:
            _relate(malware_id, sector_id, f"{malware_name} targets the {sector_name} sector.")

    for actor_name, actor_id in actors:
        for country_name, country_id in countries:
            _relate(actor_id, country_id, f"{actor_name} targets {country_name}.")

    for actor_name, actor_id in actors:
        for cve_id, vulnerability_id in vulnerabilities:
            # "names", not "exploits": the harvest semantics are "this document
            # about {actor} names {cve}" — a patched-CVE advisory must not
            # produce an overstated exploitation claim.
            _relate(
                actor_id,
                vulnerability_id,
                f"{actor_name} activity names {cve_id} (source-reported).",
            )

    return {
        "object_ids": list(dict.fromkeys(object_ids)),
        "external_reference_ids": reference_ids,
    }
