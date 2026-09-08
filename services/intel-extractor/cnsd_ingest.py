"""Explicit, controlled CNSD preview-to-OpenCTI ingestion command."""
import argparse
import copy
import hashlib
import json
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit, urlunsplit

import yaml
from pycti import ExternalReference, Identity, Indicator, Vulnerability

import stats_store
from extractor import build_stix_pattern
from opencti_client import build_pycti_client
from preview import build_collection_preview, build_document_preview


COLLECTION_URL = (
    "https://www.gob.pe/institucion/pcm/colecciones/"
    "791-alerta-integrada-de-seguridad-digital-del-cnsd"
)
SOURCE_NAME = "CNSD Integrated Digital Security Alerts"
IDENTITY_NAME = "Centro Nacional de Seguridad Digital (CNSD)"

_CONTROLLED = (
    {
        "landing_url": (
            "https://www.gob.pe/institucion/pcm/informes-publicaciones/"
            "8359341-alerta-integrada-de-seguridad-digital-n-117-2026-cnsd"
        ),
        "document_url": (
            "https://cdn.www.gob.pe/uploads/document/file/10288111/"
            "8359341-alerta-integrada-de-seguridad-digital-117-2026-cnsd.pdf"
        ),
        "publication_date": "2026-07-09",
        "vulnerabilities": (
            "CVE-2026-14544",
            "CVE-2026-8631",
            "CVE-2026-14487",
            "CVE-2026-33264",
            "CVE-2026-13019",
        ),
        "accepted_iocs": (),
    },
    {
        "landing_url": (
            "https://www.gob.pe/institucion/pcm/informes-publicaciones/"
            "8359338-alerta-integrada-de-seguridad-digital-n-116-2026-cnsd"
        ),
        "document_url": (
            "https://cdn.www.gob.pe/uploads/document/file/10288107/"
            "8359338-alerta-integrada-de-seguridad-digital-116-2026-cnsd.pdf"
        ),
        "publication_date": "2026-07-08",
        "vulnerabilities": (
            "CVE-2026-53359",
            "CVE-2026-4878",
            "CVE-2026-13356",
        ),
        "accepted_iocs": (
            ("ip", "23.133.4.108"),
            ("ip", "23.133.4.109"),
            ("ip", "27.124.40.52"),
            ("ip", "27.124.9.47"),
            ("ip", "38.45.124.19"),
            ("ip", "38.91.114.219"),
            ("ip", "154.91.75.192"),
            ("domain", "nishihaoren1.top"),
            ("domain", "nishihaoren1.org"),
        ),
    },
    {
        "landing_url": (
            "https://www.gob.pe/institucion/pcm/informes-publicaciones/"
            "8346789-alerta-integrada-de-seguridad-digital-n-115-2026-cnsd"
        ),
        "document_url": (
            "https://cdn.www.gob.pe/uploads/document/file/10271221/"
            "8346789-alerta-integrada-de-seguridad-digital-115-2026-cnsd.pdf"
        ),
        "publication_date": "2026-07-07",
        "vulnerabilities": ("CVE-2026-11405",),
        "accepted_iocs": (),
    },
)
_DEFAULT_RETRY_DELAYS = (1, 2)
_LANDING_PATH_RE = re.compile(
    r"^/institucion/pcm/informes-publicaciones/[a-z0-9-]*"
    r"alerta-integrada-de-seguridad-digital-n-(?P<number>[0-9]+)-"
    r"(?P<year>[0-9]{4})-cnsd$",
    re.IGNORECASE,
)
_DOCUMENT_PATH_RE = re.compile(
    r"^/uploads/document/file/[0-9]+/[a-z0-9-]*"
    r"alerta-integrada-de-seguridad-digital-(?P<number>[0-9]+)-"
    r"(?P<year>[0-9]{4})-cnsd\.pdf$",
    re.IGNORECASE,
)
_TITLE_RE = re.compile(
    r"^Alerta Integrada de Seguridad Digital\s+N(?:[.°º]|ro\.?)?\s*"
    r"(?P<number>[0-9]+)-(?P<year>[0-9]{4})-CNSD$",
    re.IGNORECASE,
)
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,10}$")
_REPORT_READ_ATTRIBUTES = """
    id
    standard_id
    entity_type
    name
    published
    x_opencti_stix_ids
    createdBy { ... on Identity { id standard_id entity_type name } }
    externalReferences { edges { node { id standard_id entity_type url } } }
    objects(all: true) {
        edges {
            node {
                ... on BasicObject { id entity_type }
                ... on StixObject { standard_id }
                ... on Vulnerability { name }
                ... on Indicator { name pattern }
            }
        }
    }
"""


def canonical_official_url(url: str) -> str:
    """Canonicalize a structurally valid official CNSD landing or PDF URL."""
    if not isinstance(url, str):
        raise ValueError("official URL must be a string")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("official URL has an invalid authority") from exc
    if parsed.username or parsed.password or port:
        raise ValueError("official URL contains forbidden authority data")
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    base = urlunsplit((scheme, host, parsed.path, "", ""))
    if scheme != "https":
        raise ValueError("official URL must use HTTPS")
    if host == "www.gob.pe" and _LANDING_PATH_RE.fullmatch(parsed.path):
        if parsed.query:
            raise ValueError("official landing URL query is forbidden")
        return base
    if host == "cdn.www.gob.pe" and _DOCUMENT_PATH_RE.fullmatch(parsed.path):
        return base
    raise ValueError("URL is outside the official CNSD structure")


def document_key(landing_url: str, document_url: str) -> str:
    landing = canonical_official_url(landing_url)
    document = canonical_official_url(document_url)
    return hashlib.sha256(f"{landing}\n{document}".encode()).hexdigest()


def _source(sources: list[dict], collection_url: str) -> dict:
    matches = [
        source
        for source in sources
        if source.get("type") == "html_collection"
        and source.get("url") == collection_url
        and "CNSD" in source.get("name", "")
    ]
    if len(matches) != 1:
        raise ValueError("controlled CNSD source configuration is not unique")
    source = matches[0]
    expected_pairs = [
        {"landing_url": item["landing_url"], "document_url": item["document_url"]}
        for item in _CONTROLLED
    ]
    if (
        source.get("automatic_dispatch") is not True
        or source.get("max_candidates") != 3
        or source.get("max_new_per_cycle") != 1
        or source.get("poll_interval_hours") != 24
        or source.get("dispatch_pipeline") != "cnsd_strict"
        or source.get("identity")
        != {"name": IDENTITY_NAME, "type": "Organization"}
        or source.get("processed_seed_documents") != expected_pairs
        or "controlled_documents" in source
    ):
        raise ValueError("strict CNSD source configuration is invalid")
    return source


def _load_sources() -> list[dict]:
    path = Path(__file__).with_name("sources.yaml")
    return yaml.safe_load(path.read_text())["sources"]


def _report_standard_id(landing_url: str) -> str:
    return "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, landing_url))


def _complete_extraction(metadata: dict) -> bool:
    diagnostics = metadata.get("chunk_diagnostics")
    return (
        metadata.get("status") == "complete"
        and isinstance(diagnostics, list)
        and bool(diagnostics)
        and metadata.get("chunk_count") == len(diagnostics)
        and all(item.get("status") == "complete" for item in diagnostics)
    )


def build_expected_manifest(source: dict, preview: dict) -> list[dict]:
    """Validate the fixed preview and map it to deterministic graph objects."""
    _source([source], COLLECTION_URL)
    if preview.get("errors"):
        raise ValueError("preview contains top-level errors")
    documents = preview.get("documents")
    if not isinstance(documents, list) or len(documents) != len(_CONTROLLED):
        raise ValueError("controlled preview manifest must contain exactly three documents")

    identity_standard_id = Identity.generate_id(IDENTITY_NAME, "Organization")
    manifest = []
    for position, (expected, document) in enumerate(zip(_CONTROLLED, documents)):
        try:
            landing_url = canonical_official_url(document.get("landing_url"))
            document_url = canonical_official_url(document.get("document_url"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"controlled preview URL mismatch at position {position}") from exc
        if (landing_url, document_url) != (
            expected["landing_url"],
            expected["document_url"],
        ):
            raise ValueError("controlled preview allowlist order or URL mismatch")
        if not _complete_extraction(document.get("extraction_metadata") or {}):
            raise ValueError("preview extraction is not complete")
        if document.get("publication_date") != expected["publication_date"]:
            raise ValueError("preview publication date does not match the controlled manifest")
        if not " ".join(str(document.get("title") or "").split()):
            raise ValueError("preview official title is missing")
        if tuple(document.get("vulnerabilities") or ()) != expected["vulnerabilities"]:
            raise ValueError("preview CVE set does not match the controlled manifest")
        accepted = document.get("accepted_iocs")
        if not isinstance(accepted, list):
            raise ValueError("preview IOC list is malformed")
        accepted_pairs = tuple(
            (candidate.get("type"), candidate.get("value"))
            for candidate in accepted
            if isinstance(candidate, dict)
        )
        if len(accepted_pairs) != len(accepted) or accepted_pairs != expected["accepted_iocs"]:
            raise ValueError("preview IOC set does not match the controlled manifest")
        if any(value.upper().startswith("CVE-") for _, value in accepted_pairs):
            raise ValueError("preview IOC set contains a CVE")

        vulnerabilities = [
            {
                "name": name,
                "standard_id": Vulnerability.generate_id(name),
                "entity_type": "Vulnerability",
            }
            for name in expected["vulnerabilities"]
        ]
        indicators = []
        for ioc_type, value in accepted_pairs:
            built = build_stix_pattern(ioc_type, value)
            if built is None:
                raise ValueError("preview IOC failed production STIX validation")
            pattern, observable_type = built
            indicators.append(
                {
                    "type": ioc_type,
                    "value": value,
                    "pattern": pattern,
                    "observable_type": observable_type,
                    "indicator_standard_id": Indicator.generate_id(pattern),
                    "standard_id": Indicator.generate_id(pattern),
                    "entity_type": "Indicator",
                }
            )
        external_references = [
            {
                "url": url,
                "standard_id": ExternalReference.generate_id(url=url),
                "entity_type": "External-Reference",
                "kind": kind,
            }
            for kind, url in (("landing", landing_url), ("pdf", document_url))
        ]
        manifest.append(
            {
                "document_key": document_key(landing_url, document_url),
                "landing_url": landing_url,
                "document_url": document_url,
                "title": " ".join(str(document.get("title") or "").split()),
                "publication_date": document.get("publication_date"),
                "source": source["name"],
                "identity_standard_id": identity_standard_id,
                "created_by": identity_standard_id,
                "report_standard_id": _report_standard_id(landing_url),
                "vulnerabilities": vulnerabilities,
                "indicators": indicators,
                "external_references": external_references,
                "external_reference_standard_ids": [
                    item["standard_id"] for item in external_references
                ],
                "objects": [*vulnerabilities, *indicators],
            }
        )
    return manifest


def _fallback_rows(source: dict, preview: dict | None = None) -> list[dict]:
    documents = (preview or {}).get("documents") or []
    by_landing = {
        item.get("landing_url"): item for item in documents if isinstance(item, dict)
    }
    rows = []
    for expected in _CONTROLLED:
        document = by_landing.get(expected["landing_url"], {})
        rows.append(
            {
                "document_key": document_key(
                    expected["landing_url"], expected["document_url"]
                ),
                "landing_url": expected["landing_url"],
                "document_url": expected["document_url"],
                "title": document.get("title") or expected["landing_url"].rsplit("/", 1)[-1],
                "source": source.get("name") or SOURCE_NAME,
                "vulnerability_count": len(expected["vulnerabilities"]),
                "indicator_count": len(expected["accepted_iocs"]),
                "report_standard_id": _report_standard_id(expected["landing_url"]),
            }
        )
    return rows


def _row(item: dict, *, report_id: str | None = None) -> dict:
    return {
        "document_key": item["document_key"],
        "landing_url": item["landing_url"],
        "document_url": item["document_url"],
        "title": item["title"],
        "source": item["source"],
        "vulnerability_count": len(item["vulnerabilities"]),
        "indicator_count": len(item["indicators"]),
        "report_id": report_id,
        "report_standard_id": item["report_standard_id"],
    }


def _pending_failure_row(item) -> dict:
    landing = str(getattr(item, "landing_dedup_key", "") or "")
    document = str(getattr(item, "document_dedup_key", "") or "")
    key = hashlib.sha256(f"{landing}\n{document}".encode()).hexdigest()
    return {
        "document_key": key,
        "landing_url": landing or "invalid:landing",
        "document_url": document or "invalid:document",
        "title": " ".join(str(getattr(item, "title", "") or "invalid CNSD document").split()),
        "source": getattr(item, "source_name", None) or SOURCE_NAME,
        "vulnerability_count": 0,
        "indicator_count": 0,
        "report_standard_id": "report--" + str(uuid.uuid5(uuid.NAMESPACE_URL, landing or key)),
    }


def _bulletin_coordinates(landing_url: str, document_url: str, title: str) -> tuple[str, str]:
    landing_match = _LANDING_PATH_RE.fullmatch(urlsplit(landing_url).path)
    document_match = _DOCUMENT_PATH_RE.fullmatch(urlsplit(document_url).path)
    title_match = _TITLE_RE.fullmatch(title)
    if not landing_match or not document_match or not title_match:
        raise ValueError("CNSD bulletin URL/title format is invalid")
    coordinates = {
        (match.group("number"), match.group("year"))
        for match in (landing_match, document_match, title_match)
    }
    if len(coordinates) != 1:
        raise ValueError("CNSD bulletin number/year provenance conflicts")
    return coordinates.pop()


def build_discovered_manifest(source: dict, item, preview: dict) -> list[dict]:
    """Validate one discovered document and map it to deterministic graph objects."""
    _source([source], COLLECTION_URL)
    if getattr(item, "dispatch_pipeline", None) != "cnsd_strict":
        raise ValueError("CNSD document is not assigned to the strict dispatcher")
    if not isinstance(getattr(item, "content", None), bytes) or not item.content.lstrip().startswith(
        b"%PDF-"
    ):
        raise ValueError("CNSD document bytes are not a confirmed PDF")

    landing_url = canonical_official_url(item.landing_dedup_key)
    document_url = canonical_official_url(item.document_dedup_key)
    title = " ".join(str(item.title or "").split())
    publication_date = str(item.publication_date or "")
    number, year = _bulletin_coordinates(landing_url, document_url, title)
    try:
        published = datetime.strptime(publication_date, "%Y-%m-%d")
    except ValueError as exc:
        raise ValueError("CNSD publication date is invalid") from exc
    if str(published.year) != year:
        raise ValueError("CNSD publication date conflicts with bulletin year")
    if item.title_source not in {
        "collection_anchor+landing_confirmed",
        "landing_main_h1",
        "landing_main_h2",
    } or item.publication_date_source not in {
        "collection_card_time+landing_confirmed",
        "collection_card_text+landing_confirmed",
        "landing_main_time",
        "landing_main_text",
    }:
        raise ValueError("CNSD provenance source is invalid")

    if not isinstance(preview, dict):
        raise ValueError("document preview is malformed")
    if canonical_official_url(preview.get("landing_url")) != landing_url or canonical_official_url(
        preview.get("document_url")
    ) != document_url:
        raise ValueError("document preview URL provenance conflicts")
    if " ".join(str(preview.get("title") or "").split()) != title:
        raise ValueError("document preview title provenance conflicts")
    if preview.get("publication_date") != publication_date:
        raise ValueError("document preview date provenance conflicts")
    if not _complete_extraction(preview.get("extraction_metadata") or {}):
        raise ValueError("document preview extraction is incomplete")

    vulnerability_names = preview.get("vulnerabilities")
    if not isinstance(vulnerability_names, list) or any(
        not isinstance(name, str) or not _CVE_RE.fullmatch(name)
        for name in vulnerability_names
    ) or len(vulnerability_names) != len(set(vulnerability_names)):
        raise ValueError("document preview CVE set is malformed")
    vulnerabilities = [
        {
            "name": name,
            "standard_id": Vulnerability.generate_id(name),
            "entity_type": "Vulnerability",
        }
        for name in vulnerability_names
    ]

    accepted = preview.get("accepted_iocs")
    if not isinstance(accepted, list):
        raise ValueError("document preview IOC set is malformed")
    indicators = []
    seen_iocs = set()
    for candidate in accepted:
        if not isinstance(candidate, dict) or set(candidate) != {"type", "value"}:
            raise ValueError("document preview IOC shape is malformed")
        ioc_type, value = candidate["type"], candidate["value"]
        if not isinstance(value, str) or value.upper().startswith("CVE-"):
            raise ValueError("document preview IOC policy rejected candidate")
        built = build_stix_pattern(ioc_type, value)
        if built is None:
            raise ValueError("document preview IOC failed production STIX validation")
        pattern, observable_type = built
        if (ioc_type, value) in seen_iocs:
            continue
        seen_iocs.add((ioc_type, value))
        standard_id = Indicator.generate_id(pattern)
        indicators.append(
            {
                "type": ioc_type,
                "value": value,
                "pattern": pattern,
                "observable_type": observable_type,
                "indicator_standard_id": standard_id,
                "standard_id": standard_id,
                "entity_type": "Indicator",
            }
        )

    identity_standard_id = Identity.generate_id(IDENTITY_NAME, "Organization")
    external_references = [
        {
            "url": url,
            "standard_id": ExternalReference.generate_id(url=url),
            "entity_type": "External-Reference",
            "kind": kind,
        }
        for kind, url in (("landing", landing_url), ("pdf", document_url))
    ]
    manifest_document = {
        "document_key": document_key(landing_url, document_url),
        "bulletin_number": number,
        "landing_url": landing_url,
        "document_url": document_url,
        "title": title,
        "publication_date": publication_date,
        "source": source["name"],
        "identity_standard_id": identity_standard_id,
        "created_by": identity_standard_id,
        "report_standard_id": _report_standard_id(landing_url),
        "vulnerabilities": vulnerabilities,
        "indicators": indicators,
        "external_references": external_references,
        "external_reference_standard_ids": [
            reference["standard_id"] for reference in external_references
        ],
        "objects": [*vulnerabilities, *indicators],
    }
    return [manifest_document]


def ingest_discovered_document(
    item,
    *,
    preview_builder=build_document_preview,
    client=None,
    retry_delays: tuple[int, ...] = _DEFAULT_RETRY_DELAYS,
) -> dict:
    """Preview, strictly write, and read back one dynamically discovered bulletin."""
    stats_store.init_db()
    fallback = _pending_failure_row(item)
    try:
        source = _source([item.source_config], COLLECTION_URL)
        preview = preview_builder(item)
        manifest = build_discovered_manifest(source, item, preview)
    except Exception as exc:
        stats_store.record_failed(**fallback, error=exc)
        raise

    document = manifest[0]
    stats_store.record_previewed(**_row(document))
    try:
        graph = _write_and_verify(
            client or build_pycti_client(), source, manifest, tuple(retry_delays)
        )
        report = graph["reports"][document["report_standard_id"]]
        stats_store.record_ingested(
            **_row(document, report_id=report["id"]), update_totals=True
        )
    except Exception as exc:
        stats_store.record_failed(**_row(document), error=exc)
        raise
    return {
        "ok": True,
        "document": {
            "document_key": document["document_key"],
            "report_id": report["id"],
            "report_standard_id": report["standard_id"],
            "report_canonical_id": document["report_standard_id"],
            "vulnerability_count": len(document["vulnerabilities"]),
            "indicator_count": len(document["indicators"]),
        },
    }


def _strict_create(
    api,
    payload: dict,
    retry_delays: tuple[int, ...],
    *,
    allow_standard_id_alias: bool = False,
) -> dict:
    attempts = len(retry_delays) + 1
    last_error = None
    for attempt in range(attempts):
        try:
            result = api.create(**payload)
            if not isinstance(result, dict) or not result.get("id"):
                raise RuntimeError("OpenCTI returned a malformed create result")
            if (
                result.get("standard_id") != payload["stix_id"]
                and not allow_standard_id_alias
            ):
                raise RuntimeError("OpenCTI returned a mismatched standard ID")
            return result
        except Exception as exc:
            last_error = exc
            if attempt < len(retry_delays):
                time.sleep(retry_delays[attempt])
    raise RuntimeError(f"required OpenCTI write failed: {last_error}") from last_error


def _strict_read(
    api,
    canonical_id: str,
    *,
    expected_standard_id: str | None = None,
    allow_alias: bool = False,
    custom_attributes: str | None = None,
) -> dict:
    kwargs = {"id": canonical_id}
    if custom_attributes is not None:
        kwargs["customAttributes"] = custom_attributes
    result = api.read(**kwargs)
    actual_standard_id = result.get("standard_id") if isinstance(result, dict) else None
    aliases = result.get("x_opencti_stix_ids") or [] if isinstance(result, dict) else []
    valid_alias = allow_alias and canonical_id in aliases
    standard_matches = (
        actual_standard_id == expected_standard_id
        if expected_standard_id is not None
        else actual_standard_id == canonical_id or valid_alias
    )
    if (
        not isinstance(result, dict)
        or not standard_matches
        or (actual_standard_id != canonical_id and not valid_alias)
    ):
        raise RuntimeError(f"OpenCTI read-back verification failed for {canonical_id}")
    return result


def _nodes(value) -> list[dict]:
    if value is None:
        return []
    if isinstance(value, list):
        return [item if isinstance(item, dict) else {"id": item} for item in value]
    if isinstance(value, dict) and isinstance(value.get("edges"), list):
        return [edge.get("node", {}) for edge in value["edges"]]
    return []


def _reference_ids(value) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict) and (value.get("id") or value.get("standard_id")):
        return {value.get("standard_id") or value["id"]}
    return {
        node.get("standard_id") or node.get("id")
        for node in _nodes(value)
        if node.get("standard_id") or node.get("id")
    }


def _write_and_verify(client, source: dict, manifest: list[dict], retry_delays) -> dict:
    identity_standard_id = manifest[0]["identity_standard_id"]
    identity_result = _strict_create(
        client.identity,
        {
            "type": source["identity"]["type"],
            "name": source["identity"]["name"],
            "description": "Official publisher of Peru CNSD integrated digital security alerts.",
            "stix_id": identity_standard_id,
            "update": True,
        },
        retry_delays,
    )

    reference_results = {}
    vulnerability_results = {}
    indicator_results = {}
    for document in manifest:
        for reference in document["external_references"]:
            standard_id = reference["standard_id"]
            if standard_id not in reference_results:
                reference_results[standard_id] = _strict_create(
                    client.external_reference,
                    {
                        "source_name": f"CNSD official {reference['kind']}",
                        "url": reference["url"],
                        "description": "Official CNSD bulletin provenance.",
                        "stix_id": standard_id,
                        "update": True,
                    },
                    retry_delays,
                )
        for vulnerability in document["vulnerabilities"]:
            standard_id = vulnerability["standard_id"]
            if standard_id not in vulnerability_results:
                vulnerability_results[standard_id] = _strict_create(
                    client.vulnerability,
                    {
                        "name": vulnerability["name"],
                        "description": "Vulnerability explicitly listed by the CNSD bulletin.",
                        "stix_id": standard_id,
                        "update": True,
                    },
                    retry_delays,
                )
        for indicator in document["indicators"]:
            standard_id = indicator["standard_id"]
            if standard_id not in indicator_results:
                indicator_results[standard_id] = _strict_create(
                    client.indicator,
                    {
                        "name": f"{indicator['type']}:{indicator['value']}",
                        "description": "Explicit IOC from the CNSD bulletin IOC section.",
                        "pattern_type": "stix",
                        "pattern": indicator["pattern"],
                        "x_opencti_main_observable_type": indicator["observable_type"],
                        "valid_from": document["publication_date"] + "T00:00:00Z",
                        "createdBy": identity_result["id"],
                        "stix_id": standard_id,
                        "update": True,
                    },
                    retry_delays,
                )

    report_results = {}
    for document in manifest:
        object_ids = [
            vulnerability_results[item["standard_id"]]["id"]
            for item in document["vulnerabilities"]
        ] + [
            indicator_results[item["standard_id"]]["id"]
            for item in document["indicators"]
        ]
        reference_ids = [
            reference_results[item["standard_id"]]["id"]
            for item in document["external_references"]
        ]
        report_results[document["report_standard_id"]] = _strict_create(
            client.report,
            {
                "name": document["title"],
                "description": (
                    "Official CNSD bulletin ingested from its canonical gob.pe landing "
                    "page and PDF. Vulnerabilities and indicators are limited to this "
                    "bulletin's independently verified extraction."
                ),
                "published": document["publication_date"] + "T00:00:00Z",
                "report_types": ["threat-report"],
                "createdBy": identity_result["id"],
                "externalReferences": reference_ids,
                "objects": object_ids,
                "stix_id": document["report_standard_id"],
                "update": True,
            },
            retry_delays,
            allow_standard_id_alias=True,
        )

    identity_read = _strict_read(client.identity, identity_standard_id)
    for standard_id in reference_results:
        _strict_read(client.external_reference, standard_id)
    for standard_id in vulnerability_results:
        _strict_read(client.vulnerability, standard_id)
    for standard_id in indicator_results:
        _strict_read(client.indicator, standard_id)
    for document in manifest:
        created_report = report_results[document["report_standard_id"]]
        report = _strict_read(
            client.report,
            document["report_standard_id"],
            expected_standard_id=created_report["standard_id"],
            allow_alias=True,
            custom_attributes=_REPORT_READ_ATTRIBUTES,
        )
        expected_creator = {identity_result["id"], identity_standard_id}
        if not (_reference_ids(report.get("createdBy")) & expected_creator):
            raise RuntimeError("OpenCTI Report read-back creator verification failed")
        expected_references = {
            reference_results[item["standard_id"]]["id"]
            for item in document["external_references"]
        } | set(document["external_reference_standard_ids"])
        read_references = _reference_ids(report.get("externalReferences"))
        if len(read_references) != 2 or not read_references <= expected_references:
            raise RuntimeError("OpenCTI Report read-back external reference verification failed")
        expected_objects = {
            vulnerability_results[item["standard_id"]]["id"]
            for item in document["vulnerabilities"]
        } | {
            indicator_results[item["standard_id"]]["id"]
            for item in document["indicators"]
        } | {item["standard_id"] for item in document["objects"]}
        read_objects = _reference_ids(report.get("objects"))
        if len(read_objects) != len(document["objects"]) or not read_objects <= expected_objects:
            raise RuntimeError("OpenCTI Report read-back object verification failed")
    return {
        "identity": identity_read,
        "reports": report_results,
    }


def ingest_cnsd(
    collection_url: str,
    limit: int,
    *,
    sources: list[dict] | None = None,
    preview_builder=build_collection_preview,
    client=None,
    acknowledge=None,
    retry_delays: tuple[int, ...] = _DEFAULT_RETRY_DELAYS,
) -> dict:
    """Ingest the exact 117/116/115 manifest and roll forward deterministic IDs."""
    if collection_url != COLLECTION_URL or limit != 3:
        raise ValueError("controlled ingestion requires the canonical collection URL and limit 3")
    stats_store.init_db()
    configured_source = _source(sources or _load_sources(), collection_url)
    preview = preview_builder(collection_url, limit)
    try:
        manifest = build_expected_manifest(configured_source, preview)
    except Exception as exc:
        for row in _fallback_rows(configured_source, preview):
            stats_store.record_failed(**row, error=exc)
        raise

    for document in manifest:
        stats_store.record_previewed(**_row(document))
    try:
        graph = _write_and_verify(
            client or build_pycti_client(),
            configured_source,
            manifest,
            tuple(retry_delays),
        )
        for document in manifest:
            result = graph["reports"][document["report_standard_id"]]
            stats_store.record_ingested(
                **_row(document, report_id=result["id"]),
                update_totals=True,
            )
        if acknowledge is not None:
            for document in manifest:
                acknowledge(
                    SimpleNamespace(
                        mode="pdf",
                        content=None,
                        url=None,
                        source_type="bulletin",
                        source_name=configured_source["name"],
                        landing_dedup_key=document["landing_url"],
                        document_dedup_key=document["document_url"],
                        title=document["title"],
                        publication_date=document["publication_date"],
                    )
                )
    except Exception as exc:
        for document in manifest:
            report = locals().get("graph", {}).get("reports", {}).get(
                document["report_standard_id"], {}
            )
            stats_store.record_failed(
                **_row(document, report_id=report.get("id")), error=exc
            )
        raise
    return {
        "ok": True,
        "documents": [
            {
                "document_key": document["document_key"],
                "report_id": graph["reports"][document["report_standard_id"]]["id"],
                "report_standard_id": graph["reports"][document["report_standard_id"]][
                    "standard_id"
                ],
                "report_canonical_id": document["report_standard_id"],
                "vulnerability_count": len(document["vulnerabilities"]),
                "indicator_count": len(document["indicators"]),
            }
            for document in manifest
        ],
    }


def _read_snapshot_entity(
    api,
    canonical_id: str,
    *,
    allow_alias: bool = False,
    custom_attributes: str | None = None,
) -> dict:
    entity = _strict_read(
        api,
        canonical_id,
        expected_standard_id=None,
        allow_alias=allow_alias,
        custom_attributes=custom_attributes,
    )
    return copy.deepcopy(entity)


def _standard_node(node: dict) -> dict:
    return {
        "id": node.get("id"),
        "standard_id": node.get("standard_id"),
        "entity_type": node.get("entity_type"),
        "name": node.get("name"),
        "url": node.get("url"),
    }


def _duplicate_count(api, standard_id: str) -> int:
    rows = api.list(
        filters={
            "mode": "and",
            "filters": [{"key": "standard_id", "values": [standard_id]}],
            "filterGroups": [],
        }
    )
    return max(0, len(rows) - 1)


def verify_cnsd(
    collection_url: str,
    limit: int,
    *,
    sources: list[dict] | None = None,
    client=None,
) -> dict:
    """Read the exact graph from OpenCTI and return a machine-readable snapshot."""
    if collection_url != COLLECTION_URL or limit != 3:
        raise ValueError("controlled verification requires the canonical collection URL and limit 3")
    stats_store.init_db()
    source = _source(sources or _load_sources(), collection_url)
    client = client or build_pycti_client()
    identity_standard_id = Identity.generate_id(IDENTITY_NAME, "Organization")
    identity = _read_snapshot_entity(client.identity, identity_standard_id)

    specs = []
    for controlled in _CONTROLLED:
        vulnerabilities = [
            {
                "name": name,
                "standard_id": Vulnerability.generate_id(name),
                "entity_type": "Vulnerability",
            }
            for name in controlled["vulnerabilities"]
        ]
        indicators = []
        for ioc_type, value in controlled["accepted_iocs"]:
            pattern, observable_type = build_stix_pattern(ioc_type, value)
            indicators.append(
                {
                    "type": ioc_type,
                    "value": value,
                    "pattern": pattern,
                    "observable_type": observable_type,
                    "standard_id": Indicator.generate_id(pattern),
                    "entity_type": "Indicator",
                }
            )
        refs = [
            {"url": url, "standard_id": ExternalReference.generate_id(url=url)}
            for url in (controlled["landing_url"], controlled["document_url"])
        ]
        specs.append(
            {
                **controlled,
                "report_standard_id": _report_standard_id(controlled["landing_url"]),
                "vulnerability_objects": vulnerabilities,
                "indicator_objects": indicators,
                "external_references": refs,
            }
        )

    vulnerabilities = []
    indicators = []
    external_references = []
    reports = []
    duplicate_counts = {identity_standard_id: _duplicate_count(client.identity, identity_standard_id)}
    seen = set()
    for spec in specs:
        for expected in spec["vulnerability_objects"]:
            if expected["standard_id"] in seen:
                continue
            seen.add(expected["standard_id"])
            entity = _read_snapshot_entity(client.vulnerability, expected["standard_id"])
            vulnerabilities.append(
                {
                    "id": entity.get("id"),
                    "standard_id": entity.get("standard_id"),
                    "name": entity.get("name"),
                }
            )
            duplicate_counts[expected["standard_id"]] = _duplicate_count(
                client.vulnerability, expected["standard_id"]
            )
        for expected in spec["indicator_objects"]:
            if expected["standard_id"] in seen:
                continue
            seen.add(expected["standard_id"])
            entity = _read_snapshot_entity(client.indicator, expected["standard_id"])
            indicators.append(
                {
                    "id": entity.get("id"),
                    "standard_id": entity.get("standard_id"),
                    "value": expected["value"],
                    "pattern": entity.get("pattern"),
                }
            )
            duplicate_counts[expected["standard_id"]] = _duplicate_count(
                client.indicator, expected["standard_id"]
            )
        for expected in spec["external_references"]:
            if expected["standard_id"] in seen:
                continue
            seen.add(expected["standard_id"])
            entity = _read_snapshot_entity(client.external_reference, expected["standard_id"])
            external_references.append(
                {
                    "id": entity.get("id"),
                    "standard_id": entity.get("standard_id"),
                    "url": entity.get("url"),
                }
            )
            duplicate_counts[expected["standard_id"]] = _duplicate_count(
                client.external_reference, expected["standard_id"]
            )
        report = _read_snapshot_entity(
            client.report,
            spec["report_standard_id"],
            allow_alias=True,
            custom_attributes=_REPORT_READ_ATTRIBUTES,
        )
        creator = report.get("createdBy")
        creator_standard_id = (
            creator.get("standard_id") if isinstance(creator, dict) else identity_standard_id
        )
        report_refs = sorted(
            [_standard_node(node) for node in _nodes(report.get("externalReferences"))],
            key=lambda item: item.get("standard_id") or item.get("id") or "",
        )
        report_objects = sorted(
            [_standard_node(node) for node in _nodes(report.get("objects"))],
            key=lambda item: item.get("standard_id") or item.get("id") or "",
        )
        reports.append(
            {
                "id": report.get("id"),
                "standard_id": report.get("standard_id"),
                "canonical_id": spec["report_standard_id"],
                "name": report.get("name"),
                "published": report.get("published"),
                "created_by": creator_standard_id,
                "external_references": report_refs,
                "objects": report_objects,
            }
        )
        duplicate_counts[spec["report_standard_id"]] = _duplicate_count(
            client.report, report["standard_id"]
        )

    controlled_keys = {
        document_key(item["landing_url"], item["document_url"]) for item in _CONTROLLED
    }
    document_rows = [
        row for row in stats_store.get_recent_documents(50)
        if row["document_key"] in controlled_keys
    ]
    expected_vulnerabilities = {
        item["standard_id"]: item["name"]
        for spec in specs
        for item in spec["vulnerability_objects"]
    }
    expected_indicators = {
        item["standard_id"]: (item["value"], item["pattern"])
        for spec in specs
        for item in spec["indicator_objects"]
    }
    expected_references = {
        item["standard_id"]: item["url"]
        for spec in specs
        for item in spec["external_references"]
    }
    expected_reports = {spec["report_standard_id"]: spec for spec in specs}
    reports_by_id = {report["canonical_id"]: report for report in reports}
    rows_by_report = {row["report_standard_id"]: row for row in document_rows}
    exact_report_links = True
    for standard_id, spec in expected_reports.items():
        report = reports_by_id.get(standard_id, {})
        reference_ids = {
            item.get("standard_id") for item in report.get("external_references", [])
        }
        object_ids = {item.get("standard_id") for item in report.get("objects", [])}
        expected_reference_ids = {
            item["standard_id"] for item in spec["external_references"]
        }
        expected_object_ids = {
            item["standard_id"]
            for item in (*spec["vulnerability_objects"], *spec["indicator_objects"])
        }
        row = rows_by_report.get(standard_id, {})
        exact_report_links = exact_report_links and (
            reference_ids == expected_reference_ids
            and object_ids == expected_object_ids
            and report.get("published", "")[:10] == spec["publication_date"]
            and report.get("name") == row.get("title")
            and report.get("id") == row.get("report_id")
        )
    aggregate_stats = stats_store.get_stats()
    ok = (
        identity.get("standard_id") == identity_standard_id
        and identity.get("name") == IDENTITY_NAME
        and len(reports) == 3
        and len(vulnerabilities) == 9
        and len(indicators) == 9
        and len(external_references) == 6
        and len(document_rows) == 3
        and all(row["status"] == "ingested" for row in document_rows)
        and all(value == 0 for value in duplicate_counts.values())
        and all(report["created_by"] == identity_standard_id for report in reports)
        and {item["standard_id"]: item["name"] for item in vulnerabilities}
        == expected_vulnerabilities
        and {
            item["standard_id"]: (item["value"], item["pattern"])
            for item in indicators
        }
        == expected_indicators
        and {item["standard_id"]: item["url"] for item in external_references}
        == expected_references
        and exact_report_links
        and all(len(report["external_references"]) == 2 for report in reports)
        and not any(
            obj.get("entity_type") == "Attack-Pattern"
            for report in reports
            for obj in report["objects"]
        )
    )
    return {
        "ok": ok,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "identity": {
            "id": identity.get("id"),
            "standard_id": identity.get("standard_id"),
            "name": identity.get("name"),
        },
        "reports": reports,
        "vulnerabilities": vulnerabilities,
        "indicators": indicators,
        "external_references": external_references,
        "duplicate_counts": duplicate_counts,
        "document_rows": document_rows,
        "aggregate_stats": aggregate_stats,
        "source": {
            "name": source["name"],
            "automatic_dispatch": source["automatic_dispatch"],
        },
    }


def poll_once(
    collection_url: str,
    *,
    now: str,
    force: bool = False,
    dry_run: bool = False,
) -> dict:
    """Compose the collector one-shot path without creating a client for dry runs."""
    import collector

    dispatchers = {} if dry_run else {"cnsd_strict": ingest_discovered_document}
    return collector.run_collection_poll_once(
        collection_url,
        now=now,
        force=force,
        dry_run=dry_run,
        dispatchers=dispatchers,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Controlled CNSD OpenCTI ingestion")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("ingest", "verify"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--collection-url", required=True)
        subparser.add_argument("--limit", type=int, required=True)
    poll_parser = subparsers.add_parser("poll-once")
    poll_parser.add_argument("--collection-url", required=True)
    poll_parser.add_argument("--now", required=True)
    poll_parser.add_argument("--force", action="store_true")
    poll_parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "ingest":
            result = ingest_cnsd(args.collection_url, args.limit)
        elif args.command == "verify":
            result = verify_cnsd(args.collection_url, args.limit)
        else:
            result = poll_once(
                args.collection_url,
                now=args.now,
                force=args.force,
                dry_run=args.dry_run,
            )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result.get("ok") else 1
    except Exception as exc:
        print(
            json.dumps(
                {"ok": False, "error": stats_store._sanitize_error(exc)},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
