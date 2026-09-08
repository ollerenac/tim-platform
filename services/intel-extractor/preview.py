"""Read-only CNSD extraction preview helpers and CLI."""

import argparse
import importlib
import json
import os
import re
import time

import collector
from parser import extract_pdf_text


_CVE_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"CVE\s*-\s*(?P<year>[0-9]{4})\s*-\s*"
    r"(?P<sequence>[0-9]+(?:(?:\r?\n[ \t]*|\u00ad[ \t\r\n]*|[-\u2010-\u2015]\r?\n[ \t]*)[0-9]+)*)"
    r"(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_CVE_CANONICAL_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,10}$")
_CVE_WRAP_RE = re.compile(r"\r?\n[ \t]*|\u00ad[ \t\r\n]*|[-\u2010-\u2015]\r?\n[ \t]*")

_TITLE_SOURCES = {
    "collection_anchor+landing_confirmed",
    "landing_main_h1",
    "landing_main_h2",
}
_PUBLICATION_DATE_SOURCES = {
    "collection_card_time+landing_confirmed",
    "collection_card_text+landing_confirmed",
    "landing_main_time",
    "landing_main_text",
}
_GUARD_TARGETS = {
    "collector_save_state": ("collector", "_save_state"),
    "run_extraction": ("extractor", "run_extraction"),
    "opencti_client_init": ("extractor", "build_pycti_client"),
    "create_indicator": ("extractor", "create_indicator"),
    "create_report": ("extractor", "create_report"),
    "create_relationship": ("extractor", "create_relationship"),
    "create_targeting_relationships": ("extractor", "create_targeting_relationships"),
    "stats_init_db": ("stats", "init_db"),
    "stats_increment": ("stats", "increment"),
    "stats_conn": ("stats", "_conn"),
}


def normalize_cve_candidates(text: str) -> list[dict]:
    """Return ordered CVE candidates while admitting only PDF line-wrap artifacts."""
    candidates: list[dict] = []
    by_id: dict[str, dict] = {}

    for match in _CVE_RE.finditer(text):
        sequence = _CVE_WRAP_RE.sub("", match.group("sequence"))
        canonical = f"CVE-{match.group('year')}-{sequence}".upper()
        if not _CVE_CANONICAL_RE.fullmatch(canonical):
            continue

        raw = match.group(0)
        candidate = by_id.get(canonical)
        if candidate is None:
            candidate = {
                "id": canonical,
                "raw_forms": [],
                "occurrence_count": 0,
                "offsets": [],
            }
            by_id[canonical] = candidate
            candidates.append(candidate)
        if raw not in candidate["raw_forms"]:
            candidate["raw_forms"].append(raw)
        candidate["occurrence_count"] += 1
        candidate["offsets"].append({"start": match.start(), "end": match.end()})

    return candidates


def _empty_evidence(state_before: dict, db_before: dict) -> dict:
    return {
        "opencti_credentials_present": bool(os.environ.get("OPENCTI_TOKEN")),
        "state_path": str(collector.STATE_PATH),
        "db_path": str(collector.DB_PATH),
        "state_before": state_before,
        "state_post_import": state_before,
        "state_after": state_before,
        "db_before": db_before,
        "db_post_import": db_before,
        "db_after": db_before,
        "import_state_mutated": False,
        "import_db_mutated": False,
        "collector_state_mutated": False,
        "stats_db_mutated": False,
        "write_attempts": {key: 0 for key in _GUARD_TARGETS},
    }


def _base_result(collection_url: str, requested_limit: int) -> dict:
    return {
        "collection_url": collection_url,
        "source_identity": {},
        "requested_limit": requested_limit,
        "effective_limit": 0,
        "documents": [],
        "no_write_evidence": {},
        "errors": [],
    }


def _validate_document_provenance(document) -> None:
    if not document.title or not " ".join(document.title.split()):
        raise ValueError("missing normalized title")
    if document.title_source not in _TITLE_SOURCES:
        raise ValueError("invalid title_source")
    if document.publication_date_source not in _PUBLICATION_DATE_SOURCES:
        raise ValueError("invalid publication_date_source")
    if not isinstance(document.publication_date, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}", document.publication_date
    ):
        raise ValueError("invalid publication_date")
    if not document.landing_dedup_key or not document.document_dedup_key:
        raise ValueError("missing landing or document URL")


def _document_preview(document, extractor) -> dict:
    _validate_document_provenance(document)
    if not isinstance(document.content, bytes) or not document.content:
        raise ValueError("missing PDF bytes")
    if not document.content.lstrip().startswith(b"%PDF-"):
        raise ValueError("document bytes are not a confirmed PDF")

    started = time.monotonic()
    text = extract_pdf_text(document.content)
    if not isinstance(text, str) or not text.strip():
        raise ValueError("PDF parser returned no text")
    extraction = extractor.extract_from_text(
        text, "bulletin", include_diagnostics=True
    )
    if not isinstance(extraction, dict):
        raise ValueError("extractor returned a malformed result")
    accepted = extraction.get("accepted_iocs")
    rejected = extraction.get("rejected_ioc_candidates")
    chunk_diagnostics = extraction.get("chunk_diagnostics")
    if (
        not isinstance(accepted, list)
        or not isinstance(rejected, list)
        or not isinstance(chunk_diagnostics, list)
        or not chunk_diagnostics
    ):
        raise ValueError("extractor diagnostics are incomplete")
    for candidate in accepted:
        if set(candidate) != {"type", "value"}:
            raise ValueError("accepted IOC has invalid shape")
        if str(candidate["value"]).upper().startswith("CVE-"):
            raise ValueError("CVE leaked into accepted indicators")
        if extractor.build_stix_pattern(candidate["type"], candidate["value"]) is None:
            raise ValueError("accepted IOC failed production STIX validation")
    known_stages = {
        "response_parser",
        "grounding",
        "dedup",
        "bulletin_policy",
        "shape_validation",
    }
    for candidate in rejected:
        if set(candidate) != {"type", "value", "reason", "stage"}:
            raise ValueError("rejected IOC has invalid shape")
        if not candidate["reason"] or candidate["stage"] not in known_stages:
            raise ValueError("rejected IOC lacks stable diagnostics")

    chunk_keys = {"chunk_index", "status", "attempts", "retry_count", "error"}
    for index, diagnostic in enumerate(chunk_diagnostics):
        if set(diagnostic) != chunk_keys:
            raise ValueError("chunk diagnostic has invalid shape")
        if diagnostic["chunk_index"] != index:
            raise ValueError("chunk diagnostics are out of order")
        if diagnostic["status"] not in {"complete", "error"}:
            raise ValueError("chunk diagnostic has invalid status")
        if (
            not isinstance(diagnostic["attempts"], int)
            or diagnostic["attempts"] < 1
            or not isinstance(diagnostic["retry_count"], int)
            or diagnostic["retry_count"] != diagnostic["attempts"] - 1
        ):
            raise ValueError("chunk diagnostic has invalid retry counts")
        if diagnostic["status"] == "complete" and diagnostic["error"] is not None:
            raise ValueError("complete chunk carries an error")
        if diagnostic["status"] == "error" and not diagnostic["error"]:
            raise ValueError("failed chunk lacks an error")

    cves = normalize_cve_candidates(text)
    chunks = extractor.chunk_text(text)
    if len(chunk_diagnostics) != len(chunks):
        raise ValueError("chunk diagnostic count does not match extraction chunks")
    extraction_complete = all(
        diagnostic["status"] == "complete" for diagnostic in chunk_diagnostics
    )
    if not extraction_complete:
        accepted = []
    retry_count = sum(
        diagnostic["retry_count"] for diagnostic in chunk_diagnostics
    )
    elapsed_ms = max(0, int((time.monotonic() - started) * 1000))
    return {
        "title": " ".join(document.title.split()),
        "publication_date": document.publication_date,
        "title_source": document.title_source,
        "publication_date_source": document.publication_date_source,
        "landing_url": document.landing_dedup_key,
        "document_url": document.document_dedup_key,
        "cve_candidates": cves,
        "vulnerabilities": [candidate["id"] for candidate in cves],
        "accepted_iocs": accepted,
        "rejected_ioc_candidates": rejected,
        "extraction_metadata": {
            "status": "complete" if extraction_complete else "error",
            "pdf_bytes": len(document.content),
            "text_chars": len(text),
            "chunk_count": len(chunks),
            "chunk_diagnostics": chunk_diagnostics,
            "retry_count": retry_count,
            "model": extractor.OLLAMA_MODEL,
            "source_type": "bulletin",
            "elapsed_ms": elapsed_ms,
        },
    }


def build_document_preview(document, *, extractor=None) -> dict:
    """Build one read-only preview for a previously confined collection document."""
    extractor = extractor or importlib.import_module("extractor")
    return _document_preview(document, extractor)


def build_collection_preview(collection_url: str, limit: int) -> dict:
    """Compose bounded discovery and extraction under measured fail-closed guards."""
    result = _base_result(collection_url, limit)
    state_before = collector._snapshot_path(collector.STATE_PATH)
    db_before = collector._snapshot_path(collector.DB_PATH)
    evidence = _empty_evidence(state_before, db_before)
    result["no_write_evidence"] = evidence

    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        result["errors"].append("limit must be a positive integer")
        return result
    matches = [
        source
        for source in collector._load_sources()
        if source.get("type") == "html_collection" and source.get("url") == collection_url
    ]
    if len(matches) != 1:
        result["errors"].append(
            "collection URL must exactly match one configured html_collection"
        )
        return result
    source = matches[0]
    configured_cap = source.get("max_candidates")
    if isinstance(configured_cap, bool) or not isinstance(configured_cap, int) or configured_cap < 1:
        result["errors"].append("configured max_candidates is invalid")
        return result
    effective_limit = min(limit, configured_cap)
    result["effective_limit"] = effective_limit
    result["source_identity"] = {
        "name": source.get("name"),
        "type": source.get("type"),
        "source_type": source.get("source_type"),
        "collection_url": source.get("url"),
    }

    originals: list[tuple[object, str, object]] = []
    modules: dict[str, object] = {"collector": collector}
    try:
        extractor = importlib.import_module("extractor")
        stats = importlib.import_module("stats_store")
        modules.update(extractor=extractor, stats=stats)
        evidence["state_post_import"] = collector._snapshot_path(collector.STATE_PATH)
        evidence["db_post_import"] = collector._snapshot_path(collector.DB_PATH)
        evidence["import_state_mutated"] = state_before != evidence["state_post_import"]
        evidence["import_db_mutated"] = db_before != evidence["db_post_import"]

        def guard_for(key):
            def guarded(*args, **kwargs):
                evidence["write_attempts"][key] += 1
                raise RuntimeError(f"read-only preview blocked {key}")

            return guarded

        for key, (module_name, attribute) in _GUARD_TARGETS.items():
            module = modules[module_name]
            original = getattr(module, attribute)
            originals.append((module, attribute, original))
            setattr(module, attribute, guard_for(key))

        discovery = collector.discover_html_collection(
            source,
            state={"processed_urls": []},
            limit=effective_limit,
            operational=False,
        )
        result["errors"].extend(discovery.errors)
        if not discovery.documents:
            result["errors"].append("collection produced no safe preview documents")
        built_documents: list[dict] = []
        for document in discovery.documents:
            try:
                document_preview = build_document_preview(
                    document, extractor=extractor
                )
                built_documents.append(document_preview)
                if document_preview["extraction_metadata"]["status"] != "complete":
                    result["errors"].append(
                        f"document extraction incomplete: {document_preview['document_url']}"
                    )
            except Exception as exc:
                result["errors"].append(f"document preview failed: {exc}")
        result["documents"] = built_documents
    except Exception as exc:
        result["errors"].append(f"preview failed: {exc}")
    finally:
        for module, attribute, original in reversed(originals):
            setattr(module, attribute, original)
        evidence["state_after"] = collector._snapshot_path(collector.STATE_PATH)
        evidence["db_after"] = collector._snapshot_path(collector.DB_PATH)
        evidence["collector_state_mutated"] = state_before != evidence["state_after"]
        evidence["stats_db_mutated"] = db_before != evidence["db_after"]
        no_write_failure = False
        if evidence["import_state_mutated"] or evidence["import_db_mutated"]:
            result["errors"].append("module import mutated preview state")
            no_write_failure = True
        if evidence["collector_state_mutated"] or evidence["stats_db_mutated"]:
            result["errors"].append("preview mutated state or stats storage")
            no_write_failure = True
        if any(evidence["write_attempts"].values()):
            result["errors"].append("preview attempted a guarded write")
            no_write_failure = True
        if no_write_failure:
            result["documents"] = []
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preview CNSD extraction without writes")
    parser.add_argument("--collection-url", required=True)
    parser.add_argument("--limit", type=int, default=3)
    args = parser.parse_args(argv)
    result = build_collection_preview(args.collection_url, args.limit)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if not result["errors"] and result["documents"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
