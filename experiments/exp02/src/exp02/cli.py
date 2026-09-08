"""Fail-closed command line workflow for the offline EXP-02 preparation package.

The command surface deliberately contains no model invocation. It only freezes,
checks, and joins human-input artifacts needed before experimental runs.
"""

from __future__ import annotations

import argparse
import base64
from collections.abc import Mapping
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any
from urllib.parse import urlsplit

import yaml

from .acquire import (
    INSPECTOR_DECISIONS,
    _FAILED_CANDIDATE_FIELDS,
    _SNAPSHOT_CANDIDATE_FIELDS,
    _decision_map,
    _inspection_sources,
    _validate_candidate_author_provenance,
    AcquiredDocument,
    AcquisitionError,
    Candidate,
    SourceConfig,
    acquire_selection,
    configured_sources,
    inspect_candidate,
    inspect_selection,
)
from .agreement import (apply_adjudication, build_adjudication_workbook, compare_annotation_sets,
                        freeze_reference, validate_adjudication_workbook)
from .annotations import AnnotationSet, EntityAnnotation, RelationshipAnnotation, import_annotations
from .jsonio import canonical_bytes, load_json, sha256_file, write_new_json
from .records import DocumentRecord
from .source_policy import InsufficientSourcesError, SourcePolicy, select_sources
from .workbook import build_workbook, validate_workbook


INPUT_MANIFEST = "input-manifest.v1.json"
IMPORTS_DIR = "imports"
COMPARISON_FILE = "annotation-comparison.v1.json"
ADJUDICATION_FILE = "adjudication.xlsx"
PACKAGE_FILE = "annotation-package.v1.json"
FROZEN_ANNOTATION_FILES = (
    "annotator-a.v1.json",
    "annotator-b.v1.json",
    "agreement.v1.json",
    "adjudication.v1.json",
    "reference.v1.json",
    "reference-freeze.v1.json",
)
_CONFIG_ROOT = Path(__file__).resolve().parents[2] / "config"
_ANNOTATOR_IDS = ("annotator-a", "annotator-b")
_IMPORT_NAMES = {f"{annotator}-16.v1.json" for annotator in _ANNOTATOR_IDS}


class CliError(ValueError):
    """A state or input failure that must return the closed CLI status 2."""


def _error(message: str, code: int = 2) -> int:
    print(message, file=sys.stderr)
    return code


def _event(**values: object) -> None:
    """Emit an audit line with source IDs, counts, paths, and digests only."""
    print(json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _absolute_nofollow_root(root: Path) -> Path:
    """Return a lexical absolute root after rejecting every existing link component."""
    absolute = Path(os.path.abspath(os.path.normpath(os.fspath(root))))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            break
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise CliError("evidence root is invalid")
    return absolute


def _manifest(root: Path) -> Path | None:
    path = root / INPUT_MANIFEST
    return path if path.is_file() and not path.is_symlink() else None


def _require_manifest(root: Path) -> Path:
    path = _manifest(root)
    if path is None:
        raise CliError("input manifest is not frozen")
    return path


def _input_artifact(root: Path, document: DocumentRecord, kind: str) -> Path:
    if kind == "original":
        return root / "inputs" / document.document_id / f"original.{document.media_type}"
    return root / "inputs" / document.document_id / "converted.txt"


def _eligible_inventory_counts(
    candidate_ledger: Mapping[str, object],
) -> dict[str, list[Mapping[str, object]]]:
    candidates = candidate_ledger.get("candidates")
    if not isinstance(candidates, list):
        raise CliError("input manifest is invalid")
    inventories: dict[str, list[Mapping[str, object]]] = {}
    for candidate in candidates:
        if not isinstance(candidate, Mapping) or not isinstance(candidate.get("source_id"), str):
            raise CliError("input manifest is invalid")
        eligibility = candidate.get("eligibility")
        inspection = candidate.get("inspection")
        if (
            isinstance(eligibility, Mapping)
            and eligibility.get("eligible") is True
            and isinstance(inspection, Mapping)
            and inspection.get("decision") == "eligible"
            and not candidate.get("reasons")
        ):
            inventories.setdefault(str(candidate["source_id"]), []).append(candidate)
    return inventories


def _ledger_has_forbidden_fields(value: object) -> bool:
    forbidden = {
        "entities", "entity", "relationships", "relationship", "model",
        "model_output", "result", "results", "metrics", "run", "condition",
        "tim_output",
    }
    if isinstance(value, Mapping):
        return any(
            str(key).casefold() in forbidden
            or _ledger_has_forbidden_fields(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_ledger_has_forbidden_fields(child) for child in value)
    return False


def _has_legacy_active_state(root: Path) -> bool:
    decision = root / "extension-decision.v1.json"
    if decision.exists() or decision.is_symlink():
        return True
    for directory, suffix in (
        (root / "workbooks", "-24.xlsx"),
        (root / IMPORTS_DIR, "-24.v1.json"),
    ):
        try:
            mode = os.lstat(directory).st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            continue
        with os.scandir(directory) as entries:
            if any(entry.name.endswith(suffix) for entry in entries):
                return True
    return False


def _verify_manifest_semantics(
    root: Path,
    manifest: Mapping[str, object],
    records: tuple[DocumentRecord, ...],
    candidate_ledger: Mapping[str, object],
    inspection_sources: list[SourceConfig],
    inspected_by_url: Mapping[str, Mapping[str, object]],
) -> None:
    expected_fields = {
        "schema_version", "policy_digest", "candidate_ledger_digest",
        "exclusion_ledger_digest", "inspection_manifest_digest",
        "inspector_decisions_digest", "sources", "documents",
    }
    if _has_legacy_active_state(root):
        raise CliError("unexpected active-state artifact")
    if set(manifest) != expected_fields or len(records) != 16:
        raise CliError("input manifest is invalid")
    policy_path = _CONFIG_ROOT / "source-policy.v1.json"
    policy = SourcePolicy.load(policy_path)
    if manifest.get("policy_digest") != sha256_file(policy_path):
        raise CliError("input manifest is invalid")
    raw_sources = manifest.get("sources")
    if not isinstance(raw_sources, list) or len(raw_sources) != 4:
        raise CliError("input manifest is invalid")
    sources: list[dict[str, str]] = []
    for raw in raw_sources:
        if not isinstance(raw, Mapping) or set(raw) != {
            "source_id", "source_name", "source_class", "feed_url", "publisher"
        }:
            raise CliError("input manifest is invalid")
        source = {
            key: str(raw[key])
            for key in (
                "source_id", "source_name", "source_class", "feed_url", "publisher"
            )
        }
        parsed = urlsplit(source["feed_url"])
        if parsed.scheme != "https" or not parsed.netloc:
            raise CliError("input manifest is invalid")
        sources.append(source)
    source_ids = [source["source_id"] for source in sources]
    inventories = _eligible_inventory_counts(candidate_ledger)
    expected_source_ids = select_sources(policy, inventories)
    if source_ids != expected_source_ids:
        raise CliError("input manifest is invalid")
    expected_classes = ["institutional", "institutional", "technical-research", "technical-research"]
    if [source["source_class"] for source in sources] != expected_classes:
        raise CliError("input manifest is invalid")
    inspection_by_source = {
        source.source_id: asdict(source) for source in inspection_sources
    }
    if sources != [inspection_by_source[source_id] for source_id in source_ids]:
        raise CliError("input manifest is invalid")

    expected_order: list[str] = []
    for source_id in source_ids:
        expected_order.extend([source_id] * 4)
    if [record.source_id for record in records] != expected_order:
        raise CliError("input manifest is invalid")
    for source_index, source in enumerate(sources):
        group = records[source_index * 4 : source_index * 4 + 4]
        if [record.role for record in group] != ["primary"] * 4:
            raise CliError("input manifest is invalid")
        if any(record.source_class != source["source_class"] for record in group):
            raise CliError("input manifest is invalid")
        eligible_candidates = inventories[source["source_id"]][
            : policy.documents_per_source
        ]
        if len(eligible_candidates) != len(group):
            raise CliError("input manifest is invalid")
        for record, candidate in zip(group, eligible_candidates):
            prefix = f"experiments/exp02/evidence/inputs/{record.document_id}"
            if record.original_path != f"{prefix}/original.{record.media_type}" or record.text_path != f"{prefix}/converted.txt":
                raise CliError("input manifest is invalid")
            eligibility = candidate.get("eligibility")
            if not isinstance(eligibility, Mapping):
                raise CliError("input manifest is invalid")
            inspected = inspected_by_url.get(record.origin_url)
            if inspected is None:
                raise CliError("input manifest breaks inspection provenance")
            if (
                record.source_id != candidate.get("source_id")
                or record.source_class != candidate.get("source_class")
                or record.origin_url != candidate.get("origin_url")
                or record.title != candidate.get("title")
                or record.author != candidate.get("author")
                or record.author_basis != candidate.get("author_basis")
                or record.published_at != candidate.get("published_at")
                or record.original_sha256 != candidate.get("original_sha256")
                or record.text_sha256 != candidate.get("text_sha256")
                or record.word_count != eligibility.get("word_count")
                or record.document_id != inspected.get("document_id")
                or record.source_id != inspected.get("source_id")
                or record.source_class != inspected.get("source_class")
                or record.title != inspected.get("title")
                or record.author != inspected.get("author")
                or record.author_basis != inspected.get("author_basis")
                or record.published_at != inspected.get("published_at")
                or record.media_type != inspected.get("media_type")
                or record.word_count != inspected.get("word_count")
                or record.original_sha256 != inspected.get("original_sha256")
                or record.text_sha256 != inspected.get("text_sha256")
            ):
                raise CliError("input manifest is invalid")


def _verify_candidate_inspection_bridge(
    inspection_manifest: Mapping[str, object],
    candidate_ledger: Mapping[str, object],
    decisions: Mapping[str, object],
) -> dict[str, Mapping[str, object]]:
    inspected_rows = inspection_manifest.get("candidates")
    if not isinstance(inspected_rows, list):
        raise CliError("inspection manifest is invalid")
    expected_rows: list[dict[str, object]] = []
    successful_by_url: dict[str, Mapping[str, object]] = {}
    seen_original_hashes: set[str] = set()
    for inspected in inspected_rows:
        if not isinstance(inspected, Mapping):
            raise CliError("inspection manifest is invalid")
        if set(inspected) == _FAILED_CANDIDATE_FIELDS:
            expected_rows.append(
                {
                    "source_id": inspected["source_id"],
                    "origin_url": inspected["origin_url"],
                    "title": inspected["title"],
                    "author": inspected["author"],
                    "author_basis": inspected["author_basis"],
                    "reason": "inaccessible",
                    "error": inspected["error"],
                }
            )
            continue
        if set(inspected) != _SNAPSHOT_CANDIDATE_FIELDS:
            raise CliError("inspection manifest is invalid")
        origin_url = inspected.get("origin_url")
        if not isinstance(origin_url, str) or origin_url in successful_by_url:
            raise CliError("inspection manifest is invalid")
        decision = decisions.get(origin_url)
        if decision is None:
            raise CliError("inspector decisions break inspection provenance")
        headings = inspected.get("section_headings")
        mechanical_reasons = inspected.get("mechanical_reasons")
        if (
            not isinstance(headings, list)
            or any(not isinstance(heading, str) for heading in headings)
            or not isinstance(mechanical_reasons, list)
            or any(not isinstance(reason, str) for reason in mechanical_reasons)
        ):
            raise CliError("inspection manifest is invalid")
        expected_checks = {
            "length_in_range": "out_of_length_range" not in mechanical_reasons,
            "not_previously_processed": "previously_processed" not in mechanical_reasons,
            "author_and_date_present": "missing_author_or_date" not in mechanical_reasons,
            "readable": True,
        }
        if inspected.get("mechanical_checks") != expected_checks:
            raise CliError("inspection manifest is invalid")
        candidate = Candidate(
            source_id=str(inspected["source_id"]),
            source_class=str(inspected["source_class"]),  # type: ignore[arg-type]
            origin_url=origin_url,
            title=str(inspected["title"]),
            author=str(inspected["author"]),
            author_basis=str(inspected["author_basis"]),  # type: ignore[arg-type]
            published_at=str(inspected["published_at"]),
            sha256=str(inspected["original_sha256"]),
        )
        reviewed = inspect_candidate(
            AcquiredDocument(
                candidate=candidate,
                original=b"",
                converted_text="",
                media_type=str(inspected["media_type"]),  # type: ignore[arg-type]
                headings=tuple(headings),
            ),
            decision,  # type: ignore[arg-type]
        )
        review_payload = asdict(reviewed)
        review_payload["section_headings"] = list(reviewed.section_headings)
        original_sha256 = str(inspected["original_sha256"])
        combined_reasons = list(mechanical_reasons)
        if original_sha256 in seen_original_hashes:
            combined_reasons.append("duplicate")
        seen_original_hashes.add(original_sha256)
        if reviewed.reason is not None:
            combined_reasons.append(reviewed.reason)
        expected: dict[str, object] = {
            "source_id": inspected["source_id"],
            "source_class": inspected["source_class"],
            "origin_url": origin_url,
            "title": inspected["title"],
            "author": inspected["author"],
            "author_basis": inspected["author_basis"],
            "published_at": inspected["published_at"],
            "original_sha256": inspected["original_sha256"],
            "text_sha256": inspected["text_sha256"],
            "eligibility": {
                "eligible": not mechanical_reasons,
                "reasons": list(mechanical_reasons),
                "word_count": inspected["word_count"],
            },
            "inspection": review_payload,
        }
        if combined_reasons:
            expected["reasons"] = combined_reasons
        expected_rows.append(expected)
        successful_by_url[origin_url] = inspected
    expected_ledger = {
        "schema_version": 1,
        "source_failures": inspection_manifest.get("source_failures"),
        "candidates": expected_rows,
    }
    if candidate_ledger != expected_ledger:
        raise CliError("candidate ledger breaks inspection provenance")
    return successful_by_url


def _verify_inputs(root: Path) -> tuple[dict[str, Any], str, tuple[DocumentRecord, ...]]:
    manifest_path = _require_manifest(root)
    try:
        manifest = load_json(manifest_path)
        if manifest.get("schema_version") != 1 or not isinstance(manifest.get("documents"), list):
            raise CliError("input manifest is invalid")
        try:
            records = tuple(DocumentRecord.from_dict(item) for item in manifest["documents"])
        except (TypeError, ValueError) as error:
            raise CliError("input manifest document is invalid") from error
        if len({item.document_id for item in records}) != len(records):
            raise CliError("input manifest has duplicate document IDs")
        candidate_ledger = load_json(root / "candidate-ledger.v1.json")
        exclusion_ledger = load_json(root / "exclusion-ledger.v1.json")
        inspection_manifest = load_json(root / "inspection-manifest.v1.json")
        policy_path = _CONFIG_ROOT / "source-policy.v1.json"
        exclusions_path = _CONFIG_ROOT / "exclusions.v1.json"
        policy = SourcePolicy.load(policy_path)
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
            or manifest.get("inspection_manifest_digest")
            != sha256_file(root / "inspection-manifest.v1.json")
            or inspection_manifest.get("schema_version") != 1
            or inspection_manifest.get("policy_digest") != sha256_file(policy_path)
            or inspection_manifest.get("exclusions_digest")
            != sha256_file(exclusions_path)
            or not isinstance(inspection_manifest.get("candidates"), list)
            or not isinstance(inspection_manifest.get("source_failures"), list)
            or not isinstance(inspection_manifest.get("sources"), list)
        ):
            raise CliError("inspection manifest digest mismatch")
        try:
            inspection_sources = _inspection_sources(
                inspection_manifest["sources"], policy
            )
        except AcquisitionError as error:
            raise CliError("inspection source registry is invalid") from error
        inspector_decisions_path = root / INSPECTOR_DECISIONS
        if (
            manifest.get("inspector_decisions_digest")
            != sha256_file(inspector_decisions_path)
        ):
            raise CliError("inspector decisions digest mismatch")
        decisions = _decision_map(
            inspector_decisions_path,
            str(manifest["inspection_manifest_digest"]),
            inspection_manifest["candidates"],
        )
        inspection_source_by_id = {
            source.source_id: source for source in inspection_sources
        }
        for candidate in inspection_manifest["candidates"]:
            if not isinstance(candidate, Mapping):
                raise CliError("inspection manifest is invalid")
            if set(candidate) == _FAILED_CANDIDATE_FIELDS:
                if candidate.get("reason") != "inaccessible":
                    raise CliError("inspection manifest is invalid")
                failed_candidate = Candidate(
                    source_id=str(candidate["source_id"]),
                    source_class=str(candidate["source_class"]),  # type: ignore[arg-type]
                    origin_url=str(candidate["origin_url"]),
                    title=str(candidate["title"]),
                    author=str(candidate["author"]),
                    author_basis=str(candidate["author_basis"]),  # type: ignore[arg-type]
                    published_at=str(candidate["published_at"]),
                )
                source = inspection_source_by_id.get(failed_candidate.source_id)
                if source is None:
                    raise CliError("inspection manifest is invalid")
                try:
                    _validate_candidate_author_provenance(failed_candidate, source)
                except AcquisitionError as error:
                    raise CliError("inspection author provenance is invalid") from error
                continue
            if set(candidate) != _SNAPSHOT_CANDIDATE_FIELDS:
                raise CliError("inspection manifest is invalid")
            inspected_candidate = Candidate(
                source_id=str(candidate["source_id"]),
                source_class=str(candidate["source_class"]),  # type: ignore[arg-type]
                origin_url=str(candidate["origin_url"]),
                title=str(candidate["title"]),
                author=str(candidate["author"]),
                author_basis=str(candidate["author_basis"]),  # type: ignore[arg-type]
                published_at=str(candidate["published_at"]),
                sha256=str(candidate["original_sha256"]),
            )
            source = inspection_source_by_id.get(inspected_candidate.source_id)
            if source is None:
                raise CliError("inspection manifest is invalid")
            try:
                _validate_candidate_author_provenance(inspected_candidate, source)
            except AcquisitionError as error:
                raise CliError("inspection author provenance is invalid") from error
            document_id = candidate.get("document_id")
            media_type = candidate.get("media_type")
            if not isinstance(document_id, str) or media_type not in {"html", "pdf"}:
                raise CliError("inspection manifest is invalid")
            original = root / "inspection" / document_id / f"original.{media_type}"
            text = root / "inspection" / document_id / "converted.txt"
            if (
                candidate.get("snapshot_original_path")
                != str(original.relative_to(root))
                or candidate.get("snapshot_text_path") != str(text.relative_to(root))
                or sha256_file(original) != candidate.get("original_sha256")
                or sha256_file(text) != candidate.get("text_sha256")
            ):
                raise CliError("inspection snapshot digest mismatch")
        inspected_by_url = _verify_candidate_inspection_bridge(
            inspection_manifest, candidate_ledger, decisions
        )
        for ledger, field in (("candidate-ledger.v1.json", "candidate_ledger_digest"), ("exclusion-ledger.v1.json", "exclusion_ledger_digest")):
            expected = manifest.get(field)
            if not isinstance(expected, str) or sha256_file(root / ledger) != expected:
                raise CliError("input ledger digest mismatch")
        if candidate_ledger.get("schema_version") != 1 or exclusion_ledger.get("schema_version") != 1:
            raise CliError("input manifest is invalid")
        if _ledger_has_forbidden_fields(candidate_ledger) or _ledger_has_forbidden_fields(exclusion_ledger):
            raise CliError("input eligibility ledgers contain forbidden model or entity fields")
        _verify_manifest_semantics(
            root,
            manifest,
            records,
            candidate_ledger,
            inspection_sources,
            inspected_by_url,
        )
        for document in records:
            if sha256_file(_input_artifact(root, document, "original")) != document.original_sha256:
                raise CliError("original digest mismatch")
            if sha256_file(_input_artifact(root, document, "text")) != document.text_sha256:
                raise CliError("text digest mismatch")
        return manifest, sha256_file(manifest_path), records
    except CliError:
        raise
    except (OSError, ValueError, TypeError):
        raise CliError("input artifact is unavailable or invalid") from None


class _FixtureTransport:
    def __init__(self, responses: dict[str, tuple[bytes, str]]) -> None:
        self._responses = responses

    def fetch(self, url: str) -> tuple[bytes, str]:
        try:
            return self._responses[url]
        except KeyError as error:
            raise AcquisitionError("fixture response is unavailable") from error


def _fixture(path: Path) -> tuple[list[SourceConfig], _FixtureTransport]:
    try:
        value = load_json(path)
        if value.get("schema_version") != 1 or not isinstance(value.get("sources"), list) or not isinstance(value.get("responses"), dict):
            raise CliError("offline acquisition fixture is invalid")
        sources = [
            SourceConfig(
                str(item["source_id"]),
                str(item["source_name"]),
                str(item["source_class"]),
                str(item["feed_url"]),
                str(item["publisher"]),
            )
            for item in value["sources"]
            if isinstance(item, dict)
        ]
        if len(sources) != len(value["sources"]):
            raise CliError("offline acquisition fixture is invalid")
        responses: dict[str, tuple[bytes, str]] = {}
        for url, response in value["responses"].items():
            if not isinstance(url, str) or not isinstance(response, dict):
                raise CliError("offline acquisition fixture is invalid")
            body, content_type = response.get("body_base64"), response.get("content_type")
            if not isinstance(body, str) or not isinstance(content_type, str):
                raise CliError("offline acquisition fixture is invalid")
            responses[url] = (base64.b64decode(body.encode("ascii"), validate=True), content_type)
        if set(value) != {"schema_version", "sources", "responses"}:
            raise CliError("offline acquisition fixture is invalid")
        return sources, _FixtureTransport(responses)
    except CliError:
        raise
    except (KeyError, OSError, ValueError, UnicodeError):
        raise CliError("offline acquisition fixture is invalid") from None


def _sources_inspect(arguments: argparse.Namespace) -> int:
    try:
        sources = configured_sources(Path(arguments.sources)) if arguments.sources else configured_sources()
        _event(event="sources-inspected", source_ids=[source.source_id for source in sources], source_count=len(sources))
        return 0
    except (OSError, ValueError, TypeError, yaml.YAMLError):
        return _error("source registry is unavailable or invalid")


def _inputs_acquire(arguments: argparse.Namespace) -> int:
    root = arguments.root
    if _manifest(root) is not None:
        return _error("input manifest is already frozen")
    try:
        if not arguments.decisions:
            raise CliError("inspection decisions are required")
        acquire_selection(
            Path(arguments.policy) if arguments.policy else _CONFIG_ROOT / "source-policy.v1.json", root,
            decisions_path=Path(arguments.decisions),
            exclusions_path=Path(arguments.exclusions) if arguments.exclusions else _CONFIG_ROOT / "exclusions.v1.json",
        )
        _payload, digest, records = _verify_inputs(root)
        _event(event="inputs-acquired", document_count=len(records), manifest_digest=digest)
        return 0
    except CliError as error:
        return _error(str(error))
    except AcquisitionError:
        return _error("input acquisition is invalid")
    except InsufficientSourcesError:
        return _error("external acquisition failed", 3)
    except (OSError, ValueError, TypeError, yaml.YAMLError):
        return _error("input acquisition is invalid")


def _inputs_inspect(arguments: argparse.Namespace) -> int:
    root = arguments.root
    if (root / "inspection-manifest.v1.json").exists() or (
        root / "inspection-manifest.v1.json"
    ).is_symlink():
        return _error("input inspection is already frozen")
    try:
        if arguments.fixture:
            sources, transport = _fixture(Path(arguments.fixture))
        else:
            sources = (
                configured_sources(Path(arguments.sources))
                if arguments.sources
                else None
            )
            transport = None
        path = inspect_selection(
            Path(arguments.policy)
            if arguments.policy
            else _CONFIG_ROOT / "source-policy.v1.json",
            root,
            sources=sources,
            transport=transport,
            exclusions_path=Path(arguments.exclusions)
            if arguments.exclusions
            else _CONFIG_ROOT / "exclusions.v1.json",
        )
        payload = load_json(path)
        candidates = payload.get("candidates", [])
        failures = payload.get("source_failures", [])
        _event(
            event="inputs-inspected",
            candidate_count=len(candidates),
            source_failure_count=len(failures),
            inspection_manifest_digest=sha256_file(path),
        )
        return 0
    except CliError as error:
        return _error(str(error))
    except (AcquisitionError, OSError, ValueError, TypeError, yaml.YAMLError):
        return _error("input inspection is invalid")


def _inputs_verify(arguments: argparse.Namespace) -> int:
    try:
        _payload, digest, records = _verify_inputs(arguments.root)
        _event(event="inputs-verified", document_count=len(records), manifest_digest=digest)
        return 0
    except CliError as error:
        return _error(str(error))


def _workbook_path(
    root: Path, annotator: str | None, output: str | None
) -> Path:
    if output:
        return Path(output)
    if not annotator:
        raise CliError("annotator identifier is required")
    return root / "workbooks" / f"{annotator}.xlsx"


def _workbooks_build(arguments: argparse.Namespace) -> int:
    try:
        _payload, _digest, _records = _verify_inputs(arguments.root)
        manifest = _require_manifest(arguments.root)
        output = _workbook_path(
            arguments.root, arguments.annotator, arguments.output
        )
        if not arguments.annotator:
            raise CliError("annotator identifier is required")
        build_workbook(manifest, arguments.annotator, output)
        summary = validate_workbook(output, manifest)
        _event(event="workbook-built", document_count=summary.document_count, workbook_digest=sha256_file(output))
        return 0
    except CliError as error:
        return _error(str(error))
    except (OSError, ValueError, TypeError):
        return _error("workbook build is invalid")


def _workbooks_validate(arguments: argparse.Namespace) -> int:
    try:
        _payload, _digest, _records = _verify_inputs(arguments.root)
        manifest = _require_manifest(arguments.root)
        if not arguments.workbook:
            raise CliError("workbook path is required")
        summary = validate_workbook(arguments.workbook, manifest)
        _event(event="workbook-validated", document_count=summary.document_count, entity_count=summary.entity_count, relationship_count=summary.relationship_count, workbook_digest=sha256_file(arguments.workbook))
        return 0
    except CliError as error:
        return _error(str(error))
    except (OSError, ValueError, TypeError):
        return _error("workbook is invalid")


def _annotation_from_dict(value: object) -> AnnotationSet:
    expected = {
        "schema_version", "annotator_id", "input_manifest_digest",
        "workbook_sha256", "entities", "relationships", "document_ids",
        "document_minutes", "workbook_path",
    }
    if not isinstance(value, dict) or set(value) != expected or value.get("schema_version") != 1:
        raise CliError("imported annotation is invalid")
    try:
        entities = tuple(EntityAnnotation(**dict(item)) for item in value["entities"])
        relationships = tuple(RelationshipAnnotation(**dict(item)) for item in value["relationships"])
        document_ids = tuple(value.get("document_ids", []))
        raw_minutes = value["document_minutes"]
        workbook_path = value["workbook_path"]
        if (
            not all(isinstance(item, str) for item in document_ids)
            or not isinstance(raw_minutes, dict)
            or not isinstance(workbook_path, str)
        ):
            raise TypeError
        document_minutes = tuple(
            (document_id, minutes)
            for document_id, minutes in raw_minutes.items()
            if isinstance(document_id, str) and type(minutes) is int
        )
        if len(document_minutes) != len(raw_minutes) or any(
            minutes <= 0 for _document_id, minutes in document_minutes
        ):
            raise TypeError
        return AnnotationSet(
            str(value["annotator_id"]),
            str(value["input_manifest_digest"]),
            str(value["workbook_sha256"]),
            entities,
            relationships,
            document_ids,
            document_minutes,
            workbook_path,
        )
    except (KeyError, TypeError, ValueError):
        raise CliError("imported annotation is invalid") from None


def _artifact_beneath_root(root: Path, supplied: str | Path, label: str) -> tuple[Path, str]:
    candidate = Path(os.path.abspath(os.path.normpath(os.fspath(supplied))))
    try:
        relative = candidate.relative_to(root)
        _absolute_nofollow_root(candidate.parent)
        status = os.lstat(candidate)
    except (OSError, ValueError):
        raise CliError(f"{label} must be a regular file beneath the evidence root") from None
    if not relative.parts or stat.S_ISLNK(status.st_mode) or not stat.S_ISREG(status.st_mode):
        raise CliError(f"{label} must be a regular file beneath the evidence root")
    return candidate, relative.as_posix()


def _coverage_ids(records: tuple[DocumentRecord, ...]) -> tuple[str, ...]:
    return tuple(record.document_id for record in records)


def _imports(
    root: Path,
    manifest_digest: str,
    records: tuple[DocumentRecord, ...],
) -> list[tuple[Path, AnnotationSet]]:
    directory = root / IMPORTS_DIR
    if not directory.is_dir() or directory.is_symlink():
        raise CliError("two imported annotations are required")
    paths = sorted(directory.iterdir())
    expected_names = _IMPORT_NAMES
    if any(
        path.is_symlink() or not path.is_file() or path.name not in expected_names
        for path in paths
    ) or not expected_names <= {path.name for path in paths}:
        raise CliError("imported annotation artifact set is invalid")
    found: list[tuple[Path, AnnotationSet]] = []
    expected_ids = _coverage_ids(records)
    for annotator in _ANNOTATOR_IDS:
        path = directory / f"{annotator}-16.v1.json"
        if path not in paths:
            raise CliError("two imported annotations are required")
        try:
            annotation = _annotation_from_dict(load_json(path))
        except (OSError, ValueError):
            raise CliError("imported annotation is invalid") from None
        if (
            annotation.manifest_digest != manifest_digest
            or annotation.annotator_id != annotator
            or annotation.document_ids != expected_ids
            or {document_id for document_id, _minutes in annotation.document_minutes}
            != set(expected_ids)
            or len(annotation.document_minutes) != len(expected_ids)
        ):
            raise CliError("imported annotation manifest digest mismatch")
        workbook, workbook_relative = _artifact_beneath_root(
            root, root / str(annotation.workbook_path), "imported workbook"
        )
        try:
            rebound = replace(
                import_annotations(workbook, root / INPUT_MANIFEST),
                workbook_path=workbook_relative,
            )
        except (OSError, ValueError):
            raise CliError("imported workbook no longer matches its validated import") from None
        if rebound.to_dict() != annotation.to_dict():
            raise CliError("imported workbook no longer matches its validated import")
        found.append((path, annotation))
    if found[0][1].workbook_sha256 == found[1][1].workbook_sha256:
        raise CliError("two imported annotations are required")
    return found


def _annotations_import(arguments: argparse.Namespace) -> int:
    try:
        _payload, _digest, records = _verify_inputs(arguments.root)
        manifest = _require_manifest(arguments.root)
        if not arguments.workbook:
            raise CliError("workbook path is required")
        workbook, workbook_relative = _artifact_beneath_root(
            arguments.root, arguments.workbook, "workbook"
        )
        annotation = replace(
            import_annotations(workbook, manifest), workbook_path=workbook_relative
        )
        document_count = len(annotation.document_ids)
        if document_count != 16 or annotation.document_ids != _coverage_ids(records):
            raise CliError("annotation document coverage is invalid")
        if tuple(document_id for document_id, _minutes in annotation.document_minutes) != annotation.document_ids:
            raise CliError("annotation minutes must cover every workbook document exactly once")
        payload = annotation.to_dict()
        digest = hashlib.sha256(canonical_bytes(payload)).hexdigest()
        write_new_json(
            arguments.root / IMPORTS_DIR / f"{annotation.annotator_id}-{document_count}.v1.json",
            payload,
        )
        _event(event="annotations-imported", document_count=len(annotation.document_ids), entity_count=len(annotation.entities), relationship_count=len(annotation.relationships), import_digest=digest)
        return 0
    except CliError as error:
        return _error(str(error))
    except FileExistsError:
        return _error("annotation import is already frozen")
    except (OSError, ValueError, TypeError):
        return _error("annotation import is invalid")


def _annotations_compare(arguments: argparse.Namespace) -> int:
    try:
        _payload, digest, records = _verify_inputs(arguments.root)
        imported = _imports(arguments.root, digest, records)
        output = arguments.root / COMPARISON_FILE
        adjudication = _adjudication_path(arguments.root, arguments.adjudication)
        if output.exists() or adjudication.exists():
            raise CliError("comparison or adjudication is already frozen")
        comparison = compare_annotation_sets(imported[0][1], imported[1][1])
        comparison_digest = write_new_json(output, comparison.to_dict())
        build_adjudication_workbook(comparison, adjudication)
        _event(event="annotations-compared", disagreement_count=len(comparison.disagreements), comparison_digest=comparison_digest)
        return 0
    except CliError as error:
        return _error(str(error))
    except (OSError, ValueError, TypeError):
        return _error("annotation comparison is invalid")


def _adjudication_path(root: Path, supplied: str | None) -> Path:
    raw = root / supplied if supplied and not Path(supplied).is_absolute() else (
        Path(supplied) if supplied else root / ADJUDICATION_FILE
    )
    candidate = Path(os.path.abspath(os.path.normpath(os.fspath(raw))))
    try:
        relative = candidate.relative_to(root)
        _absolute_nofollow_root(candidate.parent)
    except (OSError, ValueError):
        raise CliError("adjudication workbook must be beneath the evidence root") from None
    if not relative.parts or candidate.is_symlink():
        raise CliError("adjudication workbook must be beneath the evidence root")
    return candidate


def _base_receipt_files(
    root: Path,
    records: tuple[DocumentRecord, ...],
    imported: list[tuple[Path, AnnotationSet]],
    adjudication: Path,
) -> dict[str, str]:
    files: dict[str, str] = {
        INPUT_MANIFEST: sha256_file(root / INPUT_MANIFEST),
        "inspection-manifest.v1.json": sha256_file(
            root / "inspection-manifest.v1.json"
        ),
        INSPECTOR_DECISIONS: sha256_file(root / INSPECTOR_DECISIONS),
        "candidate-ledger.v1.json": sha256_file(root / "candidate-ledger.v1.json"),
        "exclusion-ledger.v1.json": sha256_file(root / "exclusion-ledger.v1.json"),
        COMPARISON_FILE: sha256_file(root / COMPARISON_FILE),
    }
    inspection = load_json(root / "inspection-manifest.v1.json")
    candidates = inspection.get("candidates")
    if not isinstance(candidates, list):
        raise CliError("inspection manifest is invalid")
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            raise CliError("inspection manifest is invalid")
        for field in ("snapshot_original_path", "snapshot_text_path"):
            relative = candidate.get(field)
            if relative is None:
                continue
            if not isinstance(relative, str):
                raise CliError("inspection manifest is invalid")
            snapshot, snapshot_relative = _artifact_beneath_root(
                root, root / relative, "inspection snapshot"
            )
            files[snapshot_relative] = sha256_file(snapshot)
    for document in records:
        for kind in ("original", "text"):
            path = _input_artifact(root, document, kind)
            files[str(path.relative_to(root))] = sha256_file(path)
    for path, _annotation in imported:
        files[str(path.relative_to(root))] = sha256_file(path)
    for _path, annotation in imported:
        workbook, workbook_relative = _artifact_beneath_root(
            root, root / str(annotation.workbook_path), "imported workbook"
        )
        if sha256_file(workbook) != annotation.workbook_sha256:
            raise CliError("imported workbook is unavailable for package verification")
        files[workbook_relative] = annotation.workbook_sha256
    files[str(adjudication.relative_to(root))] = sha256_file(adjudication)
    return files


def _receipt_files(
    root: Path, records: tuple[DocumentRecord, ...], imported: list[tuple[Path, AnnotationSet]], adjudication: Path,
    frozen_hashes: dict[str, str] | None = None,
) -> dict[str, str]:
    files = _base_receipt_files(root, records, imported, adjudication)
    if frozen_hashes is None:
        annotations = root / "annotations"
        if not annotations.is_dir() or annotations.is_symlink() or {path.name for path in annotations.iterdir()} != set(FROZEN_ANNOTATION_FILES):
            raise CliError("frozen annotation artifact set is incomplete")
        frozen_hashes = {
            name: sha256_file(annotations / name)
            for name in FROZEN_ANNOTATION_FILES
        }
    if set(frozen_hashes) != set(FROZEN_ANNOTATION_FILES):
        raise CliError("frozen annotation artifact set is incomplete")
    for name in FROZEN_ANNOTATION_FILES:
        files[f"annotations/{name}"] = frozen_hashes[name]
    return files


def _package_receipt(root: Path, manifest_digest: str, frozen_hashes: dict[str, str], comparison: dict[str, Any], adjudication: Path, imported: list[tuple[Path, AnnotationSet]], records: tuple[DocumentRecord, ...]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "input_manifest_digest": manifest_digest,
        "comparison_digest": hashlib.sha256(canonical_bytes(comparison)).hexdigest(),
        "adjudication_path": str(adjudication.relative_to(root)),
        "files": _receipt_files(root, records, imported, adjudication, frozen_hashes),
    }


def _reference_freeze(arguments: argparse.Namespace) -> int:
    try:
        _payload, digest, records = _verify_inputs(arguments.root)
        try:
            imported = _imports(arguments.root, digest, records)
            comparison = compare_annotation_sets(imported[0][1], imported[1][1])
            stored = load_json(arguments.root / COMPARISON_FILE)
            if stored != comparison.to_dict():
                raise ValueError
            adjudication = _adjudication_path(arguments.root, arguments.adjudication)
            decisions = validate_adjudication_workbook(adjudication, comparison)
        except CliError:
            raise CliError("two annotations and adjudication are required") from None
        except (OSError, ValueError, TypeError):
            raise CliError("two annotations and adjudication are required") from None
        annotations = arguments.root / "annotations"
        receipt = arguments.root / PACKAGE_FILE
        if annotations.exists() or annotations.is_symlink():
            raise CliError("reference freeze output is already frozen")
        if receipt.exists() or receipt.is_symlink():
            raise CliError("annotation package receipt already exists")
        # Hash every pre-existing receipt-bound input before creating immutable
        # output. This makes all path and read failures fail before freeze.
        _base_receipt_files(arguments.root, records, imported, adjudication)
        if len(imported[0][1].document_ids) != 16:
            raise CliError("reference document coverage must be exactly 16")
        reference = apply_adjudication(comparison, decisions)
        frozen = freeze_reference(reference, arguments.root, frozen_at=arguments.frozen_at)
        receipt_digest = write_new_json(arguments.root / PACKAGE_FILE, _package_receipt(arguments.root, digest, frozen.artifact_hashes, stored, adjudication, imported, records))
        _event(event="reference-frozen", document_count=frozen.document_count, freeze_digest=frozen.freeze_digest, package_digest=receipt_digest)
        return 0
    except CliError as error:
        return _error(str(error))
    except (OSError, ValueError, TypeError):
        return _error("reference freeze is invalid")


def _verify_annotation_package(arguments: argparse.Namespace) -> int:
    try:
        _payload, digest, records = _verify_inputs(arguments.root)
        receipt = load_json(arguments.root / PACKAGE_FILE)
        if receipt.get("schema_version") != 1 or receipt.get("input_manifest_digest") != digest or not isinstance(receipt.get("files"), dict):
            raise CliError("annotation package receipt is invalid")
        imported = _imports(arguments.root, digest, records)
        adjudication_value = receipt.get("adjudication_path")
        if not isinstance(adjudication_value, str):
            raise CliError("annotation package receipt is invalid")
        adjudication = _adjudication_path(arguments.root, adjudication_value)
        expected_files = _receipt_files(arguments.root, records, imported, adjudication)
        if receipt["files"] != expected_files:
            raise CliError("annotation package artifact set or digest mismatch")
        comparison = compare_annotation_sets(imported[0][1], imported[1][1])
        if receipt.get("comparison_digest") != hashlib.sha256(canonical_bytes(comparison.to_dict())).hexdigest() or comparison.to_dict() != load_json(arguments.root / COMPARISON_FILE):
            raise CliError("annotation comparison digest mismatch")
        decisions = validate_adjudication_workbook(adjudication, comparison)
        reference = apply_adjudication(comparison, decisions)
        if len(set(imported[0][1].document_ids)) != 16:
            raise CliError("annotation document coverage must be exactly 16")
        if load_json(arguments.root / "annotations" / "reference.v1.json") != reference.to_dict():
            raise CliError("frozen reference does not match adjudicated human claims")
        if (
            load_json(arguments.root / "annotations" / "annotator-a.v1.json")
            != imported[0][1].to_dict()
            or load_json(arguments.root / "annotations" / "annotator-b.v1.json")
            != imported[1][1].to_dict()
            or load_json(arguments.root / "annotations" / "agreement.v1.json")
            != comparison.to_dict()
            or load_json(arguments.root / "annotations" / "adjudication.v1.json")
            != {"schema_version": 1, "decisions": list(reference.decisions)}
        ):
            raise CliError(
                "frozen annotation provenance does not match bound human inputs"
            )
        freeze = load_json(arguments.root / "annotations" / "reference-freeze.v1.json")
        imported_hashes = {
            name: sha256_file(arguments.root / "annotations" / name)
            for name in ("annotator-a.v1.json", "annotator-b.v1.json")
        }
        if (
            freeze.get("schema_version") != 1
            or freeze.get("input_manifest_digest") != digest
            or freeze.get("document_count") != 16
            or freeze.get("annotator_a_workbook_sha256")
            != imported[0][1].workbook_sha256
            or freeze.get("annotator_b_workbook_sha256")
            != imported[1][1].workbook_sha256
            or freeze.get("imported_json_sha256") != imported_hashes
            or freeze.get("adjudication_sha256")
            != sha256_file(arguments.root / "annotations" / "adjudication.v1.json")
            or freeze.get("agreement_metrics")
            != {
                "entities": comparison.entity_metrics.to_dict(),
                "relationships": comparison.relationship_metrics.to_dict(),
                "quotes": comparison.quote_agreement.to_dict(),
            }
        ):
            raise CliError("reference freeze provenance is invalid")
        _event(event="annotation-package-verified", document_count=len(records), package_digest=sha256_file(arguments.root / PACKAGE_FILE))
        return 0
    except CliError as error:
        return _error(str(error))
    except (OSError, ValueError, TypeError):
        return _error("annotation package is invalid")


def _add_root(command: argparse.ArgumentParser) -> None:
    command.add_argument("--root", type=Path, required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m exp02.cli")
    groups = parser.add_subparsers(dest="group", required=True)
    sources = groups.add_parser("sources")
    commands = sources.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--sources")
    inspect.set_defaults(handler=_sources_inspect)
    inputs = groups.add_parser("inputs")
    commands = inputs.add_subparsers(dest="command", required=True)
    inspect_inputs = commands.add_parser("inspect")
    _add_root(inspect_inputs)
    inspect_inputs.add_argument("--policy")
    inspect_inputs.add_argument("--exclusions")
    inspect_inputs.add_argument("--sources")
    inspect_inputs.add_argument("--fixture")
    inspect_inputs.set_defaults(handler=_inputs_inspect)
    acquire = commands.add_parser("acquire")
    _add_root(acquire)
    acquire.add_argument("--policy"); acquire.add_argument("--exclusions"); acquire.add_argument("--decisions")
    acquire.set_defaults(handler=_inputs_acquire)
    verify = commands.add_parser("verify")
    _add_root(verify); verify.set_defaults(handler=_inputs_verify)
    workbooks = groups.add_parser("workbooks")
    commands = workbooks.add_subparsers(dest="command", required=True)
    build = commands.add_parser(
        "build",
        description=(
            "Build one immutable 16-document annotation workbook."
        ),
    )
    _add_root(build); build.add_argument("--annotator", help="annotator-a or annotator-b"); build.add_argument("--output"); build.set_defaults(handler=_workbooks_build)
    validate = commands.add_parser("validate")
    _add_root(validate); validate.add_argument("--workbook"); validate.set_defaults(handler=_workbooks_validate)
    annotations = groups.add_parser("annotations")
    commands = annotations.add_subparsers(dest="command", required=True)
    imported = commands.add_parser("import")
    _add_root(imported); imported.add_argument("--workbook"); imported.set_defaults(handler=_annotations_import)
    compare = commands.add_parser("compare")
    _add_root(compare); compare.add_argument("--adjudication"); compare.set_defaults(handler=_annotations_compare)
    reference = groups.add_parser("reference")
    commands = reference.add_subparsers(dest="command", required=True)
    freeze = commands.add_parser("freeze")
    _add_root(freeze); freeze.add_argument("--adjudication"); freeze.add_argument("--frozen-at"); freeze.set_defaults(handler=_reference_freeze)
    package = groups.add_parser("verify-annotation-package")
    _add_root(package); package.set_defaults(handler=_verify_annotation_package)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    if hasattr(arguments, "root"):
        try:
            arguments.root = _absolute_nofollow_root(arguments.root)
        except (CliError, OSError):
            return _error("evidence root is invalid")
    return arguments.handler(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
