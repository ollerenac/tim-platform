#!/usr/bin/env python3
"""Validate human reference annotations against frozen text and PDF pages."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from PyPDF2 import PdfReader


ENTITY_TYPES = {
    "threat-actor", "malware", "vulnerability", "attack-pattern",
    "indicator", "sector", "country", "technology",
}
IOC_TYPES = {"ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email"}
RELATIONSHIP_TYPES = {"uses", "targets", "exploits", "indicates", "attributed-to"}
STATUSES = {"PENDING_REVIEW", "APPROVED", "CORRECTED", "REJECTED"}


def fold(value: str) -> str:
    return " ".join(value.split()).casefold()


def _grounded(label: str, quote: str) -> bool:
    return bool(label.strip()) and fold(label) in fold(quote)


def validate(annotation: dict, input_text: str, pages: list[str]) -> list[str]:
    errors: list[str] = []
    if annotation.get("schema_version") != 1:
        errors.append("schema_version must be 1")
    if annotation.get("annotation_status") not in STATUSES:
        errors.append("annotation_status is invalid")
    if not isinstance(annotation.get("document"), str) or not annotation["document"].strip():
        errors.append("document is required")

    entities = annotation.get("entities")
    relationships = annotation.get("relationships")
    if not isinstance(entities, list):
        return [*errors, "entities must be a list"]
    if not isinstance(relationships, list):
        return [*errors, "relationships must be a list"]

    ids: set[str] = set()
    folded_document = fold(input_text)
    for index, entity in enumerate(entities):
        if not isinstance(entity, dict):
            errors.append(f"entities[{index}]: must be an object")
            continue
        entity_id = entity.get("id")
        label = f"entities[{entity_id or index}]"
        if not isinstance(entity_id, str) or not entity_id:
            errors.append(f"entities[{index}]: id is required")
        elif entity_id in ids:
            errors.append(f"duplicate entity id: {entity_id}")
        else:
            ids.add(entity_id)
        entity_type = entity.get("type")
        if entity_type not in ENTITY_TYPES:
            errors.append(f"{label}: unsupported type {entity_type}")
        value = entity.get("value")
        quote = entity.get("quote")
        source_value = entity.get("source_value", value)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{label}: value is required")
        if not isinstance(quote, str) or not quote.strip():
            errors.append(f"{label}: quote is required")
            continue
        if fold(quote) not in folded_document:
            errors.append(f"{label}: quote not found in input text")
        page = entity.get("page")
        if not isinstance(page, int) or page < 1 or page > len(pages):
            errors.append(f"{label}: invalid page {page}")
        elif fold(quote) not in fold(pages[page - 1] or ""):
            errors.append(f"{label}: quote not found on page {page}")
        if not isinstance(source_value, str) or not _grounded(source_value, quote):
            errors.append(f"{label}: source value not found in quote")
        if entity_type == "indicator" and entity.get("ioc_type") not in IOC_TYPES:
            errors.append(f"{label}: unsupported ioc_type {entity.get('ioc_type')}")

    for index, relationship in enumerate(relationships):
        label = f"relationships[{index}]"
        if not isinstance(relationship, dict):
            errors.append(f"{label}: must be an object")
            continue
        source = relationship.get("source")
        target = relationship.get("target")
        if source not in ids:
            errors.append(f"{label}: unknown source {source}")
        if target not in ids:
            errors.append(f"{label}: unknown target {target}")
        if relationship.get("type") not in RELATIONSHIP_TYPES:
            errors.append(f"{label}: unsupported type {relationship.get('type')}")
        quote = relationship.get("quote")
        if not isinstance(quote, str) or not quote.strip():
            errors.append(f"{label}: quote is required")
            continue
        if fold(quote) not in folded_document:
            errors.append(f"{label}: quote not found in input text")
        page = relationship.get("page")
        if not isinstance(page, int) or page < 1 or page > len(pages):
            errors.append(f"{label}: invalid page {page}")
        elif fold(quote) not in fold(pages[page - 1] or ""):
            errors.append(f"{label}: quote not found on page {page}")
    return errors


def _pdf_pages(path: Path) -> list[str]:
    return [page.extract_text() or "" for page in PdfReader(str(path)).pages]


def validate_folder(folder: Path) -> list[str]:
    annotation = json.loads((folder / "expected.json").read_text(encoding="utf-8"))
    input_text = (folder / "input.txt").read_text(encoding="utf-8")
    return validate(annotation, input_text, _pdf_pages(folder / "source.pdf"))


def main() -> int:
    cli = argparse.ArgumentParser()
    cli.add_argument("root", type=Path, nargs="?", default=Path(__file__).parent / "documents")
    args = cli.parse_args()
    failed = False
    for folder in sorted(path for path in args.root.iterdir() if path.is_dir()):
        expected = folder / "expected.json"
        if not expected.exists():
            print(f"{folder.name}: MISSING expected.json")
            failed = True
            continue
        errors = validate_folder(folder)
        print(f"{folder.name}: {'OK' if not errors else 'INVALID'}")
        for error in errors:
            print(f"  - {error}")
        failed = failed or bool(errors)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
