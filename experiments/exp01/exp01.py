#!/usr/bin/env python3
"""Reproducible command-line harness for TIM experiment EXP-01."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import stix2


class ExperimentError(Exception):
    """Raised when an experimental invariant is not satisfied."""


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExperimentError(f"cannot read {path}: {exc}") from exc


def validate_fixture(fixture_path: Path, oracle_path: Path) -> dict[str, Any]:
    fixture = load_json(fixture_path)
    oracle = load_json(oracle_path)

    try:
        stix2.parse(json.dumps(fixture), allow_custom=False)
    except Exception as exc:  # stix2 exposes several parser exception classes
        raise ExperimentError(f"invalid STIX bundle: {exc}") from exc

    objects = fixture.get("objects", [])
    by_id = {item.get("id"): item for item in objects}
    if len(by_id) != len(objects):
        raise ExperimentError("oracle mismatch: duplicate STIX object identifiers")

    actual_domains = {
        item["id"] for item in objects if item.get("type") != "relationship"
    }
    actual_relationships = {
        (item.get("source_ref"), item.get("relationship_type"), item.get("target_ref"))
        for item in objects
        if item.get("type") == "relationship"
    }
    reports = [item for item in objects if item.get("type") == "report"]
    actual_report_members = set(reports[0].get("object_refs", [])) if len(reports) == 1 else set()
    actual_created_by = {
        item["id"]: item["created_by_ref"]
        for item in objects
        if "created_by_ref" in item
    }
    actual_external_references: dict[str, str] = {}
    for item in objects:
        matching = [
            reference
            for reference in item.get("external_references", [])
            if reference.get("source_name") == "TIMEXP-EXP01"
        ]
        if len(matching) == 1 and matching[0].get("external_id"):
            actual_external_references[item["id"]] = matching[0]["external_id"]

    checks = {
        "bundle identifier": (fixture.get("id"), oracle.get("fixture_id")),
        "object identifiers": (set(by_id), set(oracle["domain_objects"]) | set(oracle["external_references"]) - set(oracle["domain_objects"])),
        "domain objects": (actual_domains, set(oracle["domain_objects"])),
        "relationships": (actual_relationships, {tuple(row) for row in oracle["relationships"]}),
        "report members": (actual_report_members, set(oracle["report_members"])),
        "created-by provenance": (actual_created_by, oracle["created_by"]),
        "external-reference provenance": (actual_external_references, oracle["external_references"]),
    }
    for label, (actual, expected) in checks.items():
        if actual != expected:
            raise ExperimentError(
                f"oracle mismatch for {label}: expected {expected!r}, got {actual!r}"
            )

    relationship_object_count = len(actual_relationships)
    relationship_fact_count = relationship_object_count + len(actual_report_members)
    provenance_fact_count = len(actual_created_by) + len(actual_external_references)
    return {
        "bundle_id": fixture["id"],
        "domain_object_count": len(actual_domains),
        "external_reference_fact_count": len(actual_external_references),
        "object_count": len(objects),
        "provenance_fact_count": provenance_fact_count,
        "relationship_fact_count": relationship_fact_count,
        "relationship_object_count": relationship_object_count,
        "status": "valid",
    }


def _ratio(actual: set[Any], expected: set[Any]) -> float:
    if not expected:
        return 1.0
    return round(len(actual & expected) / len(expected), 6)


def score_observation(observed_path: Path, oracle_path: Path) -> dict[str, Any]:
    observed = load_json(observed_path)
    oracle = load_json(oracle_path)
    objects = observed.get("objects", [])
    if not isinstance(objects, list):
        raise ExperimentError("observation must contain an objects list")

    expected_ids = set(oracle["external_references"])
    expected_by_external_id = {
        external_id: object_id
        for object_id, external_id in oracle["external_references"].items()
    }
    canonical_to_expected: dict[str, str] = {}
    for item in objects:
        for reference in item.get("external_references", []):
            expected_id = expected_by_external_id.get(reference.get("external_id"))
            if reference.get("source_name") == "TIMEXP-EXP01" and expected_id:
                canonical_to_expected[item["id"]] = expected_id

    def normalize(object_id: str) -> str:
        return canonical_to_expected.get(object_id, object_id)

    ids = [normalize(item["id"]) for item in objects if item.get("id")]
    id_counts = Counter(ids)
    actual_ids = set(ids)

    actual_relationship_facts = {
        (
            normalize(item.get("source_ref")),
            item.get("relationship_type"),
            normalize(item.get("target_ref")),
        )
        for item in objects
        if item.get("type") == "relationship"
    }
    actual_relationship_facts |= {
        (normalize(item["id"]), "object-ref", normalize(member))
        for item in objects
        if item.get("type") == "report"
        for member in item.get("object_refs", [])
    }
    expected_relationship_facts = {tuple(row) for row in oracle["relationships"]}
    expected_relationship_facts |= {
        ("report--66666666-6666-4666-8666-666666666666", "object-ref", member)
        for member in oracle["report_members"]
    }

    actual_created_by = {
        (normalize(item["id"]), normalize(item["created_by_ref"]))
        for item in objects
        if item.get("id") and item.get("created_by_ref")
    }
    expected_created_by = set(oracle["created_by"].items())
    actual_external_references = {
        (normalize(item["id"]), reference["external_id"])
        for item in objects
        if item.get("id")
        for reference in item.get("external_references", [])
        if reference.get("source_name") == "TIMEXP-EXP01"
        and reference.get("external_id")
    }
    expected_external_references = set(oracle["external_references"].items())
    actual_provenance = actual_created_by | actual_external_references
    expected_provenance = expected_created_by | expected_external_references

    result = {
        "duplicate_object_count": sum(count - 1 for count in id_counts.values() if count > 1),
        "external_reference_recall": _ratio(
            actual_external_references, expected_external_references
        ),
        "missing_object_count": len(expected_ids - actual_ids),
        "object_recall": _ratio(actual_ids, expected_ids),
        "provenance_recall": _ratio(actual_provenance, expected_provenance),
        "relationship_recall": _ratio(
            actual_relationship_facts, expected_relationship_facts
        ),
        "status": "pass",
        "unexpected_object_count": len(actual_ids - expected_ids),
    }
    if any(
        (
            result["duplicate_object_count"],
            result["missing_object_count"],
            result["unexpected_object_count"],
        )
    ) or any(
        result[key] != 1.0
        for key in (
            "object_recall",
            "relationship_recall",
            "provenance_recall",
            "external_reference_recall",
        )
    ):
        result["status"] = "fail"
    return result


def build_manifest(root: Path, output: Path) -> dict[str, Any]:
    output_resolved = output.resolve()
    entries = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if path.resolve() == output_resolved:
            continue
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        content = path.read_bytes()
        entries.append(
            {
                "bytes": len(content),
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return {"algorithm": "sha256", "file_count": len(entries), "files": entries}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-fixture")
    validate.add_argument("--fixture", type=Path, required=True)
    validate.add_argument("--oracle", type=Path, required=True)
    score = commands.add_parser("score")
    score.add_argument("--observed", type=Path, required=True)
    score.add_argument("--oracle", type=Path, required=True)
    score.add_argument("--output", type=Path)
    manifest = commands.add_parser("manifest")
    manifest.add_argument("--root", type=Path, required=True)
    manifest.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "validate-fixture":
            result = validate_fixture(args.fixture, args.oracle)
            exit_code = 0
        elif args.command == "score":
            result = score_observation(args.observed, args.oracle)
            exit_code = 0 if result["status"] == "pass" else 2
        elif args.command == "manifest":
            result = build_manifest(args.root, args.output)
            exit_code = 0
        else:  # pragma: no cover - argparse prevents this branch
            raise ExperimentError(f"unsupported command: {args.command}")
    except ExperimentError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    payload = json.dumps(result, sort_keys=True)
    output = getattr(args, "output", None)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
