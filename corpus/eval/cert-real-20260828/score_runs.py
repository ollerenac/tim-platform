#!/usr/bin/env python3
"""Score the frozen CNSD/ColCERT Bedrock runs against the reviewed reference."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from ioc_fanger import fang


EXPECTED_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
EXPECTED_REGION = "us-east-1"
REPETITIONS = (1, 2, 3)
ENTITY_TYPES = (
    "indicator",
    "vulnerability",
    "attack-pattern",
    "threat-actor",
    "malware",
    "sector",
    "country",
    "technology",
)
FLAT_FIELDS = {
    "vulnerability": "exploited_cves",
    "attack-pattern": "technique_keywords",
    "threat-actor": "threat_actors",
    "malware": "malware_families",
    "sector": "targeted_sectors",
    "country": "targeted_countries",
    "technology": "victim_technologies",
}
TID_RE = re.compile(r"\[?(T\d{4}(?:\.\d{3})?)\]?", re.IGNORECASE)


class IntegrityError(RuntimeError):
    """Raised when the frozen corpus or its twelve outputs are incomplete."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fold(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _norm_value(value: str) -> str:
    value = value.strip().lower()
    value = value.replace("[.]", ".").replace("[:]", ":").replace("hxxp", "http")
    if value.startswith("*."):
        value = value[2:]
    return value


def _norm_name(value: str) -> str:
    value = unicodedata.normalize("NFKD", value.lower())
    value = "".join(character for character in value if unicodedata.category(character) != "Mn")
    return re.sub(r"[^a-z0-9]+", " ", value).strip()


def normalize_entity(entity: dict) -> tuple[str, str]:
    """Return the exact comparison key used for an extracted/reference entity."""
    entity_type = str(entity.get("type", "")).strip().lower()
    value = str(entity.get("value", "")).strip()
    if not entity_type or not value:
        raise ValueError("entity type and value are required")
    if entity_type == "attack-pattern":
        match = TID_RE.search(value)
        normalized = match.group(1).upper() if match else _norm_name(value)
    elif entity_type in {"indicator", "vulnerability"}:
        normalized = _norm_value(value)
    else:
        normalized = _norm_name(value)
    return entity_type, normalized


def _relationship_key(relationship: dict, by_id: dict[str, dict]):
    source = by_id.get(relationship.get("source"))
    target = by_id.get(relationship.get("target"))
    relationship_type = str(relationship.get("type", "")).strip().lower()
    if source is None or target is None or not relationship_type:
        return None
    source_type, source_value = normalize_entity(source)
    target_type, target_value = normalize_entity(target)
    return (
        source_type,
        source_value,
        relationship_type,
        target_type,
        target_value,
    )


def prediction_sets(output: dict) -> dict:
    """Build entity sets from TIM's flat output and relation sets from v2 objects."""
    entities: set[tuple[str, str]] = set()
    for candidate in output.get("accepted_iocs", []) or []:
        if isinstance(candidate, dict) and candidate.get("value"):
            entities.add(normalize_entity({"type": "indicator", "value": candidate["value"]}))
    for entity_type, field in FLAT_FIELDS.items():
        for value in output.get(field, []) or []:
            if isinstance(value, str) and value.strip():
                entities.add(normalize_entity({"type": entity_type, "value": value}))

    v2_entities = [row for row in output.get("v2_entities", []) or [] if isinstance(row, dict)]
    by_id = {
        row["id"]: row
        for row in v2_entities
        if isinstance(row.get("id"), str) and row.get("id")
    }
    relationships = set()
    invalid = 0
    for relationship in output.get("v2_relationships", []) or []:
        if not isinstance(relationship, dict):
            invalid += 1
            continue
        key = _relationship_key(relationship, by_id)
        if key is None:
            invalid += 1
        else:
            relationships.add(key)
    return {
        "entities": entities,
        "relationships": relationships,
        "invalid_endpoint_relationships": invalid,
    }


def reference_sets(expected: dict) -> dict:
    entities_list = [row for row in expected.get("entities", []) if isinstance(row, dict)]
    entities = {normalize_entity(row) for row in entities_list}
    by_id = {
        row["id"]: row
        for row in entities_list
        if isinstance(row.get("id"), str) and row.get("id")
    }
    relationships = set()
    for relationship in expected.get("relationships", []) or []:
        key = _relationship_key(relationship, by_id)
        if key is None:
            raise IntegrityError("reviewed reference contains a relationship with a missing endpoint")
        relationships.add(key)
    return {"entities": entities, "relationships": relationships}


def _metrics(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    denominator = 2 * tp + fp + fn
    f1 = 2 * tp / denominator if denominator else None
    return {
        "counts": {"tp": tp, "fp": fp, "fn": fn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _score_sets(predicted: set, gold: set) -> dict:
    return _metrics(
        tp=len(predicted & gold),
        fp=len(predicted - gold),
        fn=len(gold - predicted),
    )


def _citation_metrics(output: dict, source_text: str) -> dict:
    source = _fold(fang(source_text))
    objects = [
        row
        for field in ("v2_entities", "v2_relationships")
        for row in (output.get(field, []) or [])
        if isinstance(row, dict)
    ]
    localized = sum(
        1
        for row in objects
        if isinstance(row.get("quote"), str)
        and row["quote"].strip()
        and _fold(row["quote"]) in source
    )
    total = len(objects)
    return {
        "localized": localized,
        "total": total,
        "rate": localized / total if total else None,
    }


def _serialize_entities(values: set[tuple[str, str]]) -> list[dict]:
    return [{"type": entity_type, "value": value} for entity_type, value in sorted(values)]


def _serialize_relationships(values: set[tuple]) -> list[dict]:
    return [
        {
            "source_type": row[0],
            "source_value": row[1],
            "type": row[2],
            "target_type": row[3],
            "target_value": row[4],
        }
        for row in sorted(values)
    ]


def score_run(run: dict, expected: dict, source_text: str) -> dict:
    output = run.get("model_output", {})
    predicted = prediction_sets(output)
    gold = reference_sets(expected)
    entity_score = _score_sets(predicted["entities"], gold["entities"])
    entity_score["false_positives"] = _serialize_entities(
        predicted["entities"] - gold["entities"]
    )
    entity_score["false_negatives"] = _serialize_entities(
        gold["entities"] - predicted["entities"]
    )
    by_type = {}
    for entity_type in ENTITY_TYPES:
        pred_type = {row for row in predicted["entities"] if row[0] == entity_type}
        gold_type = {row for row in gold["entities"] if row[0] == entity_type}
        if pred_type or gold_type:
            by_type[entity_type] = _score_sets(pred_type, gold_type)
    entity_score["by_type"] = by_type
    predicted_indicators = {row for row in predicted["entities"] if row[0] == "indicator"}
    gold_indicators = {row for row in gold["entities"] if row[0] == "indicator"}
    indicator_score = _score_sets(predicted_indicators, gold_indicators)
    knowledge_score = _score_sets(
        predicted["entities"] - predicted_indicators,
        gold["entities"] - gold_indicators,
    )

    relationship_score = _score_sets(
        predicted["relationships"], gold["relationships"]
    )
    relationship_score["false_positives"] = _serialize_relationships(
        predicted["relationships"] - gold["relationships"]
    )
    relationship_score["false_negatives"] = _serialize_relationships(
        gold["relationships"] - predicted["relationships"]
    )
    relationship_score["invalid_endpoint_relationships"] = predicted[
        "invalid_endpoint_relationships"
    ]
    return {
        "document": run.get("document"),
        "repetition": run.get("repetition"),
        "status": run.get("status"),
        "elapsed_seconds": run.get("elapsed_seconds"),
        "emitted_flat_entities": len(predicted["entities"]),
        "emitted_v2_entities": len(output.get("v2_entities", []) or []),
        "emitted_v2_relationships": len(output.get("v2_relationships", []) or []),
        "entities": entity_score,
        "indicators": indicator_score,
        "knowledge_entities": knowledge_score,
        "relationships": relationship_score,
        "citations": _citation_metrics(output, source_text),
    }


def aggregate_scores(rows: list[dict]) -> dict:
    result = {}
    for category in ("entities", "indicators", "knowledge_entities", "relationships"):
        counts = {
            key: sum(row[category]["counts"][key] for row in rows)
            for key in ("tp", "fp", "fn")
        }
        result[category] = _metrics(**counts)
    by_type = {}
    for entity_type in ENTITY_TYPES:
        type_rows = [
            row["entities"]["by_type"][entity_type]
            for row in rows
            if entity_type in row["entities"].get("by_type", {})
        ]
        if type_rows:
            counts = {
                key: sum(row["counts"][key] for row in type_rows)
                for key in ("tp", "fp", "fn")
            }
            by_type[entity_type] = _metrics(**counts)
    if by_type:
        result["entities"]["by_type"] = by_type
    localized = sum(row["citations"]["localized"] for row in rows)
    total = sum(row["citations"]["total"] for row in rows)
    result["citations"] = {
        "localized": localized,
        "total": total,
        "rate": localized / total if total else None,
    }
    return result


def _load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise IntegrityError(f"expected a JSON object in {path}")
    return value


def score_corpus(root: Path) -> dict:
    root = Path(root)
    manifest = _load_json(root / "manifest.json")
    documents = manifest.get("documents")
    if not isinstance(documents, list) or len(documents) != 4:
        raise IntegrityError("the frozen manifest must contain exactly four documents")
    run_paths = sorted((root / "runs").glob("*.run-*.json"))
    if len(run_paths) != 12:
        raise IntegrityError(f"expected exactly twelve run files, found {len(run_paths)}")

    scored = []
    seen = set()
    statuses = set()
    for document in documents:
        stem = document["stem"]
        folder = root / "documents" / stem
        input_path = folder / "input.txt"
        expected_path = folder / "expected.json"
        expected = _load_json(expected_path)
        source_text = input_path.read_text(encoding="utf-8")
        for repetition in REPETITIONS:
            run_path = root / "runs" / f"{stem}.run-{repetition}.json"
            run = _load_json(run_path)
            identity = (run.get("document"), run.get("repetition"))
            if identity != (stem, repetition) or identity in seen:
                raise IntegrityError(f"run identity mismatch or duplicate in {run_path}")
            seen.add(identity)
            if run.get("provider") != "bedrock":
                raise IntegrityError(f"non-Bedrock provider in {run_path}")
            if run.get("model") != EXPECTED_MODEL or run.get("aws_region") != EXPECTED_REGION:
                raise IntegrityError(f"model or region drift in {run_path}")
            if run.get("opencti_writes") != 0:
                raise IntegrityError(f"OpenCTI writes declared in {run_path}")
            if run.get("input_sha256") != _sha256(input_path):
                raise IntegrityError(f"input hash mismatch in {run_path}")
            if run.get("reference_sha256") != _sha256(expected_path):
                raise IntegrityError(f"reference hash mismatch in {run_path}")
            statuses.add(str(run.get("status")))
            scored.append(score_run(run, expected, source_text))

    aggregate = aggregate_scores(scored)
    per_document = {}
    variability = {}
    for document in documents:
        stem = document["stem"]
        rows = [row for row in scored if row["document"] == stem]
        per_document[stem] = aggregate_scores(rows)
        recalls = [row["entities"]["recall"] for row in rows if row["entities"]["recall"] is not None]
        relation_recalls = [row["relationships"]["recall"] for row in rows if row["relationships"]["recall"] is not None]
        variability[stem] = {
            "flat_entity_count_range": [
                min(row["emitted_flat_entities"] for row in rows),
                max(row["emitted_flat_entities"] for row in rows),
            ],
            "v2_relationship_count_range": [
                min(row["emitted_v2_relationships"] for row in rows),
                max(row["emitted_v2_relationships"] for row in rows),
            ],
            "entity_recall_range": [min(recalls), max(recalls)] if recalls else None,
            "relationship_recall_range": (
                [min(relation_recalls), max(relation_recalls)] if relation_recalls else None
            ),
        }
    elapsed = [row["elapsed_seconds"] for row in scored if isinstance(row["elapsed_seconds"], (int, float))]
    return {
        "schema_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "experiment": "cnsd-colcert-haiku-20260828",
        "integrity": {
            "documents": len(documents),
            "runs": len(scored),
            "repetitions_per_document": 3,
            "provider": "bedrock",
            "model": EXPECTED_MODEL,
            "aws_region": EXPECTED_REGION,
            "statuses": sorted(statuses),
            "opencti_writes": 0,
        },
        "reference": {
            "entity_instances_per_repetition": sum(
                len(_load_json(root / "documents" / row["stem"] / "expected.json")["entities"])
                for row in documents
            ),
            "relationship_instances_per_repetition": sum(
                len(_load_json(root / "documents" / row["stem"] / "expected.json")["relationships"])
                for row in documents
            ),
        },
        "aggregate": aggregate,
        "per_document": per_document,
        "variability": variability,
        "timing_seconds": {
            "min": min(elapsed),
            "max": max(elapsed),
            "mean": sum(elapsed) / len(elapsed),
        },
        "runs": scored,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = score_corpus(args.root)
    output = args.output or args.root / "results.json"
    output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"output": str(output), "runs": result["integrity"]["runs"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
