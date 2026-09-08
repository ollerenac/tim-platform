"""Deterministic scoring for the frozen CISA/STIX evaluation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import random
import re
from statistics import mean, median
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ioc_fanger import fang

from .cisa_match import EquivalenceDictionary, load_equivalences, match_entities
from .cisa_reference import CanonicalEntity, CanonicalRelation
from .cisa_runner import (
    EXPECTED_EQUIVALENCE_SHA256,
    EXPECTED_MODEL,
    EXPECTED_PROMPT_SHA256,
    EXPECTED_PROVIDER,
    EXPECTED_REGION,
    REPETITIONS,
    validate_frozen_evidence,
)
from .jsonio import canonical_bytes, load_json, sha256_file, write_new_json


PRIMARY_TYPES = (
    "indicator",
    "attack-pattern",
    "threat-actor",
    "malware",
    "vulnerability",
)
CONTEXT_TYPES = ("country", "sector", "technology")
_ALLOWED_RELATIONSHIPS = frozenset(
    {"uses", "targets", "exploits", "indicates", "attributed-to"}
)
_ALLOWED_RELATION_SIGNATURES = frozenset(
    {
        ("indicator", "indicates", "threat-actor"),
        ("indicator", "indicates", "malware"),
        ("threat-actor", "uses", "malware"),
        ("threat-actor", "uses", "attack-pattern"),
        ("threat-actor", "exploits", "vulnerability"),
        ("malware", "exploits", "vulnerability"),
    }
)
_ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_INDICATOR_SUBTYPES = frozenset(
    {"ip", "domain", "url", "email", "hash_md5", "hash_sha1", "hash_sha256"}
)
_FLAT_FIELDS = {
    "attack-pattern": "technique_keywords",
    "threat-actor": "threat_actors",
    "sector": "targeted_sectors",
    "malware": "malware_families",
    "country": "targeted_countries",
    "vulnerability": "exploited_cves",
    "technology": "victim_technologies",
}
_FINAL_FIELDS = frozenset(
    {
        "unique_iocs",
        "accepted_iocs",
        *_FLAT_FIELDS.values(),
        "campaign_summary",
        "v2_entities",
        "v2_relationships",
    }
)


class ScoreIntegrityError(RuntimeError):
    """Raised when final evidence is incomplete or does not match its seal."""


@dataclass(frozen=True)
class PredictionRelationship:
    source_id: str
    relationship_type: str
    target_id: str


@dataclass(frozen=True)
class PredictionView:
    entities: tuple[CanonicalEntity, ...]
    relationships: tuple[PredictionRelationship, ...]
    source_ids_by_identity: Mapping[tuple[str, str, str], tuple[str, ...]]
    v2_rows: tuple[Mapping[str, Any], ...]
    v2_entity_row_count: int
    v2_relationship_row_count: int
    exclusions: tuple[dict[str, str], ...]


def structural_metrics(tp: int, cisa_only: int, tim_only: int) -> dict[str, Any]:
    """Return binary structural comparison metrics for one fact scope."""
    cisa_total = tp + cisa_only
    tim_total = tp + tim_only
    counts = {
        "matched": tp,
        "cisa_only": cisa_only,
        "tim_only_unassessed": tim_only,
    }
    if cisa_total == 0:
        return {
            "status": "not_evaluable",
            "cosine": None,
            "cisa_recall": None,
            "jaccard": None,
            "counts": counts,
        }
    union = tp + cisa_only + tim_only
    return {
        "status": "evaluated",
        "cosine": tp / math.sqrt(cisa_total * tim_total) if tim_total else 0.0,
        "cisa_recall": tp / cisa_total,
        "jaccard": tp / union,
        "counts": counts,
    }


def macro_recall(rows: Iterable[Mapping[str, Any]]) -> float | None:
    """Average document recalls without weighting documents by entity count."""
    values = [float(row["recall"]) for row in rows if row.get("recall") is not None]
    return sum(values) / len(values) if values else None


def pairwise_jaccard(runs: Sequence[set[Any] | frozenset[Any]]) -> list[float]:
    """Return every pairwise Jaccard value for exactly three repetitions."""
    if len(runs) != 3:
        raise ValueError("stability requires exactly three repetitions")
    result: list[float] = []
    for left_index in range(2):
        for right_index in range(left_index + 1, 3):
            left = set(runs[left_index])
            right = set(runs[right_index])
            union = left | right
            result.append(len(left & right) / len(union) if union else 1.0)
    return result


def _percentile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def bootstrap_ci(
    document_values: Sequence[float],
    *,
    seed: int = 20260830,
    samples: int = 10_000,
    statistic: str = "mean",
) -> dict[str, float | int | str]:
    """Bootstrap a named statistic by resampling whole document-level values."""
    if not document_values:
        raise ValueError("bootstrap requires at least one document value")
    if samples <= 0:
        raise ValueError("bootstrap samples must be positive")
    if statistic not in {"mean", "median"}:
        raise ValueError("bootstrap statistic must be mean or median")
    values = [float(value) for value in document_values]
    estimator = mean if statistic == "mean" else median
    generator = random.Random(seed)
    estimates = [
        estimator([generator.choice(values) for _ in values])
        for _ in range(samples)
    ]
    return {
        "unit": "document",
        "seed": seed,
        "samples": samples,
        "confidence": 0.95,
        "statistic": statistic,
        "estimate": estimator(values),
        "lower": _percentile(estimates, 0.025),
        "upper": _percentile(estimates, 0.975),
    }


def bootstrap_ratio_ci(
    document_counts: Sequence[tuple[int, int]], *, seed: int = 20260830, samples: int = 10_000
) -> dict[str, float | int | str]:
    """Bootstrap an aggregate numerator/denominator ratio at the document unit."""
    if not document_counts:
        raise ValueError("bootstrap ratio requires at least one document")
    if samples <= 0:
        raise ValueError("bootstrap samples must be positive")
    if any(
        not isinstance(numerator, int) or not isinstance(denominator, int)
        or numerator < 0 or denominator < 0 or numerator > denominator
        for numerator, denominator in document_counts
    ):
        raise ValueError("bootstrap ratio counts must be nonnegative numerator/denominator pairs")

    def ratio(rows: Sequence[tuple[int, int]]) -> float | None:
        numerator = sum(row[0] for row in rows)
        denominator = sum(row[1] for row in rows)
        return numerator / denominator if denominator else None

    generator = random.Random(seed)
    estimates = [
        ratio([generator.choice(document_counts) for _ in document_counts])
        for _ in range(samples)
    ]
    numeric = [value for value in estimates if value is not None]
    undefined_resamples = samples - len(numeric)
    return {
        "unit": "document",
        "population_documents": len(document_counts),
        "seed": seed,
        "samples": samples,
        "confidence": 0.95,
        "statistic": "aggregate_ratio",
        "estimate": ratio(document_counts),
        "defined_resamples": len(numeric),
        "undefined_resamples": undefined_resamples,
        "lower": _percentile(numeric, 0.025) if numeric else None,
        "upper": _percentile(numeric, 0.975) if numeric else None,
    }


def _non_string_sequence(value: object, field: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ScoreIntegrityError(f"prediction field {field} must be an array")
    return value


def _fold(value: str) -> str:
    return " ".join(fang(value).split())


def _normal_url(value: str) -> str:
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.hostname:
        return value
    try:
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError:
        return value
    host = parsed.hostname.casefold()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    credentials = ""
    if parsed.username is not None:
        credentials = parsed.username
        if parsed.password is not None:
            credentials += f":{parsed.password}"
        credentials += "@"
    return urlunsplit(
        (parsed.scheme.casefold(), credentials + host + port, parsed.path, parsed.query, parsed.fragment)
    )


def _indicator_subtype(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    subtype = value.strip().casefold().replace("-", "_")
    aliases = {
        "ipv4": "ip",
        "ipv6": "ip",
        "ipv4_addr": "ip",
        "ipv6_addr": "ip",
        "domain_name": "domain",
        "md5": "hash_md5",
        "sha1": "hash_sha1",
        "sha256": "hash_sha256",
    }
    subtype = aliases.get(subtype, subtype)
    return subtype if subtype in _INDICATOR_SUBTYPES else None


def _canonical_value(canonical_type: str, value: str, subtype: str | None) -> str | None:
    value = _fold(value)
    if not value:
        return None
    if canonical_type == "indicator":
        if subtype == "ip":
            try:
                return ipaddress.ip_address(value).compressed
            except ValueError:
                return None
        if subtype == "domain":
            return value.rstrip(".").casefold()
        if subtype == "url":
            return _normal_url(value)
        if subtype in {"email", "hash_md5", "hash_sha1", "hash_sha256"}:
            return value.casefold()
        return None
    if canonical_type == "vulnerability":
        return value.upper() if _CVE_ID.fullmatch(value) else None
    return value


def _prediction_entity(
    document_id: str,
    row: Mapping[str, Any],
    *,
    source_id: str,
    origin: str,
) -> CanonicalEntity | None:
    raw_type = row.get("type")
    raw_value = row.get("value")
    if not isinstance(raw_type, str) or not isinstance(raw_value, str):
        return None
    canonical_type = raw_type.strip().casefold()
    if canonical_type == "intrusion-set":
        canonical_type = "threat-actor"
    if canonical_type not in {*PRIMARY_TYPES, *CONTEXT_TYPES}:
        return None
    subtype = _indicator_subtype(row.get("ioc_type")) if canonical_type == "indicator" else None
    value = _canonical_value(canonical_type, raw_value, subtype)
    if value is None:
        return None
    raw_aliases = row.get("aliases", [])
    aliases: set[str] = set()
    if isinstance(raw_aliases, Sequence) and not isinstance(raw_aliases, (str, bytes, bytearray)):
        aliases.update(
            _fold(alias) for alias in raw_aliases if isinstance(alias, str) and _fold(alias)
        )
    if canonical_type == "attack-pattern":
        aliases.update(match.upper() for match in _ATTACK_ID.findall(value))
    return CanonicalEntity(
        document_id=document_id,
        canonical_type=canonical_type,
        canonical_value=value,
        source_value=raw_value,
        source_object_id=source_id,
        aliases=tuple(sorted(aliases)),
        reference_origin=origin,
        grounded_in_pdf=True,
        grounding_value=value,
        indicator_subtype=subtype,
    )


def _entity_identity(entity: CanonicalEntity) -> tuple[str, str, str]:
    value = entity.canonical_value if entity.indicator_subtype == "url" else entity.canonical_value.casefold()
    return entity.canonical_type, entity.indicator_subtype or "", value


def canonicalize_prediction(
    document_id: str, output: Mapping[str, Any], *, stage: str
) -> PredictionView:
    """Adapt either raw Haiku objects or final TIM output through one strict path."""
    if stage not in {"raw", "final"}:
        raise ValueError("prediction stage must be raw or final")
    if not isinstance(output, Mapping):
        raise ScoreIntegrityError(f"{stage} prediction must be a JSON object")
    if stage == "raw":
        required = {"raw_v2_entities", "raw_v2_relationships"}
        entity_field = "raw_v2_entities"
        relationship_field = "raw_v2_relationships"
    else:
        required = _FINAL_FIELDS
        entity_field = "v2_entities"
        relationship_field = "v2_relationships"
    missing = sorted(required - set(output))
    if missing:
        raise ScoreIntegrityError(f"{stage} prediction is missing {', '.join(missing)}")

    raw_v2_rows = _non_string_sequence(output[entity_field], entity_field)
    entities_by_identity: dict[tuple[str, str, str], CanonicalEntity] = {}
    source_ids_by_identity: dict[tuple[str, str, str], set[str]] = {}
    exclusions: list[dict[str, str]] = []
    v2_rows: list[Mapping[str, Any]] = []
    accepted_indicator_identities: set[tuple[str, str, str]] = set()
    if stage == "final":
        accepted_rows = _non_string_sequence(output["accepted_iocs"], "accepted_iocs")
        for index, row in enumerate(accepted_rows):
            if not isinstance(row, Mapping):
                exclusions.append({
                    "field": "accepted_iocs", "index": str(index), "reason": "not-an-object"
                })
                continue
            accepted = _prediction_entity(
                document_id,
                {"type": "indicator", "ioc_type": row.get("type"), "value": row.get("value")},
                source_id=f"final:accepted_iocs:{index}",
                origin="tim-final",
            )
            if accepted is None:
                exclusions.append({
                    "field": "accepted_iocs", "index": str(index), "reason": "not-comparable"
                })
                continue
            accepted_indicator_identities.add(_entity_identity(accepted))
    for index, row in enumerate(raw_v2_rows):
        if not isinstance(row, Mapping):
            exclusions.append({"field": entity_field, "index": str(index), "reason": "not-an-object"})
            continue
        v2_rows.append(row)
        source_id = row.get("id") if isinstance(row.get("id"), str) and row.get("id") else f"{stage}:v2:{index}"
        entity = _prediction_entity(
            document_id, row, source_id=str(source_id), origin=f"tim-{stage}"
        )
        if entity is None:
            exclusions.append({"field": entity_field, "index": str(index), "reason": "not-comparable"})
            continue
        identity = _entity_identity(entity)
        if (
            stage == "final"
            and entity.canonical_type == "indicator"
            and identity not in accepted_indicator_identities
        ):
            exclusions.append({
                "field": entity_field, "index": str(index), "reason": "not-shape-accepted"
            })
            continue
        source_ids_by_identity.setdefault(identity, set()).add(entity.source_object_id)
        previous = entities_by_identity.get(identity)
        if previous is None:
            entities_by_identity[identity] = entity
        elif entity.aliases:
            entities_by_identity[identity] = replace(
                previous, aliases=tuple(sorted(set(previous.aliases) | set(entity.aliases)))
            )

    if stage == "final":
        ioc_rows = _non_string_sequence(output["accepted_iocs"], "accepted_iocs")
        for index, row in enumerate(ioc_rows):
            if not isinstance(row, Mapping):
                exclusions.append({"field": "accepted_iocs", "index": str(index), "reason": "not-an-object"})
                continue
            adapted = {"type": "indicator", "ioc_type": row.get("type"), "value": row.get("value")}
            entity = _prediction_entity(
                document_id,
                adapted,
                source_id=f"final:accepted_iocs:{index}",
                origin="tim-final",
            )
            if entity is None:
                exclusions.append({"field": "accepted_iocs", "index": str(index), "reason": "not-comparable"})
                continue
            identity = _entity_identity(entity)
            source_ids_by_identity.setdefault(identity, set()).add(entity.source_object_id)
            entities_by_identity.setdefault(identity, entity)
        for canonical_type, field in _FLAT_FIELDS.items():
            rows = _non_string_sequence(output[field], field)
            for index, value in enumerate(rows):
                entity = _prediction_entity(
                    document_id,
                    {"type": canonical_type, "value": value},
                    source_id=f"final:{field}:{index}",
                    origin="tim-final",
                )
                if entity is None:
                    exclusions.append({"field": field, "index": str(index), "reason": "not-comparable"})
                    continue
                identity = _entity_identity(entity)
                source_ids_by_identity.setdefault(identity, set()).add(entity.source_object_id)
                entities_by_identity.setdefault(identity, entity)

    relationship_rows = _non_string_sequence(output[relationship_field], relationship_field)
    relationships: set[PredictionRelationship] = set()
    for index, row in enumerate(relationship_rows):
        if not isinstance(row, Mapping):
            exclusions.append({"field": relationship_field, "index": str(index), "reason": "not-an-object"})
            continue
        source = row.get("source")
        relation_type = row.get("type")
        target = row.get("target")
        if not all(isinstance(value, str) and value for value in (source, relation_type, target)):
            exclusions.append({"field": relationship_field, "index": str(index), "reason": "invalid-endpoint"})
            continue
        relationships.add(PredictionRelationship(source, relation_type.casefold(), target))
    return PredictionView(
        entities=tuple(sorted(entities_by_identity.values(), key=_entity_identity)),
        relationships=tuple(sorted(relationships, key=lambda row: (row.source_id, row.relationship_type, row.target_id))),
        source_ids_by_identity={
            identity: tuple(sorted(source_ids))
            for identity, source_ids in sorted(source_ids_by_identity.items())
        },
        v2_rows=tuple(v2_rows),
        v2_entity_row_count=len(raw_v2_rows),
        v2_relationship_row_count=len(relationship_rows),
        exclusions=tuple(exclusions),
    )


def _metrics(tp: int, fn: int, additions: int) -> dict[str, Any]:
    return structural_metrics(tp=tp, cisa_only=fn, tim_only=additions)


def _serialize_entity(entity: CanonicalEntity) -> dict[str, Any]:
    return {
        "canonical_type": entity.canonical_type,
        "canonical_value": entity.canonical_value,
        "indicator_subtype": entity.indicator_subtype,
        "source_object_id": entity.source_object_id,
        "aliases": list(entity.aliases),
    }


def _pending_pair_id(reference: CanonicalEntity, prediction: CanonicalEntity) -> str:
    """Give each unresolved nominal CISA/TIM pair a stable diagnostic identity."""
    payload = {
        "cisa": _serialize_entity(reference),
        "tim": _serialize_entity(prediction),
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _technical_or_structured(entity: CanonicalEntity) -> bool:
    """Technical values are deterministic identifiers, never human alias candidates."""
    if entity.canonical_type in {"indicator", "vulnerability"}:
        return True
    values = (entity.canonical_value, *entity.aliases)
    return any(_ATTACK_ID.search(value) or _CVE_ID.search(value) for value in values)


def score_entity_type(
    reference: Sequence[CanonicalEntity],
    prediction: Sequence[CanonicalEntity],
    equivalences: EquivalenceDictionary | Mapping[str, object],
) -> dict[str, Any]:
    """Score one comparable type with automatic, conservative matching only."""
    result = match_entities(reference, prediction, equivalences)
    exact_matches = tuple(match for match in result.matches if match.layer == "exact")
    equivalent_matches = result.matches
    exact_reference = {match.reference for match in exact_matches}
    exact_prediction = {match.prediction for match in exact_matches}
    pending = tuple(
        match for match in result.pending
        if not (_technical_or_structured(match.reference) or _technical_or_structured(match.prediction))
    )
    pending_ids = {
        _pending_pair_id(match.reference, match.prediction): match for match in pending
    }
    equivalent_reference = {match.reference for match in equivalent_matches}
    equivalent_prediction = {match.prediction for match in equivalent_matches}
    cisa_missing = [row for row in reference if row not in equivalent_reference]
    tim_only_unassessed = [
        row for row in prediction if row not in equivalent_prediction
    ]
    return {
        "reference_interpretation": "official_cisa_stix_is_partial",
        "reference_count": len(reference),
        "prediction_count": len(prediction),
        "exact": _metrics(
            len(exact_matches),
            len(reference) - len(exact_reference),
            len(prediction) - len(exact_prediction),
        ),
        "equivalence_aware": _metrics(
            len(equivalent_matches),
            len(cisa_missing),
            len(tim_only_unassessed),
        ),
        "matches": [
            {
                "layer": match.layer,
                "cisa": _serialize_entity(match.reference),
                "tim": _serialize_entity(match.prediction),
            }
            for match in equivalent_matches
        ],
        "cisa_missing": [_serialize_entity(row) for row in cisa_missing],
        "tim_only_unassessed": [
            _serialize_entity(row) for row in tim_only_unassessed
        ],
        "unresolved_nominal_pairs": len(pending),
        "pending_scope": "automatic_diagnostic_only_nonblocking",
        "pending_equivalences": [
            {
                "pair_id": _pending_pair_id(match.reference, match.prediction),
                "layer": "pending",
                "cisa": _serialize_entity(match.reference),
                "tim": _serialize_entity(match.prediction),
            }
            for match in pending
        ],
    }


def citation_localization(view: PredictionView, source_text: str) -> dict[str, float | int | None]:
    """Locate quotes for final TIM v2 entities only, never raw objects or relations."""
    source = _fold(source_text)
    localized = 0
    for row in view.v2_rows:
        quote = row.get("quote")
        if isinstance(quote, str) and quote.strip() and _fold(quote) in source:
            localized += 1
    total = len(view.v2_rows)
    return {
        "localized": localized,
        "total": total,
        "rate": localized / total if total else None,
    }


def raw_to_final_effect(
    raw: PredictionView,
    final: PredictionView,
    citation_stats: Mapping[str, Any],
) -> dict[str, Any]:
    """Report citation filtering separately from TIM's deterministic flat enrichment."""
    if not isinstance(citation_stats, Mapping):
        raise ScoreIntegrityError("citation_stats must be an object")
    dropped_entities = citation_stats.get("entities_dropped")
    dropped_relationships = citation_stats.get("relationships_dropped")
    if any(
        not isinstance(value, int) or isinstance(value, bool) or value < 0
        for value in (dropped_entities, dropped_relationships)
    ):
        raise ScoreIntegrityError("citation drop counts must be nonnegative integers")
    entity_counts = {
        "raw": raw.v2_entity_row_count,
        "kept": final.v2_entity_row_count,
        "dropped": dropped_entities,
    }
    relationship_counts = {
        "raw": raw.v2_relationship_row_count,
        "kept": final.v2_relationship_row_count,
        "dropped": dropped_relationships,
    }
    if entity_counts["raw"] != entity_counts["kept"] + entity_counts["dropped"]:
        raise ScoreIntegrityError("diagnostic entity drop counts do not reconcile")
    if relationship_counts["raw"] != relationship_counts["kept"] + relationship_counts["dropped"]:
        raise ScoreIntegrityError("diagnostic relationship drop counts do not reconcile")
    return {
        "v2_entities": entity_counts,
        "v2_relationships": relationship_counts,
        "raw_comparable_entities": sum(
            entity.canonical_type in PRIMARY_TYPES for entity in raw.entities
        ),
        "final_comparable_entities": sum(
            entity.canonical_type in PRIMARY_TYPES for entity in final.entities
        ),
        "final_flat_enrichment_is_separate": True,
    }


def _stable_rows(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for row in rows:
        safe = dict(row)
        key = json.dumps(safe, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
        unique.setdefault(key, safe)
    return [unique[key] for key in sorted(unique)]


def deterministic_type_sample(
    rows: Iterable[Mapping[str, Any]],
    *,
    seed: int = 20260831,
    limit: int = 20,
    document_order: Sequence[str] | None = None,
) -> list[dict[str, Any]]:
    """Sample each type reproducibly, taking one row per document before extras."""
    if limit <= 0:
        raise ValueError("sample limit must be positive")
    grouped: dict[str, list[dict[str, Any]]] = {}
    ordered_rows = _stable_rows(rows)
    rank = {document: index for index, document in enumerate(document_order or ())}
    if document_order is not None:
        ordered_rows.sort(
            key=lambda row: (rank.get(str(row.get("document")), len(rank)), json.dumps(row, sort_keys=True))
        )
    for row in ordered_rows:
        canonical_type = row.get("canonical_type")
        document = row.get("document")
        if not isinstance(canonical_type, str) or not isinstance(document, str):
            raise ScoreIntegrityError("review rows require canonical_type and document")
        grouped.setdefault(canonical_type, []).append(row)
    sampled: list[dict[str, Any]] = []
    for canonical_type in sorted(grouped):
        type_rows = grouped[canonical_type]
        if len(type_rows) <= limit:
            sampled.extend(type_rows)
            continue
        type_seed = int.from_bytes(
            hashlib.sha256(f"{seed}:{canonical_type}".encode("utf-8")).digest()[:8],
            "big",
        )
        generator = random.Random(type_seed)
        by_document: dict[str, list[dict[str, Any]]] = {}
        for row in type_rows:
            by_document.setdefault(str(row["document"]), []).append(row)
        document_names = sorted(by_document, key=lambda name: (rank.get(name, len(rank)), name))
        generator.shuffle(document_names)
        chosen: list[dict[str, Any]] = []
        chosen_keys: set[str] = set()
        for document in document_names[:limit]:
            candidates = list(by_document[document])
            generator.shuffle(candidates)
            row = candidates[0]
            chosen.append(row)
            chosen_keys.add(json.dumps(row, sort_keys=True, separators=(",", ":")))
        remaining = [
            row
            for row in type_rows
            if json.dumps(row, sort_keys=True, separators=(",", ":")) not in chosen_keys
        ]
        generator.shuffle(remaining)
        chosen.extend(remaining[: limit - len(chosen)])
        sampled.extend(_stable_rows(chosen))
    return sampled


def relationship_design_gate(
    *, support_documents: int, grounded_relations: int
) -> dict[str, Any]:
    """Expose the frozen exploratory gate without manufacturing a verdict."""
    confirmatory = support_documents >= 8 and grounded_relations >= 20
    return {
        "mode": "confirmatory" if confirmatory else "exploratory",
        "confirmatory": confirmatory,
        "verdict": None,
        "support": {
            "documents": support_documents,
            "grounded_relations": grounded_relations,
        },
        "requirements": {"documents": 8, "grounded_relations": 20},
    }


def _entity_from_json(row: object, document_id: str, field: str) -> CanonicalEntity:
    if not isinstance(row, Mapping):
        raise ScoreIntegrityError(f"{field} must contain objects")
    required = {
        "document_id",
        "canonical_type",
        "canonical_value",
        "source_value",
        "source_object_id",
        "aliases",
        "reference_origin",
        "grounded_in_pdf",
        "grounding_value",
        "indicator_subtype",
    }
    if set(row) != required:
        raise ScoreIntegrityError(f"{field} entity schema is invalid")
    aliases = row["aliases"]
    if not isinstance(aliases, list) or not all(isinstance(alias, str) for alias in aliases):
        raise ScoreIntegrityError(f"{field} aliases must be strings")
    if row["document_id"] != document_id:
        raise ScoreIntegrityError(f"{field} document identity mismatch")
    string_fields = (
        "canonical_type",
        "canonical_value",
        "source_value",
        "source_object_id",
        "reference_origin",
    )
    if any(not isinstance(row[key], str) or not row[key] for key in string_fields):
        raise ScoreIntegrityError(f"{field} entity strings are invalid")
    if not isinstance(row["grounded_in_pdf"], bool):
        raise ScoreIntegrityError(f"{field} grounded flag is invalid")
    if row["grounding_value"] is not None and not isinstance(row["grounding_value"], str):
        raise ScoreIntegrityError(f"{field} grounding value is invalid")
    if row["indicator_subtype"] is not None and not isinstance(row["indicator_subtype"], str):
        raise ScoreIntegrityError(f"{field} indicator subtype is invalid")
    return CanonicalEntity(
        document_id=document_id,
        canonical_type=str(row["canonical_type"]),
        canonical_value=str(row["canonical_value"]),
        source_value=str(row["source_value"]),
        source_object_id=str(row["source_object_id"]),
        aliases=tuple(aliases),
        reference_origin=str(row["reference_origin"]),
        grounded_in_pdf=bool(row["grounded_in_pdf"]),
        grounding_value=row["grounding_value"],
        indicator_subtype=row["indicator_subtype"],
    )


def _relation_from_json(row: object, document_id: str) -> CanonicalRelation:
    if not isinstance(row, Mapping):
        raise ScoreIntegrityError("reference relations must contain objects")
    required = {
        "document_id",
        "source_object_id",
        "relationship_type",
        "target_object_id",
        "source_entity_id",
        "target_entity_id",
        "grounded_in_pdf",
        "grounding_value",
    }
    if set(row) != required or row.get("document_id") != document_id:
        raise ScoreIntegrityError("reference relation schema or document identity is invalid")
    strings = (
        "source_object_id",
        "relationship_type",
        "target_object_id",
        "source_entity_id",
        "target_entity_id",
        "grounding_value",
    )
    if any(not isinstance(row[key], str) or not row[key] for key in strings):
        raise ScoreIntegrityError("reference relation strings are invalid")
    if row["grounded_in_pdf"] is not True:
        raise ScoreIntegrityError("only grounded reference relations are comparable")
    return CanonicalRelation(
        document_id=document_id,
        source_object_id=str(row["source_object_id"]),
        relationship_type=str(row["relationship_type"]),
        target_object_id=str(row["target_object_id"]),
        source_entity_id=str(row["source_entity_id"]),
        target_entity_id=str(row["target_entity_id"]),
        grounded_in_pdf=True,
        grounding_value=str(row["grounding_value"]),
    )


def _load_reference(path: Path, document_id: str) -> tuple[
    tuple[CanonicalEntity, ...], tuple[CanonicalEntity, ...], tuple[CanonicalRelation, ...]
]:
    value = load_json(path)
    if value.get("schema_version") != 1 or value.get("document_id") != document_id:
        raise ScoreIntegrityError(f"canonical reference identity mismatch for {document_id}")
    for field in ("entities", "ungrounded_entities", "relations"):
        if not isinstance(value.get(field), list):
            raise ScoreIntegrityError(f"canonical reference {field} must be an array")
    entities = tuple(_entity_from_json(row, document_id, "entities") for row in value["entities"])
    ungrounded = tuple(
        _entity_from_json(row, document_id, "ungrounded_entities")
        for row in value["ungrounded_entities"]
    )
    if any(not entity.grounded_in_pdf for entity in entities):
        raise ScoreIntegrityError("primary reference entities must be PDF-grounded")
    if any(entity.grounded_in_pdf for entity in ungrounded):
        raise ScoreIntegrityError("ungrounded reference entities cannot be marked grounded")
    if any(entity.canonical_type not in PRIMARY_TYPES for entity in (*entities, *ungrounded)):
        raise ScoreIntegrityError("canonical reference contains a non-primary entity type")
    relations = tuple(_relation_from_json(row, document_id) for row in value["relations"])
    return entities, ungrounded, relations


def _load_frozen_design(root: Path) -> tuple[dict[str, Any], list[dict[str, Any]], EquivalenceDictionary]:
    v3_path = root / "execution-manifest.v3.json"
    if v3_path.is_file():
        from .cisa_execution import validate_execution_binding

        freeze, manifest = validate_execution_binding(root)
        rows = freeze.get("documents")
        if not isinstance(rows, list) or len(rows) != 24:
            raise ScoreIntegrityError("schema-v3 freeze must bind exactly 24 documents")
        frozen = {
            str(row.get("code")): {
                "code": row.get("code"),
                "input_sha256": row.get("text_sha256"),
                "reference_sha256": row.get("reference_sha256"),
            }
            for row in rows if isinstance(row, Mapping)
        }
        equivalence_path = root.parent / "config" / "cisa-equivalences.v1.json"
        equivalences = load_equivalences(equivalence_path)
        selection = load_json(root / "selection-manifest.v1.json")
        selection_rows = selection.get("documents")
        if not isinstance(selection_rows, list):
            raise ScoreIntegrityError("selection manifest documents must be an array")
        ordered = [str(row.get("code")) for row in selection_rows if isinstance(row, Mapping)]
        if len(ordered) != 24 or set(ordered) != set(frozen):
            raise ScoreIntegrityError("selection manifest document order is invalid")
        return manifest, [frozen[code] for code in ordered], equivalences
    validated_documents = validate_frozen_evidence(root)
    manifest_path = root / "execution-manifest.v1.json"
    manifest = load_json(manifest_path)
    required = {
        "schema_version": 1,
        "kind": "cisa_bedrock_execution",
        "provider": EXPECTED_PROVIDER,
        "model": EXPECTED_MODEL,
        "aws_region": EXPECTED_REGION,
        "source_type": "advisory",
        "repetitions": list(REPETITIONS),
        "expected_records": 72,
        "system_prompt_sha256": EXPECTED_PROMPT_SHA256,
        "opencti_writes": 0,
    }
    for key, expected in required.items():
        if manifest.get(key) != expected:
            raise ScoreIntegrityError(f"execution manifest has invalid {key}")
    documents = manifest.get("documents")
    if not isinstance(documents, list) or len(documents) != 24:
        raise ScoreIntegrityError("execution manifest must contain exactly 24 documents")
    codes: set[str] = set()
    for row in documents:
        if not isinstance(row, dict):
            raise ScoreIntegrityError("execution manifest documents must be objects")
        if set(("code", "input_sha256", "reference_sha256", "selection_input_sha256")) - set(row):
            raise ScoreIntegrityError("execution manifest document is incomplete")
        if not all(isinstance(row.get(key), str) and row[key] for key in (
            "code", "input_sha256", "reference_sha256", "selection_input_sha256"
        )):
            raise ScoreIntegrityError("execution manifest document strings are invalid")
        if row["code"] in codes:
            raise ScoreIntegrityError("execution manifest document codes must be unique")
        if row["input_sha256"] != row["selection_input_sha256"]:
            raise ScoreIntegrityError("selection and execution input digests differ")
        codes.add(row["code"])
    equivalence_path = root.parent / "config" / "cisa-equivalences.v1.json"
    equivalences = load_equivalences(equivalence_path)
    if (
        manifest.get("equivalence_file_sha256") != sha256_file(equivalence_path)
        or manifest.get("equivalence_sha256") != equivalences.canonical_digest
        or equivalences.canonical_digest != EXPECTED_EQUIVALENCE_SHA256
    ):
        raise ScoreIntegrityError("frozen equivalence configuration digest drift")
    validated_by_code = {row["code"]: row for row in validated_documents}
    selection = load_json(root / "selection-manifest.v1.json")
    selection_rows = selection.get("documents")
    if not isinstance(selection_rows, list):
        raise ScoreIntegrityError("selection manifest documents must be an array")
    ordered_codes = [row.get("code") if isinstance(row, Mapping) else None for row in selection_rows]
    if any(not isinstance(code, str) for code in ordered_codes):
        raise ScoreIntegrityError("selection manifest document order is invalid")
    ordered_documents = [validated_by_code[code] for code in ordered_codes]
    return manifest, ordered_documents, equivalences


def _validate_run(
    path: Path,
    *,
    document: Mapping[str, Any],
    repetition: int,
    execution_manifest_sha256: str,
    freeze_sha256: str | None = None,
) -> dict[str, Any]:
    try:
        record = load_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ScoreIntegrityError(f"cannot load run record {path.name}: {error}") from error
    if freeze_sha256 is not None:
        attempt_name = record.get("attempt_record")
        attempt_path = path.parent.parent / "attempts" / str(attempt_name)
        if (
            record.get("schema_version") != 2 or record.get("kind") != "cisa_document_extraction"
            or record.get("status") != "success" or record.get("document") != document["code"]
            or record.get("repetition") != repetition or record.get("source_type") != "advisory"
            or record.get("provider") != EXPECTED_PROVIDER or record.get("model") != EXPECTED_MODEL
            or record.get("aws_region") != EXPECTED_REGION or record.get("freeze_sha256") != freeze_sha256
            or record.get("input_sha256") != document["input_sha256"]
            or record.get("reference_sha256") != document["reference_sha256"]
            or record.get("opencti_writes") != 0 or not isinstance(attempt_name, str)
            or not attempt_path.is_file() or record.get("attempt_sha256") != sha256_file(attempt_path)
        ):
            raise ScoreIntegrityError(f"schema-v2 run record {path.name} is invalid")
        attempt = load_json(attempt_path)
        if (
            attempt.get("kind") != "cisa_document_attempt" or attempt.get("status") != "success"
            or attempt.get("document") != document["code"] or attempt.get("repetition") != repetition
            or attempt.get("freeze_sha256") != freeze_sha256
        ):
            raise ScoreIntegrityError(f"schema-v2 run record {path.name} does not bind a successful attempt")
        expected_final = {
            **attempt,
            "kind": "cisa_document_extraction",
            "attempt_record": attempt_name,
            "attempt_sha256": sha256_file(attempt_path),
        }
        if canonical_bytes(record) != canonical_bytes(expected_final):
            raise ScoreIntegrityError(f"schema-v2 run record {path.name} differs from its bound attempt")
    else:
        expected = {
        "schema_version": 1,
        "kind": "cisa_document_extraction",
        "document": document["code"],
        "repetition": repetition,
        "status": "success",
        "source_type": "advisory",
        "provider": EXPECTED_PROVIDER,
        "model": EXPECTED_MODEL,
        "aws_region": EXPECTED_REGION,
        "execution_manifest_sha256": execution_manifest_sha256,
        "input_sha256": document["input_sha256"],
        "reference_sha256": document["reference_sha256"],
        "opencti_writes": 0,
    }
        for key, value in expected.items():
            if record.get(key) != value:
                raise ScoreIntegrityError(f"run record {path.name} has invalid {key}")
    if not isinstance(record.get("created_at_utc"), str) or not record["created_at_utc"]:
        raise ScoreIntegrityError(f"run record {path.name} has invalid created_at_utc")
    if not isinstance(record.get("elapsed_seconds"), (int, float)) or isinstance(
        record.get("elapsed_seconds"), bool
    ):
        raise ScoreIntegrityError(f"run record {path.name} has invalid elapsed_seconds")
    raw = record.get("raw_model_output")
    final = record.get("tim_output")
    if not isinstance(raw, Mapping) or not isinstance(final, Mapping):
        raise ScoreIntegrityError(f"successful run record {path.name} lacks raw or final output")
    raw_required = {
        "raw_response_text",
        "raw_v2_entities",
        "raw_v2_relationships",
        "citation_stats",
        "stop_reason",
        "model_usage",
    }
    if raw_required - set(raw) or _FINAL_FIELDS - set(final):
        raise ScoreIntegrityError(f"successful run record {path.name} has incomplete output")
    return record


def _compact_entity_score(score: Mapping[str, Any]) -> dict[str, Any]:
    layer_counts: dict[str, int] = {}
    for match in score["matches"]:
        layer = str(match["layer"])
        layer_counts[layer] = layer_counts.get(layer, 0) + 1
    return {
        "reference_interpretation": score["reference_interpretation"],
        "reference_count": score["reference_count"],
        "prediction_count": score["prediction_count"],
        "exact": score["exact"],
        "equivalence_aware": score["equivalence_aware"],
        "match_layers": dict(sorted(layer_counts.items())),
    }


def _comparable_reference_relations(
    relations: Sequence[CanonicalRelation], reference: Sequence[CanonicalEntity]
) -> tuple[CanonicalRelation, ...]:
    """Keep only reference relations that satisfy the frozen comparison vocabulary."""
    reference_by_id: dict[str, set[CanonicalEntity]] = {}
    for entity in reference:
        reference_by_id.setdefault(entity.source_object_id, set()).add(entity)
    return tuple(
        relation
        for relation in relations
        if relation.relationship_type in _ALLOWED_RELATIONSHIPS
        and relation.source_object_id in reference_by_id
        and relation.target_object_id in reference_by_id
        and any(
            (source.canonical_type, relation.relationship_type, target.canonical_type)
            in _ALLOWED_RELATION_SIGNATURES
            for source in reference_by_id[relation.source_object_id]
            for target in reference_by_id[relation.target_object_id]
        )
    )


def _relation_run_score(
    relations: Sequence[CanonicalRelation],
    reference: Sequence[CanonicalEntity],
    prediction: PredictionView,
    equivalences: EquivalenceDictionary,
) -> dict[str, int | str]:
    matches = match_entities(reference, prediction.entities, equivalences).matches
    comparable_relations = _comparable_reference_relations(relations, reference)
    by_reference_id: dict[str, set[str]] = {}
    for match in matches:
        by_reference_id.setdefault(match.reference.source_object_id, set()).update(
            prediction.source_ids_by_identity[_entity_identity(match.prediction)]
        )
    entities_by_local_id: dict[str, set[CanonicalEntity]] = {}
    for identity, source_ids in prediction.source_ids_by_identity.items():
        entity = next((row for row in prediction.entities if _entity_identity(row) == identity), None)
        if entity is None:
            continue
        for source_id in source_ids:
            entities_by_local_id.setdefault(source_id, set()).add(entity)
    predicted = {
        (row.source_id, row.relationship_type, row.target_id)
        for row in prediction.relationships
        if row.relationship_type in _ALLOWED_RELATIONSHIPS
        and row.source_id in entities_by_local_id
        and row.target_id in entities_by_local_id
        and any(
            (source.canonical_type, row.relationship_type, target.canonical_type)
            in _ALLOWED_RELATION_SIGNATURES
            for source in entities_by_local_id[row.source_id]
            for target in entities_by_local_id[row.target_id]
        )
    }
    matched_predictions: set[tuple[str, str, str]] = set()
    candidate_matches = 0
    for relation in comparable_relations:
        candidates = {
            (source, relation.relationship_type, target)
            for source in by_reference_id.get(relation.source_object_id, set())
            for target in by_reference_id.get(relation.target_object_id, set())
        }
        hits = candidates & predicted
        if hits:
            candidate_matches += 1
            matched_predictions.add(sorted(hits)[0])
    return {
        "interpretation": "exploratory_partial_reference",
        "grounded_cisa_relations": len(comparable_relations),
        "tim_relations": len(predicted),
        "candidate_matches": candidate_matches,
        "cisa_unmatched": len(comparable_relations) - candidate_matches,
        "tim_additions_disagreement": len(predicted - matched_predictions),
    }


def _diagnostic_rows(
    document: str,
    repetition: int,
    scores: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    pending: list[dict[str, Any]] = []
    additions: list[dict[str, Any]] = []
    for canonical_type in PRIMARY_TYPES:
        score = scores[canonical_type]
        for row in score["pending_equivalences"]:
            pending.append({
                "pair_id": row["pair_id"],
                "document": document,
                "repetition": repetition,
                "canonical_type": canonical_type,
                "indicator_subtype": row["cisa"]["indicator_subtype"] or "",
                "cisa_value": row["cisa"]["canonical_value"],
                "tim_value": row["tim"]["canonical_value"],
                "match_status": "unresolved_conservative_difference",
            })
        for row in score["tim_only_unassessed"]:
            additions.append({
                "document": document,
                "repetition": repetition,
                "canonical_type": canonical_type,
                "indicator_subtype": row["indicator_subtype"] or "",
                "tim_value": row["canonical_value"],
                "assessment": "unassessed",
            })
    return pending, additions


def _combine(scores: Sequence[Mapping[str, Any]], layer: str) -> dict[str, Any]:
    tp = sum(int(score[layer]["counts"]["matched"]) for score in scores)
    fn = sum(int(score[layer]["counts"]["cisa_only"]) for score in scores)
    additions = sum(
        int(score[layer]["counts"]["tim_only_unassessed"]) for score in scores
    )
    return _metrics(tp, fn, additions)


def _macro_metric(document_rows: Sequence[Mapping[str, Any]], group: str, layer: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for metric in ("cosine", "cisa_recall", "jaccard"):
        values = [
            row["scores"][group][layer][metric]
            for row in document_rows
            if row["scores"][group][layer][metric] is not None
        ]
        result[metric] = sum(values) / len(values) if values else None
        result[f"documents_with_{metric}"] = len(values)
    return result


def _maybe_bootstrap(
    values: Sequence[float], *, seed: int, samples: int, statistic: str = "mean"
) -> dict[str, Any] | None:
    return bootstrap_ci(values, seed=seed, samples=samples, statistic=statistic) if values else None


def score_experiment(
    evidence_root: Path | str, *, seed: int = 20260830, bootstrap_samples: int = 10_000
) -> dict[str, Any]:
    """Score exactly 24×3 immutable successful records; incomplete evidence fails closed."""
    root = Path(evidence_root)
    design, documents, equivalences = _load_frozen_design(root)
    expected_codes = {str(document["code"]) for document in documents}
    reference_codes = {
        path.name.removesuffix(".canonical.json")
        for path in (root / "reference").glob("*.canonical.json")
    }
    if reference_codes != expected_codes:
        raise ScoreIntegrityError("canonical reference identities differ from the frozen design")
    document_codes = {
        path.name for path in (root / "documents").iterdir() if path.is_dir()
    }
    if document_codes != expected_codes:
        raise ScoreIntegrityError("input document identities differ from the frozen design")
    expected_names = {
        f"{document['code']}.run-{repetition}.json"
        for document in documents
        for repetition in REPETITIONS
    }
    actual_names = {path.name for path in (root / "runs").glob("*.run-*.json")}
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        raise ScoreIntegrityError(f"final run identities differ; missing={missing}, extra={extra}")
    manifest_name = (
        "execution-manifest.v3.json"
        if design.get("schema_version") == 3
        else "execution-manifest.v1.json"
    )
    execution_digest = sha256_file(root / manifest_name)
    freeze_digest = design.get("freeze_sha256") if design.get("schema_version") == 3 else None

    run_rows: list[dict[str, Any]] = []
    pending_pool: list[dict[str, Any]] = []
    addition_pool: list[dict[str, Any]] = []
    ungrounded_pool: list[dict[str, Any]] = []
    relation_support_documents = 0
    grounded_relation_count = 0
    for document in documents:
        code = str(document["code"])
        input_path = root / "documents" / code / "input.txt"
        reference_path = root / "reference" / f"{code}.canonical.json"
        if (
            sha256_file(input_path) != document["input_sha256"]
            or sha256_file(reference_path) != document["reference_sha256"]
        ):
            raise ScoreIntegrityError(f"frozen input or reference digest drift for {code}")
        source_text = input_path.read_text(encoding="utf-8")
        reference, ungrounded, relations = _load_reference(reference_path, code)
        comparable_relations = _comparable_reference_relations(relations, reference)
        if comparable_relations:
            relation_support_documents += 1
            grounded_relation_count += len(comparable_relations)
        for entity in ungrounded:
            ungrounded_pool.append({
                "document": code,
                "canonical_type": entity.canonical_type,
                "indicator_subtype": entity.indicator_subtype or "",
                "cisa_value": entity.canonical_value,
                "source_object_id": entity.source_object_id,
                "grounding_status": "ungrounded_in_pdf",
            })
        for repetition in REPETITIONS:
            record = _validate_run(
                root / "runs" / f"{code}.run-{repetition}.json",
                document=document,
                repetition=repetition,
                execution_manifest_sha256=execution_digest,
                freeze_sha256=freeze_digest if isinstance(freeze_digest, str) else None,
            )
            raw = canonicalize_prediction(code, record["raw_model_output"], stage="raw")
            final = canonicalize_prediction(code, record["tim_output"], stage="final")
            scores: dict[str, dict[str, Any]] = {}
            for canonical_type in PRIMARY_TYPES:
                scores[canonical_type] = score_entity_type(
                    [row for row in reference if row.canonical_type == canonical_type],
                    [row for row in final.entities if row.canonical_type == canonical_type],
                    equivalences,
                )
            scores["overall"] = score_entity_type(
                reference,
                [row for row in final.entities if row.canonical_type in PRIMARY_TYPES],
                equivalences,
            )
            scores["other_comparable_entities"] = score_entity_type(
                [row for row in reference if row.canonical_type != "indicator"],
                [
                    row
                    for row in final.entities
                    if row.canonical_type in PRIMARY_TYPES and row.canonical_type != "indicator"
                ],
                equivalences,
            )
            pending, additions = _diagnostic_rows(code, repetition, scores)
            pending_pool.extend(pending)
            addition_pool.extend(additions)
            compact_scores = {
                key: _compact_entity_score(value) for key, value in scores.items()
            }
            context_counts = {
                canonical_type: sum(
                    entity.canonical_type == canonical_type for entity in final.entities
                )
                for canonical_type in CONTEXT_TYPES
            }
            run_rows.append({
                "document": code,
                "repetition": repetition,
                "elapsed_seconds": record["elapsed_seconds"],
                "scores": compact_scores,
                "_details": compact_scores,
                "_base_scores": scores,
                "_reference": reference,
                "_final_prediction": final,
                "_entity_set": frozenset(
                    _entity_identity(entity)
                    for entity in final.entities
                    if entity.canonical_type in PRIMARY_TYPES
                ),
                "citations": citation_localization(final, source_text),
                "raw_to_final": raw_to_final_effect(
                    raw, final, record["raw_model_output"]["citation_stats"]
                ),
                "context_diagnostics": {
                    "outside_primary_score": True,
                    "prediction_counts": context_counts,
                },
                "relationships": _relation_run_score(
                    comparable_relations, reference, final, equivalences
                ),
                "prediction_exclusions": {
                    "raw": list(raw.exclusions),
                    "final": list(final.exclusions),
                },
            })

    if len(run_rows) != 72:
        raise ScoreIntegrityError(f"expected exactly 72 successful scored runs, found {len(run_rows)}")

    groups = (*PRIMARY_TYPES, "overall", "other_comparable_entities")
    document_rows: list[dict[str, Any]] = []
    stability_documents: dict[str, dict[str, Any]] = {}
    for document in documents:
        code = str(document["code"])
        rows = sorted(
            [row for row in run_rows if row["document"] == code],
            key=lambda row: row["repetition"],
        )
        if len(rows) != 3:
            raise ScoreIntegrityError(f"document {code} does not have three repetitions")
        scores = {
            group: {
                "exact": _combine([row["_details"][group] for row in rows], "exact"),
                "equivalence_aware": _combine(
                    [row["_details"][group] for row in rows], "equivalence_aware"
                ),
            }
            for group in groups
        }
        localized = sum(row["citations"]["localized"] for row in rows)
        citation_total = sum(row["citations"]["total"] for row in rows)
        pairwise = pairwise_jaccard([row["_entity_set"] for row in rows])
        stability_documents[code] = {
            "pairwise_jaccard": {
                "run_1_vs_2": pairwise[0],
                "run_1_vs_3": pairwise[1],
                "run_2_vs_3": pairwise[2],
            },
            "median_pairwise_jaccard": median(pairwise),
        }
        document_rows.append({
            "document": code,
            "scores": scores,
            "citations": {
                "localized": localized,
                "total": citation_total,
                "rate": localized / citation_total if citation_total else None,
            },
            "stability": stability_documents[code],
        })

    macro_by_document = {
        group: {
            layer: _macro_metric(document_rows, group, layer)
            for layer in ("exact", "equivalence_aware")
        }
        for group in groups
    }
    micro_instances = {
        group: {
            layer: _combine([row["_details"][group] for row in run_rows], layer)
            for layer in ("exact", "equivalence_aware")
        }
        for group in groups
    }
    overall_values = [
        row["scores"]["overall"]["equivalence_aware"]["cosine"]
        for row in document_rows
        if row["scores"]["overall"]["equivalence_aware"]["cosine"] is not None
    ]
    citation_counts = [
        (int(row["citations"]["localized"]), int(row["citations"]["total"]))
        for row in document_rows
    ]
    stability_values = [
        row["stability"]["median_pairwise_jaccard"] for row in document_rows
    ]
    coverage_ci = _maybe_bootstrap(overall_values, seed=seed, samples=bootstrap_samples)
    citation_ci = bootstrap_ratio_ci(citation_counts, seed=seed, samples=bootstrap_samples)
    stability_ci = _maybe_bootstrap(
        stability_values, seed=seed, samples=bootstrap_samples, statistic="median"
    )

    confidence_intervals_by_type = {
        group: {
            layer: {
                metric: _maybe_bootstrap(
                    [
                        row["scores"][group][layer][metric]
                        for row in document_rows
                        if row["scores"][group][layer][metric] is not None
                    ],
                    seed=seed,
                    samples=bootstrap_samples,
                )
                for metric in ("cosine", "cisa_recall", "jaccard")
            }
            for layer in ("exact", "equivalence_aware")
        }
        for group in PRIMARY_TYPES
    }

    relation_run_rows = [row["relationships"] for row in run_rows]
    relation_gate = relationship_design_gate(
        support_documents=relation_support_documents,
        grounded_relations=grounded_relation_count,
    )
    public_runs = [
        {key: value for key, value in row.items() if not key.startswith("_")}
        for row in run_rows
    ]
    diagnostic_population_counts = {
        "unresolved_nominal_pairs": {
            canonical_type: sum(
                row.get("canonical_type") == canonical_type for row in pending_pool
            )
            for canonical_type in PRIMARY_TYPES
            if any(row.get("canonical_type") == canonical_type for row in pending_pool)
        },
        "tim_only_unassessed": {
            canonical_type: sum(
                row.get("canonical_type") == canonical_type for row in addition_pool
            )
            for canonical_type in PRIMARY_TYPES
            if any(row.get("canonical_type") == canonical_type for row in addition_pool)
        },
        "cisa_ungrounded": {
            canonical_type: sum(
                row.get("canonical_type") == canonical_type for row in ungrounded_pool
            )
            for canonical_type in PRIMARY_TYPES
            if any(row.get("canonical_type") == canonical_type for row in ungrounded_pool)
        },
    }
    return {
        "schema_version": 2,
        "experiment": "exp02-cisa-structural-similarity",
        "integrity": {
            "documents": len(documents),
            "successful_runs": len(run_rows),
            "repetitions_per_document": 3,
            "provider": EXPECTED_PROVIDER,
            "model": EXPECTED_MODEL,
            "aws_region": EXPECTED_REGION,
            "opencti_writes": 0,
            "execution_manifest_sha256": execution_digest,
            "freeze_sha256": freeze_digest,
            "final_record_sha256": {
                name: sha256_file(root / "runs" / name) for name in sorted(expected_names)
            },
        },
        "method": {
            "official_reference": "partial_official_cisa_stix_grounded_in_pdf",
            "primary_types": list(PRIMARY_TYPES),
            "outside_primary_score": list(CONTEXT_TYPES),
            "matching": "frozen_exact_technical_id_declared_alias_controlled_equivalence",
            "human_adjudication": "none",
            "tim_only_interpretation": "unassessed",
            "bootstrap_unit": "document",
            "bootstrap_seed": seed,
            "bootstrap_samples": bootstrap_samples,
        },
        "primary": {
            "metric": "structural_cosine_macro_by_document",
            "structural_cosine_macro_by_document": macro_by_document[
                "overall"
            ]["equivalence_aware"]["cosine"],
            "confidence_interval_95": coverage_ci,
        },
        "macro_by_document": macro_by_document,
        "micro_instances": micro_instances,
        "confidence_intervals_by_type": confidence_intervals_by_type,
        "per_document": {row["document"]: row for row in document_rows},
        "citations": {
            "unit": "final_tim_v2_entities_aggregate_ratio_bootstrapped_by_document",
            "confidence_interval_95": citation_ci,
        },
        "raw_to_final": {
            "runs": {
                f"{row['document']}.run-{row['repetition']}": row["raw_to_final"]
                for row in public_runs
            }
        },
        "stability": {
            "per_document": stability_documents,
            "document_median_pairwise_jaccard": stability_ci,
        },
        "relationships": {
            "gate": relation_gate,
            "candidate_matches_across_repetitions": sum(
                int(row["candidate_matches"]) for row in relation_run_rows
            ),
            "reference_instances_across_repetitions": sum(
                int(row["grounded_cisa_relations"]) for row in relation_run_rows
            ),
            "tim_relation_additions_disagreement": sum(
                int(row["tim_additions_disagreement"]) for row in relation_run_rows
            ),
            "confirmatory_pass_fail": None,
        },
        "diagnostic_samples": {
            "unresolved_nominal_pairs": deterministic_type_sample(
                pending_pool,
                seed=20260831,
                limit=20,
                document_order=[str(row["code"]) for row in documents],
            ),
            "tim_only_unassessed": deterministic_type_sample(
                addition_pool,
                seed=20260831,
                limit=20,
                document_order=[str(row["code"]) for row in documents],
            ),
            "cisa_ungrounded": deterministic_type_sample(
                ungrounded_pool,
                seed=20260831,
                limit=20,
                document_order=[str(row["code"]) for row in documents],
            ),
        },
        "diagnostic_population_counts": diagnostic_population_counts,
        "diagnostics": {
            "unresolved_nominal_pairs": len(pending_pool),
            "tim_only_unassessed": len(addition_pool),
        },
        "runs": public_runs,
    }


def write_score_artifacts(evidence_root: Path | str, result: Mapping[str, Any]) -> dict[str, Any]:
    """Write automatic structural results once, refusing any overwrite."""
    root = Path(evidence_root)
    result_path = root / "results.v2.json"
    if result_path.exists():
        raise FileExistsError(f"refusing to overwrite {result_path}")
    result_sha256 = write_new_json(result_path, result)
    return {
        "results": "results.v2.json",
        "results_sha256": result_sha256,
        "runs": result.get("integrity", {}).get("successful_runs"),
    }
