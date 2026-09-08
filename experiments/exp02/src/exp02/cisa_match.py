"""Deterministic comparison of CISA and TIM canonical entities."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
from typing import Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

from ioc_fanger import fang

from .cisa_reference import CanonicalEntity
from .jsonio import canonical_bytes, load_json


_ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_TECHNICAL_INDICATOR_SUBTYPES = frozenset(
    {
        "ip",
        "domain",
        "url",
        "email",
        "hash_md5",
        "hash_sha1",
        "hash_sha256",
    }
)


@dataclass(frozen=True)
class EntityMatch:
    reference: CanonicalEntity
    prediction: CanonicalEntity
    layer: str


@dataclass(frozen=True)
class MatchResult:
    matches: tuple[EntityMatch, ...]
    pending: tuple[EntityMatch, ...]

    @property
    def exact_tp(self) -> int:
        return sum(match.layer == "exact" for match in self.matches)

    @property
    def equivalent_tp(self) -> int:
        return len(self.matches)


@dataclass(frozen=True)
class EquivalenceDictionary:
    """Validated frozen equivalence groups and their canonical-artifact digest."""

    groups: tuple[tuple[str, ...], ...]
    canonical_digest: str

    @property
    def digest(self) -> str:
        """Compatibility shorthand for the canonical configuration digest."""
        return self.canonical_digest


def load_equivalences(path: Path | str) -> EquivalenceDictionary:
    """Load the frozen dictionary, rejecting ambiguous equivalence surfaces."""
    return validate_equivalences(load_json(path))


def validate_equivalences(raw: Mapping[str, object]) -> EquivalenceDictionary:
    """Validate a supplied frozen dictionary before it can affect matching."""
    expected_keys = {"schema_version", "frozen_before_final_runs", "groups"}
    if set(raw) != expected_keys:
        raise ValueError("equivalence configuration has an unexpected schema")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ValueError("equivalence schema_version must be exactly 1")
    if raw["frozen_before_final_runs"] is not True:
        raise ValueError("equivalence configuration must be frozen before final runs")
    raw_groups = raw["groups"]
    if not isinstance(raw_groups, list):
        raise ValueError("equivalence groups must be a list")

    seen_surfaces: set[str] = set()
    groups: list[tuple[str, ...]] = []
    for group in raw_groups:
        if not isinstance(group, list) or len(group) < 2:
            raise ValueError(
                "each equivalence group must contain at least two surfaces"
            )
        if not all(isinstance(surface, str) and _surface(surface) for surface in group):
            raise ValueError("equivalence surfaces must be nonempty strings")
        normalized = tuple(_surface(surface) for surface in group)
        if len(set(normalized)) != len(normalized):
            raise ValueError(
                "equivalence group contains a duplicate normalized surface"
            )
        overlap = seen_surfaces.intersection(normalized)
        if overlap:
            raise ValueError(
                "normalized equivalence surface appears in multiple groups"
            )
        seen_surfaces.update(normalized)
        groups.append(tuple(group))
    return EquivalenceDictionary(
        groups=tuple(groups),
        canonical_digest=hashlib.sha256(canonical_bytes(raw)).hexdigest(),
    )


def equivalence_digest(path: Path | str) -> str:
    """Return the digest Task 4 binds into the execution manifest."""
    return load_equivalences(path).canonical_digest


def _surface(value: str, indicator_subtype: str | None = None) -> str:
    normalized = " ".join(fang(value).split())
    if indicator_subtype == "url":
        return _normal_url_surface(normalized)
    return normalized.casefold()


def _normal_url_surface(value: str) -> str:
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
        (
            parsed.scheme.casefold(),
            credentials + host + port,
            parsed.path,
            parsed.query,
            parsed.fragment,
        )
    )


def _exact_value(entity: CanonicalEntity) -> str:
    value = _surface(entity.canonical_value, entity.indicator_subtype)
    if entity.indicator_subtype is None:
        return value.strip(".,;:!?")
    return value


def _equivalence_groups(
    equivalences: EquivalenceDictionary,
) -> tuple[tuple[str, ...], ...]:
    return equivalences.groups


def _is_controlled_equivalence(
    reference: CanonicalEntity,
    prediction: CanonicalEntity,
    equivalences: EquivalenceDictionary,
) -> bool:
    reference_surface = _surface(reference.canonical_value)
    prediction_surface = _surface(prediction.canonical_value)
    for group in _equivalence_groups(equivalences):
        surfaces = {_surface(value) for value in group}
        if reference_surface in surfaces and prediction_surface in surfaces:
            return reference_surface != prediction_surface
    return False


def _technical_identifiers(entity: CanonicalEntity) -> frozenset[str]:
    values = [entity.canonical_value, *entity.aliases]
    identifiers = {
        _surface(identifier)
        for value in values
        for identifier in (*_ATTACK_ID.findall(value), *_CVE_ID.findall(value))
    }
    if entity.indicator_subtype in _TECHNICAL_INDICATOR_SUBTYPES:
        identifiers.add(_surface(entity.canonical_value, entity.indicator_subtype))
    return frozenset(identifiers)


def _declared_aliases(entity: CanonicalEntity) -> frozenset[str]:
    return frozenset(_surface(value) for value in entity.aliases)


def _comparable(reference: CanonicalEntity, prediction: CanonicalEntity) -> bool:
    if reference.canonical_type != prediction.canonical_type:
        return False
    if reference.canonical_type == "indicator":
        return (
            reference.indicator_subtype is not None
            and reference.indicator_subtype == prediction.indicator_subtype
        )
    return reference.indicator_subtype == prediction.indicator_subtype


def _layer(
    reference: CanonicalEntity,
    prediction: CanonicalEntity,
    equivalences: EquivalenceDictionary,
) -> str | None:
    if not _comparable(reference, prediction):
        return None
    if _exact_value(reference) == _exact_value(prediction):
        return "exact"
    if _technical_identifiers(reference) & _technical_identifiers(prediction):
        return "technical-id"
    reference_aliases = _declared_aliases(reference)
    prediction_aliases = _declared_aliases(prediction)
    if (
        reference_aliases
        & (prediction_aliases | {_surface(prediction.canonical_value)})
    ) or prediction_aliases & {_surface(reference.canonical_value)}:
        return "declared-alias"
    if _is_controlled_equivalence(reference, prediction, equivalences):
        return "controlled-equivalence"
    return None


def match_entities(
    reference: Sequence[CanonicalEntity],
    prediction: Sequence[CanonicalEntity],
    equivalences: EquivalenceDictionary | Mapping[str, object],
) -> MatchResult:
    """Match one-to-one only when a frozen comparison rule allows it."""
    validated_equivalences = (
        equivalences
        if isinstance(equivalences, EquivalenceDictionary)
        else validate_equivalences(equivalences)
    )
    layer_order = {
        "exact": 0,
        "technical-id": 1,
        "declared-alias": 2,
        "controlled-equivalence": 3,
    }
    candidates: list[tuple[int, str, str, int, int, str]] = []
    for reference_index, reference_entity in enumerate(reference):
        for prediction_index, prediction_entity in enumerate(prediction):
            layer = _layer(reference_entity, prediction_entity, validated_equivalences)
            if layer is not None:
                candidates.append(
                    (
                        layer_order[layer],
                        reference_entity.source_object_id,
                        prediction_entity.source_object_id,
                        reference_index,
                        prediction_index,
                        layer,
                    )
                )
    matches: list[EntityMatch] = []
    used_references: set[int] = set()
    used_predictions: set[int] = set()
    for _, _, _, reference_index, prediction_index, layer in sorted(candidates):
        if reference_index in used_references or prediction_index in used_predictions:
            continue
        matches.append(
            EntityMatch(reference[reference_index], prediction[prediction_index], layer)
        )
        used_references.add(reference_index)
        used_predictions.add(prediction_index)
    pending = tuple(
        EntityMatch(reference[reference_index], prediction[prediction_index], "pending")
        for reference_index, prediction_index in sorted(
            (
                (reference_index, prediction_index)
                for reference_index, reference_entity in enumerate(reference)
                if reference_index not in used_references
                for prediction_index, prediction_entity in enumerate(prediction)
                if prediction_index not in used_predictions
                and _comparable(reference_entity, prediction_entity)
            ),
            key=lambda indices: (
                reference[indices[0]].source_object_id,
                prediction[indices[1]].source_object_id,
                *indices,
            ),
        )
    )
    return MatchResult(tuple(matches), pending)
