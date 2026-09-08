"""Canonical, comparable references derived from frozen official CISA STIX."""

from __future__ import annotations

from ast import literal_eval
from collections.abc import Mapping
from dataclasses import asdict, dataclass
import ipaddress
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ioc_fanger import fang
from stix2 import parse as parse_stix
from stix2patterns.pattern import Pattern

from .jsonio import write_new_json


_PRIMARY_TYPES = frozenset({
    "attack-pattern", "intrusion-set", "malware", "threat-actor", "vulnerability",
})
_IGNORED_TYPES = frozenset({"report", "identity", "location", "marking-definition"})
_ALLOWED_RELATIONSHIPS = frozenset({"uses", "targets", "exploits", "indicates", "attributed-to"})
_ALLOWED_RELATION_SIGNATURES = frozenset({
    ("indicator", "indicates", "threat-actor"),
    ("indicator", "indicates", "malware"),
    ("threat-actor", "uses", "malware"),
    ("threat-actor", "uses", "attack-pattern"),
    ("threat-actor", "exploits", "vulnerability"),
    ("malware", "exploits", "vulnerability"),
})
_ATTACK_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_ATTACK_TACTIC = re.compile(r"\bTA\d{4}\b", re.IGNORECASE)
_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")
_PLACEHOLDERS = frozenset({"unknown", "n/a", "na", "none", "not available", "unspecified", "tbd"})


@dataclass(frozen=True)
class CanonicalEntity:
    document_id: str
    canonical_type: str
    canonical_value: str
    source_value: str
    source_object_id: str
    aliases: tuple[str, ...]
    reference_origin: str
    grounded_in_pdf: bool
    grounding_value: str | None
    indicator_subtype: str | None


@dataclass(frozen=True)
class CanonicalRelation:
    document_id: str
    source_object_id: str
    relationship_type: str
    target_object_id: str
    source_entity_id: str
    target_entity_id: str
    grounded_in_pdf: bool
    grounding_value: str


@dataclass(frozen=True)
class CanonicalReference:
    document_id: str
    entities: tuple[CanonicalEntity, ...]
    ungrounded_entities: tuple[CanonicalEntity, ...]
    relations: tuple[CanonicalRelation, ...]
    exclusions: tuple[dict[str, str], ...]
    excluded_relations: tuple[dict[str, str], ...]

    @property
    def by_source_id(self) -> dict[str, CanonicalEntity]:
        """First atom for each STIX object, for ordinary object lookups."""
        result: dict[str, CanonicalEntity] = {}
        for entity in self.entities:
            result.setdefault(entity.source_object_id, entity)
        return result

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "document_id": self.document_id,
            "entities": [asdict(entity) for entity in self.entities],
            "ungrounded_entities": [asdict(entity) for entity in self.ungrounded_entities],
            "relations": [asdict(relation) for relation in self.relations],
            "exclusions": list(self.exclusions),
            "excluded_relations": list(self.excluded_relations),
        }


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
    return urlunsplit((parsed.scheme.casefold(), credentials + host + port,
                       parsed.path, parsed.query, parsed.fragment))


def _normal_indicator(value: str, subtype: str) -> str:
    value = _fold(value)
    if subtype == "ip":
        try:
            return ipaddress.ip_address(value).compressed
        except ValueError:
            return value
    if subtype == "domain":
        return value.rstrip(".").casefold()
    if subtype == "url":
        return _normal_url(value)
    if subtype in {"email", "hash_md5", "hash_sha1", "hash_sha256"}:
        return value.casefold()
    return value


def _normal_match(value: str) -> str:
    return _fold(value).casefold()


def _aliases(raw: Mapping[str, Any]) -> tuple[str, ...]:
    values: set[str] = set()
    name = raw.get("name")
    if isinstance(name, str):
        values.update(_ATTACK_ID.findall(name))
    for reference in raw.get("external_references", []):
        if not isinstance(reference, Mapping):
            continue
        source_name = reference.get("source_name")
        external_id = reference.get("external_id")
        if (
            isinstance(source_name, str) and "attack" in source_name.casefold()
            and isinstance(external_id, str) and _ATTACK_ID.fullmatch(external_id)
        ):
            values.add(external_id)
    return tuple(sorted(values))


def _has_mention(haystack: str, candidate: str, indicator_subtype: str | None) -> bool:
    escaped = re.escape(_normal_match(candidate))
    if not escaped:
        return False
    if _ATTACK_ID.fullmatch(candidate):
        return re.search(rf"(?<![a-z0-9]){escaped}(?!(?:[a-z0-9]|\.\d))", haystack) is not None
    if indicator_subtype in {"domain", "email"}:
        return re.search(
            rf"(?<![a-z0-9_.-]){escaped}(?!(?:[a-z0-9_-]|\.(?=[a-z0-9-])))", haystack,
        ) is not None
    if indicator_subtype in {"hash_md5", "hash_sha1", "hash_sha256"}:
        return re.search(rf"(?<![a-f0-9]){escaped}(?![a-f0-9])", haystack) is not None
    if indicator_subtype == "ip":
        return _has_ip_mention(haystack, candidate, escaped)
    if indicator_subtype == "url":
        return re.search(
            rf"(?<![a-z0-9]){escaped}(?![a-z0-9_/?#=&%:-]|\.(?=[a-z0-9]))", haystack,
        ) is not None
    return re.search(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])", haystack) is not None


def _has_ip_mention(haystack: str, candidate: str, escaped: str) -> bool:
    """Ground an address exactly, accepting only bounded IPv4 numeric ports."""
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    for match in re.finditer(rf"(?<![a-z0-9:.]){escaped}", haystack):
        suffix = haystack[match.end():]
        if suffix.startswith(":"):
            if address.version != 4:
                continue
            port = re.match(r":(\d{1,5})(?![a-z0-9:]|\.\d)", suffix)
            if port is None or not 1 <= int(port.group(1)) <= 65535:
                continue
            return True
        if suffix.startswith(".") and len(suffix) > 1 and suffix[1].isdigit():
            continue
        if suffix and suffix[0].isalnum():
            continue
        return True
    return False


def _grounding(
    value: str, aliases: tuple[str, ...], source_text: str, *, normalized_source: bool = False,
    indicator_subtype: str | None = None,
) -> str | None:
    haystack = source_text if normalized_source else _normal_match(source_text)
    for index, candidate in enumerate((value, *aliases)):
        subtype = indicator_subtype if index == 0 else None
        if _has_mention(haystack, candidate, subtype):
            return candidate
    return None


def _is_placeholder(value: str) -> bool:
    return _normal_match(value) in _PLACEHOLDERS


def _is_attack_tactic(raw: Mapping[str, Any]) -> bool:
    values = [raw.get("name", "")]
    values.extend(
        reference.get("external_id", "") for reference in raw.get("external_references", [])
        if isinstance(reference, Mapping)
    )
    return any(isinstance(value, str) and _ATTACK_TACTIC.search(value) for value in values)


def _unquote(value: object) -> str:
    if not isinstance(value, str):
        return ""
    try:
        parsed = literal_eval(value)
    except (SyntaxError, ValueError):
        return value
    return parsed if isinstance(parsed, str) else value


def _indicator_subtype(object_type: str, path: list[str]) -> str | None:
    if object_type in {"ipv4-addr", "ipv6-addr"} and path == ["value"]:
        return "ip"
    if object_type == "domain-name" and path == ["value"]:
        return "domain"
    if object_type == "url" and path == ["value"]:
        return "url"
    if object_type in {"email-addr", "email-message"} and path in (["value"], ["from_ref", "value"]):
        return "email"
    if object_type == "file" and len(path) == 2 and path[0] == "hashes":
        return {"MD5": "hash_md5", "SHA-1": "hash_sha1", "SHA-256": "hash_sha256"}.get(path[1])
    return None


def _indicator_entities(
    document_id: str, raw: Mapping[str, Any], source_text: str, exclusions: list[dict[str, str]],
) -> list[CanonicalEntity]:
    object_id = str(raw["id"])
    pattern = raw.get("pattern")
    if not isinstance(pattern, str):
        exclusions.append({"source_object_id": object_id, "reason": "missing-indicator-pattern"})
        return []
    try:
        comparisons = Pattern(pattern).inspect().comparisons
    except Exception as error:  # parser errors are data exclusions, never a document failure.
        exclusions.append({"source_object_id": object_id, "reason": "indicator-pattern-parse-failure", "detail": str(error)})
        return []
    entities: list[CanonicalEntity] = []
    for object_type in sorted(comparisons):
        for path, operator, quoted_value in comparisons[object_type]:
            path_list = list(path)
            value = _unquote(quoted_value)
            if operator != "=":
                exclusions.append({"source_object_id": object_id, "reason": "unsupported-indicator-operator",
                                   "path": f"{object_type}:{'.'.join(path_list)}", "operator": operator})
                continue
            subtype = _indicator_subtype(object_type, path_list)
            if subtype is None:
                exclusions.append({"source_object_id": object_id, "reason": "unsupported-indicator-path",
                                   "path": f"{object_type}:{'.'.join(path_list)}"})
                continue
            canonical = _normal_indicator(value, subtype)
            if _is_placeholder(canonical):
                exclusions.append({"source_object_id": object_id, "reason": "placeholder-entity-value"})
                continue
            grounding = _grounding(
                canonical, (), source_text, normalized_source=True, indicator_subtype=subtype,
            )
            entities.append(CanonicalEntity(
                document_id=document_id, canonical_type="indicator", canonical_value=canonical,
                source_value=value, source_object_id=object_id, aliases=(),
                reference_origin="official-cisa-stix", grounded_in_pdf=grounding is not None,
                grounding_value=grounding, indicator_subtype=subtype,
            ))
    return entities


def _ordinary_entity(document_id: str, raw: Mapping[str, Any], source_text: str) -> CanonicalEntity | None:
    object_type = raw.get("type")
    name = raw.get("name")
    object_id = raw.get("id")
    if object_type not in _PRIMARY_TYPES or not isinstance(name, str) or not isinstance(object_id, str):
        return None
    canonical_type = "threat-actor" if object_type == "intrusion-set" else object_type
    aliases = _aliases(raw)
    grounding = _grounding(name, aliases, source_text, normalized_source=True)
    return CanonicalEntity(
        document_id=document_id, canonical_type=canonical_type, canonical_value=_fold(name),
        source_value=name, source_object_id=object_id, aliases=aliases,
        reference_origin="official-cisa-stix", grounded_in_pdf=grounding is not None,
        grounding_value=grounding, indicator_subtype=None,
    )


def _sentence_rows(source_text: str) -> tuple[str, ...]:
    return tuple(part for part in _SENTENCE.split(source_text) if part.strip())


def _mentioned(entity: CanonicalEntity, row: str) -> bool:
    return _grounding(
        entity.canonical_value, entity.aliases, row, indicator_subtype=entity.indicator_subtype,
    ) is not None


def _canonical_relations(
    document_id: str, objects: list[Mapping[str, Any]], entities: tuple[CanonicalEntity, ...], source_text: str,
    exclusions: list[dict[str, str]],
) -> tuple[CanonicalRelation, ...]:
    by_source: dict[str, list[CanonicalEntity]] = {}
    for entity in entities:
        by_source.setdefault(entity.source_object_id, []).append(entity)
    rows = _sentence_rows(source_text)
    result: list[CanonicalRelation] = []
    for raw in objects:
        if raw.get("type") != "relationship":
            continue
        relationship_id = str(raw.get("id", ""))
        relation_type = raw.get("relationship_type")
        source_ref = raw.get("source_ref")
        target_ref = raw.get("target_ref")
        base = {"source_object_id": relationship_id}
        if not isinstance(relation_type, str) or relation_type not in _ALLOWED_RELATIONSHIPS:
            exclusions.append({**base, "reason": "unsupported-relationship-type"})
            continue
        if not isinstance(source_ref, str) or not isinstance(target_ref, str) or not by_source.get(source_ref) or not by_source.get(target_ref):
            exclusions.append({**base, "reason": "unresolved-relationship-endpoint"})
            continue
        # Compound indicators can create several atoms; each grounded atom is a separate candidate.
        for source in by_source[source_ref]:
            for target in by_source[target_ref]:
                if (source.canonical_type, relation_type, target.canonical_type) not in _ALLOWED_RELATION_SIGNATURES:
                    exclusions.append({**base, "reason": "unsupported-relationship-signature"})
                    continue
                row = next((part for part in rows if _mentioned(source, part) and _mentioned(target, part)), None)
                if row is None:
                    exclusions.append({**base, "reason": "endpoints-not-co-mentioned"})
                    continue
                result.append(CanonicalRelation(
                    document_id=document_id, source_object_id=source_ref, relationship_type=relation_type,
                    target_object_id=target_ref, source_entity_id=source.source_object_id,
                    target_entity_id=target.source_object_id, grounded_in_pdf=True, grounding_value=_fold(row),
                ))
    return tuple(result)


def canonicalize_bundle(
    document_id: str, bundle: Mapping[str, Any], source_text: str,
    quarantined_object_ids: frozenset[str] = frozenset(),
) -> CanonicalReference:
    """Turn one official STIX bundle into comparable atoms and evidence-bound relations."""
    normalized_source = _normal_match(source_text)
    exclusions: list[dict[str, str]] = []
    objects: list[Mapping[str, Any]] = []
    candidate_entities: list[CanonicalEntity] = []
    raw_objects = bundle.get("objects", [])
    if not isinstance(raw_objects, list):
        raise ValueError("STIX bundle objects must be a list")
    for raw in raw_objects:
        if not isinstance(raw, Mapping):
            exclusions.append({"source_object_id": "", "reason": "invalid-stix-object"})
            continue
        object_id = raw.get("id")
        if not isinstance(object_id, str):
            exclusions.append({"source_object_id": "", "reason": "missing-stix-object-id"})
            continue
        if object_id in quarantined_object_ids:
            exclusions.append({"source_object_id": object_id, "reason": "intake-quarantined-object"})
            continue
        try:
            parse_stix(dict(raw), allow_custom=True)
        except Exception as error:
            exclusions.append({"source_object_id": object_id, "reason": "stix-parse-failure", "detail": str(error)})
            continue
        objects.append(raw)
        if raw.get("type") == "indicator":
            candidate_entities.extend(_indicator_entities(document_id, raw, normalized_source, exclusions))
        else:
            if raw.get("type") == "attack-pattern" and _is_attack_tactic(raw):
                exclusions.append({"source_object_id": object_id, "reason": "attack-tactic-not-comparable"})
                continue
            if raw.get("type") in _PRIMARY_TYPES and isinstance(raw.get("name"), str) and _is_placeholder(raw["name"]):
                exclusions.append({"source_object_id": object_id, "reason": "placeholder-entity-value"})
                continue
            entity = _ordinary_entity(document_id, raw, normalized_source)
            if entity is not None:
                candidate_entities.append(entity)
            elif raw.get("type") in {"campaign", "tool"}:
                exclusions.append({"source_object_id": object_id, "reason": "unsupported-primary-object-type"})
            elif raw.get("type") not in _IGNORED_TYPES and raw.get("type") != "relationship":
                exclusions.append({"source_object_id": object_id, "reason": "unsupported-stix-object-type"})
    ordered_candidates = tuple(sorted(candidate_entities, key=lambda entity: (
        entity.source_object_id, entity.canonical_type, entity.indicator_subtype or "", entity.canonical_value,
    )))
    ordered_entities = tuple(entity for entity in ordered_candidates if entity.grounded_in_pdf)
    ungrounded_entities = tuple(entity for entity in ordered_candidates if not entity.grounded_in_pdf)
    relations = _canonical_relations(document_id, objects, ordered_entities, source_text, exclusions)
    relation_exclusions = tuple(item for item in exclusions if item["reason"] in {
        "unsupported-relationship-type", "unresolved-relationship-endpoint",
        "unsupported-relationship-signature", "endpoints-not-co-mentioned",
    })
    return CanonicalReference(
        document_id=document_id, entities=ordered_entities,
        ungrounded_entities=ungrounded_entities,
        relations=tuple(sorted(relations, key=lambda relation: (
            relation.source_object_id, relation.relationship_type, relation.target_object_id,
        ))),
        exclusions=tuple(sorted(exclusions, key=lambda item: tuple(sorted(item.items())))),
        excluded_relations=tuple(sorted(relation_exclusions, key=lambda item: tuple(sorted(item.items())))),
    )


def build_references(evidence_root: Path) -> tuple[Path, ...]:
    """Build all canonical references from a frozen manifest without overwriting any."""
    evidence_root = Path(evidence_root)
    manifest_path = evidence_root / "selection-manifest.v1.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    documents = manifest.get("documents")
    if not isinstance(documents, list):
        raise ValueError("selection manifest documents must be a list")
    quarantines = manifest.get("quarantined_objects", {})
    if not isinstance(quarantines, Mapping):
        raise ValueError("selection manifest quarantined_objects must be a mapping")
    output_root = evidence_root / "reference"
    targets = [output_root / f"{row.get('code')}.canonical.json" for row in documents if isinstance(row, Mapping)]
    if any(path.exists() or path.is_symlink() for path in targets):
        raise FileExistsError("canonical reference already exists")
    pending: list[tuple[Path, CanonicalReference]] = []
    for row in documents:
        if not isinstance(row, Mapping):
            raise ValueError("selection manifest document must be a mapping")
        code = row.get("code")
        source_stix_path = row.get("source_stix_path")
        input_path = row.get("input_path")
        if not all(isinstance(value, str) and value for value in (code, source_stix_path, input_path)):
            raise ValueError("selection manifest document paths are incomplete")
        stix_path = Path(source_stix_path)
        if not stix_path.is_absolute():
            stix_path = evidence_root.parent / stix_path
        text_path = evidence_root / input_path
        bundle = json.loads(stix_path.read_text(encoding="utf-8"))
        quarantine_rows = quarantines.get(code, [])
        ids = frozenset(
            item["id"] for item in quarantine_rows
            if isinstance(item, Mapping) and isinstance(item.get("id"), str)
        )
        reference = canonicalize_bundle(code, bundle, text_path.read_text(encoding="utf-8"), ids)
        target = output_root / f"{code}.canonical.json"
        pending.append((target, reference))
    written: list[Path] = []
    for target, reference in pending:
        write_new_json(target, reference.to_dict())
        written.append(target)
    return tuple(written)
