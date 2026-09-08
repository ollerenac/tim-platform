"""Frozen source-policy validation and deterministic sample selection."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .jsonio import load_json
from .records import DocumentRecord, validate_document_record


_POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "institutional_order",
        "technical_research_order",
        "sources_per_class",
        "documents_per_source",
        "primary_per_source",
        "min_words",
        "max_words",
        "languages",
        "allowed_media_types",
        "exclusion_reasons",
    }
)
_EXCLUSION_REASONS = frozenset(
    {
        "previously_processed",
        "previously_evaluated",
        "development_material",
        "duplicate",
        "translation_duplicate",
        "unsupported_language",
        "not_threat_focused",
        "no_narrative_section",
        "unreadable",
        "out_of_length_range",
        "missing_author_or_date",
        "inaccessible",
    }
)
_INSTITUTIONAL_ORDER = (
    "ncsc-uk",
    "cert-eu",
    "cert-pl-en",
    "acsc-advisories",
)
_TECHNICAL_RESEARCH_ORDER = (
    "unit-42",
    "eset-welivesecurity",
    "volexity",
)


def _require_exact_keys(data: Mapping[str, Any]) -> None:
    unknown = set(data) - _POLICY_FIELDS
    if unknown:
        raise ValueError(f"unknown source policy field: {sorted(unknown)[0]}")
    missing = _POLICY_FIELDS - set(data)
    if missing:
        raise ValueError(f"missing source policy field: {sorted(missing)[0]}")


def _require_string_list(field: str, value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise ValueError(f"{field} must be a list of non-empty strings")
    return tuple(value)


def _require_exact_integer(field: str, value: object, expected: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value != expected:
        raise ValueError(f"{field} must be {expected}")
    return value


@dataclass(frozen=True)
class SourcePolicy:
    """The validated closed-world sampling rules for one EXP-02 acquisition."""

    schema_version: int
    institutional_order: tuple[str, ...]
    technical_research_order: tuple[str, ...]
    sources_per_class: int
    documents_per_source: int
    primary_per_source: int
    min_words: int
    max_words: int
    languages: tuple[str, ...]
    allowed_media_types: tuple[str, ...]
    exclusion_reasons: tuple[str, ...]

    @classmethod
    def load(cls, path: Path | str) -> "SourcePolicy":
        """Load a policy only when every sampling decision is the frozen one."""
        data = load_json(path)
        _require_exact_keys(data)

        _require_exact_integer("schema_version", data["schema_version"], 1)
        institutional_order = _require_string_list(
            "institutional_order", data["institutional_order"]
        )
        technical_research_order = _require_string_list(
            "technical_research_order", data["technical_research_order"]
        )
        all_sources = institutional_order + technical_research_order
        if len(set(all_sources)) != len(all_sources):
            if len(set(institutional_order)) != len(institutional_order) or len(
                set(technical_research_order)
            ) != len(technical_research_order):
                raise ValueError("duplicate source in source policy")
            raise ValueError("source appears in both classes")
        if institutional_order != _INSTITUTIONAL_ORDER:
            raise ValueError("institutional_order must equal the frozen source order")
        if technical_research_order != _TECHNICAL_RESEARCH_ORDER:
            raise ValueError(
                "technical_research_order must equal the frozen source order"
            )

        sources_per_class = _require_exact_integer(
            "sources_per_class", data["sources_per_class"], 2
        )
        documents_per_source = _require_exact_integer(
            "documents_per_source", data["documents_per_source"], 4
        )
        primary_per_source = _require_exact_integer(
            "primary_per_source", data["primary_per_source"], 4
        )
        min_words = _require_exact_integer("min_words", data["min_words"], 500)
        max_words = _require_exact_integer("max_words", data["max_words"], 50_000)
        languages = _require_string_list("languages", data["languages"])
        if languages != ("en", "es"):
            raise ValueError("languages must be en and es in frozen order")
        allowed_media_types = _require_string_list(
            "allowed_media_types", data["allowed_media_types"]
        )
        if allowed_media_types != ("html", "pdf"):
            raise ValueError("allowed_media_types must be html and pdf in frozen order")
        exclusion_reasons = _require_string_list(
            "exclusion_reasons", data["exclusion_reasons"]
        )
        unrecognized = set(exclusion_reasons) - _EXCLUSION_REASONS
        if unrecognized:
            raise ValueError(
                f"unrecognized exclusion reason: {sorted(unrecognized)[0]}"
            )
        if len(set(exclusion_reasons)) != len(exclusion_reasons):
            raise ValueError("duplicate exclusion reason in source policy")
        if set(exclusion_reasons) != _EXCLUSION_REASONS:
            raise ValueError("source policy must enumerate every exclusion reason")
        if len(institutional_order) < sources_per_class:
            raise ValueError("institutional_order has too few candidate sources")
        if len(technical_research_order) < sources_per_class:
            raise ValueError("technical_research_order has too few candidate sources")

        return cls(
            schema_version=1,
            institutional_order=institutional_order,
            technical_research_order=technical_research_order,
            sources_per_class=sources_per_class,
            documents_per_source=documents_per_source,
            primary_per_source=primary_per_source,
            min_words=min_words,
            max_words=max_words,
            languages=languages,
            allowed_media_types=allowed_media_types,
            exclusion_reasons=exclusion_reasons,
        )


class InsufficientSourcesError(ValueError):
    """Raised when a frozen source class cannot supply its required sources."""

    def __init__(self, institutional_found: int, technical_research_found: int) -> None:
        self.institutional_found = institutional_found
        self.technical_research_found = technical_research_found
        super().__init__(
            "insufficient eligible sources: "
            f"institutional={institutional_found}/2, "
            f"technical-research={technical_research_found}/2"
        )


def _select_class(
    source_order: Sequence[str],
    inventories: Mapping[str, Sequence[object]],
    policy: SourcePolicy,
) -> list[str]:
    selected: list[str] = []
    for source_id in source_order:
        entries = inventories.get(source_id, ())
        if isinstance(entries, (str, bytes)) or not isinstance(entries, Sequence):
            raise ValueError(f"inventory for {source_id} must be a sequence of entries")
        if len(entries) >= policy.documents_per_source:
            selected.append(source_id)
        if len(selected) == policy.sources_per_class:
            break
    return selected


def select_sources(
    policy: SourcePolicy, inventories: Mapping[str, Sequence[object]]
) -> list[str]:
    """Select the first two sufficiently populated sources in each frozen class."""
    if not isinstance(policy, SourcePolicy):
        raise ValueError("policy must be a SourcePolicy")
    if not isinstance(inventories, Mapping):
        raise ValueError("inventories must be a mapping")

    institutional = _select_class(policy.institutional_order, inventories, policy)
    technical_research = _select_class(
        policy.technical_research_order, inventories, policy
    )
    if (
        len(institutional) != policy.sources_per_class
        or len(technical_research) != policy.sources_per_class
    ):
        raise InsufficientSourcesError(len(institutional), len(technical_research))
    return institutional + technical_research


@dataclass(frozen=True)
class SelectedEntry:
    """A source entry paired with its predetermined EXP-02 sampling role."""

    entry: DocumentRecord
    role: Literal["primary"]

    @property
    def record(self) -> DocumentRecord:
        """Compatibility name for consumers that treat an entry as a record."""
        return self.entry


def assign_roles(entries: Sequence[DocumentRecord]) -> list[SelectedEntry]:
    """Sort exactly four source entries newest-first and mark all as primary."""
    if isinstance(entries, (str, bytes)) or not isinstance(entries, Sequence):
        raise ValueError("entries must be a sequence of DocumentRecord objects")
    if len(entries) != 4:
        raise ValueError("assign_roles requires exactly 4 entries")
    if any(not isinstance(entry, DocumentRecord) for entry in entries):
        raise ValueError("entries must contain only DocumentRecord objects")
    for entry in entries:
        validate_document_record(entry)

    ordered = sorted(entries, key=lambda entry: entry.published_at, reverse=True)
    return [
        SelectedEntry(
            entry=entry,
            role="primary",
        )
        for entry in ordered
    ]
