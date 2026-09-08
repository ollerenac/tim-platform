from __future__ import annotations

import json
from pathlib import Path

import pytest

from exp02.records import DocumentRecord
from exp02.source_policy import (
    InsufficientSourcesError,
    SourcePolicy,
    assign_roles,
    select_sources,
)


POLICY_PATH = (
    Path(__file__).resolve().parents[1] / "config" / "source-policy.v1.json"
)


def document(index: int, *, source_id: str = "ncsc-uk") -> DocumentRecord:
    return DocumentRecord.from_dict(
        {
            "document_id": f"doc-{index:02d}",
            "source_id": source_id,
            "source_class": "institutional",
            "role": "practice",
            "title": f"Threat report {index}",
            "author": "Example CERT",
            "author_basis": "source_publisher",
            "published_at": f"2026-08-{index:02d}T12:00:00Z",
            "origin_url": f"https://example.test/reports/{index}",
            "original_path": f"experiments/exp02/evidence/inputs/doc-{index:02d}/original.pdf",
            "text_path": f"experiments/exp02/evidence/inputs/doc-{index:02d}/converted.txt",
            "media_type": "pdf",
            "word_count": 500,
            "original_sha256": "a" * 64,
            "text_sha256": "b" * 64,
            "acquired_at": "2026-08-30T13:00:00Z",
        }
    )


def four_entries(*, newest_first: bool = False, source_id: str = "ncsc-uk") -> list[DocumentRecord]:
    entries = [document(index, source_id=source_id) for index in range(1, 5)]
    return list(reversed(entries)) if newest_first else entries


def load_policy() -> SourcePolicy:
    return SourcePolicy.load(POLICY_PATH)


def test_loads_the_frozen_policy_schema_version():
    policy = load_policy()

    assert policy.schema_version == 1
    assert policy.documents_per_source == 4
    assert policy.primary_per_source == 4
    assert not hasattr(policy, "extension_per_source")


def test_selects_first_two_eligible_sources_per_class():
    inventories = {
        "ncsc-uk": four_entries(source_id="ncsc-uk"),
        "cert-eu": four_entries(source_id="cert-eu")[:3],
        "cert-pl-en": four_entries(source_id="cert-pl-en"),
        "unit-42": four_entries(source_id="unit-42"),
        "eset-welivesecurity": four_entries(source_id="eset-welivesecurity"),
    }

    assert select_sources(load_policy(), inventories) == [
        "ncsc-uk",
        "cert-pl-en",
        "unit-42",
        "eset-welivesecurity",
    ]


def test_rejects_selection_when_one_class_has_too_few_eligible_sources():
    inventories = {
        "ncsc-uk": four_entries(source_id="ncsc-uk"),
        "cert-eu": four_entries(source_id="cert-eu")[:3],
        "cert-pl-en": four_entries(source_id="cert-pl-en")[:3],
        "unit-42": four_entries(source_id="unit-42"),
        "eset-welivesecurity": four_entries(source_id="eset-welivesecurity")[:3],
    }

    with pytest.raises(
        InsufficientSourcesError,
        match=r"institutional=1/2, technical-research=1/2",
    ):
        select_sources(load_policy(), inventories)


def test_assigns_exactly_four_primary_entries_in_date_order():
    selected = assign_roles(four_entries(newest_first=True))

    assert [item.entry.document_id for item in selected] == [
        "doc-04",
        "doc-03",
        "doc-02",
        "doc-01",
    ]
    assert [item.role for item in selected] == ["primary"] * 4


def test_assign_roles_rejects_any_count_other_than_four():
    with pytest.raises(ValueError, match="exactly 4"):
        assign_roles(four_entries()[:3])


def test_assign_roles_validates_directly_constructed_record_before_sorting():
    entries = four_entries()
    entries[0] = DocumentRecord(
        document_id="doc-01",
        source_id="ncsc-uk",
        source_class="institutional",
        role="practice",
        title="Threat report 1",
        author="Example CERT",
        author_basis="source_publisher",
        published_at="not-a-utc-timestamp",
        origin_url="https://example.test/reports/1",
        original_path="experiments/exp02/evidence/inputs/doc-01/original.pdf",
        text_path="experiments/exp02/evidence/inputs/doc-01/converted.txt",
        media_type="pdf",
        word_count=500,
        original_sha256="a" * 64,
        text_sha256="b" * 64,
        acquired_at="2026-08-30T13:00:00Z",
    )

    with pytest.raises(ValueError, match="published_at"):
        assign_roles(entries)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("schema_version", True, "schema_version must be 1"),
        ("unexpected", True, "unknown source policy field"),
        ("institutional_order", ["ncsc-uk", "ncsc-uk"], "duplicate source"),
        (
            "technical_research_order",
            ["unit-42", "ncsc-uk"],
            "source appears in both classes",
        ),
        (
            "institutional_order",
            ["cert-eu", "ncsc-uk", "cert-pl-en", "acsc-advisories"],
            "institutional_order must equal the frozen source order",
        ),
        (
            "technical_research_order",
            ["eset-welivesecurity", "unit-42", "volexity"],
            "technical_research_order must equal the frozen source order",
        ),
        (
            "institutional_order",
            ["ncsc-uk", "cert-eu", "cert-pl-en", "replacement-source"],
            "institutional_order must equal the frozen source order",
        ),
        (
            "technical_research_order",
            ["unit-42", "eset-welivesecurity", "replacement-source"],
            "technical_research_order must equal the frozen source order",
        ),
        (
            "institutional_order",
            [
                "ncsc-uk",
                "cert-eu",
                "cert-pl-en",
                "acsc-advisories",
                "extra-source",
            ],
            "institutional_order must equal the frozen source order",
        ),
        (
            "technical_research_order",
            ["unit-42", "eset-welivesecurity", "volexity", "extra-source"],
            "technical_research_order must equal the frozen source order",
        ),
        ("documents_per_source", 6, "documents_per_source must be 4"),
        ("extension_per_source", 2, "unknown source policy field"),
        ("exclusion_reasons", ["not-a-reason"], "unrecognized exclusion reason"),
    ],
)
def test_source_policy_rejects_unfrozen_contracts(tmp_path, field, value, message):
    payload = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    payload[field] = value
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=message):
        SourcePolicy.load(path)
