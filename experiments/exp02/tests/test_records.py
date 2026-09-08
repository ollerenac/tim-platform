from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from exp02.records import DocumentRecord, validate_document_record


def valid_document_dict() -> dict[str, object]:
    return {
        "document_id": "src01-doc01",
        "source_id": "src01",
        "source_class": "institutional",
        "role": "primary",
        "title": "A threat report",
        "author": "Example CERT",
        "author_basis": "source_publisher",
        "published_at": "2026-08-30T12:00:00Z",
        "origin_url": "https://example.test/reports/a-threat-report",
        "original_path": "experiments/exp02/evidence/inputs/originals/src01-doc01.pdf",
        "text_path": "experiments/exp02/evidence/inputs/text/src01-doc01.txt",
        "media_type": "pdf",
        "word_count": 500,
        "original_sha256": "a" * 64,
        "text_sha256": "b" * 64,
        "acquired_at": "2026-08-30T13:00:00Z",
    }


def test_document_record_requires_frozen_fields():
    record = DocumentRecord.from_dict(valid_document_dict())

    assert record.document_id == "src01-doc01"
    assert record.role == "primary"


def test_document_record_rejects_retired_extension_role() -> None:
    data = valid_document_dict()
    data["role"] = "extension"

    with pytest.raises(ValueError, match="primary or practice"):
        DocumentRecord.from_dict(data)


@pytest.mark.parametrize(
    "field",
    [
        "document_id",
        "source_id",
        "role",
        "original_sha256",
        "text_sha256",
        "origin_url",
        "published_at",
        "word_count",
    ],
)
def test_document_record_rejects_missing_field(field):
    data = valid_document_dict()
    data.pop(field)

    with pytest.raises(ValueError, match=field):
        DocumentRecord.from_dict(data)


def test_document_record_is_immutable_and_validates_existing_records():
    record = DocumentRecord.from_dict(valid_document_dict())

    validate_document_record(record)
    with pytest.raises(FrozenInstanceError):
        record.title = "Changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("document_id", "UPPERCASE", "document_id"),
        ("source_id", "no", "source_id"),
        ("source_class", "commercial", "source_class"),
        ("role", "supplemental", "role"),
        ("author_basis", "guessed", "author_basis"),
        ("media_type", "docx", "media_type"),
        ("origin_url", "http://example.test/report", "origin_url"),
        ("published_at", "2026-08-30T12:00:00", "published_at"),
        ("published_at", "2026-08-30T12:00:00+01:00", "published_at"),
        ("acquired_at", "not-a-timestamp", "acquired_at"),
        ("word_count", 499, "word_count"),
        ("word_count", 50001, "word_count"),
        ("original_sha256", "A" * 64, "original_sha256"),
        ("text_sha256", "short", "text_sha256"),
        ("original_path", "/tmp/src01-doc01.pdf", "original_path"),
        ("text_path", "experiments/exp02/evidence/outputs/doc.txt", "text_path"),
        ("text_path", "experiments/exp02/evidence/inputs/../outside.txt", "text_path"),
    ],
)
def test_document_record_rejects_invalid_contract_values(field, value, message):
    data = valid_document_dict()
    data[field] = value

    with pytest.raises(ValueError, match=message):
        DocumentRecord.from_dict(data)


def test_document_record_rejects_unknown_or_empty_text_fields():
    data = valid_document_dict()
    data["unexpected"] = "value"
    with pytest.raises(ValueError, match="unexpected"):
        DocumentRecord.from_dict(data)

    data = valid_document_dict()
    data["title"] = ""
    with pytest.raises(ValueError, match="title"):
        DocumentRecord.from_dict(data)


def test_validate_document_record_rejects_wrong_type():
    with pytest.raises(ValueError, match="DocumentRecord"):
        validate_document_record(object())  # type: ignore[arg-type]
