"""Validated immutable records used to freeze EXP-02 input provenance."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields
from datetime import datetime, timedelta
from pathlib import PurePosixPath
import re
from typing import Literal
from urllib.parse import urlsplit


ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
UTC_TIMESTAMP_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)$"
)
INPUTS_ROOT = PurePosixPath("experiments/exp02/evidence/inputs")


@dataclass(frozen=True)
class DocumentRecord:
    document_id: str
    source_id: str
    source_class: Literal["institutional", "technical-research"]
    role: Literal["primary", "practice"]
    title: str
    author: str
    author_basis: Literal["feed_author", "source_publisher"]
    published_at: str
    origin_url: str
    original_path: str
    text_path: str
    media_type: Literal["html", "pdf"]
    word_count: int
    original_sha256: str
    text_sha256: str
    acquired_at: str

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "DocumentRecord":
        """Construct a record only when its serialized form is complete and valid."""
        if not isinstance(data, Mapping):
            raise ValueError("document record must be a mapping")

        field_names = {field.name for field in fields(cls)}
        for field in fields(cls):
            if field.name not in data:
                raise ValueError(f"missing required field: {field.name}")
        unknown_fields = set(data) - field_names
        if unknown_fields:
            raise ValueError(f"unknown document record field: {sorted(unknown_fields)[0]}")

        record = cls(**dict(data))  # type: ignore[arg-type]
        validate_document_record(record)
        return record


def _require_nonempty_string(field: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _validate_identifier(field: str, value: object) -> None:
    value = _require_nonempty_string(field, value)
    if not ID_PATTERN.fullmatch(value):
        raise ValueError(f"{field} must match {ID_PATTERN.pattern}")


def _validate_sha256(field: str, value: object) -> None:
    value = _require_nonempty_string(field, value)
    if not SHA256_PATTERN.fullmatch(value):
        raise ValueError(f"{field} must be 64 lowercase hexadecimal characters")


def _validate_utc_timestamp(field: str, value: object) -> None:
    value = _require_nonempty_string(field, value)
    if not UTC_TIMESTAMP_PATTERN.fullmatch(value):
        raise ValueError(f"{field} must be a UTC ISO-8601 timestamp")
    timestamp = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as error:
        raise ValueError(f"{field} must be a UTC ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{field} must be a UTC ISO-8601 timestamp")


def _validate_https_url(field: str, value: object) -> None:
    value = _require_nonempty_string(field, value)
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"{field} must be an HTTPS URL")


def _validate_input_path(field: str, value: object) -> None:
    value = _require_nonempty_string(field, value)
    if "\\" in value:
        raise ValueError(f"{field} must be a repository-relative POSIX path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != value
        or path.parts[: len(INPUTS_ROOT.parts)] != INPUTS_ROOT.parts
        or len(path.parts) <= len(INPUTS_ROOT.parts)
    ):
        raise ValueError(
            f"{field} must be beneath {INPUTS_ROOT.as_posix()}/ as a repository-relative POSIX path"
        )


def validate_document_record(record: DocumentRecord) -> None:
    """Raise ``ValueError`` unless *record* satisfies the frozen input contract."""
    if not isinstance(record, DocumentRecord):
        raise ValueError("record must be a DocumentRecord")

    _validate_identifier("document_id", record.document_id)
    _validate_identifier("source_id", record.source_id)
    if record.source_class not in {"institutional", "technical-research"}:
        raise ValueError("source_class must be institutional or technical-research")
    if record.role not in {"primary", "practice"}:
        raise ValueError("role must be primary or practice")
    _require_nonempty_string("title", record.title)
    _require_nonempty_string("author", record.author)
    if record.author_basis not in {"feed_author", "source_publisher"}:
        raise ValueError("author_basis must be feed_author or source_publisher")
    _validate_utc_timestamp("published_at", record.published_at)
    _validate_https_url("origin_url", record.origin_url)
    _validate_input_path("original_path", record.original_path)
    _validate_input_path("text_path", record.text_path)
    if record.media_type not in {"html", "pdf"}:
        raise ValueError("media_type must be html or pdf")
    if isinstance(record.word_count, bool) or not isinstance(record.word_count, int):
        raise ValueError("word_count must be an integer")
    if not 500 <= record.word_count <= 50_000:
        raise ValueError("word_count must be between 500 and 50000")
    _validate_sha256("original_sha256", record.original_sha256)
    _validate_sha256("text_sha256", record.text_sha256)
    _validate_utc_timestamp("acquired_at", record.acquired_at)
