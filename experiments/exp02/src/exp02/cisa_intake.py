"""Fail-closed admission and freezing for the CISA/STIX evaluation set."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import sys
from typing import Any

from PyPDF2 import PdfReader
from stix2 import parse as parse_stix

from .jsonio import canonical_bytes, sha256_file, write_new_json


_SERVICE_ROOT = Path(__file__).resolve().parents[4] / "services" / "intel-extractor"
if str(_SERVICE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SERVICE_ROOT))
from parser import extract_pdf_text  # noqa: E402  # Reuse TIM's production conversion verbatim.


PILOT_CODES = frozenset({"AA25-203A", "AA25-239A", "AA26-097A", "AA26-204A"})
COMPARABLE_TYPES = frozenset({
    "indicator", "attack-pattern", "threat-actor", "intrusion-set", "malware", "vulnerability",
})
_CODE_RE = re.compile(r"\b(AA\d{2}-\d{3}[A-Z])\b")
_MIN_WORDS = 500
_MAX_WORDS = 50_000
_ENVELOPE_PROBE = {
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--00000000-0000-4000-8000-000000000001",
    "created": "2024-01-01T00:00:00Z",
    "modified": "2024-01-01T00:00:00Z",
    "name": "CISA intake envelope probe",
    "identity_class": "organization",
}


@dataclass(frozen=True)
class CandidateInspection:
    code: str
    published: str
    eligible: bool
    reasons: tuple[str, ...]
    pdf_sha256: str
    stix_sha256: str
    text_sha256: str
    word_count: int
    page_count: int
    comparable_objects: int


@dataclass(frozen=True)
class Selection:
    final: tuple[CandidateInspection, ...]
    reserve: tuple[CandidateInspection, ...]
    rejected: tuple[CandidateInspection, ...]


@dataclass(frozen=True)
class _InspectionDetail:
    row: CandidateInspection
    text: str
    quarantined_objects: tuple[dict[str, str], ...]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _empty_hash() -> str:
    return _sha256_bytes(b"")


def _code_from_path(path: Path) -> str:
    return path.name.upper()


def _read_regular(path: Path) -> bytes | None:
    if not path.is_file() or path.is_symlink():
        return None
    return path.read_bytes()


def _page_count(pdf_bytes: bytes) -> int:
    try:
        return len(PdfReader(io.BytesIO(pdf_bytes)).pages)
    except Exception:
        return 0


def _object_id(value: object) -> str:
    if isinstance(value, Mapping) and isinstance(value.get("id"), str):
        return str(value["id"])
    return "<missing-id>"


def _quarantine_reason(error: Exception) -> str:
    message = " ".join(str(error).split())
    return message or error.__class__.__name__


def _parse_bundle(stix_bytes: bytes) -> tuple[Mapping[str, Any] | None, str | None]:
    try:
        raw = json.loads(stix_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "stix-bundle-invalid"
    if (
        not isinstance(raw, Mapping)
        or raw.get("type") != "bundle"
        or not isinstance(raw.get("id"), str)
        or not str(raw["id"]).startswith("bundle--")
        or not isinstance(raw.get("objects"), list)
    ):
        return None, "stix-bundle-invalid"
    # Validate the bundle envelope separately.  Its objects intentionally stay
    # out of this parse so one malformed official object is quarantined below,
    # rather than invalidating every otherwise usable object in the bundle.
    envelope = dict(raw)
    # stix2 requires a non-empty bundle when parsing.  The valid probe keeps
    # envelope validation independent of every received object.
    envelope["objects"] = [_ENVELOPE_PROBE]
    try:
        parse_stix(envelope, allow_custom=True)
    except Exception:
        return None, "stix-bundle-invalid"
    return raw, None


def _parse_objects(objects: list[object]) -> tuple[list[Mapping[str, Any]], tuple[dict[str, str], ...]]:
    valid: list[Mapping[str, Any]] = []
    quarantined: list[dict[str, str]] = []
    for raw in objects:
        if not isinstance(raw, Mapping):
            quarantined.append({"id": _object_id(raw), "reason": "object-is-not-a-json-object"})
            continue
        if raw.get("spec_version") != "2.1":
            quarantined.append({"id": _object_id(raw), "reason": "object-is-not-stix-2.1"})
            continue
        try:
            parse_stix(raw, allow_custom=True)
        except Exception as error:
            quarantined.append({"id": _object_id(raw), "reason": _quarantine_reason(error)})
            continue
        valid.append(raw)
    return valid, tuple(quarantined)


def _report_details(objects: Iterable[Mapping[str, Any]], code: str) -> tuple[str, tuple[str, ...]]:
    reports = [item for item in objects if item.get("type") == "report"]
    if len(reports) != 1:
        return "", ("missing-or-ambiguous-stix-report",)
    report = reports[0]
    name = report.get("name")
    published = report.get("published")
    if not isinstance(name, str) or code not in _CODE_RE.findall(name):
        return "", ("stix-product-code-mismatch",)
    if not isinstance(published, str) or _parse_timestamp(published) is None:
        return "", ("stix-report-published-invalid",)
    return published, ()


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _inspect_detail(path: Path) -> _InspectionDetail:
    code = _code_from_path(path)
    reasons: list[str] = []
    published = ""
    comparable_objects = 0
    if _CODE_RE.fullmatch(code) is None:
        reasons.append("invalid-product-code")
    pdf_path = path / "document.pdf"
    stix_path = path / "reference.stix.json"
    pdf_bytes = _read_regular(pdf_path)
    stix_bytes = _read_regular(stix_path)
    pdf_sha256 = _sha256_bytes(pdf_bytes) if pdf_bytes is not None else _empty_hash()
    stix_sha256 = _sha256_bytes(stix_bytes) if stix_bytes is not None else _empty_hash()
    text = ""
    page_count = 0
    if pdf_bytes is None:
        reasons.append("missing-document-pdf")
    else:
        page_count = _page_count(pdf_bytes)
        try:
            text = extract_pdf_text(pdf_bytes)
        except Exception:
            reasons.append("pdf-text-extraction-failed")
        else:
            word_count = len(text.split())
            if not _MIN_WORDS <= word_count <= _MAX_WORDS:
                reasons.append("pdf-word-count-out-of-range")
    word_count = len(text.split())
    text_sha256 = _sha256_bytes(text.encode("utf-8"))

    valid_objects: list[Mapping[str, Any]] = []
    quarantined: tuple[dict[str, str], ...] = ()
    if stix_bytes is None:
        reasons.append("missing-reference-stix")
    else:
        bundle, bundle_error = _parse_bundle(stix_bytes)
        if bundle_error is not None:
            reasons.append(bundle_error)
        else:
            valid_objects, quarantined = _parse_objects(list(bundle["objects"]))
            published, report_reasons = _report_details(valid_objects, code)
            reasons.extend(report_reasons)
            comparable_objects = sum(
                item.get("type") in COMPARABLE_TYPES for item in valid_objects
            )
            if comparable_objects == 0:
                reasons.append("missing-comparable-stix-object")
    if code in PILOT_CODES:
        reasons.append("pilot-code")
    row = CandidateInspection(
        code=code,
        published=published,
        eligible=not reasons,
        reasons=tuple(dict.fromkeys(reasons)),
        pdf_sha256=pdf_sha256,
        stix_sha256=stix_sha256,
        text_sha256=text_sha256,
        word_count=word_count,
        page_count=page_count,
        comparable_objects=comparable_objects,
    )
    return _InspectionDetail(row=row, text=text, quarantined_objects=quarantined)


def inspect_candidate(path: Path) -> CandidateInspection:
    """Inspect one intake directory without altering it."""
    return _inspect_detail(Path(path)).row


def _descending_iso(value: str) -> str:
    """Produce a lexical key that places a valid ISO timestamp newest first."""
    parsed = _parse_timestamp(value)
    if parsed is None:
        return "~"
    milliseconds = int(parsed.timestamp() * 1000)
    return f"{9_999_999_999_999 - milliseconds:013d}"


def selection_key(row: CandidateInspection) -> tuple[str, str]:
    return (_descending_iso(row.published), row.code)


def _duplicate_rejection(row: CandidateInspection) -> CandidateInspection:
    return replace(row, eligible=False, reasons=("duplicate-input-hash",))


def select_candidates(rows: Iterable[CandidateInspection], final_count: int = 24) -> Selection:
    """Order eligible candidates, reserve extras, and reject duplicate inputs."""
    if final_count <= 0:
        raise ValueError("final_count must be positive")
    eligible = sorted((row for row in rows if row.eligible), key=selection_key)
    rejected = [row for row in rows if not row.eligible]
    retained: list[CandidateInspection] = []
    seen_hashes: set[str] = set()
    for row in eligible:
        hashes = {row.pdf_sha256, row.stix_sha256, row.text_sha256}
        if hashes & seen_hashes:
            rejected.append(_duplicate_rejection(row))
            continue
        retained.append(row)
        seen_hashes.update(hashes)
    return Selection(
        final=tuple(retained[:final_count]),
        reserve=tuple(retained[final_count:]),
        rejected=tuple(sorted(rejected, key=lambda row: row.code)),
    )


def _apply_cutoff(row: CandidateInspection, cutoff: datetime) -> CandidateInspection:
    published = _parse_timestamp(row.published)
    if row.eligible and (published is None or published > cutoff):
        return replace(row, eligible=False, reasons=("published-after-cutoff",))
    return row


def _manifest_entry(row: CandidateInspection) -> dict[str, object]:
    return {
        **asdict(row),
        "official_page_url": (
            "https://www.cisa.gov/news-events/cybersecurity-advisories/"
            f"{row.code.lower()}"
        ),
    }


def freeze_selection(
    intake_root: Path,
    evidence_root: Path,
    cutoff_utc: str,
    final_count: int = 24,
) -> dict[str, object]:
    """Freeze a deterministic selection, preserving converted input text once."""
    if final_count != 24:
        raise ValueError("CISA evaluation requires exactly 24 final documents")
    intake_root = Path(intake_root)
    evidence_root = Path(evidence_root)
    manifest_path = evidence_root / "selection-manifest.v1.json"
    if manifest_path.exists() or manifest_path.is_symlink():
        raise FileExistsError(f"selection manifest already exists: {manifest_path}")
    cutoff = _parse_timestamp(cutoff_utc)
    if cutoff is None:
        raise ValueError("cutoff_utc must be an ISO-8601 timestamp with timezone")
    details = [_inspect_detail(path) for path in sorted(intake_root.iterdir()) if path.is_dir()]
    rows = [_apply_cutoff(detail.row, cutoff) for detail in details]
    selection = select_candidates(rows, final_count=final_count)
    if len(selection.final) != 24:
        raise ValueError("CISA evaluation requires exactly 24 eligible final documents")
    detail_by_code = {detail.row.code: detail for detail in details}
    documents: list[dict[str, object]] = []
    output_paths = [evidence_root / "documents" / row.code / "input.txt" for row in selection.final]
    if any(path.exists() or path.is_symlink() for path in output_paths):
        raise FileExistsError("selection evidence already exists")
    for row in selection.final:
        detail = detail_by_code[row.code]
        output = evidence_root / "documents" / row.code / "input.txt"
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8", newline="") as handle:
            handle.write(detail.text)
        if sha256_file(output) != row.text_sha256:
            raise RuntimeError("converted text digest changed while freezing")
        documents.append({
            **_manifest_entry(row),
            "input_path": f"documents/{row.code}/input.txt",
            "source_pdf_path": f"cisa-intake/{row.code}/document.pdf",
            "source_stix_path": f"cisa-intake/{row.code}/reference.stix.json",
        })
    quarantined = {
        detail.row.code: list(detail.quarantined_objects)
        for detail in details
        if detail.quarantined_objects
    }
    manifest: dict[str, object] = {
        "schema_version": 1,
        "cutoff_utc": cutoff_utc,
        "final_count": final_count,
        "documents": documents,
        "reserve": [_manifest_entry(row) for row in selection.reserve],
        "rejected": [_manifest_entry(row) for row in selection.rejected],
        "quarantined_objects": quarantined,
        "selection_digest": _sha256_bytes(canonical_bytes([_manifest_entry(row) for row in rows])),
    }
    write_new_json(manifest_path, manifest)
    return manifest
