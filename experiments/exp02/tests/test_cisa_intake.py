import hashlib
import json
from pathlib import Path

from PyPDF2 import PdfWriter
import pytest

from exp02.cisa_intake import (
    CandidateInspection,
    freeze_selection,
    inspect_candidate,
    select_candidates,
    selection_key,
)
from exp02.cisa_cli import main as cisa_main


def make_pair(tmp_path: Path, *, folder_code: str, report_name: str) -> Path:
    pair = tmp_path / folder_code
    pair.mkdir(parents=True)
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.add_metadata({"/Title": folder_code})
    with (pair / "document.pdf").open("wb") as handle:
        writer.write(handle)
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": [
            {
                "type": "report",
                "spec_version": "2.1",
                "id": "report--00000000-0000-4000-8000-000000000001",
                "created": "2024-01-01T00:00:00Z",
                "modified": "2024-01-01T00:00:00Z",
                "name": report_name,
                "published": "2024-01-01T00:00:00Z",
                "object_refs": ["vulnerability--00000000-0000-4000-8000-000000000001"],
            },
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": "vulnerability--00000000-0000-4000-8000-000000000001",
                "created": "2024-01-01T00:00:00Z",
                "modified": "2024-01-01T00:00:00Z",
                "name": "CVE-2024-0001",
            },
        ],
    }
    (pair / "reference.stix.json").write_text(json.dumps(bundle), encoding="utf-8")
    return pair


def test_rejects_stix_report_with_different_product_code(tmp_path, monkeypatch):
    pair = make_pair(tmp_path, folder_code="AA24-060B", report_name="AA24-053A Ivanti")
    monkeypatch.setattr("exp02.cisa_intake.extract_pdf_text", lambda _: "word " * 500)
    row = inspect_candidate(pair)
    assert row.eligible is False
    assert row.reasons == ("stix-product-code-mismatch",)


def test_rejects_structurally_invalid_stix_bundle_envelope(tmp_path, monkeypatch):
    pair = make_pair(tmp_path, folder_code="AA24-001A", report_name="AA24-001A test")
    bundle_path = pair / "reference.stix.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["id"] = "bundle--not-a-uuid"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    monkeypatch.setattr("exp02.cisa_intake.extract_pdf_text", lambda _: "word " * 500)

    row = inspect_candidate(pair)

    assert row.eligible is False
    assert row.reasons == ("stix-bundle-invalid",)


def make_inspections(*, eligible: int, rejected: int) -> list[CandidateInspection]:
    rows = []
    for index in range(eligible):
        rows.append(CandidateInspection(
            code=f"AA24-{index:03d}A",
            published=f"2024-01-{index + 1:02d}T00:00:00Z",
            eligible=True,
            reasons=(),
            pdf_sha256=f"pdf-{index}",
            stix_sha256=f"stix-{index}",
            text_sha256=f"text-{index}",
            word_count=500,
            page_count=1,
            comparable_objects=1,
        ))
    for index in range(rejected):
        rows.append(CandidateInspection(
            code=f"AA23-{index:03d}A",
            published="",
            eligible=False,
            reasons=("rejected",),
            pdf_sha256=f"bad-pdf-{index}",
            stix_sha256=f"bad-stix-{index}",
            text_sha256=f"bad-text-{index}",
            word_count=0,
            page_count=0,
            comparable_objects=0,
        ))
    return rows


def test_selects_24_newest_eligible_and_retains_reserves():
    rows = make_inspections(eligible=27, rejected=2)
    selection = select_candidates(rows, final_count=24)
    assert len(selection.final) == 24
    assert len(selection.reserve) == 3
    assert len(selection.rejected) == 2
    assert selection.final == tuple(sorted(selection.final, key=selection_key)[:24])


def test_freeze_requires_the_fixed_final_cardinality(tmp_path):
    with pytest.raises(ValueError, match="exactly 24"):
        freeze_selection(tmp_path, tmp_path / "evidence", "2024-01-02T00:00:00Z", final_count=23)


def test_freeze_refuses_to_seal_an_incomplete_24_document_selection(tmp_path, monkeypatch):
    make_pair(tmp_path / "intake", folder_code="AA24-001A", report_name="AA24-001A test")
    monkeypatch.setattr("exp02.cisa_intake.extract_pdf_text", lambda _: "word " * 500)

    with pytest.raises(ValueError, match="requires exactly 24 eligible"):
        freeze_selection(tmp_path / "intake", tmp_path / "evidence", "2024-01-02T00:00:00Z")


def test_cli_refuses_a_non_24_final_count(capsys):
    status = cisa_main([
        "freeze", "--intake", "ignored", "--evidence", "ignored",
        "--cutoff-utc", "2024-01-02T00:00:00Z", "--final-count", "1",
    ])

    assert status == 2
    assert "exactly 24" in capsys.readouterr().err


def test_frozen_manifest_records_official_urls_for_all_selection_outcomes(tmp_path, monkeypatch):
    intake = tmp_path / "intake"
    for index in range(1, 28):
        code = f"AA24-{index:03d}A"
        make_pair(intake, folder_code=code, report_name=f"{code} test")
    make_pair(intake, folder_code="AA24-100A", report_name="AA24-999A test")
    make_pair(intake, folder_code="AA24-101A", report_name="AA24-998A test")
    monkeypatch.setattr(
        "exp02.cisa_intake.extract_pdf_text",
        lambda pdf: "word " * 500 + hashlib.sha256(pdf).hexdigest(),
    )

    manifest = freeze_selection(intake, tmp_path / "evidence", "2024-01-02T00:00:00Z")
    rows = manifest["documents"] + manifest["reserve"] + manifest["rejected"]

    assert len(manifest["documents"]) == 24
    assert len(manifest["reserve"]) == 3
    assert len(manifest["rejected"]) == 2
    assert all(
        row["official_page_url"]
        == "https://www.cisa.gov/news-events/cybersecurity-advisories/" + row["code"].lower()
        for row in rows
    )


def test_freeze_quarantines_bad_object_but_keeps_usable_bundle(tmp_path, monkeypatch):
    intake = tmp_path / "intake"
    for index in range(1, 25):
        code = f"AA24-{index:03d}A"
        make_pair(intake, folder_code=code, report_name=f"{code} test")
    pair = intake / "AA24-001A"
    bundle_path = pair / "reference.stix.json"
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["objects"].append({
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--00000000-0000-4000-8000-000000000001",
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-01-01T00:00:00Z",
    })
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    monkeypatch.setattr(
        "exp02.cisa_intake.extract_pdf_text",
        lambda pdf: "word " * 500 + hashlib.sha256(pdf).hexdigest(),
    )

    evidence = tmp_path / "evidence"
    manifest = freeze_selection(intake, evidence, "2024-01-02T00:00:00Z")

    assert len(manifest["documents"]) == 24
    assert manifest["documents"][0]["code"] == "AA24-001A"
    assert manifest["quarantined_objects"]["AA24-001A"][0]["id"].startswith("indicator--")
    document = manifest["documents"][0]
    assert set(document) >= {"pdf_sha256", "stix_sha256", "text_sha256"}
    assert hashlib.sha256((evidence / document["input_path"]).read_bytes()).hexdigest() == document["text_sha256"]
    with pytest.raises(FileExistsError):
        freeze_selection(intake, evidence, "2024-01-02T00:00:00Z")
