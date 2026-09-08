import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


def _document(source, number, date, *, pdf=True):
    return SimpleNamespace(
        content=(b"%PDF-1.7\n" if pdf else b"<html>") + f"document-{number}".encode(),
        landing_dedup_key=f"https://example.test/{source}/landing/{number}",
        document_dedup_key=f"https://example.test/{source}/document/{number}.pdf",
        title=f"{source} document {number}",
        publication_date=date,
        title_source="landing_h1",
        publication_date_source="landing_main_time",
    )


def _source(name, seed_number):
    short = "cnsd" if name.startswith("CNSD") else "colcert"
    return {
        "name": name,
        "type": "html_collection",
        "url": f"https://example.test/{short}/collection",
        "max_candidates": 3,
        "processed_seed_documents": [
            {
                "landing_url": f"https://example.test/{short}/landing/{seed_number}",
                "document_url": f"https://example.test/{short}/document/{seed_number}.pdf",
            }
        ],
    }


def test_capture_selects_two_unseen_documents_per_source_without_llm_or_opencti(tmp_path):
    """Catches seed leakage, wrong per-source count, or a capture path that dispatches extraction."""
    from capture_corpus import capture

    cnsd_name = "CNSD Integrated Digital Security Alerts"
    colcert_name = "ColCERT Boletines"
    sources = [_source(cnsd_name, 100), _source(colcert_name, 200)]
    discoveries = {
        cnsd_name: [
            _document("cnsd", 100, "2026-08-28"),
            _document("cnsd", 102, "2026-08-27"),
            _document("cnsd", 101, "2026-08-26"),
        ],
        colcert_name: [
            _document("colcert", 200, "2026-08-28"),
            _document("colcert", 202, "2026-08-27"),
            _document("colcert", 201, "2026-08-26"),
        ],
    }

    def discover(source, *, state, limit, operational):
        assert state == {}
        assert limit == 12
        assert operational is False
        return SimpleNamespace(documents=discoveries[source["name"]], errors=[])

    def parse_pdf_text(content):
        return "parsed " + content.decode(errors="replace")

    manifest = capture(
        source_names=[cnsd_name, colcert_name],
        per_source=2,
        output_dir=tmp_path,
        sources=sources,
        discover=discover,
        parse_pdf_text=parse_pdf_text,
        now_utc="2026-08-28T12:00:00Z",
    )

    assert manifest["llm_calls"] == 0
    assert manifest["opencti_writes"] == 0
    assert [row["source_name"] for row in manifest["documents"]] == [
        cnsd_name, cnsd_name, colcert_name, colcert_name
    ]
    selected_urls = {row["document_url"] for row in manifest["documents"]}
    assert "https://example.test/cnsd/document/100.pdf" not in selected_urls
    assert "https://example.test/colcert/document/200.pdf" not in selected_urls
    assert len(selected_urls) == 4

    persisted = json.loads((tmp_path / "manifest.json").read_text())
    assert persisted == manifest
    for row in manifest["documents"]:
        folder = tmp_path / "documents" / row["stem"]
        pdf = folder / "source.pdf"
        text = folder / "input.txt"
        metadata = folder / "metadata.json"
        assert pdf.read_bytes().startswith(b"%PDF-")
        assert text.read_text().startswith("parsed %PDF-")
        assert json.loads(metadata.read_text())["document_url"] == row["document_url"]
        assert row["sha256_pdf"] == hashlib.sha256(pdf.read_bytes()).hexdigest()
        assert row["sha256_text"] == hashlib.sha256(text.read_bytes()).hexdigest()


def test_capture_fails_closed_when_a_source_has_fewer_than_two_unseen_documents(tmp_path):
    """Catches silent creation of an undersized corpus after seed filtering."""
    from capture_corpus import capture

    name = "CNSD Integrated Digital Security Alerts"
    source = _source(name, 100)

    def discover(*args, **kwargs):
        return SimpleNamespace(
            documents=[
                _document("cnsd", 100, "2026-08-28"),
                _document("cnsd", 101, "2026-08-27"),
            ],
            errors=[],
        )

    with pytest.raises(ValueError, match="2 unseen PDF documents"):
        capture(
            source_names=[name],
            per_source=2,
            output_dir=tmp_path,
            sources=[source],
            discover=discover,
            parse_pdf_text=lambda _: "text",
            now_utc="2026-08-28T12:00:00Z",
        )

    assert not (tmp_path / "manifest.json").exists()
    assert not (tmp_path / "documents").exists()


def test_capture_rejects_non_pdf_content_before_persisting_any_artifact(tmp_path):
    """Catches trusting a URL suffix when the downloaded body is not a PDF."""
    from capture_corpus import capture

    name = "ColCERT Boletines"
    source = _source(name, 200)

    def discover(*args, **kwargs):
        return SimpleNamespace(
            documents=[
                _document("colcert", 201, "2026-08-28", pdf=False),
                _document("colcert", 202, "2026-08-27"),
            ],
            errors=[],
        )

    with pytest.raises(ValueError, match="confirmed PDF"):
        capture(
            source_names=[name],
            per_source=2,
            output_dir=tmp_path,
            sources=[source],
            discover=discover,
            parse_pdf_text=lambda _: "text",
            now_utc="2026-08-28T12:00:00Z",
        )

    assert list(tmp_path.iterdir()) == []


def test_capture_rejects_duplicate_document_urls(tmp_path):
    """Catches counting the same PDF twice when collection cards are duplicated."""
    from capture_corpus import capture

    name = "CNSD Integrated Digital Security Alerts"
    source = _source(name, 100)
    duplicate = _document("cnsd", 101, "2026-08-28")

    def discover(*args, **kwargs):
        return SimpleNamespace(documents=[duplicate, duplicate], errors=[])

    with pytest.raises(ValueError, match="2 unseen PDF documents"):
        capture(
            source_names=[name],
            per_source=2,
            output_dir=tmp_path,
            sources=[source],
            discover=discover,
            parse_pdf_text=lambda _: "text",
            now_utc="2026-08-28T12:00:00Z",
        )


def test_capture_rejects_text_that_exceeds_the_experimental_context_guard(tmp_path):
    """Catches treating the parser's 4M-character safety cap as a Haiku context guarantee."""
    from capture_corpus import capture

    name = "ColCERT Boletines"
    source = _source(name, 200)

    def discover(*args, **kwargs):
        return SimpleNamespace(
            documents=[
                _document("colcert", 201, "2026-08-28"),
                _document("colcert", 202, "2026-08-27"),
            ],
            errors=[],
        )

    with pytest.raises(ValueError, match="context guard"):
        capture(
            source_names=[name],
            per_source=2,
            output_dir=tmp_path,
            sources=[source],
            discover=discover,
            parse_pdf_text=lambda _: "x" * 600_001,
            now_utc="2026-08-28T12:00:00Z",
        )

    assert list(tmp_path.iterdir()) == []
