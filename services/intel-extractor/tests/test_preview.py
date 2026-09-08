import json
import os
import subprocess
import sys
import textwrap
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


def _normalize(text):
    from preview import normalize_cve_candidates

    return normalize_cve_candidates(text)


@pytest.mark.parametrize(
    "raw",
    [
        "CVE-2026-1234",
        "cve-2026-1234",
        "CVE - 2026 - 1234",
        "CVE-2026-12\n34",
        "CVE-2026-12\r\n  34",
        "CVE-2026-12\u00ad34",
        "CVE-2026-12-\n34",
        "CVE-2026-12\u2013\n  34",
    ],
)
def test_cve_normalizer_accepts_only_canonical_and_pdf_wrap_forms(raw):
    candidate = _normalize(f"prefix {raw} suffix")[0]

    assert candidate["id"] == "CVE-2026-1234"
    assert candidate["raw_forms"] == [raw]
    assert candidate["occurrence_count"] == 1
    assert candidate["offsets"] == [{"start": 7, "end": 7 + len(raw)}]


@pytest.mark.parametrize(
    "raw",
    [
        "CVE-2026-12-34",
        "CVE-2026-12 - 34",
        "CVE-2026-12 – 34",
        "CVE-2026-12- 34",
        "CVE-2026-12 -34",
        "XCVE-2026-1234",
        "CVE-2026-1234suffix",
        "CVE-26-1234",
        "CVE-2026-123",
        "CVE-2026-12345678901",
        "token9CVE-2026-1234x",
    ],
)
def test_cve_normalizer_rejects_internal_separators_and_lookalikes(raw):
    assert _normalize(raw) == []


def test_cve_normalizer_preserves_first_seen_order_raw_forms_and_offsets():
    text = "cve-2027-9999 then CVE-2026-12\n34 and CVE-2026-1234 again"

    candidates = _normalize(text)

    assert [candidate["id"] for candidate in candidates] == [
        "CVE-2027-9999",
        "CVE-2026-1234",
    ]
    second = candidates[1]
    assert second["raw_forms"] == ["CVE-2026-12\n34", "CVE-2026-1234"]
    assert second["occurrence_count"] == 2
    wrapped = "CVE-2026-12\n34"
    canonical = "CVE-2026-1234"
    assert second["offsets"] == [
        {"start": text.index(wrapped), "end": text.index(wrapped) + len(wrapped)},
        {"start": text.rindex(canonical), "end": text.rindex(canonical) + len(canonical)},
    ]


def test_cve_normalizer_keeps_neighboring_identifiers_separate():
    text = "CVE-2026-1234, CVE-2026-5678"

    assert [candidate["id"] for candidate in _normalize(text)] == [
        "CVE-2026-1234",
        "CVE-2026-5678",
    ]


CNSD_COLLECTION_URL = (
    "https://www.gob.pe/institucion/pcm/colecciones/"
    "791-alerta-integrada-de-seguridad-digital-del-cnsd"
)
TITLE_SOURCES = {
    "collection_anchor+landing_confirmed",
    "landing_main_h1",
    "landing_main_h2",
}
DATE_SOURCES = {
    "collection_card_time+landing_confirmed",
    "collection_card_text+landing_confirmed",
    "landing_main_time",
    "landing_main_text",
}
GUARD_KEYS = {
    "collector_save_state",
    "run_extraction",
    "opencti_client_init",
    "create_indicator",
    "create_report",
    "create_relationship",
    "create_targeting_relationships",
    "stats_init_db",
    "stats_increment",
    "stats_conn",
}


def _source():
    return {
        "name": "CNSD Integrated Digital Security Alerts",
        "type": "html_collection",
        "url": CNSD_COLLECTION_URL,
        "source_type": "bulletin",
        "max_candidates": 3,
        "automatic_dispatch": False,
    }


def _fake_modules(monkeypatch, *, extraction_error=None):
    import preview

    extraction = {
        "unique_iocs": [{"type": "ip", "value": "203.0.113.7"}],
        "technique_keywords": set(),
        "targeted_sectors": set(),
        "victim_technologies": set(),
        "campaign_summary": "",
        "chunk_diagnostics": [
            {
                "chunk_index": 0,
                "status": "complete",
                "attempts": 2,
                "retry_count": 1,
                "error": None,
            }
        ],
        "accepted_iocs": [{"type": "ip", "value": "203.0.113.7"}],
        "rejected_ioc_candidates": [
            {
                "type": "url",
                "value": "https://vendor.example/update",
                "reason": "bulletin_reference_only",
                "stage": "bulletin_policy",
            }
        ],
    }
    extractor = SimpleNamespace(
        run_extraction=lambda *args, **kwargs: None,
        build_pycti_client=lambda: object(),
        create_indicator=lambda *args, **kwargs: None,
        create_report=lambda *args, **kwargs: None,
        create_relationship=lambda *args, **kwargs: None,
        create_targeting_relationships=lambda *args, **kwargs: None,
        build_stix_pattern=lambda ioc_type, value: ("pattern", "Type"),
        chunk_text=lambda text: [text],
        extract_from_text=MagicMock(
            side_effect=extraction_error or (lambda *args, **kwargs: extraction)
        ),
        OLLAMA_MODEL="llama3.2:3b",
    )
    stats = SimpleNamespace(
        init_db=lambda: None,
        increment=lambda *args, **kwargs: None,
        _conn=lambda: None,
    )
    real_import = preview.importlib.import_module

    def fake_import(name):
        if name == "extractor":
            return extractor
        if name == "stats_store":
            return stats
        return real_import(name)

    monkeypatch.setattr(preview.importlib, "import_module", fake_import)
    return extractor, stats


def test_preview_build_composes_bounded_documents_with_exact_schema(monkeypatch, tmp_path):
    import collector
    import preview

    state_path = tmp_path / "state.json"
    db_path = tmp_path / "stats.db"
    monkeypatch.setattr(collector, "STATE_PATH", state_path)
    monkeypatch.setattr(collector, "DB_PATH", db_path)
    monkeypatch.setattr(collector, "_load_sources", lambda: [_source()])
    documents = [
        collector.PendingDocument(
            mode="pdf",
            content=b"%PDF-one",
            url=None,
            source_type="bulletin",
            source_name=_source()["name"],
            landing_dedup_key="https://www.gob.pe/institucion/pcm/informes-publicaciones/1-one-cnsd",
            document_dedup_key="https://cdn.www.gob.pe/uploads/document/file/1/one.pdf",
            title="Alerta Integrada 1",
            publication_date="2026-07-11",
            title_source="collection_anchor+landing_confirmed",
            publication_date_source="collection_card_time+landing_confirmed",
        ),
        collector.PendingDocument(
            mode="pdf",
            content=b"%PDF-two",
            url=None,
            source_type="bulletin",
            source_name=_source()["name"],
            landing_dedup_key="https://www.gob.pe/institucion/pcm/informes-publicaciones/2-two-cnsd",
            document_dedup_key="https://cdn.www.gob.pe/uploads/document/file/2/two.pdf",
            title="Alerta Integrada 2",
            publication_date="2026-07-10",
            title_source="landing_main_h1",
            publication_date_source="landing_main_time",
        ),
    ]
    discover = MagicMock(
        return_value=collector.CollectionDiscovery(documents=documents)
    )
    monkeypatch.setattr(collector, "discover_html_collection", discover)
    parse = MagicMock(side_effect=["CVE-2026-12\n34 and 203.0.113.7", "No CVEs"])
    monkeypatch.setattr(preview, "extract_pdf_text", parse)
    extractor, _ = _fake_modules(monkeypatch)

    result = preview.build_collection_preview(CNSD_COLLECTION_URL, 99)

    assert set(result) == {
        "collection_url",
        "source_identity",
        "requested_limit",
        "effective_limit",
        "documents",
        "no_write_evidence",
        "errors",
    }
    assert result["source_identity"] == {
        "name": _source()["name"],
        "type": "html_collection",
        "source_type": "bulletin",
        "collection_url": CNSD_COLLECTION_URL,
    }
    assert result["requested_limit"] == 99
    assert result["effective_limit"] == 3
    assert result["errors"] == []
    discover.assert_called_once_with(_source(), state={"processed_urls": []}, limit=3, operational=False)
    assert parse.call_count == 2
    assert extractor.extract_from_text.call_count == 2
    assert all(
        call.args[1:] == ("bulletin",) and call.kwargs == {"include_diagnostics": True}
        for call in extractor.extract_from_text.call_args_list
    )

    expected_document_keys = {
        "title",
        "publication_date",
        "title_source",
        "publication_date_source",
        "landing_url",
        "document_url",
        "cve_candidates",
        "vulnerabilities",
        "accepted_iocs",
        "rejected_ioc_candidates",
        "extraction_metadata",
    }
    assert all(set(document) == expected_document_keys for document in result["documents"])
    assert result["documents"][0]["vulnerabilities"] == ["CVE-2026-1234"]
    cve = result["documents"][0]["cve_candidates"][0]
    assert set(cve) == {"id", "raw_forms", "occurrence_count", "offsets"}
    assert cve["raw_forms"]
    assert cve["occurrence_count"] == len(cve["offsets"]) > 0
    assert all(
        set(offset) == {"start", "end"}
        and isinstance(offset["start"], int)
        and isinstance(offset["end"], int)
        and offset["start"] < offset["end"]
        for offset in cve["offsets"]
    )
    assert result["documents"][0]["accepted_iocs"] == [
        {"type": "ip", "value": "203.0.113.7"}
    ]
    assert result["documents"][0]["extraction_metadata"]["retry_count"] == 1
    assert result["documents"][0]["extraction_metadata"]["chunk_diagnostics"] == [
        {
            "chunk_index": 0,
            "status": "complete",
            "attempts": 2,
            "retry_count": 1,
            "error": None,
        }
    ]
    assert all(document["title_source"] in TITLE_SOURCES for document in result["documents"])
    assert all(
        document["publication_date_source"] in DATE_SOURCES
        for document in result["documents"]
    )
    assert set(result["no_write_evidence"]["write_attempts"]) == GUARD_KEYS
    assert all(value == 0 for value in result["no_write_evidence"]["write_attempts"].values())
    assert not state_path.exists()
    assert not db_path.exists()


def test_preview_no_write_guards_fail_closed_and_restore_symbols(monkeypatch, tmp_path):
    import collector
    import preview

    state_path = tmp_path / "state.json"
    db_path = tmp_path / "stats.db"
    state_path.write_bytes(b"state-sentinel")
    db_path.write_bytes(b"db-sentinel")
    monkeypatch.setattr(collector, "STATE_PATH", state_path)
    monkeypatch.setattr(collector, "DB_PATH", db_path)
    monkeypatch.setattr(collector, "_load_sources", lambda: [_source()])
    document = collector.PendingDocument(
        mode="pdf",
        content=b"%PDF-one",
        url=None,
        source_type="bulletin",
        landing_dedup_key="https://www.gob.pe/institucion/pcm/informes-publicaciones/1-one-cnsd",
        document_dedup_key="https://cdn.www.gob.pe/uploads/document/file/1/one.pdf",
        title="Alerta 1",
        publication_date="2026-07-11",
        title_source="landing_main_h1",
        publication_date_source="landing_main_time",
    )
    monkeypatch.setattr(
        collector,
        "discover_html_collection",
        lambda *args, **kwargs: collector.CollectionDiscovery(documents=[document]),
    )
    monkeypatch.setattr(preview, "extract_pdf_text", lambda content: "text")
    extractor, _ = _fake_modules(monkeypatch)
    original_run_extraction = extractor.run_extraction
    extractor.extract_from_text.side_effect = lambda *args, **kwargs: extractor.run_extraction()

    result = preview.build_collection_preview(CNSD_COLLECTION_URL, 1)

    assert result["errors"]
    assert result["documents"] == []
    assert result["no_write_evidence"]["write_attempts"]["run_extraction"] == 1
    assert extractor.run_extraction is original_run_extraction
    assert state_path.read_bytes() == b"state-sentinel"
    assert db_path.read_bytes() == b"db-sentinel"
    evidence = result["no_write_evidence"]
    assert evidence["state_before"] == evidence["state_post_import"] == evidence["state_after"]
    assert evidence["db_before"] == evidence["db_post_import"] == evidence["db_after"]


def test_preview_chunk_failure_is_incomplete_with_errors_and_nonzero_cli(
    monkeypatch, tmp_path, capsys
):
    import collector
    import preview

    monkeypatch.setattr(collector, "STATE_PATH", tmp_path / "state.json")
    monkeypatch.setattr(collector, "DB_PATH", tmp_path / "stats.db")
    monkeypatch.setattr(collector, "_load_sources", lambda: [_source()])
    document = collector.PendingDocument(
        mode="pdf",
        content=b"%PDF-one",
        url=None,
        source_type="bulletin",
        landing_dedup_key="https://www.gob.pe/institucion/pcm/informes-publicaciones/1-one-cnsd",
        document_dedup_key="https://cdn.www.gob.pe/uploads/document/file/1/one.pdf",
        title="Alerta 1",
        publication_date="2026-07-11",
        title_source="landing_main_h1",
        publication_date_source="landing_main_time",
    )
    monkeypatch.setattr(
        collector,
        "discover_html_collection",
        lambda *args, **kwargs: collector.CollectionDiscovery(documents=[document]),
    )
    monkeypatch.setattr(preview, "extract_pdf_text", lambda content: "CVE-2026-1234")
    extractor, _ = _fake_modules(monkeypatch)
    extractor.extract_from_text.side_effect = lambda *args, **kwargs: {
        "unique_iocs": [],
        "technique_keywords": set(),
        "targeted_sectors": set(),
        "victim_technologies": set(),
        "campaign_summary": "",
        "accepted_iocs": [],
        "rejected_ioc_candidates": [],
        "chunk_diagnostics": [
            {
                "chunk_index": 0,
                "status": "error",
                "attempts": 2,
                "retry_count": 1,
                "error": "model_call_failed",
            }
        ],
    }

    result = preview.build_collection_preview(CNSD_COLLECTION_URL, 1)

    assert result["errors"]
    assert len(result["documents"]) == 1
    assert result["documents"][0]["extraction_metadata"]["status"] == "error"
    assert result["documents"][0]["extraction_metadata"]["retry_count"] == 1
    monkeypatch.setattr(preview, "build_collection_preview", lambda *args: result)
    assert preview.main(["--collection-url", CNSD_COLLECTION_URL, "--limit", "1"]) == 1
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["errors"] == result["errors"]


def test_preview_import_is_lazy_in_fresh_process(tmp_path):
    env = os.environ.copy()
    env.update(
        PYTHONPATH=os.path.dirname(os.path.dirname(__file__)),
        STATE_PATH=str(tmp_path / "absent-state.json"),
        DB_PATH=str(tmp_path / "absent-db.json"),
    )
    code = (
        "import json,sys; import preview; "
        "print(json.dumps({'extractor': 'extractor' in sys.modules, "
        "'stats_store': 'stats_store' in sys.modules}))"
    )

    completed = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(completed.stdout) == {"extractor": False, "stats_store": False}
    assert not (tmp_path / "absent-state.json").exists()
    assert not (tmp_path / "absent-db.json").exists()


@pytest.mark.parametrize("mode", ["success", "guard_error"])
@pytest.mark.parametrize("sentinel", [False, True])
def test_preview_fresh_process_preserves_absent_and_sentinel_storage(
    tmp_path, mode, sentinel
):
    state_path = tmp_path / f"{mode}-{sentinel}-state.json"
    db_path = tmp_path / f"{mode}-{sentinel}-stats.db"
    if sentinel:
        state_path.write_bytes(b"state-sentinel")
        db_path.write_bytes(b"db-sentinel")
    before_state = state_path.read_bytes() if sentinel else None
    before_db = db_path.read_bytes() if sentinel else None
    env = os.environ.copy()
    env.update(
        PYTHONPATH=os.path.dirname(os.path.dirname(__file__)),
        STATE_PATH=str(state_path),
        DB_PATH=str(db_path),
        OPENCTI_TOKEN="",
        PREVIEW_TEST_MODE=mode,
    )
    code = textwrap.dedent(
        f"""
        import json, os
        from types import SimpleNamespace
        import collector, preview

        source = {_source()!r}
        document = collector.PendingDocument(
            mode='pdf', content=b'%PDF-test', url=None, source_type='bulletin',
            landing_dedup_key='https://www.gob.pe/institucion/pcm/informes-publicaciones/1-one-cnsd',
            document_dedup_key='https://cdn.www.gob.pe/uploads/document/file/1/one.pdf',
            title='Alerta 1', publication_date='2026-07-11',
            title_source='landing_main_h1', publication_date_source='landing_main_time',
        )
        collector._load_sources = lambda: [source]
        collector.discover_html_collection = lambda *a, **k: collector.CollectionDiscovery(documents=[document])
        preview.extract_pdf_text = lambda content: 'Observed CVE-2026-1234'
        stats = SimpleNamespace(init_db=lambda: None, increment=lambda *a, **k: None, _conn=lambda: None)
        extractor = SimpleNamespace(
            run_extraction=lambda *a, **k: None,
            build_pycti_client=lambda: object(),
            create_indicator=lambda *a, **k: None,
            create_report=lambda *a, **k: None,
            create_relationship=lambda *a, **k: None,
            create_targeting_relationships=lambda *a, **k: None,
            build_stix_pattern=lambda *a, **k: ('pattern', 'Type'),
            chunk_text=lambda text: [text], OLLAMA_MODEL='llama3.2:3b',
        )
        original_run = extractor.run_extraction
        def extract(*args, **kwargs):
            if os.environ['PREVIEW_TEST_MODE'] == 'guard_error':
                extractor.run_extraction()
            return {{
                'accepted_iocs': [], 'rejected_ioc_candidates': [],
                'unique_iocs': [], 'technique_keywords': set(),
                'targeted_sectors': set(), 'victim_technologies': set(),
                'campaign_summary': '',
            }}
        extractor.extract_from_text = extract
        real_import = preview.importlib.import_module
        preview.importlib.import_module = lambda name: extractor if name == 'extractor' else stats if name == 'stats_store' else real_import(name)
        result = preview.build_collection_preview(source['url'], 1)
        print(json.dumps({{'result': result, 'restored': extractor.run_extraction is original_run}}, sort_keys=True))
        """
    )

    completed = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)
    evidence = payload["result"]["no_write_evidence"]

    assert payload["restored"] is True
    assert set(evidence["write_attempts"]) == GUARD_KEYS
    assert evidence["collector_state_mutated"] is False
    assert evidence["stats_db_mutated"] is False
    assert evidence["import_state_mutated"] is False
    assert evidence["import_db_mutated"] is False
    expected_attempts = 1 if mode == "guard_error" else 0
    assert evidence["write_attempts"]["run_extraction"] == expected_attempts
    assert all(
        value == 0
        for key, value in evidence["write_attempts"].items()
        if key != "run_extraction"
    )
    if sentinel:
        assert state_path.read_bytes() == before_state
        assert db_path.read_bytes() == before_db
    else:
        assert not state_path.exists()
        assert not db_path.exists()
