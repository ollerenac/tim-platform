import copy
import hashlib
import importlib
import sqlite3
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import yaml


COLLECTION_URL = (
    "https://www.gob.pe/institucion/pcm/colecciones/"
    "791-alerta-integrada-de-seguridad-digital-del-cnsd"
)
SOURCE_NAME = "CNSD Integrated Digital Security Alerts"
IDENTITY_NAME = "Centro Nacional de Seguridad Digital (CNSD)"
IDENTITY_ID = "identity--43e42b52-41cd-5bd7-85d6-f102059cccea"

DOCUMENTS = [
    {
        "number": "117",
        "landing_url": (
            "https://www.gob.pe/institucion/pcm/informes-publicaciones/"
            "8359341-alerta-integrada-de-seguridad-digital-n-117-2026-cnsd"
        ),
        "document_url": (
            "https://cdn.www.gob.pe/uploads/document/file/10288111/"
            "8359341-alerta-integrada-de-seguridad-digital-117-2026-cnsd.pdf"
        ),
        "title": "Alerta Integrada de Seguridad Digital N. 117-2026-CNSD",
        "publication_date": "2026-07-09",
        "report_standard_id": "report--cb830d89-a2d2-566f-b336-9a22b518951a",
        "vulnerabilities": [
            "CVE-2026-14544",
            "CVE-2026-8631",
            "CVE-2026-14487",
            "CVE-2026-33264",
            "CVE-2026-13019",
        ],
        "accepted_iocs": [],
    },
    {
        "number": "116",
        "landing_url": (
            "https://www.gob.pe/institucion/pcm/informes-publicaciones/"
            "8359338-alerta-integrada-de-seguridad-digital-n-116-2026-cnsd"
        ),
        "document_url": (
            "https://cdn.www.gob.pe/uploads/document/file/10288107/"
            "8359338-alerta-integrada-de-seguridad-digital-116-2026-cnsd.pdf"
        ),
        "title": "Alerta Integrada de Seguridad Digital N. 116-2026-CNSD",
        "publication_date": "2026-07-08",
        "report_standard_id": "report--e8e1bd54-5734-5c17-91dc-fbbb2ed26b07",
        "vulnerabilities": [
            "CVE-2026-53359",
            "CVE-2026-4878",
            "CVE-2026-13356",
        ],
        "accepted_iocs": [
            {"type": "ip", "value": "23.133.4.108"},
            {"type": "ip", "value": "23.133.4.109"},
            {"type": "ip", "value": "27.124.40.52"},
            {"type": "ip", "value": "27.124.9.47"},
            {"type": "ip", "value": "38.45.124.19"},
            {"type": "ip", "value": "38.91.114.219"},
            {"type": "ip", "value": "154.91.75.192"},
            {"type": "domain", "value": "nishihaoren1.top"},
            {"type": "domain", "value": "nishihaoren1.org"},
        ],
    },
    {
        "number": "115",
        "landing_url": (
            "https://www.gob.pe/institucion/pcm/informes-publicaciones/"
            "8346789-alerta-integrada-de-seguridad-digital-n-115-2026-cnsd"
        ),
        "document_url": (
            "https://cdn.www.gob.pe/uploads/document/file/10271221/"
            "8346789-alerta-integrada-de-seguridad-digital-115-2026-cnsd.pdf"
        ),
        "title": "Alerta Integrada de Seguridad Digital N. 115-2026-CNSD",
        "publication_date": "2026-07-07",
        "report_standard_id": "report--cffb8fb7-e6de-5ac9-a734-4295720dda6c",
        "vulnerabilities": ["CVE-2026-11405"],
        "accepted_iocs": [],
    },
]

FUTURE_DOCUMENT = {
    "number": "118",
    "landing_url": (
        "https://www.gob.pe/institucion/pcm/informes-publicaciones/"
        "8400118-alerta-integrada-de-seguridad-digital-n-118-2026-cnsd"
    ),
    "document_url": (
        "https://cdn.www.gob.pe/uploads/document/file/10300118/"
        "8400118-alerta-integrada-de-seguridad-digital-118-2026-cnsd.pdf"
    ),
    "title": "Alerta Integrada de Seguridad Digital N. 118-2026-CNSD",
    "publication_date": "2026-07-10",
    "vulnerabilities": ["CVE-2026-60001"],
    "accepted_iocs": [{"type": "domain", "value": "future-c2.example"}],
}

INDICATOR_IDS = [
    "indicator--de15aa21-60aa-5646-9224-a5cd54664e26",
    "indicator--f8742abb-1a3a-5787-bb7b-a9a8524b2b5d",
    "indicator--545699aa-056b-587e-b420-62372e76747b",
    "indicator--e8206f04-84da-598a-ae55-2bd97e8278d4",
    "indicator--ad8507e0-f1ab-522d-ba2b-0f788fbeaf07",
    "indicator--0b196e4a-be74-56b3-b078-dee199bac5da",
    "indicator--6220e6c5-54c7-5d69-a572-49397d12b7bc",
    "indicator--b9dc50ab-4fc7-5605-9013-c8a9c092492e",
    "indicator--e9e31422-f641-5c26-ad8b-253c4bb1aed5",
]


def _cnsd():
    return importlib.import_module("cnsd_ingest")


def _configured_source():
    path = Path(__file__).parents[1] / "sources.yaml"
    sources = yaml.safe_load(path.read_text())["sources"]
    matches = [source for source in sources if source.get("url") == COLLECTION_URL]
    assert len(matches) == 1
    return copy.deepcopy(matches[0])


def _preview():
    return {
        "source": {
            "name": SOURCE_NAME,
            "url": COLLECTION_URL,
            "source_type": "bulletin",
            "requested_limit": 3,
            "effective_limit": 3,
            "automatic_dispatch": False,
        },
        "documents": [
            {
                "title": document["title"],
                "title_source": "collection_anchor+landing_confirmed",
                "publication_date": document["publication_date"],
                "publication_date_source": "collection_card_time+landing_confirmed",
                "landing_url": document["landing_url"],
                "document_url": document["document_url"],
                "source_type": "bulletin",
                "vulnerabilities": list(document["vulnerabilities"]),
                "accepted_iocs": copy.deepcopy(document["accepted_iocs"]),
                "rejected_ioc_candidates": [],
                "extraction_metadata": {
                    "status": "complete",
                    "chunk_count": 1,
                    "completed_chunks": 1,
                    "failed_chunks": 0,
                    "retry_count": 0,
                    "chunk_diagnostics": [
                        {
                            "chunk_index": 0,
                            "status": "complete",
                            "attempts": 1,
                            "retry_count": 0,
                            "error": None,
                        }
                    ],
                },
            }
            for document in DOCUMENTS
        ],
        "errors": [],
    }


def _future_pending(**overrides):
    values = {
        "mode": "pdf",
        "content": b"%PDF-1.7 synthetic future fixture",
        "url": None,
        "source_type": "bulletin",
        "source_name": SOURCE_NAME,
        "landing_dedup_key": FUTURE_DOCUMENT["landing_url"],
        "document_dedup_key": FUTURE_DOCUMENT["document_url"],
        "title": FUTURE_DOCUMENT["title"],
        "publication_date": FUTURE_DOCUMENT["publication_date"],
        "title_source": "collection_anchor+landing_confirmed",
        "publication_date_source": "collection_card_time+landing_confirmed",
        "dispatch_pipeline": "cnsd_strict",
        "source_config": _configured_source(),
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _future_preview(**overrides):
    preview = {
        "title": FUTURE_DOCUMENT["title"],
        "title_source": "collection_anchor+landing_confirmed",
        "publication_date": FUTURE_DOCUMENT["publication_date"],
        "publication_date_source": "collection_card_time+landing_confirmed",
        "landing_url": FUTURE_DOCUMENT["landing_url"],
        "document_url": FUTURE_DOCUMENT["document_url"],
        "vulnerabilities": list(FUTURE_DOCUMENT["vulnerabilities"]),
        "accepted_iocs": copy.deepcopy(FUTURE_DOCUMENT["accepted_iocs"]),
        "rejected_ioc_candidates": [],
        "extraction_metadata": {
            "status": "complete",
            "pdf_bytes": 37,
            "chunk_count": 1,
            "chunk_diagnostics": [
                {
                    "chunk_index": 0,
                    "status": "complete",
                    "attempts": 1,
                    "retry_count": 0,
                    "error": None,
                }
            ],
        },
    }
    preview.update(overrides)
    return preview


def _pipeline_row(document, *, status="previewed", report_id=None, error=None):
    cnsd = _cnsd()
    return {
        "document_key": cnsd.document_key(
            document["landing_url"], document["document_url"]
        ),
        "landing_url": document["landing_url"],
        "document_url": document["document_url"],
        "title": document["title"],
        "source": SOURCE_NAME,
        "status": status,
        "vulnerability_count": len(document["vulnerabilities"]),
        "indicator_count": len(document["accepted_iocs"]),
        "report_id": report_id,
        "report_standard_id": document["report_standard_id"],
        "error": error,
    }


class FakeEntityApi:
    def __init__(
        self,
        kind,
        *,
        fail_on_create=None,
        mismatch_read=False,
        report_aliases=False,
    ):
        self.kind = kind
        self.fail_on_create = fail_on_create
        self.mismatch_read = mismatch_read
        self.report_aliases = report_aliases
        self.created = []
        self.read_calls = []
        self.by_standard_id = {}

    def create(self, **kwargs):
        self.created.append(copy.deepcopy(kwargs))
        if self.fail_on_create == len(self.created):
            raise RuntimeError(f"{self.kind} write failed")
        requested_id = kwargs["stix_id"]
        standard_id = requested_id
        if self.kind == "report" and self.report_aliases:
            standard_id = "report--" + str(uuid.uuid5(uuid.NAMESPACE_OID, requested_id))
        value = {"id": f"internal-{standard_id}", "standard_id": standard_id, **kwargs}
        if self.kind == "report":
            value["createdBy"] = kwargs.get("createdBy")
            value["externalReferences"] = list(kwargs.get("externalReferences", []))
            value["objects"] = list(kwargs.get("objects", []))
            value["x_opencti_stix_ids"] = [requested_id]
        self.by_standard_id[standard_id] = value
        self.by_standard_id[requested_id] = value
        return {"id": value["id"], "standard_id": standard_id}

    def read(self, **kwargs):
        self.read_calls.append(copy.deepcopy(kwargs))
        standard_id = kwargs.get("id") or kwargs.get("stix_id")
        result = copy.deepcopy(self.by_standard_id.get(standard_id))
        if result and self.mismatch_read:
            result["standard_id"] = f"{self.kind}--mismatch"
        return result

    def list(self, **kwargs):
        return list(copy.deepcopy(self.by_standard_id).values())


class FakeClient:
    def __init__(
        self,
        *,
        fail_kind=None,
        fail_on_create=None,
        mismatch_kind=None,
        report_aliases=False,
    ):
        self.identity = FakeEntityApi(
            "identity",
            fail_on_create=fail_on_create if fail_kind == "identity" else None,
            mismatch_read=mismatch_kind == "identity",
        )
        self.external_reference = FakeEntityApi(
            "external-reference",
            fail_on_create=fail_on_create if fail_kind == "external_reference" else None,
            mismatch_read=mismatch_kind == "external_reference",
        )
        self.vulnerability = FakeEntityApi(
            "vulnerability",
            fail_on_create=fail_on_create if fail_kind == "vulnerability" else None,
            mismatch_read=mismatch_kind == "vulnerability",
        )
        self.indicator = FakeEntityApi(
            "indicator",
            fail_on_create=fail_on_create if fail_kind == "indicator" else None,
            mismatch_read=mismatch_kind == "indicator",
        )
        self.report = FakeEntityApi(
            "report",
            fail_on_create=fail_on_create if fail_kind == "report" else None,
            mismatch_read=mismatch_kind == "report",
            report_aliases=report_aliases,
        )
        self.attack_pattern = MagicMock()
        self.stix_core_relationship = MagicMock()


def _configure_db(monkeypatch, tmp_path):
    import stats_store

    db_path = tmp_path / "stats.db"
    monkeypatch.setattr(stats_store, "DB_PATH", str(db_path))
    stats_store.init_db()
    return stats_store, db_path


def _ingest(monkeypatch, tmp_path, *, preview=None, client=None):
    cnsd = _cnsd()
    stats_store, _ = _configure_db(monkeypatch, tmp_path)
    acknowledge = MagicMock()
    result = cnsd.ingest_cnsd(
        COLLECTION_URL,
        3,
        sources=[_configured_source()],
        preview_builder=lambda *_: copy.deepcopy(preview or _preview()),
        client=client or FakeClient(),
        acknowledge=acknowledge,
        retry_delays=(),
    )
    return result, acknowledge, stats_store


def test_source_is_periodic_bounded_seeded_and_strict():
    source = _configured_source()

    assert source["automatic_dispatch"] is True
    assert source["poll_interval_hours"] == 24
    assert source["max_candidates"] == 3
    assert source["max_new_per_cycle"] == 1
    assert source["dispatch_pipeline"] == "cnsd_strict"
    assert source["identity"] == {"name": IDENTITY_NAME, "type": "Organization"}
    assert source["processed_seed_documents"] == [
        {
            "landing_url": document["landing_url"],
            "document_url": document["document_url"],
        }
        for document in DOCUMENTS
    ]
    assert "controlled_documents" not in source


def test_dynamic_future_document_uses_deterministic_document_local_graph(
    monkeypatch, tmp_path
):
    cnsd = _cnsd()
    stats_store, _ = _configure_db(monkeypatch, tmp_path)
    client = FakeClient()
    pending = _future_pending()

    result = cnsd.ingest_discovered_document(
        pending,
        preview_builder=lambda document: _future_preview(),
        client=client,
        retry_delays=(),
    )

    expected_report = "report--" + str(
        uuid.uuid5(uuid.NAMESPACE_URL, FUTURE_DOCUMENT["landing_url"])
    )
    assert result["ok"] is True
    assert result["document"]["report_canonical_id"] == expected_report
    assert client.report.created[0]["stix_id"] == expected_report
    assert len(client.report.created[0]["externalReferences"]) == 2
    assert len(client.report.created[0]["objects"]) == 2
    assert client.attack_pattern.mock_calls == []
    assert client.stix_core_relationship.mock_calls == []
    row = stats_store.get_recent_documents()[0]
    assert row["status"] == "ingested"
    assert row["landing_url"] == FUTURE_DOCUMENT["landing_url"]
    assert stats_store.get_stats()["total_docs"] == 1
    assert stats_store.get_stats()["total_iocs"] == 1


@pytest.mark.parametrize(
    ("pending_change", "preview_change"),
    [
        ({"landing_dedup_key": "https://www.gob.pe.evil.test/institucion/pcm/informes-publicaciones/x-cnsd"}, {}),
        ({"landing_dedup_key": FUTURE_DOCUMENT["landing_url"] + "?write=1"}, {}),
        ({"landing_dedup_key": FUTURE_DOCUMENT["landing_url"].replace("https://", "https://user@")}, {}),
        ({"document_dedup_key": FUTURE_DOCUMENT["document_url"].replace(".pdf", ".txt")}, {}),
        ({"content": b"not a PDF"}, {}),
        ({"title": "Alerta Integrada de Seguridad Digital N. 119-2026-CNSD"}, {}),
        ({"publication_date": "2025-07-10"}, {}),
        ({}, {"extraction_metadata": {"status": "error", "chunk_count": 1, "chunk_diagnostics": [{"status": "error"}]}}),
        ({}, {"accepted_iocs": [{"type": "cve", "value": "CVE-2026-60001"}]}),
        ({}, {"accepted_iocs": [{"type": "domain", "value": "bad value"}]}),
    ],
    ids=[
        "suffix_host",
        "landing_query",
        "credentials",
        "wrong_pdf_path",
        "non_pdf_bytes",
        "title_conflict",
        "date_conflict",
        "incomplete_chunks",
        "cve_as_ioc",
        "invalid_stix_ioc",
    ],
)
def test_dynamic_future_trust_gate_rejections_record_failed_without_writes(
    monkeypatch, tmp_path, pending_change, preview_change
):
    cnsd = _cnsd()
    stats_store, _ = _configure_db(monkeypatch, tmp_path)
    client = FakeClient()
    pending = _future_pending(**pending_change)

    with pytest.raises((ValueError, RuntimeError)):
        cnsd.ingest_discovered_document(
            pending,
            preview_builder=lambda document: _future_preview(**preview_change),
            client=client,
            retry_delays=(),
        )

    assert client.identity.created == []
    assert stats_store.get_stats()["total_docs"] == 0
    rows = stats_store.get_recent_documents()
    assert rows and rows[0]["status"] == "failed"


def test_dynamic_future_readback_mismatch_is_failed_and_not_counted(
    monkeypatch, tmp_path
):
    cnsd = _cnsd()
    stats_store, _ = _configure_db(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="read-back|verification"):
        cnsd.ingest_discovered_document(
            _future_pending(),
            preview_builder=lambda document: _future_preview(),
            client=FakeClient(mismatch_kind="report"),
            retry_delays=(),
        )

    assert stats_store.get_recent_documents()[0]["status"] == "failed"
    assert stats_store.get_stats()["total_docs"] == 0


def test_manual_recovery_dry_run_delegates_to_same_periodic_poll(monkeypatch):
    cnsd = _cnsd()
    periodic = MagicMock(return_value={"ok": True, "outcome": "due"})
    fake_collector = SimpleNamespace(run_collection_poll_once=periodic)
    monkeypatch.setitem(__import__("sys").modules, "collector", fake_collector)

    result = cnsd.poll_once(
        COLLECTION_URL,
        now="2026-07-12T12:00:00+00:00",
        force=True,
        dry_run=True,
    )

    assert result == {"ok": True, "outcome": "due"}
    periodic.assert_called_once_with(
        COLLECTION_URL,
        now="2026-07-12T12:00:00+00:00",
        force=True,
        dry_run=True,
        dispatchers={},
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda preview: preview["documents"].pop(),
        lambda preview: preview["documents"].append(copy.deepcopy(preview["documents"][0])),
        lambda preview: preview["documents"].append(
            {**copy.deepcopy(preview["documents"][0]), "landing_url": "https://www.gob.pe/future"}
        ),
        lambda preview: preview["documents"][0].update(
            {"landing_url": preview["documents"][0]["landing_url"] + "/redirected"}
        ),
        lambda preview: preview["documents"][0].update(
            {"landing_url": preview["documents"][0]["landing_url"] + "?variant=1"}
        ),
        lambda preview: preview["documents"].reverse(),
    ],
    ids=["missing", "duplicate", "extra", "redirected", "query_variant", "drift_order"],
)
def test_scope_drift_fails_before_any_opencti_write(monkeypatch, tmp_path, mutate):
    preview = _preview()
    mutate(preview)
    client = FakeClient()

    with pytest.raises(ValueError, match="controlled|allowlist|manifest"):
        _ingest(monkeypatch, tmp_path, preview=preview, client=client)

    assert not client.identity.created
    assert not client.external_reference.created
    assert not client.vulnerability.created
    assert not client.indicator.created
    assert not client.report.created


@pytest.mark.parametrize(
    "mutate",
    [
        lambda preview: preview["errors"].append("preview failed"),
        lambda preview: preview["documents"][0]["extraction_metadata"].update(
            {"status": "error", "failed_chunks": 1}
        ),
        lambda preview: preview["documents"][0]["vulnerabilities"].append("CVE-2099-9999"),
        lambda preview: preview["documents"][1]["accepted_iocs"].pop(),
        lambda preview: preview["documents"][1]["accepted_iocs"].append(
            {"type": "cve", "value": "CVE-2026-53359"}
        ),
        lambda preview: preview["documents"][0]["accepted_iocs"].append(
            {"type": "url", "value": "https://vendor.example/reference"}
        ),
    ],
    ids=["top_error", "chunk_error", "wrong_cve", "wrong_ioc", "cve_ioc", "editorial_url"],
)
def test_preview_policy_failures_are_unacknowledged(monkeypatch, tmp_path, mutate):
    preview = _preview()
    mutate(preview)
    client = FakeClient()
    acknowledge = MagicMock()
    cnsd = _cnsd()
    _configure_db(monkeypatch, tmp_path)

    with pytest.raises(ValueError, match="preview|CVE|IOC|complete|controlled"):
        cnsd.ingest_cnsd(
            COLLECTION_URL,
            3,
            sources=[_configured_source()],
            preview_builder=lambda *_: preview,
            client=client,
            acknowledge=acknowledge,
            retry_delays=(),
        )

    acknowledge.assert_not_called()
    assert not client.identity.created


def test_canonical_urls_and_document_key_are_confined_and_stable():
    cnsd = _cnsd()
    landing = DOCUMENTS[0]["landing_url"]
    pdf = DOCUMENTS[0]["document_url"]

    assert cnsd.canonical_official_url(landing + "#section") == landing
    assert cnsd.canonical_official_url(pdf + "?cache=transient#page=2") == pdf
    assert cnsd.document_key(landing, pdf) == hashlib.sha256(
        f"{landing}\n{pdf}".encode()
    ).hexdigest()
    with pytest.raises(ValueError):
        cnsd.canonical_official_url("https://example.com" + landing)
    with pytest.raises(ValueError):
        cnsd.canonical_official_url(landing + "?not-allowed=1")
    with pytest.raises(ValueError):
        cnsd.canonical_official_url(pdf.replace(".pdf", ".exe") + "?cache=1")


def test_manifest_pins_standard_ids_and_report_ids_ignore_title_changes():
    cnsd = _cnsd()
    preview = _preview()
    manifest = cnsd.build_expected_manifest(_configured_source(), preview)
    renamed = _preview()
    renamed["documents"][0]["title"] = "Corrected official title"
    renamed_manifest = cnsd.build_expected_manifest(_configured_source(), renamed)

    assert [item["report_standard_id"] for item in manifest] == [
        document["report_standard_id"] for document in DOCUMENTS
    ]
    assert manifest[0]["document_key"] == renamed_manifest[0]["document_key"]
    assert manifest[0]["report_standard_id"] == renamed_manifest[0]["report_standard_id"]
    assert manifest[0]["identity_standard_id"] == IDENTITY_ID
    assert [item["indicator_standard_id"] for item in manifest[1]["indicators"]] == INDICATOR_IDS
    assert all(item["external_reference_standard_ids"] for item in manifest)


def test_graph_mapping_is_document_local_and_has_only_provenance_links():
    cnsd = _cnsd()
    manifest = cnsd.build_expected_manifest(_configured_source(), _preview())

    assert [len(item["objects"]) for item in manifest] == [5, 12, 1]
    assert [
        [obj["entity_type"] for obj in item["objects"]].count("Indicator")
        for item in manifest
    ] == [0, 9, 0]
    assert all(item["created_by"] == IDENTITY_ID for item in manifest)
    assert all(len(item["external_references"]) == 2 for item in manifest)
    assert not any(
        obj["entity_type"] in {"Attack-Pattern", "Relationship"}
        for item in manifest
        for obj in item["objects"]
    )


@pytest.mark.parametrize(
    "kind,occurrence",
    [
        ("identity", 1),
        ("external_reference", 1),
        ("vulnerability", 1),
        ("indicator", 1),
        ("report", 1),
    ],
)
def test_required_write_failure_records_failed_without_acknowledgement(
    monkeypatch, tmp_path, kind, occurrence
):
    client = FakeClient(fail_kind=kind, fail_on_create=occurrence)

    with pytest.raises(RuntimeError, match="failed"):
        _ingest(monkeypatch, tmp_path, client=client)

    import stats_store

    rows = stats_store.get_recent_documents()
    assert len(rows) == 3
    assert any(row["status"] == "failed" and row["error"] for row in rows)
    assert not any(row["status"] == "ingested" for row in rows)
    assert stats_store.get_stats()["total_docs"] == 0


@pytest.mark.parametrize(
    "kind",
    ["identity", "external_reference", "vulnerability", "indicator", "report"],
)
def test_required_readback_mismatch_records_failed_without_acknowledgement(
    monkeypatch, tmp_path, kind
):
    client = FakeClient(mismatch_kind=kind)

    with pytest.raises(RuntimeError, match="read-back|verification"):
        _ingest(monkeypatch, tmp_path, client=client)

    import stats_store

    assert not any(row["status"] == "ingested" for row in stats_store.get_recent_documents())
    assert stats_store.get_stats()["total_docs"] == 0


def test_success_reads_back_then_acknowledges_and_marks_ingested(monkeypatch, tmp_path):
    client = FakeClient()
    result, acknowledge, stats_store = _ingest(monkeypatch, tmp_path, client=client)

    assert result["ok"] is True
    assert len(result["documents"]) == 3
    assert acknowledge.call_count == 3
    assert [row["status"] for row in stats_store.get_recent_documents()] == [
        "ingested",
        "ingested",
        "ingested",
    ]
    assert stats_store.get_stats()["total_docs"] == 3
    assert stats_store.get_stats()["total_iocs"] == 9
    assert client.attack_pattern.mock_calls == []
    assert client.stix_core_relationship.mock_calls == []
    for api in (
        client.identity,
        client.external_reference,
        client.vulnerability,
        client.indicator,
        client.report,
    ):
        assert all(call["update"] is True and call["stix_id"] for call in api.created)


def test_report_create_accepts_live_opencti_canonical_alias(monkeypatch, tmp_path):
    client = FakeClient(report_aliases=True)

    result, acknowledge, stats_store = _ingest(
        monkeypatch, tmp_path, client=client
    )

    assert result["ok"] is True
    assert acknowledge.call_count == 3
    assert [item["report_canonical_id"] for item in result["documents"]] == [
        document["report_standard_id"] for document in DOCUMENTS
    ]
    assert all(
        item["report_standard_id"] != item["report_canonical_id"]
        for item in result["documents"]
    )
    assert all(
        "... on BasicObject" in call["customAttributes"]
        and "... on StixObject" in call["customAttributes"]
        for call in client.report.read_calls
    )
    assert {
        row["report_standard_id"] for row in stats_store.get_recent_documents()
    } == {document["report_standard_id"] for document in DOCUMENTS}


def test_partial_failure_rolls_forward_same_ids_without_duplicate_history(
    monkeypatch, tmp_path
):
    cnsd = _cnsd()
    stats_store, _ = _configure_db(monkeypatch, tmp_path)
    client = FakeClient(fail_kind="report", fail_on_create=2)
    common = {
        "sources": [_configured_source()],
        "preview_builder": lambda *_: _preview(),
        "client": client,
        "acknowledge": MagicMock(),
        "retry_delays": (),
    }

    with pytest.raises(RuntimeError):
        cnsd.ingest_cnsd(COLLECTION_URL, 3, **common)
    first_ids = {
        call["stix_id"]
        for api in (client.identity, client.external_reference, client.vulnerability,
                    client.indicator, client.report)
        for call in api.created
    }
    failed_rows = stats_store.get_recent_documents()
    first_previewed = {row["document_key"]: row["previewed_at"] for row in failed_rows}

    client.report.fail_on_create = None
    result = cnsd.ingest_cnsd(COLLECTION_URL, 3, **common)
    second_ids = {
        call["stix_id"]
        for api in (client.identity, client.external_reference, client.vulnerability,
                    client.indicator, client.report)
        for call in api.created
    }
    rows = stats_store.get_recent_documents()
    first_ingested = {row["document_key"]: row["first_ingested_at"] for row in rows}

    assert result["ok"] is True
    assert first_ids <= second_ids
    assert len(rows) == 3
    assert {row["document_key"]: row["previewed_at"] for row in rows} == first_previewed
    assert stats_store.get_stats()["total_docs"] == 3
    assert stats_store.get_stats()["total_iocs"] == 9

    cnsd.ingest_cnsd(COLLECTION_URL, 3, **common)
    rerun_rows = stats_store.get_recent_documents()
    assert {row["document_key"]: row["first_ingested_at"] for row in rerun_rows} == first_ingested
    assert stats_store.get_stats()["total_docs"] == 3
    assert stats_store.get_stats()["total_iocs"] == 9


def test_pipeline_migration_and_transitions_are_idempotent(monkeypatch, tmp_path):
    stats_store, db_path = _configure_db(monkeypatch, tmp_path)
    stats_store.init_db()
    row = _pipeline_row(DOCUMENTS[0])

    stats_store.record_previewed(**row)
    stats_store.record_failed(**{**row, "error": "token=secret\nwrite failed"})
    stats_store.record_ingested(
        **{
            **row,
            "report_id": "internal-report-117",
            "error": None,
            "update_totals": True,
        }
    )
    first = stats_store.get_recent_documents()[0]
    stats_store.record_previewed(**{**row, "title": "Updated title"})
    stats_store.record_ingested(
        **{
            **row,
            "title": "Updated title",
            "report_id": "internal-report-117",
            "error": None,
            "update_totals": True,
        }
    )
    second = stats_store.get_recent_documents()[0]

    assert first["status"] == second["status"] == "ingested"
    assert first["first_ingested_at"] == second["first_ingested_at"]
    assert second["previewed_at"] == first["previewed_at"]
    assert second["filename"] == second["title"] == "Updated title"
    assert second["ingested_at"] == second["first_ingested_at"]
    assert second["ioc_count"] == second["indicator_count"] == 0
    assert second["error"] is None
    assert stats_store.get_stats()["total_docs"] == 1
    with sqlite3.connect(db_path) as con:
        assert con.execute("SELECT count(*) FROM document_pipeline").fetchone()[0] == 1


def test_recent_documents_are_newest_first_and_main_uses_sqlite(monkeypatch, tmp_path):
    stats_store, _ = _configure_db(monkeypatch, tmp_path)
    for document in DOCUMENTS:
        stats_store.record_previewed(**_pipeline_row(document))
        stats_store.record_ingested(
            **{
                **_pipeline_row(document),
                "report_id": "internal-" + document["number"],
                "update_totals": False,
            }
        )

    rows = stats_store.get_recent_documents(limit=2)
    assert len(rows) == 2
    assert rows[0]["updated_at"] >= rows[1]["updated_at"]
    required = {
        "filename",
        "ingested_at",
        "ioc_count",
        "status",
        "title",
        "source",
        "vulnerability_count",
        "indicator_count",
        "previewed_at",
        "first_ingested_at",
        "last_attempt_at",
        "failed_at",
        "updated_at",
        "report_id",
        "report_standard_id",
        "error",
    }
    assert all(required <= set(row) for row in rows)

    import asyncio
    import fastapi.dependencies.utils

    monkeypatch.setattr(
        fastapi.dependencies.utils, "ensure_multipart_is_installed", lambda: None
    )
    import main

    monkeypatch.setattr(main.stats_store, "get_recent_documents", lambda limit: rows)
    main.recent_docs.clear()
    main.recent_docs.appendleft({"filename": "volatile"})
    assert asyncio.run(main.recent()) == {"docs": rows}


@pytest.mark.parametrize("terminal", ["success", "parse_failure", "client_failure"])
def test_generic_extractor_mirrors_terminal_rows_without_replacing_behavior(
    monkeypatch, tmp_path, terminal
):
    import extractor

    stats_store, _ = _configure_db(monkeypatch, tmp_path)
    monkeypatch.setattr(extractor.stats_store, "increment", MagicMock())
    monkeypatch.setattr(extractor, "extract_url_text", lambda *_: "Observed 203.0.113.7")
    monkeypatch.setattr(
        extractor,
        "extract_from_text",
        lambda *_: {
            "unique_iocs": [{"type": "ip", "value": "203.0.113.7"}],
            "technique_keywords": set(),
            "targeted_sectors": set(),
            "victim_technologies": set(),
            "campaign_summary": "",
        },
    )
    monkeypatch.setattr(extractor, "build_pycti_client", lambda: object())
    monkeypatch.setattr(extractor, "create_indicator", lambda **_: {"id": "indicator--1"})
    monkeypatch.setattr(extractor, "lookup_attack_pattern", lambda *_: None)
    monkeypatch.setattr(extractor, "create_report", lambda **_: {"id": "report--1"})
    if terminal == "parse_failure":
        monkeypatch.setattr(
            extractor, "extract_url_text", lambda *_: (_ for _ in ()).throw(ValueError("bad URL"))
        )
    if terminal == "client_failure":
        monkeypatch.setattr(
            extractor,
            "build_pycti_client",
            lambda: (_ for _ in ()).throw(RuntimeError("OpenCTI unavailable")),
        )

    extractor.jobs.clear()
    extractor.recent_docs.clear()
    job_id = "generic-" + terminal
    url = "https://example.test/" + terminal
    extractor.register_job(job_id)
    extractor.run_extraction(job_id, "url", None, url)

    row = stats_store.get_recent_documents()[0]
    if terminal == "success":
        assert extractor.jobs[job_id]["status"] == "complete"
        assert extractor.jobs[job_id]["report_id"] == "report--1"
        assert extractor.recent_docs[0]["status"] == "complete"
        assert row["status"] == "ingested"
        extractor.stats_store.increment.assert_called_once_with(docs=1, iocs=1)
    else:
        assert extractor.jobs[job_id]["status"] == "failed"
        assert extractor.recent_docs[0]["status"].startswith("error:")
        assert row["status"] == "failed"
        extractor.stats_store.increment.assert_not_called()
    assert row["landing_url"] == url
    assert stats_store.get_stats()["total_docs"] == 0
