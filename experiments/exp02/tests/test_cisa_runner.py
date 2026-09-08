import hashlib
import json
from pathlib import Path
import sys

import pytest
from extractor import DiagnosticExtractionError, SYSTEM_PROMPT_V21

from exp02.cisa_runner import (
    EXPECTED_MODEL,
    SafetyError,
    run_all,
    run_once,
    run_smoke,
    seal_execution,
    validate_frozen_evidence,
    validate_preflight,
    load_runtime,
)


class FakeRuntime:
    LLM_PROVIDER = "bedrock"
    BEDROCK_MODEL = EXPECTED_MODEL
    AWS_REGION = "us-east-1"
    ANTHROPIC_API_KEY = ""
    SYSTEM_PROMPT_V21 = SYSTEM_PROMPT_V21

    def __init__(self, result=None):
        self.result = result or {
            "unique_iocs": [], "technique_keywords": set(), "threat_actors": set(),
            "targeted_sectors": set(), "malware_families": set(),
            "targeted_countries": set(), "exploited_cves": [],
            "victim_technologies": set(), "campaign_summary": "",
            "v2_entities": [], "v2_relationships": [],
            "raw_response_text": "{}", "raw_v2_entities": [],
            "raw_v2_relationships": [],
            "citation_stats": {"entities_dropped": 0, "relationships_dropped": 0},
            "stop_reason": "end_turn",
            "model_usage": {"input_tokens": 1, "output_tokens": 1},
            "accepted_iocs": [],
        }
        self.calls = []

    def extract_from_text(self, text, source_type, include_diagnostics):
        self.calls.append((text, source_type, include_diagnostics))
        return self.result

    def _get_anthropic_client(self):
        class Messages:
            @staticmethod
            def create(**_kwargs):
                return type("Response", (), {
                    "content": [type("Text", (), {"type": "text", "text": "OK"})()],
                    "stop_reason": "end_turn",
                    "usage": type("Usage", (), {"input_tokens": 2, "output_tokens": 1})(),
                })()

        return type("Client", (), {"messages": Messages()})()


class Evidence:
    def __init__(self, root: Path, manifest: dict):
        self.root = root
        self.manifest = manifest


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_evidence(tmp_path: Path) -> Evidence:
    root = tmp_path / "cisa-evidence"
    selection_documents = []
    for index in range(24):
        code = "AA26-222A" if index == 0 else f"AA25-{index:03d}A"
        input_path = root / "documents" / code / "input.txt"
        input_path.parent.mkdir(parents=True, exist_ok=True)
        input_path.write_text(f"Document {code}.", encoding="utf-8")
        pdf_path = root.parent / "cisa-intake" / code / "document.pdf"
        stix_path = root.parent / "cisa-intake" / code / "reference.stix.json"
        pdf_path.parent.mkdir(parents=True, exist_ok=True)
        pdf_path.write_bytes(f"PDF {code}".encode("utf-8"))
        stix_path.write_text(json.dumps({"objects": []}), encoding="utf-8")
        reference_path = root / "reference" / f"{code}.canonical.json"
        reference_path.parent.mkdir(parents=True, exist_ok=True)
        reference_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "document_id": code,
                    "entities": [],
                    "ungrounded_entities": [],
                    "relations": [],
                    "exclusions": [],
                    "excluded_relations": [],
                }
            ),
            encoding="utf-8",
        )
        selection_documents.append({
            "code": code,
            "input_path": f"documents/{code}/input.txt",
            "source_pdf_path": f"cisa-intake/{code}/document.pdf",
            "source_stix_path": f"cisa-intake/{code}/reference.stix.json",
            "pdf_sha256": _sha(pdf_path),
            "stix_sha256": _sha(stix_path),
            "text_sha256": _sha(input_path),
        })
    selection = {"schema_version": 1, "selection_digest": "frozen-selection", "documents": selection_documents}
    (root / "selection-manifest.v1.json").write_text(json.dumps(selection), encoding="utf-8")
    config = root.parent / "config" / "cisa-equivalences.v1.json"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({
        "schema_version": 1, "frozen_before_final_runs": True,
        "groups": [["China", "People's Republic of China", "PRC"]],
    }), encoding="utf-8")
    manifest = seal_execution(root, FakeRuntime(), equivalence_path=config)
    return Evidence(root, manifest)


@pytest.fixture
def runtime():
    return FakeRuntime()


@pytest.fixture
def evidence(tmp_path):
    return make_evidence(tmp_path)


@pytest.fixture
def complete_evidence(evidence):
    return evidence


def test_preflight_requires_exact_24_and_frozen_hashes(runtime, evidence):
    evidence.manifest["documents"].pop()
    with pytest.raises(SafetyError, match="exactly 24"):
        validate_preflight(evidence.root, runtime, manifest=evidence.manifest)


def test_offline_frozen_evidence_validation_shares_selection_manifest_checks(evidence):
    """An offline consumer must not bypass the selection digest bound by the runner."""
    assert len(validate_frozen_evidence(evidence)) == 24
    evidence.manifest["selection_digest"] = "different-selection"

    with pytest.raises(SafetyError, match="selection digest"):
        validate_frozen_evidence(evidence)


def test_run_refuses_overwrite(runtime, complete_evidence):
    run_once(complete_evidence, "AA26-222A", 1, runtime)
    with pytest.raises(FileExistsError):
        run_once(complete_evidence, "AA26-222A", 1, runtime)


def test_run_uses_advisory_diagnostics_and_records_raw_and_final_output(runtime, evidence):
    record = run_once(evidence, "AA26-222A", 1, runtime)

    assert record["status"] == "success"
    assert runtime.calls == [("Document AA26-222A.", "advisory", True)]
    assert record["raw_model_output"]["raw_response_text"] == "{}"
    assert record["tim_output"]["v2_entities"] == []
    assert record["tim_output"]["accepted_iocs"] == []


def test_run_all_requires_same_configuration_successful_smoke(runtime, evidence):
    with pytest.raises(SafetyError, match="smoke"):
        run_all(evidence, runtime, sleep=lambda _seconds: None)
    smoke = run_smoke(evidence, runtime)
    assert smoke["status"] == "success"
    records = run_all(evidence, runtime, sleep=lambda _seconds: None)
    assert len(records) == 72


def test_run_all_rejects_a_truncated_existing_record(runtime, evidence):
    run_smoke(evidence, runtime)
    record = run_once(evidence, "AA26-222A", 1, runtime)
    path = evidence.root / "runs" / "AA26-222A.run-1.json"
    path.write_text(json.dumps(record)[:-1], encoding="utf-8")

    with pytest.raises(SafetyError, match="cannot read existing run record"):
        run_all(evidence, runtime, sleep=lambda _seconds: None)


def test_run_all_rejects_existing_record_with_wrong_identity_or_configuration(runtime, evidence):
    run_smoke(evidence, runtime)
    record = run_once(evidence, "AA26-222A", 1, runtime)
    record["document"] = "AA00-000A"
    path = evidence.root / "runs" / "AA26-222A.run-1.json"
    path.write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(SafetyError, match="document"):
        run_all(evidence, runtime, sleep=lambda _seconds: None)


def test_run_once_records_a_typed_diagnostic_failure(evidence):
    class FailingRuntime(FakeRuntime):
        def extract_from_text(self, *_args, **_kwargs):
            raise DiagnosticExtractionError("Claude transport error")

    record = run_once(evidence, "AA26-222A", 1, FailingRuntime())

    assert record["status"] == "error"
    assert record["error_type"] == "DiagnosticExtractionError"
    assert record["error"] == "Claude transport error"


def test_evaluation_runtime_import_does_not_load_the_opencti_client_stack():
    assert "opencti_client" not in sys.modules

    runtime = load_runtime()

    assert runtime.extract_from_text
    assert "opencti_client" not in sys.modules
