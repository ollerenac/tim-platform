import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import run_bedrock


MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


class FakeRuntime:
    LLM_PROVIDER = "bedrock"
    BEDROCK_MODEL = MODEL
    AWS_REGION = "us-east-1"
    ANTHROPIC_API_KEY = ""

    def __init__(self, result=None, response=None):
        self.result = result or {
            "unique_iocs": [{"type": "ip", "value": "203.0.113.7"}],
            "technique_keywords": {"phishing"},
            "threat_actors": {"Example Group"},
            "targeted_sectors": set(),
            "malware_families": set(),
            "targeted_countries": set(),
            "exploited_cves": [],
            "victim_technologies": set(),
            "campaign_summary": "",
            "v2_entities": [],
            "v2_relationships": [],
            "chunk_diagnostics": [
                {
                    "chunk_index": 0,
                    "status": "complete",
                    "attempts": 1,
                    "retry_count": 0,
                    "error": None,
                }
            ],
        }
        self.extract_calls = []
        self.response = response
        self.message_calls = []

    def extract_from_text(self, text, source_type, include_diagnostics):
        self.extract_calls.append((text, source_type, include_diagnostics))
        return self.result

    def _get_anthropic_client(self):
        runtime = self

        class Messages:
            def create(self, **kwargs):
                runtime.message_calls.append(kwargs)
                return runtime.response

        return SimpleNamespace(messages=Messages())


def make_corpus(tmp_path: Path, *, status="CORRECTED") -> Path:
    root = tmp_path / "corpus"
    documents = []
    reference_hashes = {}
    for index in range(4):
        stem = f"doc-{index + 1}"
        folder = root / "documents" / stem
        folder.mkdir(parents=True)
        text = f"Document {index + 1} with IOC 203.0.113.{index + 1}"
        (folder / "input.txt").write_text(text, encoding="utf-8")
        expected_path = folder / "expected.json"
        expected_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "document": stem,
                    "annotation_status": status,
                    "entities": [],
                    "relationships": [],
                }
            ),
            encoding="utf-8",
        )
        import hashlib

        documents.append(
            {
                "stem": stem,
                "sha256_text": hashlib.sha256(text.encode()).hexdigest(),
            }
        )
        reference_hashes[stem] = hashlib.sha256(expected_path.read_bytes()).hexdigest()
    (root / "manifest.json").write_text(
        json.dumps({"documents": documents, "llm_calls": 0, "opencti_writes": 0}),
        encoding="utf-8",
    )
    (root / "reference-manifest.json").write_text(
        json.dumps({"documents": reference_hashes}), encoding="utf-8"
    )
    return root


@pytest.mark.parametrize(
    ("attribute", "bad_value"),
    [
        ("LLM_PROVIDER", "anthropic"),
        ("BEDROCK_MODEL", "anthropic.claude-haiku-4-5"),
        ("AWS_REGION", "us-west-2"),
        ("ANTHROPIC_API_KEY", "personal-key-must-not-be-used"),
    ],
)
def test_preflight_rejects_any_route_that_is_not_the_approved_bedrock_path(
    tmp_path, attribute, bad_value
):
    root = make_corpus(tmp_path)
    runtime = FakeRuntime()
    setattr(runtime, attribute, bad_value)

    with pytest.raises(run_bedrock.SafetyError):
        run_bedrock.validate_preflight(root, runtime)


def test_preflight_rejects_a_reference_that_has_not_completed_review(tmp_path):
    root = make_corpus(tmp_path, status="PENDING_REVIEW")

    with pytest.raises(run_bedrock.SafetyError, match="review"):
        run_bedrock.validate_preflight(root, FakeRuntime())


def test_preflight_rejects_input_text_changed_after_manifest_capture(tmp_path):
    root = make_corpus(tmp_path)
    (root / "documents" / "doc-2" / "input.txt").write_text(
        "changed after capture", encoding="utf-8"
    )

    with pytest.raises(run_bedrock.SafetyError, match="SHA-256"):
        run_bedrock.validate_preflight(root, FakeRuntime())


def test_preflight_rejects_reference_changed_after_review(tmp_path):
    root = make_corpus(tmp_path)
    expected = root / "documents" / "doc-3" / "expected.json"
    value = json.loads(expected.read_text(encoding="utf-8"))
    value["entities"].append({"id": "late-change"})
    expected.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(run_bedrock.SafetyError, match="reference SHA-256"):
        run_bedrock.validate_preflight(root, FakeRuntime())


def test_run_once_calls_the_pure_extractor_once_and_refuses_to_overwrite(tmp_path):
    root = make_corpus(tmp_path)
    runtime = FakeRuntime()

    record = run_bedrock.run_once(
        root,
        "doc-1",
        1,
        runtime,
        now_utc=lambda: "2026-08-28T11:00:00Z",
        monotonic=lambda: 10.0,
    )

    assert record["status"] == "success"
    assert record["provider"] == "bedrock"
    assert record["model"] == MODEL
    assert record["model_output"]["technique_keywords"] == ["phishing"]
    assert runtime.extract_calls == [
        ("Document 1 with IOC 203.0.113.1", "bulletin", True)
    ]
    saved = json.loads(
        (root / "runs" / "doc-1.run-1.json").read_text(encoding="utf-8")
    )
    assert saved == record

    with pytest.raises(FileExistsError):
        run_bedrock.run_once(root, "doc-1", 1, runtime)
    assert len(runtime.extract_calls) == 1


def test_run_once_preserves_a_model_error_without_retrying(tmp_path):
    root = make_corpus(tmp_path)
    runtime = FakeRuntime(
        result={
            "unique_iocs": [],
            "v2_entities": [],
            "v2_relationships": [],
            "chunk_diagnostics": [
                {
                    "chunk_index": 0,
                    "status": "error",
                    "attempts": 1,
                    "retry_count": 0,
                    "error": "model_call_failed",
                }
            ],
        }
    )

    record = run_bedrock.run_once(root, "doc-1", 2, runtime)

    assert record["status"] == "model_error"
    assert record["model_output"]["chunk_diagnostics"][0]["error"] == "model_call_failed"
    assert len(runtime.extract_calls) == 1


def test_smoke_uses_exact_bedrock_model_and_records_response_usage(tmp_path):
    root = make_corpus(tmp_path)
    response = SimpleNamespace(
        content=[SimpleNamespace(type="text", text="OK")],
        usage=SimpleNamespace(input_tokens=8, output_tokens=1),
        stop_reason="end_turn",
    )
    runtime = FakeRuntime(response=response)

    record = run_bedrock.run_smoke(
        root, runtime, now_utc=lambda: "2026-08-28T11:01:00Z"
    )

    assert record == {
        "schema_version": 1,
        "kind": "bedrock_smoke",
        "status": "success",
        "created_at_utc": "2026-08-28T11:01:00Z",
        "provider": "bedrock",
        "model": MODEL,
        "aws_region": "us-east-1",
        "max_tokens": 10,
        "response_text": "OK",
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 8, "output_tokens": 1},
    }
    assert runtime.message_calls == [
        {
            "model": MODEL,
            "max_tokens": 10,
            "messages": [{"role": "user", "content": "Reply with exactly OK"}],
        }
    ]


def test_run_all_requires_a_successful_smoke_before_any_document_call(tmp_path):
    root = make_corpus(tmp_path)
    runtime = FakeRuntime()

    with pytest.raises(run_bedrock.SafetyError, match="smoke"):
        run_bedrock.run_all(root, runtime, sleep=lambda _seconds: None)

    assert runtime.extract_calls == []


def test_run_all_rejects_a_success_record_from_a_different_model(tmp_path):
    root = make_corpus(tmp_path)
    (root / "runs").mkdir()
    (root / "runs" / "smoke.json").write_text(
        json.dumps(
            {
                "status": "success",
                "provider": "bedrock",
                "model": "different-model",
                "aws_region": "us-east-1",
            }
        ),
        encoding="utf-8",
    )
    runtime = FakeRuntime()

    with pytest.raises(run_bedrock.SafetyError, match="smoke configuration"):
        run_bedrock.run_all(root, runtime, sleep=lambda _seconds: None)

    assert runtime.extract_calls == []
