"""Unit tests for the sanitized PE1 local extractor evidence capture."""

import hashlib
import importlib.util
import json
import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest


SCRIPT = Path(__file__).with_name("capture-pe1-local-evidence.py")
SPEC = importlib.util.spec_from_file_location("capture_pe1_local_evidence", SCRIPT)
m = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(m)

CAPTURE_COMMIT = "c4ca7405ddc5181d9884120f3bfe364283e6964e"
READ_COMMIT = "e19f63ed9f2cf718b94b2fca040e5f229479c321"
TOOL_PATH = "scripts/capture-pe1-local-evidence.py"
VALID_TOOLING = {
    "capture_submission": {"path": TOOL_PATH, "commit": CAPTURE_COMMIT},
    "final_report_read": {"path": TOOL_PATH, "commit": READ_COMMIT},
}


class JsonResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


def test_provider_guard_rejects_bedrock():
    with pytest.raises(RuntimeError, match="ollama"):
        m.require_local_provider({"LLM_PROVIDER": "bedrock"})


def test_provider_guard_rejects_wrong_ollama_model():
    with pytest.raises(RuntimeError, match="llama3.2:3b"):
        m.require_local_provider(
            {"LLM_PROVIDER": "ollama", "OLLAMA_MODEL": "llama3.3:70b"}
        )


def test_terminal_job_requires_report_indicators_and_relationships():
    job = {
        "job_id": "12345678-job",
        "status": "complete",
        "report_id": "report-internal-1",
        "iocs_extracted": 4,
        "techniques_found": 2,
        "processing_time_s": 12.5,
    }
    report = {
        "found": True,
        "id": "report-internal-1",
        "standard_id": "report--public-1",
        "name": "pdf-upload-12345678",
        "object_count": 7,
        "indicator_count": 4,
        "relationship_count": 3,
    }
    accepted = m.validate_result(job, report)
    assert accepted == {
        "job_id": "12345678-job",
        "report_id": "report-internal-1",
        "document_reference": "pdf-upload-12345678",
        "indicator_count": 4,
        "relationship_count": 3,
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [("found", False), ("indicator_count", 0), ("relationship_count", 0)],
)
def test_terminal_result_rejects_empty_contract(field, value):
    job = {
        "job_id": "12345678-job",
        "status": "complete",
        "report_id": "r1",
        "iocs_extracted": 2,
    }
    report = {
        "found": True,
        "id": "r1",
        "standard_id": "report--1",
        "name": "pdf-upload-12345678",
        "object_count": 3,
        "indicator_count": 2,
        "relationship_count": 1,
    }
    report[field] = value
    with pytest.raises(RuntimeError, match="contrato integrado"):
        m.validate_result(job, report)


def test_terminal_result_rejects_mismatched_report():
    job = {
        "job_id": "12345678-job",
        "status": "complete",
        "report_id": "r1",
        "iocs_extracted": 2,
    }
    report = {
        "found": True,
        "id": "r2",
        "standard_id": "report--2",
        "name": "pdf-upload-12345678",
        "object_count": 3,
        "indicator_count": 2,
        "relationship_count": 1,
    }
    with pytest.raises(RuntimeError, match="contrato integrado"):
        m.validate_result(job, report)


@pytest.mark.parametrize("job_id", [None, ""])
def test_terminal_result_rejects_missing_job_identity(job_id):
    job = {
        "job_id": job_id,
        "status": "complete",
        "report_id": "r1",
        "iocs_extracted": 2,
    }
    report = {
        "found": True,
        "id": "r1",
        "standard_id": "report--1",
        "name": "pdf-upload-12345678",
        "object_count": 3,
        "indicator_count": 2,
        "relationship_count": 1,
    }

    with pytest.raises(RuntimeError, match="identidad"):
        m.validate_result(job, report)


@pytest.mark.parametrize("name", [None, "pdf-upload-different", "source.pdf"])
def test_terminal_result_rejects_missing_or_mismatched_document_reference(name):
    job = {
        "job_id": "12345678-job",
        "status": "complete",
        "report_id": "r1",
        "iocs_extracted": 2,
    }
    report = {
        "found": True,
        "id": "r1",
        "standard_id": "report--1",
        "name": name,
        "object_count": 3,
        "indicator_count": 2,
        "relationship_count": 1,
    }

    with pytest.raises(RuntimeError, match="referencia documental"):
        m.validate_result(job, report)


@pytest.mark.parametrize(
    "tooling",
    [
        {},
        {
            **VALID_TOOLING,
            "capture_submission": {
                "path": "scripts/another-capture.py",
                "commit": CAPTURE_COMMIT,
            },
        },
        {
            **VALID_TOOLING,
            "final_report_read": {"path": TOOL_PATH, "commit": "e19f63e"},
        },
        {**VALID_TOOLING, "unexpected_stage": VALID_TOOLING["final_report_read"]},
    ],
)
def test_tooling_provenance_rejects_non_allowlisted_or_ambiguous_values(tooling):
    with pytest.raises(RuntimeError, match="procedencia"):
        m.validate_tooling_provenance(tooling)


def test_tool_revision_accepts_blob_matching_loaded_source():
    source = SCRIPT.read_text(encoding="utf-8")
    results = [
        subprocess.CompletedProcess([], 0, "", ""),
        subprocess.CompletedProcess([], 0, CAPTURE_COMMIT + "\n", ""),
        subprocess.CompletedProcess([], 0, source, ""),
    ]
    with patch.object(m, "_run", side_effect=results) as run:
        assert m.tool_revision() == CAPTURE_COMMIT
    assert [call.args[0] for call in run.call_args_list] == [
        [
            "git",
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            TOOL_PATH,
        ],
        ["git", "log", "-1", "--format=%H", "--", TOOL_PATH],
        ["git", "show", f"{CAPTURE_COMMIT}:{TOOL_PATH}"],
    ]


def test_tool_revision_rejects_blob_different_from_loaded_source():
    source = SCRIPT.read_text(encoding="utf-8")
    changed_source = source.replace(
        "safe_name = pdf.name.replace",
        'safe_name = "different.pdf".replace',
        1,
    )
    assert changed_source != source
    results = [
        subprocess.CompletedProcess([], 0, "", ""),
        subprocess.CompletedProcess([], 0, READ_COMMIT + "\n", ""),
        subprocess.CompletedProcess([], 0, changed_source, ""),
    ]
    with (
        patch.object(m, "_run", side_effect=results),
        pytest.raises(RuntimeError, match="cargado"),
    ):
        m.tool_revision()


def _replace_top_level_line(source, prefix, replacement):
    lines = source.splitlines(keepends=True)
    matches = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    assert len(matches) == 1
    index = matches[0]
    newline = "\n" if lines[index].endswith("\n") else ""
    lines[index] = replacement + newline
    return "".join(lines)


@pytest.mark.parametrize(
    ("probe", "candidate_source"),
    [
        (
            "urllib import rebinding",
            lambda source: source.replace(
                "import urllib.request",
                "import urllib.parse as urllib",
                1,
            ),
        ),
        (
            "loaded fingerprint bootstrap forgery",
            lambda source: _replace_top_level_line(
                source,
                "LOADED_TOOL_FINGERPRINT = ",
                'LOADED_TOOL_FINGERPRINT = "forged"',
            ),
        ),
        (
            "main guard action",
            lambda source: source.replace(
                "raise SystemExit(main())",
                "raise SystemExit(0)",
                1,
            ),
        ),
        (
            "conditional report reader override",
            lambda source: source.replace(
                "\n'''\n\n\ndef _run",
                "\n'''; globals()[\"REPORT_READ_SCRIPT\"] = "
                "(\"override\" if sys.version_info else REPORT_READ_SCRIPT)\n\n\ndef _run",
                1,
            ),
        ),
    ],
)
def test_source_fingerprint_covers_complete_module_semantics(
    probe,
    candidate_source,
):
    source = SCRIPT.read_text(encoding="utf-8")
    candidate = candidate_source(source)
    assert candidate != source, probe
    assert (
        m.source_tool_fingerprint(candidate, m.main.__code__.co_filename)
        != m.LOADED_TOOL_FINGERPRINT
    ), probe


@pytest.mark.parametrize(
    "candidate_source",
    [
        lambda source: source.replace(
            "REPORT_READ_SCRIPT = r'''",
            "MISSING_REPORT_READ_SCRIPT = r'''",
            1,
        ),
        lambda source: source.replace(
            "REPORT_READ_SCRIPT = r'''",
            "REPORT_READ_SCRIPT = 7\nIGNORED_REPORT_READ_SCRIPT = r'''",
            1,
        ),
    ],
)
def test_source_fingerprint_covers_missing_or_malformed_report_reader(
    candidate_source,
):
    source = candidate_source(SCRIPT.read_text(encoding="utf-8"))
    assert (
        m.source_tool_fingerprint(source, m.main.__code__.co_filename)
        != m.LOADED_TOOL_FINGERPRINT
    )


def test_sanitized_evidence_omits_tokens_and_ioc_values(tmp_path):
    sample = tmp_path / "sample.pdf"
    sample.write_bytes(b"known PDF bytes\n")
    evidence = m.build_evidence(
        captured_at="2026-08-27T09:00:00Z",
        target="local-gpu",
        provider={"LLM_PROVIDER": "ollama", "OLLAMA_MODEL": "llama3.2:3b"},
        source_path=sample,
        job={
            "job_id": "12345678-job",
            "status": "complete",
            "report_id": "r1",
            "iocs_extracted": 2,
            "techniques_found": 1,
            "processing_time_s": 8.0,
            "ioc_values": ["198.51.100.10"],
        },
        report={
            "found": True,
            "id": "r1",
            "standard_id": "report--1",
            "name": "pdf-upload-12345678",
            "object_count": 4,
            "indicator_count": 2,
            "relationship_count": 1,
            "OPENCTI_TOKEN": "must-not-escape",
        },
        tooling=VALID_TOOLING,
    )
    encoded = json.dumps(evidence)
    assert evidence == {
        "schema": "pe1-local-extractor-evidence/v2",
        "captured_at": "2026-08-27T09:00:00Z",
        "target": "local-gpu",
        "provider": {"name": "ollama", "model": "llama3.2:3b"},
        "source": {
            "path": sample.as_posix(),
            "sha256": "ddfefd896908abc48680899445a752032b671fd0e62257318ac4910e3d2db5bd",
        },
        "job": {
            "job_id": "12345678-job",
            "status": "complete",
            "report_id": "r1",
            "iocs_extracted": 2,
            "techniques_found": 1,
            "processing_time_s": 8.0,
        },
        "opencti": {
            "report_found": True,
            "report_id": "r1",
            "standard_id": "report--1",
            "document_reference": "pdf-upload-12345678",
            "object_count": 4,
            "indicator_count": 2,
            "relationship_count": 1,
        },
        "tooling": VALID_TOOLING,
    }
    assert "OPENCTI_TOKEN" not in encoded
    assert "Authorization" not in encoded
    assert "198.51.100.10" not in encoded
    assert evidence["source"]["sha256"] == hashlib.sha256(sample.read_bytes()).hexdigest()


def test_compose_command_uses_target_script_without_shell():
    completed = subprocess.CompletedProcess(
        [], 0, "docker compose -f docker-compose.yml --profile extractor\n", ""
    )
    with patch.object(m.subprocess, "run", return_value=completed) as run:
        command = m.compose_command("local-gpu")
    assert command == [
        "docker",
        "compose",
        "-f",
        "docker-compose.yml",
        "--profile",
        "extractor",
    ]
    run.assert_called_once_with(
        ["./scripts/compose-target.sh", "local-gpu"],
        check=True,
        capture_output=True,
        text=True,
    )


def test_effective_provider_returns_only_guarded_values():
    compose = ["docker", "compose", "-f", "docker-compose.yml"]
    results = [
        subprocess.CompletedProcess([], 0, "container-123\n", ""),
        subprocess.CompletedProcess(
            [],
            0,
            json.dumps(
                [
                    "LLM_PROVIDER=ollama",
                    "OLLAMA_MODEL=llama3.2:3b",
                    "OPENCTI_TOKEN=secret",
                ]
            ),
            "",
        ),
    ]
    with patch.object(m.subprocess, "run", side_effect=results) as run:
        provider = m.effective_provider(compose)
    assert provider == {"LLM_PROVIDER": "ollama", "OLLAMA_MODEL": "llama3.2:3b"}
    assert run.call_args_list[0].args[0] == compose + ["ps", "-q", "intel-extractor"]
    assert run.call_args_list[1].args[0] == [
        "docker",
        "inspect",
        "container-123",
        "--format",
        "{{json .Config.Env}}",
    ]


def test_submit_pdf_requires_nonempty_job_id(tmp_path):
    pdf = tmp_path / "source.pdf"
    pdf.write_bytes(b"pdf")
    with patch.object(m.urllib.request, "urlopen", return_value=JsonResponse({"status": "queued"})):
        with pytest.raises(RuntimeError, match="job_id"):
            m.submit_pdf("http://127.0.0.1:8004", pdf)


def test_poll_job_returns_complete_terminal_payload():
    replies = [
        JsonResponse({"job_id": "j1", "status": "queued"}),
        JsonResponse({"job_id": "j1", "status": "processing"}),
        JsonResponse({"job_id": "j1", "status": "complete", "report_id": "r1"}),
    ]
    with (
        patch.object(m.urllib.request, "urlopen", side_effect=replies),
        patch.object(m.time, "sleep"),
    ):
        result = m.poll_job("http://127.0.0.1:8004", "j1", 30, interval_s=0)
    assert result == {
        "job_id": "j1",
        "status": "complete",
        "report_id": "r1",
    }


def test_poll_job_rejects_unknown_status():
    with patch.object(
        m.urllib.request,
        "urlopen",
        return_value=JsonResponse({"job_id": "j1", "status": "mystery"}),
    ):
        with pytest.raises(RuntimeError, match="estado desconocido"):
            m.poll_job("http://127.0.0.1:8004", "j1", 30, interval_s=0)


def test_poll_job_sanitizes_failed_message():
    failure = {
        "job_id": "j1",
        "status": "failed",
        "error": (
            '{"AWS_SESSION_TOKEN":"session-secret",'
            '"Authorization":"Bearer top-secret",'
            '"candidate":"198.51.100.42"}'
        ),
    }
    with patch.object(m.urllib.request, "urlopen", return_value=JsonResponse(failure)):
        with pytest.raises(RuntimeError) as exc_info:
            m.poll_job("http://127.0.0.1:8004", "j1", 30, interval_s=0)
    message = str(exc_info.value)
    assert "job fallido" in message
    assert "top-secret" not in message
    assert "session-secret" not in message
    assert "198.51.100.42" not in message


def test_poll_job_rejects_mismatched_job_id():
    with patch.object(
        m.urllib.request,
        "urlopen",
        return_value=JsonResponse(
            {"job_id": "different", "status": "complete", "report_id": "r1"}
        ),
    ):
        with pytest.raises(RuntimeError, match="identidad"):
            m.poll_job("http://127.0.0.1:8004", "expected", 30, interval_s=0)


def test_read_report_runs_inside_extractor_and_parses_json():
    compose = ["docker", "compose", "-f", "docker-compose.yml"]
    payload = {
        "found": True,
        "id": "r1",
        "standard_id": "report--1",
        "name": "source",
        "object_count": 4,
        "indicator_count": 2,
        "relationship_count": 1,
    }
    completed = subprocess.CompletedProcess([], 0, json.dumps(payload), "")
    with patch.object(m.subprocess, "run", return_value=completed) as run:
        assert m.read_report(compose, "r1") == payload
    assert run.call_args.args[0] == compose + [
        "exec",
        "-T",
        "intel-extractor",
        "python3",
        "-c",
        m.REPORT_READ_SCRIPT,
        "r1",
    ]


def test_embedded_report_reader_counts_only_matching_indicates(monkeypatch, capsys):
    class Relationships:
        def list(self, *, fromId, toId, relationship_type, first):
            assert fromId == "indicator-id"
            assert toId == "attack-id"
            assert relationship_type == "indicates"
            assert first == 10
            return [
                {
                    "id": "good",
                    "standard_id": "relationship--good",
                    "relationship_type": "indicates",
                    "from": {"id": "indicator-id"},
                    "to": {"id": "attack-id"},
                },
                {
                    "id": "wrong-type",
                    "relationship_type": "uses",
                    "from": {"id": "indicator-id"},
                    "to": {"id": "attack-id"},
                },
                {
                    "id": "wrong-endpoint",
                    "relationship_type": "indicates",
                    "from": {"id": "another-indicator"},
                    "to": {"id": "attack-id"},
                },
            ]

    class Client:
        def __init__(self, *_args, **_kwargs):
            self.report = types.SimpleNamespace(read=self.read_report)
            self.stix_core_relationship = Relationships()

        @staticmethod
        def read_report(*, id):
            assert id == "report-id"
            return {
                "id": "report-id",
                "standard_id": "report--1",
                "name": "pdf-upload-job",
                "objects": [
                    {
                        "id": "indicator-id",
                        "entity_type": "Indicator",
                        "standard_id": "indicator--1",
                    },
                    {
                        "id": "attack-id",
                        "entity_type": "Attack-Pattern",
                        "standard_id": "attack-pattern--1",
                    },
                    {
                        "entity_type": "Indicator",
                        "standard_id": "indicator--missing-id",
                    },
                    {
                        "id": "unrelated",
                        "entity_type": "stix-core-relationship",
                        "standard_id": "relationship--unrelated",
                    },
                ],
            }

    fake_pycti = types.ModuleType("pycti")
    fake_pycti.OpenCTIApiClient = Client
    monkeypatch.setitem(sys.modules, "pycti", fake_pycti)
    monkeypatch.setenv("OPENCTI_URL", "http://opencti:8080")
    monkeypatch.setenv("OPENCTI_TOKEN", "internal-only")
    monkeypatch.setattr(sys, "argv", ["embedded", "report-id"])

    exec(m.REPORT_READ_SCRIPT, {"__name__": "__main__"})
    payload = json.loads(capsys.readouterr().out.splitlines()[-1])
    assert payload["indicator_count"] == 1
    assert payload["relationship_count"] == 1


def test_main_checks_provider_before_submit(tmp_path):
    pdf = tmp_path / "source.pdf"
    pdf.write_bytes(b"pdf")
    output = tmp_path / "evidence.json"
    with (
        patch.object(m, "compose_command", return_value=["docker", "compose"]),
        patch.object(m, "effective_provider", return_value={"LLM_PROVIDER": "bedrock"}),
        patch.object(m, "submit_pdf", side_effect=AssertionError("submission must not run")),
    ):
        result = m.main(
            [
                "--target",
                "local-gpu",
                "--pdf",
                str(pdf),
                "--output",
                str(output),
            ]
        )
    assert result != 0
    assert not output.exists()


def test_main_rejects_committed_source_different_from_loaded_source(tmp_path):
    pdf = tmp_path / "source.pdf"
    pdf.write_bytes(b"pdf")
    output = tmp_path / "evidence.json"
    current_source = SCRIPT.read_text(encoding="utf-8")
    committed_source = current_source.replace(
        "safe_name = pdf.name.replace",
        'safe_name = "different.pdf".replace',
        1,
    )
    assert committed_source != current_source

    def git_run(command):
        if command == [
            "git",
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            TOOL_PATH,
        ]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command == ["git", "log", "-1", "--format=%H", "--", TOOL_PATH]:
            return subprocess.CompletedProcess(command, 0, READ_COMMIT + "\n", "")
        if command == ["git", "show", f"{READ_COMMIT}:{TOOL_PATH}"]:
            return subprocess.CompletedProcess(command, 0, committed_source, "")
        raise AssertionError(f"unexpected command: {command}")

    with (
        patch.object(m, "compose_command", return_value=["docker", "compose"]),
        patch.object(
            m,
            "effective_provider",
            return_value={
                "LLM_PROVIDER": "ollama",
                "OLLAMA_MODEL": "llama3.2:3b",
            },
        ),
        patch.object(m, "_run", side_effect=git_run),
        patch.object(m, "submit_pdf", return_value="j1") as submit,
        patch.object(
            m,
            "poll_job",
            return_value={
                "job_id": "j1",
                "status": "complete",
                "report_id": "r1",
                "iocs_extracted": 2,
                "techniques_found": 1,
                "processing_time_s": 8.0,
            },
        ),
        patch.object(
            m,
            "read_report",
            return_value={
                "found": True,
                "id": "r1",
                "standard_id": "report--1",
                "name": "pdf-upload-j1",
                "object_count": 4,
                "indicator_count": 2,
                "relationship_count": 1,
            },
        ),
    ):
        result = m.main(
            [
                "--target",
                "local-gpu",
                "--pdf",
                str(pdf),
                "--output",
                str(output),
            ]
        )
    assert result != 0
    submit.assert_not_called()
    assert not output.exists()


def test_main_rejects_revision_change_before_report_read(tmp_path):
    pdf = tmp_path / "source.pdf"
    pdf.write_bytes(b"pdf")
    output = tmp_path / "evidence.json"
    job = {
        "job_id": "j1",
        "status": "complete",
        "report_id": "r1",
        "iocs_extracted": 2,
        "techniques_found": 1,
        "processing_time_s": 8.0,
    }
    with (
        patch.object(m, "compose_command", return_value=["docker", "compose"]),
        patch.object(
            m,
            "effective_provider",
            return_value={
                "LLM_PROVIDER": "ollama",
                "OLLAMA_MODEL": "llama3.2:3b",
            },
        ),
        patch.object(m, "submit_pdf", return_value="j1"),
        patch.object(m, "poll_job", return_value=job),
        patch.object(m, "read_report") as read_report,
        patch.object(m, "tool_revision", side_effect=[CAPTURE_COMMIT, READ_COMMIT]),
    ):
        result = m.main(
            [
                "--target",
                "local-gpu",
                "--pdf",
                str(pdf),
                "--output",
                str(output),
            ]
        )
    assert result != 0
    read_report.assert_not_called()
    assert not output.exists()


def test_main_rejects_revision_change_during_report_read(tmp_path):
    pdf = tmp_path / "source.pdf"
    pdf.write_bytes(b"pdf")
    output = tmp_path / "evidence.json"
    job = {
        "job_id": "j1",
        "status": "complete",
        "report_id": "r1",
        "iocs_extracted": 2,
        "techniques_found": 1,
        "processing_time_s": 8.0,
    }
    report = {
        "found": True,
        "id": "r1",
        "standard_id": "report--1",
        "name": "pdf-upload-j1",
        "object_count": 4,
        "indicator_count": 2,
        "relationship_count": 1,
    }
    with (
        patch.object(m, "compose_command", return_value=["docker", "compose"]),
        patch.object(
            m,
            "effective_provider",
            return_value={
                "LLM_PROVIDER": "ollama",
                "OLLAMA_MODEL": "llama3.2:3b",
            },
        ),
        patch.object(m, "submit_pdf", return_value="j1"),
        patch.object(m, "poll_job", return_value=job),
        patch.object(m, "read_report", return_value=report) as read_report,
        patch.object(
            m,
            "tool_revision",
            side_effect=[CAPTURE_COMMIT, CAPTURE_COMMIT, READ_COMMIT],
        ),
    ):
        result = m.main(
            [
                "--target",
                "local-gpu",
                "--pdf",
                str(pdf),
                "--output",
                str(output),
            ]
        )
    assert result != 0
    read_report.assert_called_once_with(["docker", "compose"], "r1")
    assert not output.exists()


def test_main_pins_revision_across_submission_and_report_read(tmp_path):
    pdf = tmp_path / "source.pdf"
    pdf.write_bytes(b"pdf")
    output = tmp_path / "evidence.json"
    job = {
        "job_id": "j1",
        "status": "complete",
        "report_id": "r1",
        "iocs_extracted": 2,
        "techniques_found": 1,
        "processing_time_s": 8.0,
    }
    report = {
        "found": True,
        "id": "r1",
        "standard_id": "report--1",
        "name": "pdf-upload-j1",
        "object_count": 4,
        "indicator_count": 2,
        "relationship_count": 1,
    }
    with (
        patch.object(m, "compose_command", return_value=["docker", "compose"]),
        patch.object(
            m,
            "effective_provider",
            return_value={
                "LLM_PROVIDER": "ollama",
                "OLLAMA_MODEL": "llama3.2:3b",
            },
        ),
        patch.object(m, "submit_pdf", return_value="j1") as submit,
        patch.object(m, "poll_job", return_value=job) as poll,
        patch.object(m, "read_report", return_value=report),
        patch.object(
            m,
            "tool_revision",
            side_effect=[CAPTURE_COMMIT, CAPTURE_COMMIT, CAPTURE_COMMIT],
        ),
    ):
        result = m.main(
            [
                "--target",
                "local-gpu",
                "--pdf",
                str(pdf),
                "--output",
                str(output),
            ]
        )
    assert result == 0
    assert output.exists()
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert evidence["job"]["job_id"] == "j1"
    assert evidence["opencti"]["document_reference"] == "pdf-upload-j1"
    assert evidence["tooling"] == {
        "capture_submission": {"path": TOOL_PATH, "commit": CAPTURE_COMMIT},
        "final_report_read": {"path": TOOL_PATH, "commit": CAPTURE_COMMIT},
    }
    submit.assert_called_once_with(m.ENDPOINT, pdf)
    poll.assert_called_once_with(m.ENDPOINT, "j1", 1800)


def test_cli_has_no_existing_job_bypass():
    option_strings = {
        option
        for action in m._parser()._actions
        for option in action.option_strings
    }
    assert "--existing-job-id" not in option_strings
