"""Contratos offline del experimento PE-1 de plataforma e integración."""

import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


MODULE_PATH = Path(__file__).parents[1] / "run_pe1.py"


def load_module():
    if not MODULE_PATH.is_file():
        pytest.fail("run_pe1.py todavía no existe")
    spec = importlib.util.spec_from_file_location("run_pe1", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def healthy_inventory():
    expected = [f"service-{number:02d}" for number in range(1, 39)]
    expected.append("connector-opencti")
    rows = {
        service: {
            "Service": service,
            "State": "running",
            "Health": "" if service == "connector-opencti" else "healthy",
        }
        for service in expected
    }
    states = {
        service: {"OOMKilled": False, "Restarting": False}
        for service in expected
    }
    return expected, rows, states


def test_inventory_accepts_39_running_services_with_38_satisfied_probes():
    module = load_module()
    expected, rows, states = healthy_inventory()

    result = module.assess_inventory(expected, rows, states)

    assert result == {
        "accepted": True,
        "expected": 39,
        "running": 39,
        "healthy": 38,
        "without_healthcheck": ["connector-opencti"],
        "issues": [],
    }


def test_inventory_rejects_oomkilled_even_when_compose_reports_running():
    module = load_module()
    expected, rows, states = healthy_inventory()
    states["service-01"]["OOMKilled"] = True

    result = module.assess_inventory(expected, rows, states)

    assert result["accepted"] is False
    assert result["issues"] == ["service-01=oom-killed"]


def test_aggregate_requires_startup_and_integration_in_all_three_repetitions():
    module = load_module()
    summaries = [
        {
            "repetition": 1,
            "startup": {"accepted": True, "duration_s": 81.25},
            "integration": {"accepted": True, "processing_time_s": 103.51},
        },
        {
            "repetition": 2,
            "startup": {"accepted": True, "duration_s": 79.75},
            "integration": {"accepted": False, "processing_time_s": 110.0},
        },
        {
            "repetition": 3,
            "startup": {"accepted": True, "duration_s": 82.0},
            "integration": {"accepted": True, "processing_time_s": 99.0},
        },
    ]

    result = module.aggregate_summaries(summaries)

    assert result["accepted"] is False
    assert result["startup_passed"] == 3
    assert result["integration_passed"] == 2
    assert result["repetitions"] == 3
    assert result["startup_mean_s"] == pytest.approx(81.0)
    assert result["integration_mean_s"] == 101.25


def test_aggregate_excludes_failed_uncompleted_conditions_from_duration_means():
    module = load_module()
    summaries = [
        {
            "repetition": 1,
            "startup": {"accepted": False, "duration_s": 200.0},
            "integration": {"accepted": False, "processing_time_s": 0.0},
        },
        {
            "repetition": 2,
            "startup": {"accepted": True, "duration_s": 80.0},
            "integration": {"accepted": True, "processing_time_s": 10.0},
        },
        {
            "repetition": 3,
            "startup": {"accepted": True, "duration_s": 100.0},
            "integration": {"accepted": True, "processing_time_s": 20.0},
        },
    ]

    result = module.aggregate_summaries(summaries)

    assert result["startup_mean_s"] == 90.0
    assert result["integration_mean_s"] == 15.0


def test_results_markdown_marks_skipped_integration_as_not_evaluable():
    module = load_module()
    results = {
        "accepted": False,
        "aggregate": {
            "startup_passed": 2,
            "integration_passed": 2,
        },
        "runs": [
            {
                "repetition": 1,
                "startup": {"accepted": False, "duration_s": 200.0},
                "integration": {"accepted": False, "processing_time_s": 0.0},
            },
            {
                "repetition": 2,
                "startup": {"accepted": True, "duration_s": 90.0},
                "integration": {
                    "accepted": True,
                    "processing_time_s": 10.0,
                    "indicator_count": 4,
                    "relationship_count": 3,
                },
            },
            {
                "repetition": 3,
                "startup": {"accepted": True, "duration_s": 95.0},
                "integration": {
                    "accepted": True,
                    "processing_time_s": 12.0,
                    "indicator_count": 4,
                    "relationship_count": 3,
                },
            },
        ],
    }

    rendered = module._results_markdown(results)

    assert "| 1 | No aprobado | 200.000 | No evaluable | — | — | — |" in rendered
    assert "Integración: 2/3 ciclos planeados y 2/2 ciclos evaluables." in rendered


def test_manifest_hashes_every_evidence_file_except_itself(tmp_path):
    module = load_module()
    (tmp_path / "PROTOCOL.md").write_text("protocol\n", encoding="utf-8")
    run_dir = tmp_path / "runs" / "rep-1"
    run_dir.mkdir(parents=True)
    (run_dir / "summary.json").write_text('{"accepted": true}\n', encoding="utf-8")
    output = tmp_path / "MANIFEST.json"

    manifest = module.build_manifest(tmp_path, output)

    expected = {
        "PROTOCOL.md": hashlib.sha256(b"protocol\n").hexdigest(),
        "runs/rep-1/summary.json": hashlib.sha256(b'{"accepted": true}\n').hexdigest(),
    }
    assert manifest == {"algorithm": "sha256", "files": expected}
    assert json.loads(output.read_text(encoding="utf-8")) == manifest


def accepted_integration(pdf_hash):
    return {
        "schema": "pe1-local-extractor-evidence/v2",
        "target": "local-gpu",
        "provider": {"name": "ollama", "model": "llama3.2:3b"},
        "source": {"path": "fixture.pdf", "sha256": pdf_hash},
        "job": {
            "job_id": "job-1",
            "status": "complete",
            "report_id": "report-1",
            "iocs_extracted": 4,
            "techniques_found": 1,
            "processing_time_s": 12.5,
        },
        "opencti": {
            "report_found": True,
            "report_id": "report-1",
            "standard_id": "report--1",
            "document_reference": "pdf-upload-job-1",
            "object_count": 5,
            "indicator_count": 4,
            "relationship_count": 3,
        },
        "tooling": {},
    }


def fake_inventory_payloads():
    expected, rows, states = healthy_inventory()
    ids = {service: f"cid-{service}" for service in expected}
    inspections = [
        {
            "Config": {"Labels": {"com.docker.compose.service": service}},
            "State": states[service],
        }
        for service in expected
    ]
    ps = "\n".join(json.dumps(rows[service]) for service in expected) + "\n"
    return expected, ids, inspections, ps


def test_run_cycle_writes_accepted_evidence_and_stops_platform(tmp_path):
    module = load_module()
    pdf = tmp_path / "fixture.pdf"
    pdf.write_bytes(b"known pdf")
    pdf_hash = hashlib.sha256(b"known pdf").hexdigest()
    expected, ids, inspections, ps = fake_inventory_payloads()
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if command == ["./scripts/bootstrap-platform.sh", "local-gpu"]:
            return SimpleNamespace(returncode=0, stdout="READY\n", stderr="")
        if command[-2:] == ["config", "--services"]:
            return SimpleNamespace(returncode=0, stdout="\n".join(expected) + "\n", stderr="")
        if command[-4:] == ["ps", "-a", "--format", "json"]:
            return SimpleNamespace(returncode=0, stdout=ps, stderr="")
        if command[-2:] == ["ps", "-q"]:
            return SimpleNamespace(returncode=0, stdout="\n".join(ids.values()) + "\n", stderr="")
        if command[:2] == ["docker", "inspect"]:
            return SimpleNamespace(returncode=0, stdout=json.dumps(inspections), stderr="")
        if "capture-pe1-local-evidence.py" in " ".join(command):
            output = Path(command[command.index("--output") + 1])
            output.write_text(json.dumps(accepted_integration(pdf_hash)), encoding="utf-8")
            return SimpleNamespace(returncode=0, stdout='{"status":"accepted"}\n', stderr="")
        if command[-1:] == ["stop"]:
            return SimpleNamespace(returncode=0, stdout="stopped\n", stderr="")
        raise AssertionError(command)

    clock_values = iter((10.0, 90.0))
    summary = module.run_cycle(
        1,
        {
            "target": "local-gpu",
            "pdf": pdf,
            "pdf_sha256": pdf_hash,
            "output_root": tmp_path,
            "compose": ["docker", "compose"],
            "capture_timeout_s": 60,
            "command_timeout_s": 120,
        },
        command_runner=runner,
        clock=lambda: next(clock_values),
    )

    assert summary["startup"]["accepted"] is True
    assert summary["startup"]["duration_s"] == 80.0
    assert summary["integration"]["accepted"] is True
    assert summary["integration"]["report_id"] == "report-1"
    assert (tmp_path / "runs/rep-1/inventory.json").is_file()
    assert (tmp_path / "runs/rep-1/summary.json").is_file()
    assert calls[-1][-1] == "stop"


def test_run_cycle_preserves_failure_and_stops_after_bootstrap_error(tmp_path):
    module = load_module()
    pdf = tmp_path / "fixture.pdf"
    pdf.write_bytes(b"known pdf")
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        if command == ["./scripts/bootstrap-platform.sh", "local-gpu"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="failed\n")
        if command[-1:] == ["stop"]:
            return SimpleNamespace(returncode=0, stdout="stopped\n", stderr="")
        raise AssertionError(command)

    clock_values = iter((1.0, 2.0))
    summary = module.run_cycle(
        1,
        {
            "target": "local-gpu",
            "pdf": pdf,
            "pdf_sha256": hashlib.sha256(b"known pdf").hexdigest(),
            "output_root": tmp_path,
            "compose": ["docker", "compose"],
            "capture_timeout_s": 60,
            "command_timeout_s": 120,
        },
        command_runner=runner,
        clock=lambda: next(clock_values),
    )

    assert summary["startup"]["accepted"] is False
    assert summary["integration"]["accepted"] is False
    assert (tmp_path / "runs/rep-1/bootstrap.log").read_text() == "failed\n"
    assert calls[-1][-1] == "stop"


@pytest.mark.parametrize(
    ("target", "repetitions", "error"),
    [
        ("aws", 3, "local-gpu"),
        ("local-gpu", 2, "tres repeticiones"),
    ],
)
def test_prepare_config_rejects_protocol_changes(tmp_path, target, repetitions, error):
    module = load_module()
    pdf = tmp_path / "fixture.pdf"
    pdf.write_bytes(b"known pdf")
    digest = hashlib.sha256(b"known pdf").hexdigest()

    with pytest.raises(module.ExperimentError, match=error):
        module.prepare_config(
            target=target,
            pdf=pdf,
            repetitions=repetitions,
            output_root=tmp_path,
            compose=["docker", "compose"],
            expected_pdf_sha256=digest,
        )


def test_prepare_config_rejects_wrong_pdf_and_existing_results(tmp_path):
    module = load_module()
    pdf = tmp_path / "fixture.pdf"
    pdf.write_bytes(b"changed pdf")

    with pytest.raises(module.ExperimentError, match="huella del PDF"):
        module.prepare_config(
            target="local-gpu",
            pdf=pdf,
            repetitions=3,
            output_root=tmp_path,
            compose=["docker", "compose"],
            expected_pdf_sha256="0" * 64,
        )

    digest = hashlib.sha256(b"changed pdf").hexdigest()
    (tmp_path / "RESULTS.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(module.ExperimentError, match="resultados previos"):
        module.prepare_config(
            target="local-gpu",
            pdf=pdf,
            repetitions=3,
            output_root=tmp_path,
            compose=["docker", "compose"],
            expected_pdf_sha256=digest,
        )


def test_verify_manifest_detects_tampered_evidence(tmp_path):
    module = load_module()
    evidence = tmp_path / "RESULTS.json"
    evidence.write_text('{"accepted": true}\n', encoding="utf-8")
    manifest_path = tmp_path / "MANIFEST.json"
    module.build_manifest(tmp_path, manifest_path)
    assert module.verify_manifest(tmp_path, manifest_path)["verified"] == 1

    evidence.write_text('{"accepted": false}\n', encoding="utf-8")
    with pytest.raises(module.ExperimentError, match="deriva"):
        module.verify_manifest(tmp_path, manifest_path)


def test_rebuild_results_uses_preserved_summaries_without_rerunning(tmp_path):
    module = load_module()
    (tmp_path / "PROTOCOL.md").write_text("protocol\n", encoding="utf-8")
    (tmp_path / "ENVIRONMENT.json").write_text("{}\n", encoding="utf-8")
    summaries = [
        {
            "repetition": 1,
            "startup": {"accepted": False, "duration_s": 200.0},
            "integration": {"accepted": False, "processing_time_s": 0.0},
        },
        {
            "repetition": 2,
            "startup": {"accepted": True, "duration_s": 80.0},
            "integration": {"accepted": True, "processing_time_s": 10.0},
        },
        {
            "repetition": 3,
            "startup": {"accepted": True, "duration_s": 100.0},
            "integration": {"accepted": True, "processing_time_s": 20.0},
        },
    ]
    for summary in summaries:
        run_dir = tmp_path / "runs" / f"rep-{summary['repetition']}"
        run_dir.mkdir(parents=True)
        (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")

    results = module.rebuild_results(tmp_path)

    assert results["aggregate"]["startup_mean_s"] == 90.0
    assert results["aggregate"]["integration_mean_s"] == 15.0
    assert results["accepted"] is False
    assert module.verify_manifest(tmp_path, tmp_path / "MANIFEST.json")["verified"] >= 5
