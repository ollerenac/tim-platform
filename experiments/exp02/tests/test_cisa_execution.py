"""Pre-run sealing and fail-closed verification contracts."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from exp02.cisa_execution import ExecutionIntegrityError, finalize_execution, verify_execution, write_pilot
from exp02.cisa_runner import SafetyError, run_all, run_once, run_smoke
from exp02.cisa_score import score_experiment, write_score_artifacts
from test_cisa_runner import FakeRuntime, make_evidence


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_finalize_v3_is_write_once_preserves_v2_and_binds_no_human_design(tmp_path):
    """Reusing v2 paths would overwrite history or certify the superseded human protocol."""
    evidence = make_evidence(tmp_path)
    legacy_freeze = evidence.root / "freeze.v1.json"
    legacy_manifest = evidence.root / "execution-manifest.v2.json"
    legacy_freeze.write_text('{"historical":"v2"}', encoding="utf-8")
    legacy_manifest.write_text('{"historical":"v2"}', encoding="utf-8")

    manifest = finalize_execution(evidence.root, FakeRuntime())
    freeze = json.loads((evidence.root / "freeze.v3.json").read_text(encoding="utf-8"))

    assert manifest["schema_version"] == 3
    assert manifest["freeze_sha256"] == _sha(evidence.root / "freeze.v3.json")
    assert (evidence.root / "freeze.v3.sha256").read_text(encoding="utf-8").strip().endswith("freeze.v3.json")
    assert freeze["design"]["human_gates"] == []
    assert freeze["design"]["primary_metric"] == "structural_cosine"
    assert len(freeze["design"]["spec_sha256"]) == 64
    assert "thresholds" not in freeze
    assert legacy_freeze.read_text(encoding="utf-8") == '{"historical":"v2"}'
    assert legacy_manifest.read_text(encoding="utf-8") == '{"historical":"v2"}'
    with pytest.raises(FileExistsError):
        finalize_execution(evidence.root, FakeRuntime())


def test_pilot_isolated_from_runs_and_binds_all_four_historical_source_hashes(tmp_path):
    """A comparator diagnostic must not become untracked final-run evidence."""
    evidence = make_evidence(tmp_path)
    pilot = write_pilot(evidence.root)

    assert [row["code"] for row in pilot["documents"]] == [
        "AA25-203A", "AA25-239A", "AA26-097A", "AA26-204A",
    ]
    assert all(len(row["stix_sha256"]) == 64 and len(row["output_sha256"]) == 64 for row in pilot["documents"])
    assert not (evidence.root / "runs").exists()
    assert pilot["historical_metadata_untrusted"] is True


def test_finalize_rejects_any_existing_attempt_or_final_record(tmp_path):
    """A seal must precede, rather than silently bless, attempted execution."""
    evidence = make_evidence(tmp_path)
    attempts = evidence.root / "attempts"
    attempts.mkdir()
    (attempts / "AA26-222A.run-1.attempt-1.json").write_text("{}", encoding="utf-8")

    with pytest.raises(FileExistsError, match="execution artifacts"):
        finalize_execution(evidence.root, FakeRuntime())


def test_pre_run_verification_fails_closed_when_frozen_input_drifts(tmp_path):
    """Changing text after sealing must stop execution before any runtime call."""
    evidence = make_evidence(tmp_path)
    finalize_execution(evidence.root, FakeRuntime())
    write_pilot(evidence.root)
    assert verify_execution(evidence.root, stage="pre-run")["stage"] == "pre-run"
    (evidence.root / "documents" / "AA26-222A" / "input.txt").write_text("drift", encoding="utf-8")

    with pytest.raises(ExecutionIntegrityError, match="drift"):
        verify_execution(evidence.root, stage="pre-run")


def test_finalize_rejects_selection_bound_pdf_or_stix_drift(tmp_path):
    """A changed official PDF/STIX pair must not be blessed by a new freeze."""
    evidence = make_evidence(tmp_path)
    (evidence.root.parent / "cisa-intake" / "AA26-222A" / "document.pdf").write_bytes(b"changed")

    with pytest.raises(ExecutionIntegrityError, match="PDF, STIX, or text"):
        finalize_execution(evidence.root, FakeRuntime())


def test_finalize_uses_sibling_intake_paths_and_rejects_their_drift(tmp_path):
    """Selection source paths are package-relative, not children of cisa-evidence."""
    evidence = make_evidence(tmp_path)
    finalize_execution(evidence.root, FakeRuntime())
    frozen = json.loads((evidence.root / "freeze.v3.json").read_text(encoding="utf-8"))
    assert frozen["documents"][0]["pdf_sha256"]


def test_finalize_rejects_traversal_in_package_relative_source_path(tmp_path):
    """A selection may not escape the package root through a source path."""
    evidence = make_evidence(tmp_path)
    path = evidence.root / "selection-manifest.v1.json"
    selection = json.loads(path.read_text(encoding="utf-8"))
    selection["documents"][0]["source_pdf_path"] = "../outside.pdf"
    path.write_text(json.dumps(selection), encoding="utf-8")

    with pytest.raises(ExecutionIntegrityError, match="safe relative"):
        finalize_execution(evidence.root, FakeRuntime())


def test_complete_verification_rejects_error_or_extra_final_identity(tmp_path):
    """An error-shaped or unknown final file must never be counted as a completed run."""
    evidence = make_evidence(tmp_path)
    finalize_execution(evidence.root, FakeRuntime())
    write_pilot(evidence.root)
    runs = evidence.root / "runs"
    runs.mkdir()
    (runs / "AA00-EXTRA.run-1.json").write_text(json.dumps({"status": "success"}), encoding="utf-8")

    with pytest.raises(ExecutionIntegrityError, match="unexpected final"):
        verify_execution(evidence.root, stage="complete")


def test_schema_v2_retries_preserve_failed_attempt_then_create_success_identity(tmp_path):
    """Treating a failed response as a run identity would hide a missing model extraction."""
    class FlakyRuntime(FakeRuntime):
        def __init__(self):
            super().__init__()
            self.fail = True

        def extract_from_text(self, *args, **kwargs):
            if self.fail:
                raise RuntimeError("temporary transport failure")
            return super().extract_from_text(*args, **kwargs)

    evidence = make_evidence(tmp_path)
    runtime = FlakyRuntime()
    finalize_execution(evidence.root, runtime)
    failed = run_once(evidence.root, "AA26-222A", 1, runtime)
    assert failed["status"] == "error"
    assert not (evidence.root / "runs" / "AA26-222A.run-1.json").exists()
    assert (evidence.root / "attempts" / "AA26-222A.run-1.attempt-1.json").is_file()

    runtime.fail = False
    succeeded = run_once(evidence.root, "AA26-222A", 1, runtime)
    assert succeeded["status"] == "success"
    final = json.loads((evidence.root / "runs" / "AA26-222A.run-1.json").read_text(encoding="utf-8"))
    assert final["attempt_record"] == "AA26-222A.run-1.attempt-2.json"


def test_schema_v2_missing_tim_field_is_attempt_error_without_final_identity(tmp_path):
    """A missing TIM field must not consume a successful canonical run identity."""
    result = FakeRuntime().result.copy()
    result.pop("accepted_iocs")
    evidence = make_evidence(tmp_path)
    finalize_execution(evidence.root, FakeRuntime())

    attempt = run_once(evidence.root, "AA26-222A", 1, FakeRuntime(result))

    assert attempt["status"] == "error"
    assert "accepted_iocs" in attempt["error"]
    assert not (evidence.root / "runs" / "AA26-222A.run-1.json").exists()


def test_schema_v2_smoke_retries_without_overwriting_failed_attempt(tmp_path):
    """A smoke retry must retain its prior transport failure instead of overwriting it."""
    class FlakySmoke(FakeRuntime):
        def __init__(self):
            super().__init__()
            self.fail = True

        def _get_anthropic_client(self):
            if self.fail:
                raise RuntimeError("temporary smoke failure")
            return super()._get_anthropic_client()

    evidence = make_evidence(tmp_path)
    runtime = FlakySmoke()
    finalize_execution(evidence.root, runtime)
    assert run_smoke(evidence.root, runtime)["status"] == "error"
    assert not (evidence.root / "runs" / "smoke.json").exists()
    runtime.fail = False
    assert run_smoke(evidence.root, runtime)["status"] == "success"
    assert (evidence.root / "attempts" / "smoke.attempt-1.json").is_file()


def test_schema_v2_run_all_validates_each_attempt_and_fails_after_one_incomplete_pass(tmp_path):
    """Skipping an error attempt as if it were final would leave the 72-run population incomplete."""
    class FailsFirst(FakeRuntime):
        def __init__(self):
            super().__init__()
            self.remaining_failures = 1

        def extract_from_text(self, *args, **kwargs):
            if self.remaining_failures:
                self.remaining_failures -= 1
                raise RuntimeError("transient")
            return super().extract_from_text(*args, **kwargs)

    evidence = make_evidence(tmp_path)
    runtime = FailsFirst()
    finalize_execution(evidence.root, runtime)
    run_smoke(evidence.root, runtime)
    with pytest.raises(SafetyError, match="missing successful final identities"):
        run_all(evidence.root, runtime, sleep=lambda _seconds: None)
    assert len(list((evidence.root / "runs").glob("*.run-*.json"))) == 71


def test_complete_verification_recomputes_v2_results_without_human_artifacts(tmp_path):
    """Requiring review CSVs after valid automatic scoring would restore a human gate."""
    evidence = make_evidence(tmp_path)
    runtime = FakeRuntime()
    finalize_execution(evidence.root, runtime)
    write_pilot(evidence.root)
    run_smoke(evidence.root, runtime)
    run_all(evidence.root, runtime, sleep=lambda _seconds: None)
    write_score_artifacts(evidence.root, score_experiment(evidence.root))

    assert not (evidence.root / "review").exists()
    assert verify_execution(evidence.root, stage="complete")["stage"] == "complete"

    (evidence.root / "results.v2.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ExecutionIntegrityError, match="results"):
        verify_execution(evidence.root, stage="complete")


def test_schema_v2_rate_limit_reconstructs_prior_attempt_starts(tmp_path):
    """Resuming after a smoke may not issue a ninth attempt in its trailing minute."""
    evidence = make_evidence(tmp_path)
    runtime = FakeRuntime()
    clock = [0.0]
    sleeps: list[float] = []

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        clock[0] += seconds

    finalize_execution(evidence.root, runtime)
    run_smoke(evidence.root, runtime, wall_time=lambda: clock[0])
    run_all(evidence.root, runtime, sleep=sleep, wall_time=lambda: clock[0])
    starts = sorted(
        json.loads(path.read_text(encoding="utf-8"))["started_at_unix"]
        for path in (evidence.root / "attempts").glob("*.attempt-*.json")
    )
    assert sleeps
    assert all(sum(start <= other < start + 60 for other in starts) <= 8 for start in starts)


def test_complete_verification_rejects_final_tampering_with_intact_attempt(tmp_path):
    """A final must be an exact immutable projection of its successful attempt."""
    evidence = make_evidence(tmp_path)
    runtime = FakeRuntime()
    finalize_execution(evidence.root, runtime)
    write_pilot(evidence.root)
    run_smoke(evidence.root, runtime)
    run_all(evidence.root, runtime, sleep=lambda _seconds: None)
    path = evidence.root / "runs" / "AA26-222A.run-1.json"
    final = json.loads(path.read_text(encoding="utf-8"))
    final["tim_output"]["campaign_summary"] = "forged"
    path.write_text(json.dumps(final), encoding="utf-8")

    with pytest.raises(ExecutionIntegrityError, match="differs from its bound attempt"):
        verify_execution(evidence.root, stage="complete")
