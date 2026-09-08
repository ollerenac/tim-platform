import json
import hashlib
import subprocess
import sys
from pathlib import Path

import yaml

from experiments.exp01 import runtime


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "experiments/exp01/exp01.py"
REPLICATE = ROOT / "experiments/exp01/replicate.py"
AGGREGATE = ROOT / "experiments/exp01/aggregate.py"
FIXTURE = ROOT / "experiments/exp01/fixture.stix.json"
ORACLE = ROOT / "experiments/exp01/oracle.json"
COMPOSE = ROOT / "experiments/exp01/compose.yml"


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_validate_fixture_reports_independent_expected_cardinalities():
    completed = run_cli(
        "validate-fixture", "--fixture", str(FIXTURE), "--oracle", str(ORACLE)
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "bundle_id": "bundle--77777777-7777-4777-8777-777777777777",
        "domain_object_count": 6,
        "external_reference_fact_count": 9,
        "object_count": 9,
        "provenance_fact_count": 17,
        "relationship_fact_count": 10,
        "relationship_object_count": 3,
        "status": "valid",
    }


def test_validate_fixture_rejects_a_missing_relationship(tmp_path: Path):
    fixture = json.loads(FIXTURE.read_text())
    fixture["objects"] = [
        item
        for item in fixture["objects"]
        if item["id"] != "relationship--55555555-5555-4555-8555-555555555553"
    ]
    mutated = tmp_path / "missing-relationship.json"
    mutated.write_text(json.dumps(fixture))

    completed = run_cli(
        "validate-fixture", "--fixture", str(mutated), "--oracle", str(ORACLE)
    )

    assert completed.returncode != 0
    assert "oracle mismatch" in completed.stderr.lower()


def test_score_accepts_an_exact_observation():
    completed = run_cli("score", "--observed", str(FIXTURE), "--oracle", str(ORACLE))

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "duplicate_object_count": 0,
        "external_reference_recall": 1.0,
        "missing_object_count": 0,
        "object_recall": 1.0,
        "provenance_recall": 1.0,
        "relationship_recall": 1.0,
        "status": "pass",
        "unexpected_object_count": 0,
    }


def test_score_can_persist_the_machine_readable_result(tmp_path: Path):
    output = tmp_path / "score.json"
    completed = run_cli(
        "score",
        "--observed",
        str(FIXTURE),
        "--oracle",
        str(ORACLE),
        "--output",
        str(output),
    )

    assert completed.returncode == 0
    assert json.loads(output.read_text()) == json.loads(completed.stdout)


def test_score_exposes_loss_and_duplicates(tmp_path: Path):
    observed = json.loads(FIXTURE.read_text())
    removed = next(
        item
        for item in observed["objects"]
        if item["id"] == "relationship--55555555-5555-4555-8555-555555555553"
    )
    observed["objects"].remove(removed)
    observed["objects"].append(observed["objects"][0].copy())
    path = tmp_path / "imperfect-observation.json"
    path.write_text(json.dumps(observed))

    completed = run_cli("score", "--observed", str(path), "--oracle", str(ORACLE))

    assert completed.returncode == 2
    result = json.loads(completed.stdout)
    assert result["status"] == "fail"
    assert result["missing_object_count"] == 1
    assert result["duplicate_object_count"] == 1
    assert result["relationship_recall"] == 0.9


def test_score_accepts_opencti_canonicalized_standard_ids(tmp_path: Path):
    observed = json.loads(FIXTURE.read_text())
    id_map = {
        item["id"]: f"{item['type']}--aaaaaaaa-aaaa-4aaa-8aaa-{index:012d}"
        for index, item in enumerate(observed["objects"], start=1)
    }
    for item in observed["objects"]:
        item["id"] = id_map[item["id"]]
        for ref_field in ("created_by_ref", "source_ref", "target_ref"):
            if ref_field in item:
                item[ref_field] = id_map[item[ref_field]]
        if "object_refs" in item:
            item["object_refs"] = [id_map[ref] for ref in item["object_refs"]]
    path = tmp_path / "canonicalized-observation.json"
    path.write_text(json.dumps(observed))

    completed = run_cli("score", "--observed", str(path), "--oracle", str(ORACLE))

    assert completed.returncode == 0, completed.stdout
    assert json.loads(completed.stdout)["status"] == "pass"


def test_compose_is_pinned_local_only_and_project_scoped():
    compose = yaml.safe_load(COMPOSE.read_text())

    assert set(compose["services"]) == {
        "elasticsearch",
        "redis",
        "rabbitmq",
        "minio",
        "opencti",
        "worker",
        "harness",
    }
    assert all("@sha256:" in service["image"] for service in compose["services"].values())
    assert compose["services"]["opencti"]["ports"] == ["127.0.0.1:18080:8080"]
    assert all(
        "ports" not in service or name == "opencti"
        for name, service in compose["services"].items()
    )
    assert all("container_name" not in service for service in compose["services"].values())
    assert all(
        "name" not in settings and "external" not in settings
        for settings in compose["volumes"].values()
    )


def test_manifest_hashes_every_evidence_file(tmp_path: Path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "result.json").write_text('{"status":"pass"}\n')
    output = tmp_path / "MANIFEST.json"

    completed = run_cli("manifest", "--root", str(evidence), "--output", str(output))

    assert completed.returncode == 0, completed.stderr
    manifest = json.loads(output.read_text())
    assert manifest == {
        "algorithm": "sha256",
        "file_count": 1,
        "files": [
            {
                "bytes": 18,
                "path": "result.json",
                "sha256": hashlib.sha256(b'{"status":"pass"}\n').hexdigest(),
            }
        ],
    }


def test_replication_dry_run_exposes_the_complete_isolated_protocol():
    completed = subprocess.run(
        [sys.executable, str(REPLICATE), "--replica", "2", "--dry-run"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    protocol = json.loads(completed.stdout)
    assert protocol["normal_project"] == "timexp_exp01_r2_normal"
    assert protocol["interrupted_project"] == "timexp_exp01_r2_interrupted"
    assert protocol["normal_steps"] == [
        "fresh-stack",
        "empty-baseline",
        "import",
        "wait-complete",
        "export-and-score",
        "exact-replay",
        "wait-complete",
        "export-and-score",
        "stop-preserve",
    ]
    assert protocol["interrupted_steps"] == [
        "fresh-stack",
        "empty-baseline",
        "stop-worker",
        "enqueue",
        "record-pending-work-queue-and-empty-graph",
        "start-worker",
        "wait-complete",
        "record-immediate-queue-sample",
        "wait-for-drained-queue",
        "export-and-score",
        "stop-preserve",
    ]


def test_queue_wait_rejects_stale_management_samples_until_queue_is_drained(
    monkeypatch, tmp_path: Path
):
    samples = iter(
        [
            {
                "consumers": 0,
                "messages": 1,
                "messages_ready": 1,
                "messages_unacknowledged": 0,
                "name": "push_exp01",
            },
            {
                "consumers": 1,
                "messages": 0,
                "messages_ready": 0,
                "messages_unacknowledged": 0,
                "name": "push_exp01",
            },
        ]
    )
    monkeypatch.setattr(runtime, "read_queue", lambda _name: next(samples))
    monkeypatch.setattr(runtime.time, "sleep", lambda _seconds: None)
    output = tmp_path / "queue.json"

    status = runtime.wait_queue(
        "push_exp01",
        messages_ready=0,
        min_consumers=1,
        timeout=5,
        poll_interval=0,
        output=output,
    )

    assert status == 0
    result = json.loads(output.read_text())
    assert result["status"] == "converged"
    assert result["observation_count"] == 2
    assert result["messages_ready"] == 0
    assert result["consumers"] == 1


def test_aggregate_reports_three_independent_passes(tmp_path: Path):
    output = tmp_path / "aggregate.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(AGGREGATE),
            "--summaries",
            str(ROOT / "experiments/exp01/summaries"),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    result = json.loads(output.read_text())
    assert result["overall_status"] == "pass"
    assert result["replications"] == {"passed": 3, "total": 3}
    assert result["scored_conditions"] == {"passed": 9, "total": 9}
    assert result["timings_seconds"]["normal_import"]["n"] == 3
    assert result["timings_seconds"]["automated_worker_recovery"]["n"] == 2
