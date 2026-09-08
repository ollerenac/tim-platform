#!/usr/bin/env python3
"""Execute one independent, clean replication of EXP-01."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any


EXPERIMENT_DIR = Path(__file__).resolve().parent
ROOT = EXPERIMENT_DIR.parents[1]
COMPOSE_FILE = EXPERIMENT_DIR / "compose.yml"
RUNS_DIR = EXPERIMENT_DIR / "runs"
SUMMARIES_DIR = EXPERIMENT_DIR / "summaries"
CONNECTOR_QUEUE = "push_88888888-8888-4888-8888-888888888888"

NORMAL_STEPS = [
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
INTERRUPTED_STEPS = [
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


def protocol(replica: int, leave_running: bool) -> dict[str, Any]:
    return {
        "replica": replica,
        "normal_project": f"timexp_exp01_r{replica}_normal",
        "interrupted_project": f"timexp_exp01_r{replica}_interrupted",
        "normal_steps": NORMAL_STEPS,
        "interrupted_steps": INTERRUPTED_STEPS,
        "leave_running": leave_running,
    }


def run(command: list[str]) -> None:
    print(f"+ {shlex.join(command)}", file=sys.stderr, flush=True)
    subprocess.run(command, cwd=ROOT, check=True)


def compose(project: str, *arguments: str) -> None:
    run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE_FILE),
            "-p",
            project,
            *arguments,
        ]
    )


def harness(project: str, *arguments: str) -> None:
    compose(project, "run", "--rm", "harness", *arguments)


def score(project: str, observed: str, output: str) -> None:
    compose(
        project,
        "run",
        "--rm",
        "--entrypoint",
        "python",
        "harness",
        "/experiment/exp01.py",
        "score",
        "--observed",
        observed,
        "--oracle",
        "/experiment/oracle.json",
        "--output",
        output,
    )


def read_evidence(replica: int, condition: str, name: str) -> dict[str, Any]:
    path = RUNS_DIR / f"replica-{replica}" / condition / name
    return json.loads(path.read_text(encoding="utf-8"))


def duration_seconds(work: dict[str, Any]) -> float:
    start = datetime.fromisoformat(work["timestamp"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(work["completed_time"].replace("Z", "+00:00"))
    return round((end - start).total_seconds(), 3)


def logical_ids(snapshot: dict[str, Any]) -> dict[str, str]:
    result = {}
    for item in snapshot["objects"]:
        reference = next(
            ref
            for ref in item.get("external_references", [])
            if ref.get("source_name") == "TIMEXP-EXP01"
        )
        result[reference["external_id"]] = item["id"]
    return result


def summarize(replica: int, definition: dict[str, Any]) -> dict[str, Any]:
    normal_first = read_evidence(replica, "normal", "work-1-complete.json")
    normal_replay = read_evidence(replica, "normal", "work-2-replay-complete.json")
    interrupted_before = read_evidence(
        replica, "interrupted", "work-before-restart.json"
    )
    interrupted_after = read_evidence(
        replica, "interrupted", "work-after-restart-complete.json"
    )
    normal_snapshot = read_evidence(replica, "normal", "after-import-1.json")
    replay_snapshot = read_evidence(replica, "normal", "after-replay.json")
    recovered_snapshot = read_evidence(
        replica, "interrupted", "after-restart.json"
    )
    normal_score = read_evidence(replica, "normal", "score-after-import-1.json")
    replay_score = read_evidence(replica, "normal", "score-after-replay.json")
    recovered_score = read_evidence(
        replica, "interrupted", "score-after-restart.json"
    )
    queue_before = read_evidence(
        replica, "interrupted", "queue-before-restart.json"
    )
    queue_after = read_evidence(
        replica, "interrupted", "queue-after-restart.json"
    )
    baseline_normal = read_evidence(replica, "normal", "baseline.json")
    baseline_interrupted = read_evidence(
        replica, "interrupted", "baseline.json"
    )
    before_restart = read_evidence(
        replica, "interrupted", "before-restart.json"
    )

    ids_normal = logical_ids(normal_snapshot)
    ids_replay = logical_ids(replay_snapshot)
    ids_recovered = logical_ids(recovered_snapshot)
    status = "pass" if all(
        (
            normal_score["status"] == "pass",
            replay_score["status"] == "pass",
            recovered_score["status"] == "pass",
            not baseline_normal["objects"],
            not baseline_interrupted["objects"],
            not before_restart["objects"],
            interrupted_before["status"] == "progress",
            interrupted_after["status"] == "complete",
            queue_before["messages_ready"] == 1,
            queue_before["consumers"] == 0,
            queue_after["messages_ready"] == 0,
            ids_normal == ids_replay == ids_recovered,
        )
    ) else "fail"
    return {
        "replica": replica,
        "status": status,
        "projects": {
            "normal": definition["normal_project"],
            "interrupted": definition["interrupted_project"],
        },
        "baseline_object_counts": {
            "normal": len(baseline_normal["objects"]),
            "interrupted": len(baseline_interrupted["objects"]),
            "worker_stopped": len(before_restart["objects"]),
        },
        "durations_seconds": {
            "normal_import": duration_seconds(normal_first),
            "exact_replay": duration_seconds(normal_replay),
            "interrupted_including_outage": duration_seconds(interrupted_after),
        },
        "scores": {
            "normal_import": normal_score,
            "exact_replay": replay_score,
            "worker_recovery": recovered_score,
        },
        "queue_transition": {
            "before_restart": queue_before,
            "after_restart": queue_after,
        },
        "work_transition": {
            "before_restart": interrupted_before["status"],
            "after_restart": interrupted_after["status"],
        },
        "canonical_ids_stable": ids_normal == ids_replay == ids_recovered,
    }


def run_normal(replica: int, project: str) -> None:
    base = f"/runs/replica-{replica}/normal"
    compose(project, "up", "-d", "--wait", "--wait-timeout", "600")
    try:
        harness(
            project,
            "snapshot",
            "--oracle",
            "/experiment/oracle.json",
            "--output",
            f"{base}/baseline.json",
        )
        harness(
            project,
            "submit",
            "--fixture",
            "/experiment/fixture.stix.json",
            "--output",
            f"{base}/submit-1.json",
        )
        work_id = read_evidence(replica, "normal", "submit-1.json")["work_id"]
        harness(
            project,
            "wait",
            "--work-id",
            work_id,
            "--timeout",
            "300",
            "--output",
            f"{base}/work-1-complete.json",
        )
        harness(
            project,
            "snapshot",
            "--oracle",
            "/experiment/oracle.json",
            "--output",
            f"{base}/after-import-1.json",
        )
        score(project, f"{base}/after-import-1.json", f"{base}/score-after-import-1.json")

        harness(
            project,
            "submit",
            "--fixture",
            "/experiment/fixture.stix.json",
            "--output",
            f"{base}/submit-2-replay.json",
        )
        replay_id = read_evidence(replica, "normal", "submit-2-replay.json")[
            "work_id"
        ]
        harness(
            project,
            "wait",
            "--work-id",
            replay_id,
            "--timeout",
            "300",
            "--output",
            f"{base}/work-2-replay-complete.json",
        )
        harness(
            project,
            "snapshot",
            "--oracle",
            "/experiment/oracle.json",
            "--output",
            f"{base}/after-replay.json",
        )
        score(project, f"{base}/after-replay.json", f"{base}/score-after-replay.json")
    finally:
        compose(project, "stop")


def run_interrupted(replica: int, project: str, leave_running: bool) -> None:
    base = f"/runs/replica-{replica}/interrupted"
    complete = False
    compose(project, "up", "-d", "--wait", "--wait-timeout", "600")
    try:
        harness(
            project,
            "snapshot",
            "--oracle",
            "/experiment/oracle.json",
            "--output",
            f"{base}/baseline.json",
        )
        compose(project, "stop", "worker")
        harness(
            project,
            "submit",
            "--fixture",
            "/experiment/fixture.stix.json",
            "--output",
            f"{base}/submit-worker-stopped.json",
        )
        work_id = read_evidence(
            replica, "interrupted", "submit-worker-stopped.json"
        )["work_id"]
        harness(
            project,
            "work",
            "--work-id",
            work_id,
            "--output",
            f"{base}/work-before-restart.json",
        )
        harness(
            project,
            "queue",
            "--name",
            CONNECTOR_QUEUE,
            "--output",
            f"{base}/queue-before-restart.json",
        )
        harness(
            project,
            "snapshot",
            "--oracle",
            "/experiment/oracle.json",
            "--output",
            f"{base}/before-restart.json",
        )
        compose(project, "start", "worker")
        harness(
            project,
            "wait",
            "--work-id",
            work_id,
            "--timeout",
            "300",
            "--output",
            f"{base}/work-after-restart-complete.json",
        )
        harness(
            project,
            "queue",
            "--name",
            CONNECTOR_QUEUE,
            "--output",
            f"{base}/queue-after-restart-immediate.json",
        )
        harness(
            project,
            "queue-wait",
            "--name",
            CONNECTOR_QUEUE,
            "--messages-ready",
            "0",
            "--min-consumers",
            "1",
            "--timeout",
            "30",
            "--output",
            f"{base}/queue-after-restart.json",
        )
        harness(
            project,
            "snapshot",
            "--oracle",
            "/experiment/oracle.json",
            "--output",
            f"{base}/after-restart.json",
        )
        score(project, f"{base}/after-restart.json", f"{base}/score-after-restart.json")
        complete = True
    finally:
        if not (leave_running and complete):
            compose(project, "stop")


def execute(replica: int, leave_running: bool) -> dict[str, Any]:
    definition = protocol(replica, leave_running)
    run_normal(replica, definition["normal_project"])
    run_interrupted(replica, definition["interrupted_project"], leave_running)
    result = summarize(replica, definition)
    SUMMARIES_DIR.mkdir(parents=True, exist_ok=True)
    output = SUMMARIES_DIR / f"replica-{replica}.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replica", type=int, required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--leave-running", action="store_true")
    args = parser.parse_args()
    if args.replica < 2:
        parser.error("replica must be 2 or greater; replica 1 is the original run")
    definition = protocol(args.replica, args.leave_running)
    if args.dry_run:
        print(json.dumps(definition, sort_keys=True))
        return 0
    result = execute(args.replica, args.leave_running)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
