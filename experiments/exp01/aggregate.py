#!/usr/bin/env python3
"""Aggregate independent EXP-01 replication summaries."""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path
from typing import Any


def describe(values: list[float]) -> dict[str, float | int]:
    result: dict[str, float | int] = {
        "n": len(values),
        "mean": round(statistics.mean(values), 3),
        "median": round(statistics.median(values), 3),
        "min": round(min(values), 3),
        "max": round(max(values), 3),
    }
    if len(values) > 1:
        result["sample_standard_deviation"] = round(statistics.stdev(values), 3)
    return result


def load_summaries(directory: Path) -> list[dict[str, Any]]:
    summaries = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(directory.glob("replica-*.json"))
    ]
    if not summaries:
        raise ValueError(f"no replica summaries found in {directory}")
    replica_ids = [summary["replica"] for summary in summaries]
    if len(replica_ids) != len(set(replica_ids)):
        raise ValueError("replica identifiers must be unique")
    return sorted(summaries, key=lambda summary: summary["replica"])


def aggregate(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    scores = [
        score
        for summary in summaries
        for score in summary["scores"].values()
    ]
    baseline_counts = [
        count
        for summary in summaries
        for count in summary["baseline_object_counts"].values()
    ]

    def queue_recovered(summary: dict[str, Any]) -> bool:
        before = summary["queue_transition"]["before_restart"]
        after = summary["queue_transition"]["after_restart"]
        work = summary["work_transition"]
        return all(
            (
                before["messages_ready"] == 1,
                before["consumers"] == 0,
                after["messages_ready"] == 0,
                after["messages_unacknowledged"] == 0,
                after["consumers"] >= 1,
                work["before_restart"] == "progress",
                work["after_restart"] == "complete",
            )
        )

    normal_times = [
        summary["durations_seconds"]["normal_import"] for summary in summaries
    ]
    replay_times = [
        summary["durations_seconds"]["exact_replay"] for summary in summaries
    ]
    automated_recovery_times = [
        summary["durations_seconds"]["interrupted_including_outage"]
        for summary in summaries
        if "timing_note" not in summary
    ]
    manual_recovery_times = [
        {
            "replica": summary["replica"],
            "seconds": summary["durations_seconds"]["interrupted_including_outage"],
            "note": summary["timing_note"],
        }
        for summary in summaries
        if "timing_note" in summary
    ]

    passed_replications = sum(summary["status"] == "pass" for summary in summaries)
    passed_scores = sum(score["status"] == "pass" for score in scores)
    empty_baselines = sum(count == 0 for count in baseline_counts)
    stable_ids = sum(summary["canonical_ids_stable"] for summary in summaries)
    recovered_queues = sum(queue_recovered(summary) for summary in summaries)
    total = len(summaries)
    overall_pass = all(
        (
            passed_replications == total,
            passed_scores == len(scores),
            empty_baselines == len(baseline_counts),
            stable_ids == total,
            recovered_queues == total,
        )
    )
    return {
        "experiment_id": "EXP-01",
        "overall_status": "pass" if overall_pass else "fail",
        "replications": {"passed": passed_replications, "total": total},
        "scored_conditions": {"passed": passed_scores, "total": len(scores)},
        "invariants": {
            "empty_baselines": {
                "passed": empty_baselines,
                "total": len(baseline_counts),
            },
            "canonical_ids_stable": {"passed": stable_ids, "total": total},
            "queue_recovery_confirmed": {
                "passed": recovered_queues,
                "total": total,
            },
        },
        "timings_seconds": {
            "normal_import": describe(normal_times),
            "exact_replay": describe(replay_times),
            "automated_worker_recovery": describe(automated_recovery_times),
            "manual_worker_recovery_observations": manual_recovery_times,
        },
        "replica_ids": [summary["replica"] for summary in summaries],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summaries", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = aggregate(load_summaries(args.summaries))
    except (KeyError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(payload, encoding="utf-8")
    print(payload, end="")
    return 0 if result["overall_status"] == "pass" else 2


if __name__ == "__main__":
    raise SystemExit(main())
