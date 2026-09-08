#!/usr/bin/env python3
"""Runtime harness executed inside the pinned OpenCTI worker image."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
from pycti import OpenCTIApiClient, OpenCTIConnectorHelper


CONNECTOR_ID = "88888888-8888-4888-8888-888888888888"


def api_client() -> OpenCTIApiClient:
    return OpenCTIApiClient(
        os.environ["OPENCTI_URL"],
        os.environ["OPENCTI_TOKEN"],
        log_level="error",
        perform_health_check=True,
    )


def connector_helper() -> OpenCTIConnectorHelper:
    return OpenCTIConnectorHelper(
        {
            "opencti": {
                "url": os.environ["OPENCTI_URL"],
                "token": os.environ["OPENCTI_TOKEN"],
                "ssl_verify": False,
            },
            "connector": {
                "id": CONNECTOR_ID,
                "name": "TIMEXP EXP-01 deterministic injector",
                "type": "EXTERNAL_IMPORT",
                "scope": "identity,indicator,malware,attack-pattern,relationship,report",
                "duration_period": 0,
                "run_and_terminate": True,
                "send_to_queue": True,
                "log_level": "error",
            },
        }
    )


def emit(value: Any, output: Path | None = None) -> None:
    payload = json.dumps(value, indent=2, sort_keys=True)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")
    print(payload)


def submit(fixture_path: Path, output: Path | None) -> int:
    bundle = fixture_path.read_text(encoding="utf-8")
    helper = connector_helper()
    work_id = helper.api.work.initiate_work(
        helper.connector_id, "TIMEXP EXP-01 deterministic STIX import"
    )
    chunks = helper.send_stix2_bundle(
        bundle,
        work_id=work_id,
        no_split=True,
        update=True,
        bypass_validation=True,
    )
    helper.api.work.to_processed(work_id, "EXP-01 bundle submitted to queue")
    emit(
        {
            "bundle_sha256": hashlib.sha256(bundle.encode("utf-8")).hexdigest(),
            "connector_id": helper.connector_id,
            "queued_chunk_count": len(chunks),
            "work_id": work_id,
        },
        output,
    )
    return 0


def get_work(work_id: str, output: Path | None) -> int:
    work = api_client().work.get_work(work_id)
    emit(work, output)
    return 0


def wait_work(work_id: str, timeout: int, output: Path | None) -> int:
    api = api_client()
    deadline = time.monotonic() + timeout
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        last = api.work.get_work(work_id)
        if last and (last.get("status") == "complete" or last.get("errors")):
            emit(last, output)
            return 0 if last.get("status") == "complete" and not last.get("errors") else 2
        time.sleep(1)
    emit({"status": "timeout", "last_work_state": last}, output)
    return 3


def snapshot(oracle_path: Path, output: Path) -> int:
    oracle = json.loads(oracle_path.read_text(encoding="utf-8"))
    expected_ids = sorted(oracle["external_references"])
    expected_external_ids = set(oracle["external_references"].values())
    api = api_client()
    entities = api.opencti_stix_object_or_stix_relationship.list(
        search="TIMEXP-EXP01",
        first=1000,
        getAll=True,
    )
    entities = [
        entity
        for entity in entities
        if any(
            reference.get("source_name") == "TIMEXP-EXP01"
            and reference.get("external_id") in expected_external_ids
            for reference in entity.get("externalReferences", [])
        )
    ]
    objects = [api.get_stix_content(entity["id"]) for entity in entities]
    emit(
        {
            "type": "bundle",
            "id": "bundle--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "objects": objects,
            "query": {
                "expected_external_ids": sorted(expected_external_ids),
                "expected_original_standard_ids": expected_ids,
            },
        },
        output,
    )
    return 0


def read_queue(queue_name: str) -> dict[str, Any]:
    base_url = os.environ["RABBITMQ_MANAGEMENT_URL"].rstrip("/")
    url = f"{base_url}/api/queues/{quote('/', safe='')}/{quote(queue_name, safe='')}"
    response = requests.get(
        url,
        auth=(os.environ["RABBITMQ_USER"], os.environ["RABBITMQ_PASSWORD"]),
        timeout=15,
    )
    response.raise_for_status()
    queue = response.json()
    return {
        "consumers": queue["consumers"],
        "messages": queue["messages"],
        "messages_ready": queue["messages_ready"],
        "messages_unacknowledged": queue["messages_unacknowledged"],
        "name": queue["name"],
    }


def queue_status(queue_name: str, output: Path) -> int:
    emit(read_queue(queue_name), output)
    return 0


def wait_queue(
    queue_name: str,
    messages_ready: int,
    min_consumers: int,
    timeout: int,
    poll_interval: float,
    output: Path,
) -> int:
    started = time.monotonic()
    deadline = started + timeout
    observation_count = 0
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        last = read_queue(queue_name)
        observation_count += 1
        if (
            last["messages_ready"] == messages_ready
            and last["messages_unacknowledged"] == 0
            and last["consumers"] >= min_consumers
        ):
            emit(
                {
                    **last,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "expected_messages_ready": messages_ready,
                    "minimum_consumers": min_consumers,
                    "observation_count": observation_count,
                    "status": "converged",
                },
                output,
            )
            return 0
        time.sleep(poll_interval)
    emit(
        {
            **(last or {"name": queue_name}),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "expected_messages_ready": messages_ready,
            "minimum_consumers": min_consumers,
            "observation_count": observation_count,
            "status": "timeout",
        },
        output,
    )
    return 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    submit_parser = commands.add_parser("submit")
    submit_parser.add_argument("--fixture", type=Path, required=True)
    submit_parser.add_argument("--output", type=Path)

    work_parser = commands.add_parser("work")
    work_parser.add_argument("--work-id", required=True)
    work_parser.add_argument("--output", type=Path)

    wait_parser = commands.add_parser("wait")
    wait_parser.add_argument("--work-id", required=True)
    wait_parser.add_argument("--timeout", type=int, default=300)
    wait_parser.add_argument("--output", type=Path)

    snapshot_parser = commands.add_parser("snapshot")
    snapshot_parser.add_argument("--oracle", type=Path, required=True)
    snapshot_parser.add_argument("--output", type=Path, required=True)
    queue_parser = commands.add_parser("queue")
    queue_parser.add_argument("--name", required=True)
    queue_parser.add_argument("--output", type=Path, required=True)
    queue_wait_parser = commands.add_parser("queue-wait")
    queue_wait_parser.add_argument("--name", required=True)
    queue_wait_parser.add_argument("--messages-ready", type=int, required=True)
    queue_wait_parser.add_argument("--min-consumers", type=int, default=0)
    queue_wait_parser.add_argument("--timeout", type=int, default=30)
    queue_wait_parser.add_argument("--poll-interval", type=float, default=1.0)
    queue_wait_parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "submit":
            return submit(args.fixture, args.output)
        if args.command == "work":
            return get_work(args.work_id, args.output)
        if args.command == "wait":
            return wait_work(args.work_id, args.timeout, args.output)
        if args.command == "snapshot":
            return snapshot(args.oracle, args.output)
        if args.command == "queue":
            return queue_status(args.name, args.output)
        if args.command == "queue-wait":
            return wait_queue(
                args.name,
                args.messages_ready,
                args.min_consumers,
                args.timeout,
                args.poll_interval,
                args.output,
            )
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
