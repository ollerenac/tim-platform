#!/usr/bin/env python3
"""Run the frozen CNSD/ColCERT evaluation through Amazon Bedrock only."""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


EXPECTED_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
EXPECTED_REGION = "us-east-1"
REVIEWED_STATUSES = {"APPROVED", "CORRECTED"}
REPETITIONS = (1, 2, 3)
MAX_CALLS_PER_MINUTE = 8


class SafetyError(RuntimeError):
    """Raised when an execution guard is not satisfied."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest(root: Path) -> dict:
    try:
        return json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError(f"cannot read frozen manifest: {exc}") from exc


def validate_preflight(root: Path, runtime) -> list[Path]:
    """Fail closed unless the approved Bedrock route and reviewed corpus exist."""
    root = Path(root)
    if getattr(runtime, "LLM_PROVIDER", None) != "bedrock":
        raise SafetyError("LLM_PROVIDER must be bedrock")
    if getattr(runtime, "BEDROCK_MODEL", None) != EXPECTED_MODEL:
        raise SafetyError("BEDROCK_MODEL does not match the frozen Haiku model")
    if getattr(runtime, "AWS_REGION", None) != EXPECTED_REGION:
        raise SafetyError("AWS_REGION must be us-east-1")
    if getattr(runtime, "ANTHROPIC_API_KEY", ""):
        raise SafetyError("direct Anthropic credentials are forbidden")

    manifest = _manifest(root)
    try:
        reference_manifest = json.loads(
            (root / "reference-manifest.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError(f"cannot read frozen reference manifest: {exc}") from exc
    reference_hashes = reference_manifest.get("documents")
    if not isinstance(reference_hashes, dict) or len(reference_hashes) != 4:
        raise SafetyError("reference manifest must contain exactly four documents")
    rows = manifest.get("documents")
    if not isinstance(rows, list) or len(rows) != 4:
        raise SafetyError("frozen manifest must contain exactly four documents")
    if manifest.get("llm_calls") != 0 or manifest.get("opencti_writes") != 0:
        raise SafetyError("capture manifest does not represent a pre-LLM corpus")

    folders: list[Path] = []
    seen: set[str] = set()
    for row in rows:
        stem = row.get("stem") if isinstance(row, dict) else None
        if not isinstance(stem, str) or not stem or stem in seen:
            raise SafetyError("manifest document stems must be present and unique")
        seen.add(stem)
        folder = root / "documents" / stem
        input_path = folder / "input.txt"
        expected_path = folder / "expected.json"
        if not input_path.is_file() or not expected_path.is_file():
            raise SafetyError(f"missing frozen input or reference for {stem}")
        if _sha256(input_path) != row.get("sha256_text"):
            raise SafetyError(f"input SHA-256 drift for {stem}")
        try:
            expected = json.loads(expected_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SafetyError(f"cannot read reference for {stem}: {exc}") from exc
        if expected.get("document") != stem:
            raise SafetyError(f"reference document id mismatch for {stem}")
        if expected.get("annotation_status") not in REVIEWED_STATUSES:
            raise SafetyError(f"reference review is incomplete for {stem}")
        if _sha256(expected_path) != reference_hashes.get(stem):
            raise SafetyError(f"reference SHA-256 drift for {stem}")
        folders.append(folder)
    return folders


def _json_safe(value):
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, set):
        return sorted(_json_safe(item) for item in value)
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _write_exclusive_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, ensure_ascii=False, sort_keys=True)
        handle.write("\n")


def run_once(
    root: Path,
    stem: str,
    repetition: int,
    runtime,
    *,
    now_utc: Callable[[], str] = _utc_now,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict:
    """Perform exactly one pure extraction and persist it without overwriting."""
    root = Path(root)
    folders = validate_preflight(root, runtime)
    by_stem = {folder.name: folder for folder in folders}
    if stem not in by_stem:
        raise SafetyError(f"document is not part of the frozen corpus: {stem}")
    if repetition not in REPETITIONS:
        raise SafetyError("repetition must be 1, 2, or 3")

    output_path = root / "runs" / f"{stem}.run-{repetition}.json"
    if output_path.exists():
        raise FileExistsError(f"refusing to overwrite {output_path}")

    folder = by_stem[stem]
    input_path = folder / "input.txt"
    expected_path = folder / "expected.json"
    text = input_path.read_text(encoding="utf-8")
    started_at = now_utc()
    started = monotonic()
    result = runtime.extract_from_text(
        text, source_type="bulletin", include_diagnostics=True
    )
    elapsed = max(0.0, monotonic() - started)
    safe_result = _json_safe(result)
    diagnostics = safe_result.get("chunk_diagnostics", [])
    status = (
        "model_error"
        if any(row.get("status") == "error" for row in diagnostics if isinstance(row, dict))
        else "success"
    )
    record = {
        "schema_version": 1,
        "kind": "document_extraction",
        "status": status,
        "created_at_utc": started_at,
        "elapsed_seconds": round(elapsed, 6),
        "document": stem,
        "repetition": repetition,
        "provider": runtime.LLM_PROVIDER,
        "model": runtime.BEDROCK_MODEL,
        "aws_region": runtime.AWS_REGION,
        "source_type": "bulletin",
        "input_sha256": _sha256(input_path),
        "reference_sha256": _sha256(expected_path),
        "opencti_writes": 0,
        "model_output": safe_result,
    }
    _write_exclusive_json(output_path, record)
    return record


def run_smoke(
    root: Path,
    runtime,
    *,
    now_utc: Callable[[], str] = _utc_now,
) -> dict:
    """Make one ten-token Bedrock call before any document is processed."""
    root = Path(root)
    validate_preflight(root, runtime)
    output_path = root / "runs" / "smoke.json"
    if output_path.exists():
        raise FileExistsError(f"refusing to overwrite {output_path}")

    created_at = now_utc()
    try:
        response = runtime._get_anthropic_client().messages.create(
            model=runtime.BEDROCK_MODEL,
            max_tokens=10,
            messages=[{"role": "user", "content": "Reply with exactly OK"}],
        )
        response_text = "".join(
            block.text
            for block in getattr(response, "content", [])
            if getattr(block, "type", None) == "text"
        ).strip()
        if not response_text:
            raise SafetyError("Bedrock smoke returned no text")
        usage = getattr(response, "usage", None)
        record = {
            "schema_version": 1,
            "kind": "bedrock_smoke",
            "status": "success",
            "created_at_utc": created_at,
            "provider": runtime.LLM_PROVIDER,
            "model": runtime.BEDROCK_MODEL,
            "aws_region": runtime.AWS_REGION,
            "max_tokens": 10,
            "response_text": response_text,
            "stop_reason": getattr(response, "stop_reason", None),
            "usage": {
                "input_tokens": getattr(usage, "input_tokens", None),
                "output_tokens": getattr(usage, "output_tokens", None),
            },
        }
    except Exception as exc:
        record = {
            "schema_version": 1,
            "kind": "bedrock_smoke",
            "status": "error",
            "created_at_utc": created_at,
            "provider": runtime.LLM_PROVIDER,
            "model": runtime.BEDROCK_MODEL,
            "aws_region": runtime.AWS_REGION,
            "max_tokens": 10,
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
    _write_exclusive_json(output_path, record)
    return record


def run_all(
    root: Path,
    runtime,
    *,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> list[dict]:
    """Run all missing document/repetition pairs after a successful smoke."""
    root = Path(root)
    folders = validate_preflight(root, runtime)
    smoke_path = root / "runs" / "smoke.json"
    try:
        smoke = json.loads(smoke_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SafetyError(f"successful smoke is required before corpus runs: {exc}") from exc
    if smoke.get("status") != "success":
        raise SafetyError("successful smoke is required before corpus runs")
    expected_smoke = {
        "provider": runtime.LLM_PROVIDER,
        "model": runtime.BEDROCK_MODEL,
        "aws_region": runtime.AWS_REGION,
    }
    if any(smoke.get(key) != value for key, value in expected_smoke.items()):
        raise SafetyError("smoke configuration does not match the frozen execution")

    records: list[dict] = []
    previous_start: float | None = None
    minimum_interval = 60.0 / MAX_CALLS_PER_MINUTE
    for folder in folders:
        for repetition in REPETITIONS:
            output_path = root / "runs" / f"{folder.name}.run-{repetition}.json"
            if output_path.exists():
                continue
            now = monotonic()
            if previous_start is not None:
                remaining = minimum_interval - (now - previous_start)
                if remaining > 0:
                    sleep(remaining)
            previous_start = monotonic()
            records.append(run_once(root, folder.name, repetition, runtime))
    return records


def _load_runtime():
    service_dir = Path("/app")
    if not (service_dir / "extractor.py").is_file():
        service_dir = Path(__file__).resolve().parents[3] / "services" / "intel-extractor"
    sys.path.insert(0, str(service_dir))
    return importlib.import_module("extractor")


def main() -> int:
    cli = argparse.ArgumentParser()
    cli.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    mode = cli.add_mutually_exclusive_group(required=True)
    mode.add_argument("--smoke", action="store_true")
    mode.add_argument("--run-all", action="store_true")
    mode.add_argument("--stem")
    cli.add_argument("--repetition", type=int)
    args = cli.parse_args()
    runtime = _load_runtime()
    if args.smoke:
        value = run_smoke(args.root, runtime)
        print(json.dumps(value, ensure_ascii=False))
        return 0 if value["status"] == "success" else 1
    if args.run_all:
        value = run_all(args.root, runtime)
        print(json.dumps({"new_runs": len(value)}, ensure_ascii=False))
        return 0
    if args.repetition is None:
        cli.error("--stem requires --repetition")
    value = run_once(args.root, args.stem, args.repetition, runtime)
    print(json.dumps(value, ensure_ascii=False))
    return 0 if value["status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
