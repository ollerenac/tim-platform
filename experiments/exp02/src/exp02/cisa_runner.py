"""Guarded, write-once CISA evaluation runner for the approved Bedrock route."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime, timezone
import hashlib
import importlib
import json
from pathlib import Path
import re
import sys
import time
from typing import Any

from .cisa_match import equivalence_digest
from .jsonio import canonical_bytes, load_json, sha256_file, write_new_json


EXPECTED_PROVIDER = "bedrock"
EXPECTED_MODEL = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
EXPECTED_REGION = "us-east-1"
EXPECTED_PROMPT_SHA256 = "8731ecb15b5fecbeccab3b9e155fad95038a9c12e798492359a2d6c3ca0fc2d2"
EXPECTED_EQUIVALENCE_SHA256 = "d872eba3c784287bf08892d2aff3b463e371c66bc7f5b63910150d3e5945445c"
REPETITIONS = (1, 2, 3)
MAX_STARTS_PER_MINUTE = 8
_TIM_KEYS = (
    "unique_iocs", "accepted_iocs", "technique_keywords", "threat_actors", "targeted_sectors",
    "malware_families", "targeted_countries", "exploited_cves",
    "victim_technologies", "campaign_summary", "v2_entities", "v2_relationships",
)
_RAW_KEYS = (
    "raw_response_text", "raw_v2_entities", "raw_v2_relationships",
    "citation_stats", "stop_reason", "model_usage",
)


def _require_complete_extractor_output(value: Mapping[str, Any]) -> None:
    """Reject partial diagnostic results before they can claim a final identity."""
    missing = [key for key in (*_RAW_KEYS, *_TIM_KEYS) if key not in value]
    if missing:
        raise SafetyError(f"diagnostic extractor output is missing {', '.join(missing)}")
    list_fields = (*_TIM_KEYS[:2], *_TIM_KEYS[2:9], _TIM_KEYS[10], _TIM_KEYS[11])
    if any(not isinstance(value[key], list) for key in list_fields) or not isinstance(
        value["campaign_summary"], str
    ):
        raise SafetyError("diagnostic extractor output has invalid TIM field types")
    if (
        not isinstance(value["raw_response_text"], str)
        or not isinstance(value["raw_v2_entities"], list)
        or not isinstance(value["raw_v2_relationships"], list)
        or not isinstance(value["citation_stats"], Mapping)
        or not isinstance(value["model_usage"], Mapping)
    ):
        raise SafetyError("diagnostic extractor output has invalid raw field types")


class SafetyError(RuntimeError):
    """Raised when frozen CISA evidence or the approved runtime route has drifted."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _root(evidence: Path | object) -> Path:
    if isinstance(evidence, Path):
        return evidence
    return Path(getattr(evidence, "root", evidence))


def _manifest_argument(evidence: Path | object) -> dict[str, Any] | None:
    value = getattr(evidence, "manifest", None)
    return value if isinstance(value, dict) else None


def _execution_manifest_path(root: Path) -> Path:
    return root / "execution-manifest.v1.json"


def _equivalence_path(root: Path) -> Path:
    return root.parent / "config" / "cisa-equivalences.v1.json"


def _safe_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _safe_json(item) for key, item in value.items()}
    if isinstance(value, set):
        return sorted(_safe_json(item) for item in value)
    if isinstance(value, (list, tuple)):
        return [_safe_json(item) for item in value]
    return value


def _runtime_prompt_digest(runtime: object) -> str:
    prompt = getattr(runtime, "SYSTEM_PROMPT_V21", None)
    if not isinstance(prompt, str):
        raise SafetyError("runtime does not expose SYSTEM_PROMPT_V21")
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def _require_runtime(runtime: object) -> None:
    if getattr(runtime, "LLM_PROVIDER", None) != EXPECTED_PROVIDER:
        raise SafetyError("LLM_PROVIDER must be bedrock")
    if getattr(runtime, "BEDROCK_MODEL", None) != EXPECTED_MODEL:
        raise SafetyError("BEDROCK_MODEL does not match the frozen Haiku model")
    if getattr(runtime, "AWS_REGION", None) != EXPECTED_REGION:
        raise SafetyError("AWS_REGION must be us-east-1")
    if getattr(runtime, "ANTHROPIC_API_KEY", ""):
        raise SafetyError("direct Anthropic credentials are forbidden")
    if _runtime_prompt_digest(runtime) != EXPECTED_PROMPT_SHA256:
        raise SafetyError("SYSTEM_PROMPT_V21 does not match the frozen prompt digest")


def _load_execution_manifest(root: Path, manifest: dict[str, Any] | None) -> dict[str, Any]:
    return manifest if manifest is not None else load_json(_execution_manifest_path(root))


def _selection_rows(root: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    selection_path = root / "selection-manifest.v1.json"
    selection = load_json(selection_path)
    rows = selection.get("documents")
    if not isinstance(rows, list) or len(rows) != 24:
        raise SafetyError("selection manifest must contain exactly 24 final documents")
    by_code: dict[str, dict[str, Any]] = {}
    for row in rows:
        code = row.get("code") if isinstance(row, dict) else None
        input_path = row.get("input_path") if isinstance(row, dict) else None
        text_hash = row.get("text_sha256") if isinstance(row, dict) else None
        if not isinstance(code, str) or not isinstance(input_path, str) or not isinstance(text_hash, str):
            raise SafetyError("selection rows must bind code, input path, and text hash")
        if code in by_code:
            raise SafetyError("selection document codes must be unique")
        by_code[code] = row
    return selection, by_code


def _manifest_documents(manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = manifest.get("documents")
    if not isinstance(rows, list) or len(rows) != 24:
        raise SafetyError("execution manifest must contain exactly 24 final documents")
    by_code: dict[str, dict[str, Any]] = {}
    for row in rows:
        code = row.get("code") if isinstance(row, dict) else None
        if not isinstance(code, str) or code in by_code:
            raise SafetyError("execution manifest document codes must be unique")
        by_code[code] = row
    return by_code


def seal_execution(
    evidence: Path | object,
    runtime: object,
    *,
    equivalence_path: Path | None = None,
) -> dict[str, Any]:
    """Write the immutable run manifest after all 24 inputs and references are frozen."""
    root = _root(evidence)
    _require_runtime(runtime)
    selection, rows = _selection_rows(root)
    runs_dir = root / "runs"
    if runs_dir.exists() and any(runs_dir.glob("*.run-*.json")):
        raise SafetyError("cannot seal after a final run record exists")
    equivalences = equivalence_path or _equivalence_path(root)
    if not equivalences.is_file():
        raise SafetyError("frozen equivalence configuration is missing")
    canonical_equivalence_digest = equivalence_digest(equivalences)
    if canonical_equivalence_digest != EXPECTED_EQUIVALENCE_SHA256:
        raise SafetyError("equivalence configuration does not match the frozen digest")
    documents: list[dict[str, str]] = []
    for code in sorted(rows):
        row = rows[code]
        input_path = root / str(row["input_path"])
        reference_path = root / "reference" / f"{code}.canonical.json"
        if not input_path.is_file() or not reference_path.is_file():
            raise SafetyError(f"missing frozen input or canonical reference for {code}")
        if sha256_file(input_path) != row["text_sha256"]:
            raise SafetyError(f"selection input SHA-256 drift for {code}")
        documents.append({
            "code": code,
            "input_sha256": sha256_file(input_path),
            "reference_sha256": sha256_file(reference_path),
            "selection_input_sha256": str(row["text_sha256"]),
        })
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "kind": "cisa_bedrock_execution",
        "selection_manifest_sha256": sha256_file(root / "selection-manifest.v1.json"),
        "selection_digest": selection.get("selection_digest"),
        "documents": documents,
        "provider": EXPECTED_PROVIDER,
        "model": EXPECTED_MODEL,
        "aws_region": EXPECTED_REGION,
        "source_type": "advisory",
        "repetitions": list(REPETITIONS),
        "expected_records": 72,
        "system_prompt_sha256": _runtime_prompt_digest(runtime),
        "equivalence_file_sha256": sha256_file(equivalences),
        "equivalence_sha256": canonical_equivalence_digest,
        "opencti_writes": 0,
    }
    write_new_json(_execution_manifest_path(root), manifest)
    return manifest


def validate_frozen_evidence(
    evidence: Path | object,
    *,
    manifest: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Recompute frozen evidence without loading or calling a model runtime."""
    root = _root(evidence)
    supplied_manifest = manifest if manifest is not None else _manifest_argument(evidence)
    bound = _load_execution_manifest(root, supplied_manifest)
    required = {
        "schema_version": 1, "kind": "cisa_bedrock_execution",
        "provider": EXPECTED_PROVIDER, "model": EXPECTED_MODEL,
        "aws_region": EXPECTED_REGION, "source_type": "advisory",
        "repetitions": list(REPETITIONS), "expected_records": 72,
        "system_prompt_sha256": EXPECTED_PROMPT_SHA256, "opencti_writes": 0,
    }
    for key, value in required.items():
        if bound.get(key) != value:
            raise SafetyError(f"execution manifest {key} does not match the frozen configuration")
    selection, selection_by_code = _selection_rows(root)
    if bound.get("selection_manifest_sha256") != sha256_file(root / "selection-manifest.v1.json"):
        raise SafetyError("selection manifest SHA-256 drift")
    if bound.get("selection_digest") != selection.get("selection_digest"):
        raise SafetyError("selection digest drift")
    bound_by_code = _manifest_documents(bound)
    if set(bound_by_code) != set(selection_by_code):
        raise SafetyError("execution manifest has an extra or missing final document")
    document_dirs = {path.name for path in (root / "documents").iterdir() if path.is_dir()}
    references = {
        path.name.removesuffix(".canonical.json")
        for path in (root / "reference").glob("*.canonical.json")
    }
    if document_dirs != set(selection_by_code) or references != set(selection_by_code):
        raise SafetyError("evidence has an extra or missing final document")
    for code in sorted(selection_by_code):
        selection_row = selection_by_code[code]
        bound_row = bound_by_code[code]
        input_path = root / str(selection_row["input_path"])
        reference_path = root / "reference" / f"{code}.canonical.json"
        if not input_path.is_file() or not reference_path.is_file():
            raise SafetyError(f"missing frozen input or canonical reference for {code}")
        actual_input = sha256_file(input_path)
        actual_reference = sha256_file(reference_path)
        if (
            actual_input != selection_row["text_sha256"]
            or bound_row.get("input_sha256") != actual_input
            or bound_row.get("selection_input_sha256") != actual_input
        ):
            raise SafetyError(f"input SHA-256 drift for {code}")
        if bound_row.get("reference_sha256") != actual_reference:
            raise SafetyError(f"canonical reference SHA-256 drift for {code}")
        if load_json(reference_path).get("document_id") != code:
            raise SafetyError(f"canonical reference document id mismatch for {code}")
    equivalences = _equivalence_path(root)
    if (
        bound.get("equivalence_file_sha256") != sha256_file(equivalences)
        or bound.get("equivalence_sha256") != equivalence_digest(equivalences)
        or bound.get("equivalence_sha256") != EXPECTED_EQUIVALENCE_SHA256
    ):
        raise SafetyError("equivalence configuration digest drift")
    return [bound_by_code[code] for code in sorted(bound_by_code)]


def validate_preflight(
    evidence: Path | object,
    runtime: object,
    *,
    manifest: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Validate the runtime plus every sealing input before an immutable call."""
    _require_runtime(runtime)
    return validate_frozen_evidence(evidence, manifest=manifest)


def _record_configuration(runtime: object, root: Path) -> dict[str, Any]:
    return {
        "provider": runtime.LLM_PROVIDER,
        "model": runtime.BEDROCK_MODEL,
        "aws_region": runtime.AWS_REGION,
        "execution_manifest_sha256": sha256_file(_execution_manifest_path(root)),
    }


def _validate_existing_run_record(
    path: Path,
    document: Mapping[str, Any],
    repetition: int,
    runtime: object,
    root: Path,
) -> None:
    """Accept only a complete immutable record for this exact final-run identity."""
    try:
        record = load_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SafetyError(f"cannot read existing run record {path.name}: {error}") from error
    expected = {
        "schema_version": 1,
        "kind": "cisa_document_extraction",
        "document": document["code"],
        "repetition": repetition,
        "source_type": "advisory",
        "input_sha256": document["input_sha256"],
        "reference_sha256": document["reference_sha256"],
        "opencti_writes": 0,
        **_record_configuration(runtime, root),
    }
    for key, value in expected.items():
        if record.get(key) != value:
            raise SafetyError(f"existing run record {path.name} has invalid {key}")
    if not isinstance(record.get("created_at_utc"), str) or not isinstance(
        record.get("elapsed_seconds"), (int, float)
    ):
        raise SafetyError(f"existing run record {path.name} is incomplete")
    status = record.get("status")
    if status == "success":
        raw = record.get("raw_model_output")
        final = record.get("tim_output")
        if (
            not isinstance(raw, Mapping)
            or not isinstance(final, Mapping)
            or any(key not in raw for key in _RAW_KEYS)
            or any(key not in final for key in _TIM_KEYS)
        ):
            raise SafetyError(f"existing successful run record {path.name} is incomplete")
        return
    if status == "error":
        if not all(
            isinstance(record.get(key), str) and record[key]
            for key in ("error_type", "error")
        ):
            raise SafetyError(f"existing error run record {path.name} is incomplete")
        return
    raise SafetyError(f"existing run record {path.name} has invalid status")


def _validate_existing_run_records(
    root: Path, documents: list[dict[str, Any]], runtime: object
) -> None:
    """Reject unknown, corrupt, or incomplete artifacts before resumability skips them."""
    runs_dir = root / "runs"
    if not runs_dir.exists():
        return
    expected = {
        f"{document['code']}.run-{repetition}.json": (document, repetition)
        for document in documents
        for repetition in REPETITIONS
    }
    for path in runs_dir.glob("*.run-*.json"):
        identity = expected.get(path.name)
        if identity is None:
            raise SafetyError(f"unexpected final run record: {path.name}")
        _validate_existing_run_record(path, *identity, runtime, root)


def _v2_manifest(root: Path) -> dict[str, Any] | None:
    path = root / "execution-manifest.v3.json"
    return load_json(path) if path.is_file() else None


def _v2_documents(root: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Keep v2 validation lazy to avoid a module cycle with sealing utilities."""
    from .cisa_execution import validate_execution_binding

    freeze, manifest = validate_execution_binding(root)
    documents = freeze.get("documents")
    if not isinstance(documents, list) or len(documents) != 24:
        raise SafetyError("schema-v3 freeze must bind exactly 24 documents")
    return documents, manifest


def _v2_config(runtime: object, manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "provider": runtime.LLM_PROVIDER,
        "model": runtime.BEDROCK_MODEL,
        "aws_region": runtime.AWS_REGION,
        "freeze_sha256": manifest["freeze_sha256"],
    }


def _next_attempt(attempts: Path, stem: str) -> tuple[int, Path]:
    number = 1
    while (attempts / f"{stem}.attempt-{number}.json").exists():
        number += 1
    return number, attempts / f"{stem}.attempt-{number}.json"


def _run_once_v2(
    root: Path,
    code: str,
    repetition: int,
    runtime: object,
    *,
    now_utc: Callable[[], str],
    monotonic: Callable[[], float],
    wall_time: Callable[[], float] = time.time,
) -> dict[str, Any]:
    _require_runtime(runtime)
    documents, manifest = _v2_documents(root)
    by_code = {str(row.get("code")): row for row in documents}
    if code not in by_code or repetition not in REPETITIONS:
        raise SafetyError("document or repetition is not part of the frozen CISA selection")
    final = root / "runs" / f"{code}.run-{repetition}.json"
    if final.exists():
        raise FileExistsError(f"refusing to overwrite {final}")
    attempts = root / "attempts"
    number, target = _next_attempt(attempts, f"{code}.run-{repetition}")
    document = by_code[code]
    started = monotonic()
    base = {
        "schema_version": 2, "kind": "cisa_document_attempt", "created_at_utc": now_utc(),
        "started_at_unix": wall_time(),
        "document": code, "repetition": repetition, "attempt": number, "source_type": "advisory",
        "input_sha256": document["text_sha256"], "reference_sha256": document["reference_sha256"],
        "opencti_writes": 0, **_v2_config(runtime, manifest),
    }
    try:
        result = runtime.extract_from_text(
            (root / "documents" / code / "input.txt").read_text(encoding="utf-8"),
            source_type="advisory", include_diagnostics=True,
        )
        safe = _safe_json(result)
        _require_complete_extractor_output(safe)
        attempt = {
            **base, "status": "success", "elapsed_seconds": round(max(0.0, monotonic() - started), 6),
            "raw_model_output": {key: safe[key] for key in _RAW_KEYS},
            "tim_output": {key: safe.get(key) for key in _TIM_KEYS},
        }
    except Exception as error:
        attempt = {
            **base, "status": "error", "elapsed_seconds": round(max(0.0, monotonic() - started), 6),
            "error_type": type(error).__name__, "error": str(error),
        }
    digest = write_new_json(target, attempt)
    if attempt["status"] != "success":
        return attempt
    final_record = {
        **attempt, "kind": "cisa_document_extraction", "attempt_record": target.name,
        "attempt_sha256": digest,
    }
    write_new_json(final, final_record)
    return final_record


def _run_smoke_v2(
    root: Path, runtime: object, *, now_utc: Callable[[], str], wall_time: Callable[[], float] = time.time
) -> dict[str, Any]:
    _require_runtime(runtime)
    _freeze, manifest = _v2_documents(root)
    final = root / "runs" / "smoke.json"
    if final.exists():
        raise FileExistsError(f"refusing to overwrite {final}")
    attempts = root / "attempts"
    number, target = _next_attempt(attempts, "smoke")
    base = {
        "schema_version": 2, "kind": "cisa_bedrock_smoke_attempt", "created_at_utc": now_utc(),
        "started_at_unix": wall_time(),
        "attempt": number, "max_tokens": 10, "opencti_writes": 0, **_v2_config(runtime, manifest),
    }
    try:
        response = runtime._get_anthropic_client().messages.create(
            model=runtime.BEDROCK_MODEL, max_tokens=10,
            messages=[{"role": "user", "content": "Reply with exactly OK"}],
        )
        response_text = "".join(
            block.text for block in getattr(response, "content", []) if getattr(block, "type", None) == "text"
        ).strip()
        if not response_text:
            raise SafetyError("Bedrock smoke returned no text")
        usage = getattr(response, "usage", None)
        attempt = {
            **base, "status": "success", "response_text": response_text,
            "stop_reason": getattr(response, "stop_reason", None),
            "usage": {"input_tokens": getattr(usage, "input_tokens", None), "output_tokens": getattr(usage, "output_tokens", None)},
        }
    except Exception as error:
        attempt = {**base, "status": "error", "error_type": type(error).__name__, "error": str(error)}
    digest = write_new_json(target, attempt)
    if attempt["status"] != "success":
        return attempt
    record = {**attempt, "kind": "cisa_bedrock_smoke", "attempt_record": target.name, "attempt_sha256": digest}
    write_new_json(final, record)
    return record


def _validate_v2_existing(root: Path, documents: list[dict[str, Any]], manifest: Mapping[str, Any]) -> None:
    expected = {
        f"{row['code']}.run-{repetition}.json": (str(row["code"]), repetition)
        for row in documents for repetition in REPETITIONS
    }
    attempts = root / "attempts"
    attempts_by_name: dict[str, dict[str, Any]] = {}
    expected_stems = {"smoke", *(f"{row['code']}.run-{repetition}" for row in documents for repetition in REPETITIONS)}
    if attempts.exists():
        paths = [path for path in attempts.iterdir() if path.is_file()]
        if len(paths) != len(list(attempts.iterdir())):
            raise SafetyError("unexpected attempt artifact")
        for path in paths:
            if not re.fullmatch(r"(?:smoke|[A-Z0-9-]+\.run-[123])\.attempt-[1-9][0-9]*\.json", path.name):
                raise SafetyError(f"unexpected attempt record: {path.name}")
            if path.name.rsplit(".attempt-", 1)[0] not in expected_stems:
                raise SafetyError(f"unexpected attempt record: {path.name}")
            try:
                record = load_json(path)
            except (OSError, ValueError, json.JSONDecodeError) as error:
                raise SafetyError(f"cannot read existing attempt record {path.name}: {error}") from error
            if (
                record.get("schema_version") != 2 or record.get("freeze_sha256") != manifest["freeze_sha256"]
                or record.get("provider") != EXPECTED_PROVIDER or record.get("model") != EXPECTED_MODEL
                or record.get("aws_region") != EXPECTED_REGION
            ):
                raise SafetyError(f"existing attempt record {path.name} has invalid configuration")
            if record.get("status") not in {"success", "error"} or record.get("opencti_writes") != 0:
                raise SafetyError(f"existing attempt record {path.name} is incomplete")
            attempts_by_name[path.name] = record
    runs = root / "runs"
    if not runs.exists():
        return
    for path in runs.glob("*.run-*.json"):
        identity = expected.get(path.name)
        if identity is None:
            raise SafetyError(f"unexpected final run record: {path.name}")
        try:
            record = load_json(path)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise SafetyError(f"cannot read existing run record {path.name}: {error}") from error
        if (
            record.get("schema_version") != 2 or record.get("kind") != "cisa_document_extraction"
            or record.get("status") != "success" or record.get("document") != identity[0]
            or record.get("repetition") != identity[1] or record.get("freeze_sha256") != manifest["freeze_sha256"]
            or record.get("opencti_writes") != 0 or record.get("attempt_record") not in attempts_by_name
            or not isinstance(record.get("raw_model_output"), Mapping) or not isinstance(record.get("tim_output"), Mapping)
            or record.get("attempt_sha256") != sha256_file(root / "attempts" / str(record.get("attempt_record")))
        ):
            raise SafetyError(f"existing final run record {path.name} is incomplete or invalid")
        attempt = attempts_by_name[str(record["attempt_record"])]
        if (
            attempt.get("kind") != "cisa_document_attempt" or attempt.get("status") != "success"
            or attempt.get("document") != identity[0] or attempt.get("repetition") != identity[1]
            or attempt.get("input_sha256") != record.get("input_sha256")
            or attempt.get("reference_sha256") != record.get("reference_sha256")
            or not isinstance(attempt.get("raw_model_output"), Mapping)
            or not isinstance(attempt.get("tim_output"), Mapping)
            or any(key not in attempt["raw_model_output"] for key in _RAW_KEYS)
            or any(key not in attempt["tim_output"] for key in _TIM_KEYS)
        ):
            raise SafetyError(f"existing final run record {path.name} does not bind a complete attempt")
        if any(key not in record["raw_model_output"] for key in _RAW_KEYS) or any(
            key not in record["tim_output"] for key in _TIM_KEYS
        ):
            raise SafetyError(f"existing final run record {path.name} has incomplete output")
        expected_final = {
            **attempt,
            "kind": "cisa_document_extraction",
            "attempt_record": record["attempt_record"],
            "attempt_sha256": record["attempt_sha256"],
        }
        if canonical_bytes(record) != canonical_bytes(expected_final):
            raise SafetyError(f"existing final run record {path.name} differs from its bound attempt")


def _run_all_v2(
    root: Path,
    runtime: object,
    *,
    sleep: Callable[[float], None],
    monotonic: Callable[[], float],
    wall_time: Callable[[], float],
) -> list[dict[str, Any]]:
    _require_runtime(runtime)
    documents, manifest = _v2_documents(root)
    _validate_v2_existing(root, documents, manifest)
    smoke_path = root / "runs" / "smoke.json"
    try:
        smoke = load_json(smoke_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SafetyError(f"successful same-configuration smoke is required before final runs: {error}") from error
    if (
        smoke.get("schema_version") != 2 or smoke.get("status") != "success"
        or smoke.get("freeze_sha256") != manifest["freeze_sha256"] or smoke.get("opencti_writes") != 0
    ):
        raise SafetyError("successful same-configuration smoke is required before final runs")
    records: list[dict[str, Any]] = []
    starts: list[float] = []
    attempts_root = root / "attempts"
    if attempts_root.exists():
        for path in attempts_root.glob("*.attempt-*.json"):
            record = load_json(path)
            value = record.get("started_at_unix")
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise SafetyError(f"existing attempt record {path.name} has invalid started_at_unix")
            starts.append(float(value))
    for document in documents:
        code = str(document["code"])
        for repetition in REPETITIONS:
            if (root / "runs" / f"{code}.run-{repetition}.json").exists():
                continue
            wall_now = wall_time()
            starts = [started for started in starts if started > wall_now - 60.0]
            if len(starts) >= MAX_STARTS_PER_MINUTE:
                sleep(max(0.0, min(starts) + 60.0 - wall_now))
                wall_now = wall_time()
                if wall_now <= min(starts):
                    wall_now = min(starts) + 60.0
                starts = [started for started in starts if started > wall_now - 60.0]
            starts.append(wall_now)
            records.append(_run_once_v2(
                root, code, repetition, runtime, now_utc=_utc_now, monotonic=monotonic, wall_time=wall_time
            ))
    _validate_v2_existing(root, documents, manifest)
    missing = [
        f"{row['code']}.run-{repetition}.json" for row in documents for repetition in REPETITIONS
        if not (root / "runs" / f"{row['code']}.run-{repetition}.json").is_file()
    ]
    if missing:
        raise SafetyError(f"missing successful final identities after one pass: {missing}")
    return records


def run_once(
    evidence: Path | object,
    code: str,
    repetition: int,
    runtime: object,
    *,
    now_utc: Callable[[], str] = _utc_now,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Run one advisory extraction and persist either final output or explicit failure."""
    root = _root(evidence)
    if _v2_manifest(root) is not None:
        return _run_once_v2(root, code, repetition, runtime, now_utc=now_utc, monotonic=monotonic)
    documents = {row["code"]: row for row in validate_preflight(evidence, runtime)}
    if code not in documents:
        raise SafetyError(f"document is not part of the frozen CISA selection: {code}")
    if repetition not in REPETITIONS:
        raise SafetyError("repetition must be 1, 2, or 3")
    output = root / "runs" / f"{code}.run-{repetition}.json"
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")
    input_path = root / "documents" / code / "input.txt"
    started_at = now_utc()
    started = monotonic()
    base = {
        "schema_version": 1,
        "kind": "cisa_document_extraction",
        "created_at_utc": started_at,
        "document": code,
        "repetition": repetition,
        "source_type": "advisory",
        "input_sha256": documents[code]["input_sha256"],
        "reference_sha256": documents[code]["reference_sha256"],
        "opencti_writes": 0,
        **_record_configuration(runtime, root),
    }
    try:
        result = runtime.extract_from_text(
            input_path.read_text(encoding="utf-8"),
            source_type="advisory",
            include_diagnostics=True,
        )
        safe = _safe_json(result)
        missing = [key for key in _RAW_KEYS if key not in safe]
        if missing:
            raise SafetyError(f"diagnostic extractor output is missing {', '.join(missing)}")
        record = {
            **base,
            "status": "success",
            "elapsed_seconds": round(max(0.0, monotonic() - started), 6),
            "raw_model_output": {key: safe[key] for key in _RAW_KEYS},
            "tim_output": {key: safe.get(key) for key in _TIM_KEYS},
        }
    except Exception as error:
        record = {
            **base,
            "status": "error",
            "elapsed_seconds": round(max(0.0, monotonic() - started), 6),
            "error_type": type(error).__name__,
            "error": str(error),
        }
    write_new_json(output, record)
    return record


def run_smoke(
    evidence: Path | object,
    runtime: object,
    *,
    now_utc: Callable[[], str] = _utc_now,
    wall_time: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """Create one small Bedrock-only smoke record; callers decide when to invoke it."""
    root = _root(evidence)
    if _v2_manifest(root) is not None:
        return _run_smoke_v2(root, runtime, now_utc=now_utc, wall_time=wall_time)
    validate_preflight(evidence, runtime)
    output = root / "runs" / "smoke.json"
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")
    base = {
        "schema_version": 1, "kind": "cisa_bedrock_smoke", "created_at_utc": now_utc(),
        "max_tokens": 10, "opencti_writes": 0, **_record_configuration(runtime, root),
    }
    try:
        response = runtime._get_anthropic_client().messages.create(
            model=runtime.BEDROCK_MODEL,
            max_tokens=10,
            messages=[{"role": "user", "content": "Reply with exactly OK"}],
        )
        response_text = "".join(
            block.text for block in getattr(response, "content", [])
            if getattr(block, "type", None) == "text"
        ).strip()
        if not response_text:
            raise SafetyError("Bedrock smoke returned no text")
        usage = getattr(response, "usage", None)
        record = {
            **base, "status": "success", "response_text": response_text,
            "stop_reason": getattr(response, "stop_reason", None),
            "usage": {"input_tokens": getattr(usage, "input_tokens", None),
                      "output_tokens": getattr(usage, "output_tokens", None)},
        }
    except Exception as error:
        record = {**base, "status": "error", "error_type": type(error).__name__, "error": str(error)}
    write_new_json(output, record)
    return record


def run_all(
    evidence: Path | object,
    runtime: object,
    *,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    wall_time: Callable[[], float] = time.time,
) -> list[dict[str, Any]]:
    """Resume only absent run identities after a successful same-configuration smoke."""
    root = _root(evidence)
    if _v2_manifest(root) is not None:
        return _run_all_v2(root, runtime, sleep=sleep, monotonic=monotonic, wall_time=wall_time)
    documents = validate_preflight(evidence, runtime)
    _validate_existing_run_records(root, documents, runtime)
    try:
        smoke = load_json(root / "runs" / "smoke.json")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SafetyError(f"successful smoke is required before final runs: {error}") from error
    expected = {"status": "success", "opencti_writes": 0, **_record_configuration(runtime, root)}
    if any(smoke.get(key) != value for key, value in expected.items()):
        raise SafetyError("successful same-configuration smoke is required before final runs")
    records: list[dict[str, Any]] = []
    previous_start: float | None = None
    minimum_interval = 60.0 / MAX_STARTS_PER_MINUTE
    for document in documents:
        for repetition in REPETITIONS:
            output = root / "runs" / f"{document['code']}.run-{repetition}.json"
            if output.exists():
                continue
            now = monotonic()
            if previous_start is not None:
                wait = minimum_interval - (now - previous_start)
                if wait > 0:
                    sleep(wait)
            previous_start = monotonic()
            records.append(run_once(root, document["code"], repetition, runtime))
    _validate_existing_run_records(root, documents, runtime)
    return records


def load_runtime() -> object:
    """Load TIM's extractor module without invoking its HTTP or OpenCTI surfaces."""
    service_root = Path(__file__).resolve().parents[4] / "services" / "intel-extractor"
    if str(service_root) not in sys.path:
        sys.path.insert(0, str(service_root))
    return importlib.import_module("extractor")
