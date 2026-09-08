"""Immutable schema-v3 sealing and verification for CISA execution evidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .cisa_match import equivalence_digest, load_equivalences, match_entities
from .cisa_reference import canonicalize_bundle
from .cisa_runner import (
    EXPECTED_EQUIVALENCE_SHA256,
    EXPECTED_MODEL,
    EXPECTED_PROMPT_SHA256,
    EXPECTED_PROVIDER,
    EXPECTED_REGION,
    MAX_STARTS_PER_MINUTE,
    REPETITIONS,
    _RAW_KEYS,
    _TIM_KEYS,
    _runtime_prompt_digest,
    _selection_rows,
)
from .cisa_score import canonicalize_prediction
from .jsonio import canonical_bytes, load_json, sha256_file, write_new_json


class ExecutionIntegrityError(RuntimeError):
    """Raised when schema-v2 execution evidence is missing, corrupt, or drifted."""


FREEZE_NAME = "freeze.v3.json"
FREEZE_DIGEST_NAME = "freeze.v3.sha256"
MANIFEST_NAME = "execution-manifest.v3.json"
RESULTS_NAME = "results.v2.json"
PILOT_NAME = "pilot.v1.json"


def _root(evidence: Path | str | object) -> Path:
    if isinstance(evidence, Path):
        return evidence
    return Path(getattr(evidence, "root", evidence))


def _path(root: Path, name: str) -> Path:
    return root / name


def _source_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _write_digest(path: Path, digest: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(f"{digest}  {FREEZE_NAME}\n")


def _read_digest(root: Path) -> str:
    path = _path(root, FREEZE_DIGEST_NAME)
    try:
        line = path.read_text(encoding="utf-8").strip()
    except OSError as error:
        raise ExecutionIntegrityError("freeze digest record is missing") from error
    prefix = f"  {FREEZE_NAME}"
    if not line.endswith(prefix) or len(line) != 64 + len(prefix):
        raise ExecutionIntegrityError("freeze digest record is malformed")
    digest = line[:64]
    if any(character not in "0123456789abcdef" for character in digest):
        raise ExecutionIntegrityError("freeze digest record is malformed")
    return digest


def _artifact_paths(root: Path) -> list[Path]:
    paths = [
        _path(root, FREEZE_NAME), _path(root, FREEZE_DIGEST_NAME), _path(root, MANIFEST_NAME),
        _path(root, RESULTS_NAME),
    ]
    for directory in (root / "runs", root / "attempts", root / "review"):
        if directory.exists():
            paths.extend(path for path in directory.rglob("*") if path.is_file())
    return [path for path in paths if path.exists() or path.is_symlink()]


def _code_hashes() -> dict[str, str]:
    package = Path(__file__).resolve().parent
    hashes = {
        name: sha256_file(package / name)
        for name in (
            "cisa_execution.py", "cisa_runner.py", "cisa_score.py", "cisa_match.py",
            "cisa_reference.py", "cisa_cli.py",
        )
    }
    hashes["extractor.py"] = sha256_file(_source_root() / "services" / "intel-extractor" / "extractor.py")
    return hashes


def _safe_artifact_path(base: Path, relative: str, *, label: str) -> Path:
    """Resolve a manifest-relative artifact without allowing traversal or absolute paths."""
    path = Path(relative)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ExecutionIntegrityError(f"{label} must be a safe relative artifact path")
    return base.joinpath(*path.parts)


def _freeze_documents(root: Path) -> list[dict[str, str]]:
    _selection, rows = _selection_rows(root)
    documents: list[dict[str, str]] = []
    for code, row in sorted(rows.items()):
        required = (
            "input_path", "source_pdf_path", "source_stix_path", "text_sha256", "pdf_sha256", "stix_sha256",
        )
        if any(not isinstance(row.get(key), str) for key in required):
            raise ExecutionIntegrityError(f"selection lacks an immutable input binding for {code}")
        if Path(code).name != code or code in {"", ".", ".."}:
            raise ExecutionIntegrityError("selection document code is not a safe path component")
        paths = {
            "text_sha256": _safe_artifact_path(root, row["input_path"], label="selection input"),
            "pdf_sha256": _safe_artifact_path(root.parent, row["source_pdf_path"], label="selection PDF"),
            "stix_sha256": _safe_artifact_path(root.parent, row["source_stix_path"], label="selection STIX"),
            "reference_sha256": root / "reference" / f"{code}.canonical.json",
        }
        try:
            bound = {key: sha256_file(path) for key, path in paths.items()}
        except (OSError, ValueError) as error:
            raise ExecutionIntegrityError(f"missing or unsafe frozen PDF, STIX, text, or reference for {code}") from error
        selection_hashes: dict[str, str] = {
            "text_sha256": row["text_sha256"],
            "pdf_sha256": row["pdf_sha256"],
            "stix_sha256": row["stix_sha256"],
        }
        if any(bound[key] != value for key, value in selection_hashes.items()):
            raise ExecutionIntegrityError(f"selection PDF, STIX, or text SHA-256 drift for {code}")
        documents.append({"code": code, **bound})
    return documents


def _freeze_payload(root: Path, runtime: object) -> dict[str, Any]:
    selection, _rows = _selection_rows(root)
    equivalences = root.parent / "config" / "cisa-equivalences.v1.json"
    if not equivalences.is_file() or equivalence_digest(equivalences) != EXPECTED_EQUIVALENCE_SHA256:
        raise ExecutionIntegrityError("equivalence configuration drift")
    if _runtime_prompt_digest(runtime) != EXPECTED_PROMPT_SHA256:
        raise ExecutionIntegrityError("runtime prompt drift")
    if (
        getattr(runtime, "LLM_PROVIDER", None) != EXPECTED_PROVIDER
        or getattr(runtime, "BEDROCK_MODEL", None) != EXPECTED_MODEL
        or getattr(runtime, "AWS_REGION", None) != EXPECTED_REGION
        or getattr(runtime, "ANTHROPIC_API_KEY", "")
    ):
        raise ExecutionIntegrityError("runtime provider, model, region, or credentials drift")
    design_spec = _source_root() / "docs" / "superpowers" / "specs" / (
        "2026-09-01-exp-02-cisa-structural-similarity-design.md"
    )
    if not design_spec.is_file():
        raise ExecutionIntegrityError("structural-similarity design specification is missing")
    return {
        "schema_version": 3,
        "kind": "cisa_structural_similarity_freeze",
        "selection_manifest_sha256": sha256_file(root / "selection-manifest.v1.json"),
        "selection_digest": selection.get("selection_digest"),
        "documents": _freeze_documents(root),
        "provider": EXPECTED_PROVIDER,
        "model": EXPECTED_MODEL,
        "aws_region": EXPECTED_REGION,
        "source_type": "advisory",
        "max_tokens": 32000,
        "sampling_arguments": {"temperature": None, "top_p": None, "sampling": None},
        "system_prompt_sha256": EXPECTED_PROMPT_SHA256,
        "equivalence_file_sha256": sha256_file(equivalences),
        "equivalence_sha256": EXPECTED_EQUIVALENCE_SHA256,
        "parser": "TIM diagnostic extractor v2.1",
        "canonicalizer": "exp02.cisa_reference.canonicalize_bundle",
        "matcher": "exp02.cisa_match.match_entities",
        "scorer": "exp02.cisa_score.score_experiment",
        "code_sha256": _code_hashes(),
        "design": {
            "spec_path": "docs/superpowers/specs/2026-09-01-exp-02-cisa-structural-similarity-design.md",
            "spec_sha256": sha256_file(design_spec),
            "primary_metric": "structural_cosine",
            "supporting_metrics": ["cisa_recall", "jaccard"],
            "matching": "automatic_one_to_one",
            "unresolved_nominal_pairs": "conservative_differences",
            "tim_only": "unassessed",
            "human_gates": [],
            "aggregation": "mean_three_repetitions_then_macro_mean_24_documents",
            "empty_cisa_scope": "not_evaluable",
        },
        "seeds": {
            "bootstrap": 20260830,
            "bootstrap_samples": 10000,
            "diagnostic_samples": 20260831,
        },
        "repetitions": list(REPETITIONS),
        "max_starts_per_minute": MAX_STARTS_PER_MINUTE,
        "opencti_writes": 0,
    }


def finalize_execution(evidence: Path | str | object, runtime: object) -> dict[str, Any]:
    """Write the freeze, its digest record, and schema-v3 manifest exactly once."""
    root = _root(evidence)
    existing = _artifact_paths(root)
    if existing:
        raise FileExistsError(f"refusing finalize after execution artifacts exist: {existing[0]}")
    freeze = _freeze_payload(root, runtime)
    digest = write_new_json(_path(root, FREEZE_NAME), freeze)
    _write_digest(_path(root, FREEZE_DIGEST_NAME), digest)
    manifest = {
        "schema_version": 3,
        "kind": "cisa_bedrock_execution",
        "freeze_sha256": digest,
        "provider": EXPECTED_PROVIDER,
        "model": EXPECTED_MODEL,
        "aws_region": EXPECTED_REGION,
        "source_type": "advisory",
        "max_tokens": 32000,
        "repetitions": list(REPETITIONS),
        "expected_records": 72,
        "max_starts_per_minute": MAX_STARTS_PER_MINUTE,
        "opencti_writes": 0,
    }
    write_new_json(_path(root, MANIFEST_NAME), manifest)
    return manifest


def _validate_freeze(root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        freeze = load_json(_path(root, FREEZE_NAME))
        manifest = load_json(_path(root, MANIFEST_NAME))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ExecutionIntegrityError("schema-v3 freeze or manifest is missing or corrupt") from error
    digest = _read_digest(root)
    if sha256_file(_path(root, FREEZE_NAME)) != digest:
        raise ExecutionIntegrityError("freeze digest drift")
    required_manifest = {
        "schema_version": 3, "kind": "cisa_bedrock_execution", "freeze_sha256": digest,
        "provider": EXPECTED_PROVIDER, "model": EXPECTED_MODEL, "aws_region": EXPECTED_REGION,
        "source_type": "advisory", "max_tokens": 32000, "repetitions": list(REPETITIONS),
        "expected_records": 72, "max_starts_per_minute": MAX_STARTS_PER_MINUTE, "opencti_writes": 0,
    }
    if any(manifest.get(key) != value for key, value in required_manifest.items()):
        raise ExecutionIntegrityError("schema-v3 execution manifest drift")
    expected = _freeze_payload(root, _FrozenRuntime())
    if canonical_bytes(freeze) != canonical_bytes(expected):
        raise ExecutionIntegrityError("frozen execution inputs or code drift")
    return freeze, manifest


def validate_execution_binding(evidence: Path | str | object) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate v3's immutable input/code/design graph for runner preflight checks."""
    return _validate_freeze(_root(evidence))


class _FrozenRuntime:
    LLM_PROVIDER = EXPECTED_PROVIDER
    BEDROCK_MODEL = EXPECTED_MODEL
    AWS_REGION = EXPECTED_REGION
    ANTHROPIC_API_KEY = ""
    SYSTEM_PROMPT_V21 = None

    def __init__(self) -> None:
        # Keep runtime verification independent of import side effects while reproducing the bound digest.
        self.SYSTEM_PROMPT_V21 = _prompt_from_extractor()


def _prompt_from_extractor() -> str:
    import importlib
    import sys

    service_root = _source_root() / "services" / "intel-extractor"
    if str(service_root) not in sys.path:
        sys.path.insert(0, str(service_root))
    return str(importlib.import_module("extractor").SYSTEM_PROMPT_V21)


_PILOT_SOURCES = {
    "AA25-203A": ("aa25-203a/AA25-203A-interlock-stix.json", "aa25-203a.txt", "aa25-203a.haiku-heldout-20260824.json"),
    "AA25-239A": ("aa25-239a/AA25-239A.stix_.json", "aa25-239a.txt", "aa25-239a.haiku-heldout-20260824.json"),
    "AA26-097A": ("aa26-097a/AA26-097A.stix_.json", "aa26-097a.txt", "aa26-097a.haiku-heldout-20260824.json"),
    "AA26-204A": ("aa26-204a/AA26-204A.stix_.json", "aa26-204a.txt", "aa26-204a.haiku-devrun2-20260818.json"),
}


def _historical_prediction(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Adapt legacy bare entity arrays to Task 5's explicit final-output contract."""
    entities = raw.get("entities")
    relationships = raw.get("relationships")
    if not isinstance(entities, list) or not isinstance(relationships, list):
        raise ExecutionIntegrityError("historical pilot output must contain entity and relationship arrays")
    accepted_iocs = [
        {"type": row.get("ioc_type"), "value": row.get("value")}
        for row in entities
        if isinstance(row, Mapping) and str(row.get("type", "")).casefold() == "indicator"
    ]
    return {
        "unique_iocs": [], "accepted_iocs": accepted_iocs, "technique_keywords": [],
        "threat_actors": [], "targeted_sectors": [], "malware_families": [],
        "targeted_countries": [], "exploited_cves": [], "victim_technologies": [],
        "campaign_summary": "", "v2_entities": entities, "v2_relationships": relationships,
    }


def write_pilot(evidence: Path | str | object, *, corpus_root: Path | None = None) -> dict[str, Any]:
    """Write a four-document comparator diagnostic without invoking a model."""
    root = _root(evidence)
    target = _path(root, PILOT_NAME)
    if target.exists():
        raise FileExistsError(f"refusing to overwrite {target}")
    corpus = corpus_root or _source_root() / "corpus"
    equivalences = load_equivalences(root.parent / "config" / "cisa-equivalences.v1.json")
    rows: list[dict[str, Any]] = []
    for code, (stix_relative, text_name, output_name) in sorted(_PILOT_SOURCES.items()):
        stix = corpus / stix_relative
        text = corpus / "eval" / text_name
        output = corpus / "eval" / "runs" / output_name
        bundle = load_json(stix)
        source = text.read_text(encoding="utf-8")
        prediction_output = _historical_prediction(load_json(output))
        reference = canonicalize_bundle(code, bundle, source)
        prediction = canonicalize_prediction(code, prediction_output, stage="final")
        match = match_entities(reference.entities, prediction.entities, equivalences)
        rows.append({
            "code": code, "stix_sha256": sha256_file(stix), "text_sha256": sha256_file(text),
            "output_sha256": sha256_file(output), "reference_entities": len(reference.entities),
            "prediction_entities": len(prediction.entities), "match_layers": {
                "exact": match.exact_tp, "equivalent": match.equivalent_tp,
            }, "pending_pairs": len(match.pending),
        })
    pilot = {
        "schema_version": 1, "kind": "cisa_historical_comparator_pilot", "documents": rows,
        "historical_metadata_untrusted": True,
        "provenance_notice": "Historical bare outputs lack trustworthy model, prompt, and status metadata; this validates comparator behavior and does not reproduce a sealed numerical baseline.",
        "final_metrics_affected": False, "opencti_writes": 0,
    }
    write_new_json(target, pilot)
    return pilot


def _validate_pilot(root: Path) -> None:
    try:
        pilot = load_json(_path(root, PILOT_NAME))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ExecutionIntegrityError("valid pilot is required before pre-run verification") from error
    if (
        pilot.get("kind") != "cisa_historical_comparator_pilot"
        or pilot.get("historical_metadata_untrusted") is not True
        or pilot.get("final_metrics_affected") is not False
        or pilot.get("opencti_writes") != 0
        or not isinstance(pilot.get("documents"), list)
        or len(pilot["documents"]) != 4
    ):
        raise ExecutionIntegrityError("pilot is incomplete or has invalid provenance")
    corpus = _source_root() / "corpus"
    rows = {row.get("code"): row for row in pilot["documents"] if isinstance(row, Mapping)}
    if set(rows) != set(_PILOT_SOURCES):
        raise ExecutionIntegrityError("pilot has extra or missing historical documents")
    for code, (stix_relative, text_name, output_name) in _PILOT_SOURCES.items():
        row = rows[code]
        expected = {
            "stix_sha256": sha256_file(corpus / stix_relative),
            "text_sha256": sha256_file(corpus / "eval" / text_name),
            "output_sha256": sha256_file(corpus / "eval" / "runs" / output_name),
        }
        if any(row.get(key) != value for key, value in expected.items()):
            raise ExecutionIntegrityError(f"pilot historical source drift for {code}")


def _validate_no_execution_artifacts(root: Path) -> None:
    if (root / RESULTS_NAME).exists():
        raise ExecutionIntegrityError("pre-run verification requires zero result artifacts")
    for directory in (root / "runs", root / "attempts"):
        if directory.exists() and any(path.is_file() for path in directory.rglob("*")):
            raise ExecutionIntegrityError("pre-run verification requires zero execution artifacts")


def _attempt_paths(root: Path) -> list[Path]:
    attempts = root / "attempts"
    return sorted(attempts.glob("*.attempt-*.json")) if attempts.exists() else []


def _validate_complete(root: Path, freeze: Mapping[str, Any], manifest: Mapping[str, Any]) -> None:
    runs = root / "runs"
    expected = {f"{row['code']}.run-{repeat}.json" for row in freeze["documents"] for repeat in REPETITIONS}
    actual = {path.name for path in runs.glob("*.run-*.json")} if runs.exists() else set()
    if actual != expected:
        raise ExecutionIntegrityError(f"unexpected final identities; missing={sorted(expected - actual)}, extra={sorted(actual - expected)}")
    if runs.exists() and {path.name for path in runs.iterdir() if path.is_file()} != {*expected, "smoke.json"}:
        raise ExecutionIntegrityError("unexpected final artifact")
    freeze_digest = str(manifest["freeze_sha256"])
    documents = {str(row["code"]): row for row in freeze["documents"]}
    attempts: dict[str, dict[str, Any]] = {}
    for path in _attempt_paths(root):
        try:
            attempt = load_json(path)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            raise ExecutionIntegrityError(f"corrupt attempt record {path.name}") from error
        if (
            attempt.get("freeze_sha256") != freeze_digest or attempt.get("opencti_writes") != 0
            or attempt.get("status") not in {"success", "error"}
            or attempt.get("provider") != EXPECTED_PROVIDER or attempt.get("model") != EXPECTED_MODEL
            or attempt.get("aws_region") != EXPECTED_REGION or attempt.get("schema_version") != 2
            or not isinstance(attempt.get("attempt"), int) or attempt["attempt"] < 1
        ):
            raise ExecutionIntegrityError(f"attempt configuration drift: {path.name}")
        stem = path.name.rsplit(".attempt-", 1)[0]
        if stem == "smoke":
            if attempt.get("kind") != "cisa_bedrock_smoke_attempt":
                raise ExecutionIntegrityError(f"smoke attempt identity is invalid: {path.name}")
        else:
            code, marker, repetition = stem.partition(".run-")
            document = documents.get(code)
            if (
                marker != ".run-" or repetition not in {"1", "2", "3"}
                or attempt.get("kind") != "cisa_document_attempt" or attempt.get("document") != code
                or attempt.get("repetition") != int(repetition) or document is None
                or attempt.get("input_sha256") != document["text_sha256"]
                or attempt.get("reference_sha256") != document["reference_sha256"]
            ):
                raise ExecutionIntegrityError(f"attempt identity is invalid: {path.name}")
            if attempt["status"] == "success" and (
                not isinstance(attempt.get("raw_model_output"), Mapping)
                or not isinstance(attempt.get("tim_output"), Mapping)
                or any(key not in attempt["raw_model_output"] for key in _RAW_KEYS)
                or any(key not in attempt["tim_output"] for key in _TIM_KEYS)
            ):
                raise ExecutionIntegrityError(f"successful attempt output is incomplete: {path.name}")
            if attempt["status"] == "error" and not all(
                isinstance(attempt.get(key), str) and attempt[key] for key in ("error_type", "error")
            ):
                raise ExecutionIntegrityError(f"failed attempt error is incomplete: {path.name}")
        attempts[path.name] = attempt
    if (root / "attempts").exists() and len(attempts) != len(list((root / "attempts").iterdir())):
        raise ExecutionIntegrityError("unexpected attempt artifact")
    for name in sorted(expected):
        record = load_json(runs / name)
        attempt_name = record.get("attempt_record")
        if (
            record.get("schema_version") != 2 or record.get("kind") != "cisa_document_extraction"
            or record.get("status") != "success" or record.get("document") != name.rsplit(".run-", 1)[0]
            or record.get("freeze_sha256") != freeze_digest or record.get("opencti_writes") != 0
            or record.get("provider") != EXPECTED_PROVIDER or record.get("model") != EXPECTED_MODEL
            or record.get("aws_region") != EXPECTED_REGION or record.get("source_type") != "advisory"
            or not isinstance(attempt_name, str) or attempt_name not in attempts
            or not isinstance(record.get("raw_model_output"), Mapping) or not isinstance(record.get("tim_output"), Mapping)
            or any(key not in record["raw_model_output"] for key in _RAW_KEYS)
            or any(key not in record["tim_output"] for key in _TIM_KEYS)
        ):
            raise ExecutionIntegrityError(f"invalid final record {name}")
        attempt = attempts[attempt_name]
        if (
            attempt.get("status") != "success" or attempt.get("document") != record.get("document")
            or attempt.get("repetition") != record.get("repetition")
            or record.get("attempt_sha256") != sha256_file(root / "attempts" / attempt_name)
        ):
            raise ExecutionIntegrityError(f"final record {name} does not bind a successful matching attempt")
        expected_final = {
            **attempt,
            "kind": "cisa_document_extraction",
            "attempt_record": attempt_name,
            "attempt_sha256": sha256_file(root / "attempts" / attempt_name),
        }
        if canonical_bytes(record) != canonical_bytes(expected_final):
            raise ExecutionIntegrityError(f"final record {name} differs from its bound attempt")
    smoke = root / "runs" / "smoke.json"
    if not smoke.is_file():
        raise ExecutionIntegrityError("successful schema-v2 smoke is required")
    row = load_json(smoke)
    smoke_attempt = row.get("attempt_record")
    if (
        row.get("schema_version") != 2 or row.get("kind") != "cisa_bedrock_smoke"
        or row.get("status") != "success" or row.get("freeze_sha256") != freeze_digest
        or row.get("opencti_writes") != 0 or row.get("provider") != EXPECTED_PROVIDER
        or row.get("model") != EXPECTED_MODEL or row.get("aws_region") != EXPECTED_REGION
        or not isinstance(smoke_attempt, str) or smoke_attempt not in attempts
        or row.get("attempt_sha256") != sha256_file(root / "attempts" / str(smoke_attempt))
        or not isinstance(row.get("response_text"), str) or not row["response_text"]
        or not isinstance(row.get("usage"), Mapping)
    ):
        raise ExecutionIntegrityError("successful same-configuration smoke is required")
    smoke_attempt_row = attempts[str(smoke_attempt)]
    expected_smoke = {
        **smoke_attempt_row,
        "kind": "cisa_bedrock_smoke",
        "attempt_record": smoke_attempt,
        "attempt_sha256": sha256_file(root / "attempts" / str(smoke_attempt)),
    }
    if canonical_bytes(row) != canonical_bytes(expected_smoke):
        raise ExecutionIntegrityError("successful smoke differs from its bound attempt")
    result = root / RESULTS_NAME
    if not result.is_file():
        raise ExecutionIntegrityError("complete verification requires structural results")
    try:
        scored = load_json(result)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ExecutionIntegrityError("results artifact is corrupt") from error
    integrity = scored.get("integrity")
    method = scored.get("method")
    final_digests = {name: sha256_file(runs / name) for name in sorted(expected)}
    if (
        scored.get("schema_version") != 2 or not isinstance(integrity, Mapping) or not isinstance(method, Mapping)
        or integrity.get("documents") != 24 or integrity.get("successful_runs") != 72
        or integrity.get("opencti_writes") != 0 or integrity.get("freeze_sha256") != freeze_digest
        or integrity.get("final_record_sha256") != final_digests
        or method.get("bootstrap_seed") != 20260830 or method.get("bootstrap_samples") != 10000
        or method.get("human_adjudication") != "none"
        or method.get("tim_only_interpretation") != "unassessed"
        or scored.get("primary", {}).get("metric") != "structural_cosine_macro_by_document"
    ):
        raise ExecutionIntegrityError("results artifact does not bind the complete final population")
    from .cisa_score import ScoreIntegrityError, score_experiment

    try:
        recomputed = score_experiment(root)
    except (OSError, ValueError, ScoreIntegrityError, json.JSONDecodeError) as error:
        raise ExecutionIntegrityError("results artifact cannot be recomputed from final evidence") from error
    if canonical_bytes(scored) != canonical_bytes(recomputed):
        raise ExecutionIntegrityError("results artifact differs from recomputed final evidence")


def verify_execution(evidence: Path | str | object, *, stage: str) -> dict[str, Any]:
    """Fail closed at pre-run or complete stage without scoring partial evidence."""
    if stage not in {"pre-run", "complete"}:
        raise ValueError("stage must be pre-run or complete")
    root = _root(evidence)
    freeze, manifest = _validate_freeze(root)
    _validate_pilot(root)
    if stage == "pre-run":
        _validate_no_execution_artifacts(root)
    else:
        _validate_complete(root, freeze, manifest)
    return {"stage": stage, "freeze_sha256": manifest["freeze_sha256"], "opencti_writes": 0}
