#!/usr/bin/env python3
"""Remeasure the fixed-P3 experiment without rewriting its signed raw evidence.

The run was captured with the evaluator available on the VPS.  This analysis is
deliberately derived: it reads the frozen contexts and outputs, applies a named
evaluator version, and records hashes for both layers.  ``results.jsonl`` is
never opened for writing.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path
from typing import Callable, Iterable


SCHEMA_VERSION = 2
ANALYSIS_ID = "PE-5-confirmatory-fixed-P3-remeasurement"
COUNT_RE = re.compile(
    r"IOC activity in period:\s*(\d+) indicators total\s*"
    r"\((\d+) newly created,\s*(-?\d+) pre-existing ones re-updated\)"
)
STAGES = ("draft", "final")
STRATA = ("confirmatory", "replication")
REVIEW_MARKER = "[Verificación de anclaje]"
MANIFEST_LINE_RE = re.compile(r"^([0-9a-f]{64})\s+(.+)$")


def sha256_path(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict]:
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"JSONL inválido en {path}:{line_number}") from exc
    return rows


def _verify_export_manifest(evidence_root: Path) -> str | None:
    """Verify every file in the VPS export when its signed inventory is present."""
    manifest_path = evidence_root / "SHA256SUMS"
    if not manifest_path.is_file():
        return None
    seen = set()
    for line_number, line in enumerate(
        manifest_path.read_text(encoding="utf-8").splitlines(), 1
    ):
        if not line.strip():
            continue
        match = MANIFEST_LINE_RE.fullmatch(line)
        if not match:
            raise RuntimeError(f"línea inválida en manifiesto de exportación: {line_number}")
        expected, relative = match.groups()
        relative = relative.removeprefix("./")
        candidate = (evidence_root / relative).resolve()
        if evidence_root.resolve() not in candidate.parents:
            raise RuntimeError("ruta fuera del paquete en manifiesto de exportación")
        if relative in seen or not candidate.is_file():
            raise RuntimeError(f"miembro inválido en manifiesto de exportación: {relative}")
        seen.add(relative)
        if sha256_path(candidate) != expected:
            raise RuntimeError(f"deriva respecto del manifiesto de exportación: {relative}")
    if not {"run/results.jsonl", "run/protocol.json"} <= seen:
        raise RuntimeError("el manifiesto de exportación omite resultados o protocolo")
    return sha256_path(manifest_path)


def _context_path(run_dir: Path, block: str, suffix: str) -> Path:
    return run_dir / "contexts" / f"{block.replace(' ', 'T')}.{suffix}"


def _load_and_validate(evidence_root: Path) -> tuple[dict, list[dict], dict[str, str]]:
    run_dir = evidence_root / "run"
    protocol_path = run_dir / "protocol.json"
    results_path = run_dir / "results.jsonl"
    protocol = _read_json(protocol_path)
    rows = _read_jsonl(results_path)

    hours = protocol.get("hours", [])
    repetitions = protocol.get("repetitions")
    strata = protocol.get("strata", {})
    if not hours or len(hours) != len(set(hours)):
        raise RuntimeError("el protocolo no contiene bloques únicos")
    if not isinstance(repetitions, int) or repetitions < 1:
        raise RuntimeError("número de repeticiones inválido")
    if set(strata) != set(hours) or not set(strata.values()) <= set(STRATA):
        raise RuntimeError("estratos incompletos o desconocidos")

    expected_keys = {
        (block, repetition)
        for block in hours
        for repetition in range(1, repetitions + 1)
    }
    observed_keys = {(row.get("block"), row.get("repetition")) for row in rows}
    if observed_keys != expected_keys or len(rows) != len(expected_keys):
        raise RuntimeError("results.jsonl no contiene exactamente las corridas del protocolo")

    contexts = {}
    for block in hours:
        text_path = _context_path(run_dir, block, "txt")
        meta_path = _context_path(run_dir, block, "json")
        context = text_path.read_text(encoding="utf-8")
        metadata = _read_json(meta_path)
        context_hash = hashlib.sha256(context.encode("utf-8")).hexdigest()
        if metadata.get("block") != block or metadata.get("context_sha256") != context_hash:
            raise RuntimeError(f"contexto congelado inválido para {block}")
        contexts[block] = context

    for row in rows:
        block = row["block"]
        if row.get("stratum") != strata[block]:
            raise RuntimeError(f"estrato incorrecto para {block}")
        if row.get("context_sha256") != hashlib.sha256(
            contexts[block].encode("utf-8")
        ).hexdigest():
            raise RuntimeError(f"hash de contexto incorrecto para {block}")
        for key in ("provider", "model", "prompt_sha256"):
            if row.get(key) != protocol.get(key):
                raise RuntimeError(f"{key} no coincide con el protocolo para {block}")
        retried = bool(row.get("verifier", {}).get("retried"))
        if row.get("llm_calls") != 1 + int(retried):
            raise RuntimeError(f"número de llamadas incorrecto para {block}")
        for stage in STAGES:
            if not isinstance(row.get(stage, {}).get("text"), str):
                raise RuntimeError(f"texto {stage} ausente para {block}")

    return protocol, rows, contexts


def _count_design(context: str) -> str:
    match = COUNT_RE.search(context)
    if not match:
        raise RuntimeError("el contexto no contiene la partición total/nuevos esperada")
    total, new, preexisting = map(int, match.groups())
    if new < 0 or preexisting < 0 or new > total or new + preexisting != total:
        return "invalid_partition"
    if new in (0, total):
        return "boundary"
    return "discriminating_valid"


def _ratio(successes: int, total: int) -> str | None:
    return f"{successes}/{total}" if total else None


def _rounded(value: float | None) -> float | None:
    return round(value, 4) if value is not None else None


def _stage_summary(records: list[dict], stage: str) -> dict:
    metrics = [record[stage]["metrics"] for record in records]
    emitted = sum(value["identificadores_totales"] for value in metrics)
    anchored = sum(value["identificadores_anclados"] for value in metrics)

    count_all = [value.get("conteos_correctos_conjuntos") for value in metrics]
    discriminating = [
        record[stage]["metrics"].get("conteos_correctos_conjuntos")
        for record in records
        if record["count_design"] == "discriminating_valid"
    ]
    exact = sum(value.get("nombres_exactos", 0) for value in metrics)
    opportunities = sum(value.get("entidades_contexto", 0) for value in metrics)
    format_values = [value.get("formato_sin_markdown") for value in metrics]
    words = [value.get("palabras") for value in metrics if value.get("palabras") is not None]

    non_tid_emitted = sum(len(record[stage]["non_tid_facts"]) for record in records)
    non_tid_unanchored = sum(
        len(record[stage]["non_tid_unanchored"]) for record in records
    )
    non_tid_evaluable = sum(bool(record[stage]["non_tid_facts"]) for record in records)
    non_tid_instruction_evaluable = sum(
        len(record["available_non_tid_facts"]) >= 3 for record in records
    )
    non_tid_at_least_three_anchored = sum(
        len(
            set(record[stage]["non_tid_facts"])
            - set(record[stage]["non_tid_unanchored"])
        ) >= 3
        for record in records
        if len(record["available_non_tid_facts"]) >= 3
    )

    by_block = defaultdict(list)
    for record in records:
        by_block[record["block"]].append(set(record[stage]["facts"]))
    jaccards = []
    exact_pairs = 0
    pairs = 0
    for block_sets in by_block.values():
        for left, right in itertools.combinations(block_sets, 2):
            pairs += 1
            union = left | right
            if not union:
                continue
            jaccards.append(len(left & right) / len(union))
            exact_pairs += left == right

    return {
        "anchor": {
            "evaluable_runs": sum(value["identificadores_totales"] > 0 for value in metrics),
            "emitted": emitted,
            "anchored": anchored,
            "unanchored": emitted - anchored,
            "rate": _rounded(anchored / emitted if emitted else None),
        },
        "counts": {
            "joint": _ratio(sum(value is True for value in count_all), len(count_all)),
            "discriminating_valid": _ratio(
                sum(value is True for value in discriminating), len(discriminating)
            ),
        },
        "names": {
            "exact": exact,
            "opportunities": opportunities,
            "exact_rate": _rounded(exact / opportunities if opportunities else None),
        },
        "format": {
            "plain_prose": _ratio(
                sum(value is True for value in format_values), len(format_values)
            ),
        },
        "detectable_non_tid_values": {
            "evaluable_runs": non_tid_evaluable,
            "instruction_success": _ratio(
                non_tid_at_least_three_anchored, non_tid_instruction_evaluable
            ),
            "emitted": non_tid_emitted,
            "anchored": non_tid_emitted - non_tid_unanchored,
            "unanchored": non_tid_unanchored,
            "anchor_rate": _rounded(
                (non_tid_emitted - non_tid_unanchored) / non_tid_emitted
                if non_tid_emitted else None
            ),
            "scope_note": "excludes ATT&CK TIDs; detector does not recognize file hashes",
        },
        "words": {"mean": _rounded(statistics.mean(words) if words else None)},
        "repeatability": {
            "pairs": pairs,
            "nonempty_pairs": len(jaccards),
            "exact_nonempty_pairs": exact_pairs,
            "mean_jaccard": _rounded(statistics.mean(jaccards) if jaccards else None),
            "median_jaccard": _rounded(statistics.median(jaccards) if jaccards else None),
        },
    }


def _stratum_summary(records: list[dict]) -> dict:
    blocks = sorted({record["block"] for record in records})
    count_classes = {block: records_for_block[0]["count_design"] for block in blocks
                     if (records_for_block := [r for r in records if r["block"] == block])}
    return {
        "blocks": len(blocks),
        "runs": len(records),
        "retries": sum(bool(record["retried"]) for record in records),
        "actual_llm_calls": sum(record["llm_calls"] for record in records),
        "count_design": {
            "boundary_blocks": sum(value == "boundary" for value in count_classes.values()),
            "discriminating_valid_blocks": sum(
                value == "discriminating_valid" for value in count_classes.values()
            ),
            "invalid_partition_blocks": sum(
                value == "invalid_partition" for value in count_classes.values()
            ),
        },
        "stages": {stage: _stage_summary(records, stage) for stage in STAGES},
    }


def analyze_experiment(
    evidence_root: Path,
    *,
    measure_fn: Callable[[str, str], dict],
    facts_fn: Callable[[str], Iterable[tuple[str, str]]],
    evaluator_version: str,
    evaluator_sha256: str,
    anchor_sha256: str,
    analyzer_sha256: str | None = None,
) -> dict:
    evidence_root = Path(evidence_root)
    export_manifest_sha256 = _verify_export_manifest(evidence_root)
    protocol, rows, contexts = _load_and_validate(evidence_root)
    measured = []
    for row in rows:
        record = {
            "block": row["block"],
            "stratum": row["stratum"],
            "repetition": row["repetition"],
            "llm_calls": row["llm_calls"],
            "retried": bool(row.get("verifier", {}).get("retried")),
            "count_design": _count_design(contexts[row["block"]]),
            "available_non_tid_facts": sorted({
                f"{kind}:{value}"
                for kind, value in facts_fn(contexts[row["block"]])
                if kind != "tid"
            }),
        }
        for stage in STAGES:
            text = row[stage]["text"]
            metrics = measure_fn(text, contexts[row["block"]])
            facts = sorted({f"{kind}:{value}" for kind, value in facts_fn(text)})
            non_tid_facts = [value for value in facts if not value.startswith("tid:")]
            unanchored = list(metrics.get("unanchored", []))
            record[stage] = {
                "metrics": metrics,
                "facts": facts,
                "non_tid_facts": non_tid_facts,
                "non_tid_unanchored": [
                    value for value in unanchored if not value.startswith("tid:")
                ],
                "review_marker": REVIEW_MARKER in text,
            }
        measured.append(record)

    initial_calls = len(rows)
    actual_calls = sum(row["llm_calls"] for row in rows)
    report = {
        "schema_version": SCHEMA_VERSION,
        "analysis_id": ANALYSIS_ID,
        "provenance": {
            "source_results_sha256": sha256_path(evidence_root / "run/results.jsonl"),
            "source_protocol_sha256": sha256_path(evidence_root / "run/protocol.json"),
            "evaluator_version": evaluator_version,
            "evaluator_sha256": evaluator_sha256,
            "anchor_sha256": anchor_sha256,
            "analyzer_sha256": analyzer_sha256,
            "export_manifest_sha256": export_manifest_sha256,
            "raw_outputs_modified": False,
        },
        "runtime": {
            "provider": protocol["provider"],
            "model": protocol["model"],
            "prompt_sha256": protocol["prompt_sha256"],
            "repetitions_per_block": protocol["repetitions"],
        },
        "execution": {
            "blocks": len(protocol["hours"]),
            "runs": len(rows),
            "initial_llm_calls": initial_calls,
            "retry_calls": actual_calls - initial_calls,
            "actual_llm_calls": actual_calls,
            "stage_measurements": len(rows) * len(STAGES),
        },
        "strata": {
            stratum: _stratum_summary([r for r in measured if r["stratum"] == stratum])
            for stratum in STRATA
        },
        "pooled": _stratum_summary(measured),
        "final_unanchored": [
            {
                "block": record["block"],
                "stratum": record["stratum"],
                "repetition": record["repetition"],
                "identifiers": record["final"]["metrics"].get("unanchored", []),
                "published_with_review_marker": record["final"]["review_marker"],
            }
            for record in measured
            if record["final"]["metrics"].get("unanchored")
        ],
        "remeasured_runs": measured,
    }
    return report


def _write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    project_root = Path(__file__).resolve().parents[4]
    service_dir = project_root / "services/briefing-generator"
    sys.path.insert(0, str(service_dir))
    from anchor import _hard_facts
    from eval_sintesis import EVALUATOR_VERSION, measure

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=project_root / "corpus/eval/sintetizador/experimento-p3-confirmatorio",
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    output = args.output or args.evidence_root / "analysis.v2.json"
    report = analyze_experiment(
        args.evidence_root,
        measure_fn=measure,
        facts_fn=_hard_facts,
        evaluator_version=EVALUATOR_VERSION,
        evaluator_sha256=sha256_path(service_dir / "eval_sintesis.py"),
        anchor_sha256=sha256_path(service_dir / "anchor.py"),
        analyzer_sha256=sha256_path(Path(__file__)),
    )
    _write_json(output, report)
    compact = {key: value for key, value in report.items() if key != "remeasured_runs"}
    print(json.dumps(compact, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
