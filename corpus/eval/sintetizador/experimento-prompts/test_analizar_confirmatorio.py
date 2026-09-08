import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).with_name("analizar_confirmatorio.py")
SPEC = importlib.util.spec_from_file_location("analizar_confirmatorio", SCRIPT)
analysis = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(analysis)


def _write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _build_fixture(root):
    hours = ["2026-09-01 10", "2026-08-01 10"]
    protocol = {
        "hours": hours,
        "repetitions": 3,
        "strata": {
            hours[0]: "confirmatory",
            hours[1]: "replication",
        },
        "provider": "bedrock",
        "model": "haiku-fixed",
        "prompt_sha256": "prompt-hash",
    }
    _write_json(root / "run/protocol.json", protocol)
    rows = []
    for block, stratum, total, new in (
        (hours[0], "confirmatory", 7, 2),
        (hours[1], "replication", 4, 0),
    ):
        context = (
            f"IOC activity in period: {total} indicators total "
            f"({new} newly created, {total-new} pre-existing ones re-updated).\n"
        )
        slug = block.replace(" ", "T")
        context_path = root / f"run/contexts/{slug}.txt"
        context_path.parent.mkdir(parents=True, exist_ok=True)
        context_path.write_text(context, encoding="utf-8")
        context_hash = analysis.sha256_path(context_path)
        _write_json(
            root / f"run/contexts/{slug}.json",
            {"block": block, "context_sha256": context_hash, "source": {}},
        )
        for repetition in range(1, 4):
            draft = "a.example T1001" if repetition < 3 else "b.example T1001"
            final = "a.example b.example T1001"
            rows.append({
                "block": block,
                "stratum": stratum,
                "repetition": repetition,
                "provider": "bedrock",
                "model": "haiku-fixed",
                "prompt_sha256": "prompt-hash",
                "context_sha256": context_hash,
                "llm_calls": 2 if repetition == 1 else 1,
                "verifier": {"retried": repetition == 1},
                "draft": {"text": draft, "metrics": {"legacy": True}},
                "final": {"text": final, "metrics": {"legacy": True}},
            })
    (root / "run/results.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )
    return rows


def _measure(text, context):
    total = 2 if "b.example" in text else 1
    anchored = total if "b.example" in text else 0
    return {
        "identificadores_totales": total,
        "identificadores_anclados": anchored,
        "unanchored": [] if anchored == total else ["dominio:a.example"],
        "conteo_total_correcto": True,
        "conteo_nuevos_correcto": True,
        "conteos_correctos_conjuntos": True,
        "nombres_exactos": 3,
        "entidades_contexto": 4,
        "formato_sin_markdown": True,
        "palabras": len(text.split()),
    }


def _facts(text):
    values = []
    if "a.example" in text:
        values.append(("dominio", "a.example"))
    if "b.example" in text:
        values.append(("dominio", "b.example"))
    if "T1001" in text:
        values.append(("tid", "T1001"))
    return values


def test_analysis_remeasures_without_changing_the_signed_results(tmp_path):
    _build_fixture(tmp_path)
    results_path = tmp_path / "run/results.jsonl"
    before = results_path.read_bytes()

    report = analysis.analyze_experiment(
        tmp_path,
        measure_fn=_measure,
        facts_fn=_facts,
        evaluator_version="2.0.0",
        evaluator_sha256="eval-hash",
        anchor_sha256="anchor-hash",
    )

    assert results_path.read_bytes() == before
    assert report["provenance"]["source_results_sha256"] == analysis.sha256_path(results_path)
    assert report["provenance"]["evaluator_version"] == "2.0.0"
    assert report["execution"] == {
        "blocks": 2,
        "runs": 6,
        "initial_llm_calls": 6,
        "retry_calls": 2,
        "actual_llm_calls": 8,
        "stage_measurements": 12,
    }

    confirmatory = report["strata"]["confirmatory"]
    assert confirmatory["blocks"] == 1
    assert confirmatory["count_design"] == {
        "boundary_blocks": 0,
        "discriminating_valid_blocks": 1,
        "invalid_partition_blocks": 0,
    }
    assert confirmatory["stages"]["final"]["anchor"] == {
        "evaluable_runs": 3,
        "emitted": 6,
        "anchored": 6,
        "unanchored": 0,
        "rate": 1.0,
    }
    assert confirmatory["stages"]["final"]["counts"]["joint"] == "3/3"
    assert confirmatory["stages"]["final"]["counts"]["discriminating_valid"] == "3/3"
    assert confirmatory["stages"]["final"]["names"]["exact"] == 9
    assert confirmatory["stages"]["final"]["names"]["opportunities"] == 12
    assert confirmatory["stages"]["final"]["names"]["exact_rate"] == 0.75
    assert confirmatory["stages"]["final"]["repeatability"] == {
        "pairs": 3,
        "nonempty_pairs": 3,
        "exact_nonempty_pairs": 3,
        "mean_jaccard": 1.0,
        "median_jaccard": 1.0,
    }


def test_analysis_separates_boundary_and_invalid_count_inputs(tmp_path):
    rows = _build_fixture(tmp_path)
    # The replication fixture is a boundary case (zero new). Turn one context
    # into an invalid partition to ensure it is never reported as discriminating.
    block = "2026-08-01 10"
    slug = block.replace(" ", "T")
    context_path = tmp_path / f"run/contexts/{slug}.txt"
    context_path.write_text(
        "IOC activity in period: 4 indicators total (5 newly created, -1 pre-existing ones re-updated).\n",
        encoding="utf-8",
    )
    context_hash = analysis.sha256_path(context_path)
    meta_path = tmp_path / f"run/contexts/{slug}.json"
    meta = json.loads(meta_path.read_text())
    meta["context_sha256"] = context_hash
    _write_json(meta_path, meta)
    for row in rows:
        if row["block"] == block:
            row["context_sha256"] = context_hash
    (tmp_path / "run/results.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )

    report = analysis.analyze_experiment(
        tmp_path,
        measure_fn=_measure,
        facts_fn=_facts,
        evaluator_version="2.0.0",
        evaluator_sha256="eval-hash",
        anchor_sha256="anchor-hash",
    )

    assert report["strata"]["replication"]["count_design"] == {
        "boundary_blocks": 0,
        "discriminating_valid_blocks": 0,
        "invalid_partition_blocks": 1,
    }


def test_analysis_rejects_a_file_that_drifted_from_the_export_manifest(tmp_path):
    _build_fixture(tmp_path)
    results = tmp_path / "run/results.jsonl"
    (tmp_path / "SHA256SUMS").write_text(
        f"{analysis.sha256_path(results)}  ./run/results.jsonl\n",
        encoding="utf-8",
    )
    results.write_text(results.read_text() + "{}\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="manifiesto de exportación"):
        analysis.analyze_experiment(
            tmp_path,
            measure_fn=_measure,
            facts_fn=_facts,
            evaluator_version="2.0.0",
            evaluator_sha256="eval-hash",
            anchor_sha256="anchor-hash",
        )
