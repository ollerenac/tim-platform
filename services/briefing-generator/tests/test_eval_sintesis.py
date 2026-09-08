"""Comprobaciones del arné de evaluación del sintetizador.

La fidelidad nominal se calibra contra verdad conocida: las 20 corridas
congeladas de agosto de 2026 emiten «Darkhosel» en siete salidas y
«PittyPiger»/«PittyPig» en cuatro, once corridas en total repartidas seis
directas y cinco de pipeline. Si el umbral de corrupción deja de reproducir
ese reparto, la métrica cambió de significado.
"""
import json
import sys
from pathlib import Path

import pytest

_SERVICE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_SERVICE))
# El corpus congelado vive en el repositorio, no en la imagen: dentro del
# contenedor estas comprobaciones no aplican y el módulo entero se omite.
_CORPUS = _SERVICE.parent.parent / "corpus" / "eval" / "sintetizador"
if not _CORPUS.is_dir():
    pytest.skip("corpus congelado no disponible (imagen de servicio)",
                allow_module_level=True)

from eval_sintesis import context_entities, measure, name_fidelity, summarize  # noqa: E402


@pytest.fixture(scope="module")
def frozen():
    context = (_CORPUS / "ctx-72h.txt").read_text(encoding="utf-8")
    runs = {}
    for mode, fname in (("raw", "runs-haiku-raw.jsonl"), ("system", "runs-haiku-system.jsonl")):
        runs[mode] = [json.loads(line) for line in (_CORPUS / fname).read_text().splitlines() if line.strip()]
    return context, runs


def test_name_fidelity_splits_exact_corrupt_and_missing():
    entities = ["Darkhotel", "PittyTiger", "APT29"]
    text = "The platform tracks Darkhosel and APT29 in its knowledge base."
    result = name_fidelity(text, entities)
    assert [n for n in result["exactos"]] == ["APT29"]
    assert result["corruptos"] == [("Darkhotel", "Darkhosel")]
    assert result["omitidos"] == ["PittyTiger"]


def test_frozen_runs_reproduce_known_corruption_split(frozen):
    context, runs = frozen
    entities = context_entities(context)
    flagged = {}
    for mode, rows in runs.items():
        flagged[mode] = sum(
            1 for r in rows if name_fidelity(r["texto"], entities)["corruptos"]
        )
    assert flagged == {"raw": 6, "system": 5}, flagged


def test_frozen_runs_name_the_two_known_corruptions(frozen):
    context, runs = frozen
    entities = context_entities(context)
    emitted = {
        emitido
        for rows in runs.values()
        for r in rows
        for _, emitido in name_fidelity(r["texto"], entities)["corruptos"]
    }
    assert emitted == {"Darkhosel", "PittyPiger", "PittyPig"}, emitted


def test_fidelity_partitions_every_context_entity(frozen):
    """Las tres clases son exhaustivas y disjuntas: exacto + corrupto + omitido = total.

    Los registros sellados llevan el esquema viejo (`cobertura`, `hechos_totales`,
    `tasa_anclaje: 1.0` con denominador cero), así que la comparación se hace
    contra la remedición, nunca contra el campo almacenado.
    """
    context, runs = frozen
    for rows in runs.values():
        for r in rows:
            m = measure(r["texto"], context)
            total = m["nombres_exactos"] + m["nombres_corruptos"] + m["nombres_omitidos"]
            assert total == m["entidades_contexto"]
            assert m["cobertura_nominal"] == round(m["nombres_exactos"] / m["entidades_contexto"], 4)


def test_summary_reports_corrupt_runs_over_total(frozen):
    context, runs = frozen
    measured = [measure(r["texto"], context) for r in runs["raw"]]
    summary = summarize(measured, provider="haiku", mode="raw")
    assert summary["corridas_con_nombre_corrupto"] == "6/10"
    assert summary["cobertura_nominal_media"] == 0.71


def test_markdown_compliance_is_measured(frozen):
    """El prompt prohíbe markdown; el incumplimiento es comprobable sin juicio humano."""
    context, runs = frozen
    flagged = {
        mode: sum(1 for r in rows if not measure(r["texto"], context)["formato_sin_markdown"])
        for mode, rows in runs.items()
    }
    assert flagged == {"raw": 8, "system": 9}, flagged


def test_thousands_separator_does_not_break_the_total_count():
    """Regresión 2026-08-26: «1,071» no casaba con el total 1071 y las diez
    corridas se puntuaban como error cuando todas lo reportaban bien."""
    context = (
        "IOC activity in period: 1071 indicators total (807 newly created, "
        "264 pre-existing ones re-updated).\n"
    )
    text = (
        "The platform detected 1,071 indicators of compromise, comprising 807 "
        "newly created indicators and 264 updates to pre-existing ones."
    )
    result = measure(text, context)
    assert result["conteo_total_correcto"] is True
    assert result["conteo_nuevos_correcto"] is True


def test_spelled_out_total_and_zero_new_count_are_recognized():
    """Regression: Haiku writes small counts as words instead of digits."""
    context = (
        "IOC activity in period: 4 indicators total (0 newly created, "
        "4 pre-existing ones re-updated).\n"
    )
    text = (
        "The platform identified four indicators of compromise, all of which "
        "were pre-existing. No new indicators were created."
    )

    result = measure(text, context)

    assert result["conteo_total_correcto"] is True
    assert result["conteo_nuevos_correcto"] is True


def test_new_word_count_and_zero_preexisting_derive_the_total():
    """A complete partition states the total even when no total label is repeated."""
    context = (
        "IOC activity in period: 70 indicators total (66 newly created, "
        "4 pre-existing ones re-updated).\n"
    )
    text = (
        "The platform detected seventy indicators of compromise, with "
        "sixty-six newly generated and four pre-existing indicators updated."
    )

    result = measure(text, context)

    assert result["conteo_total_correcto"] is True
    assert result["conteo_nuevos_correcto"] is True


def test_new_count_plus_explicit_zero_preexisting_derives_total():
    context = (
        "IOC activity in period: 2 indicators total (2 newly created, "
        "0 pre-existing ones re-updated).\n"
    )
    text = (
        "Two newly created indicators of compromise were detected. "
        "No pre-existing indicators were updated."
    )

    result = measure(text, context)

    assert result["conteo_total_correcto"] is True
    assert result["conteo_nuevos_correcto"] is True


def test_spelled_out_wrong_total_is_rejected():
    context = (
        "IOC activity in period: 4 indicators total (0 newly created, "
        "4 pre-existing ones re-updated).\n"
    )
    text = "The platform identified five indicators of compromise and no new indicators."

    result = measure(text, context)

    assert result["conteo_total_correcto"] is False


def test_conjunction_between_partition_counts_is_not_read_as_zero():
    context = (
        "IOC activity in period: 56 indicators total (49 newly created, "
        "7 pre-existing ones re-updated).\n"
    )
    text = (
        "The platform detected 56 indicators of compromise, comprising "
        "49 newly identified and 7 previously tracked indicators. "
        "The confidence levels and volume of newly emergent indicators warrant "
        "continued monitoring."
    )

    result = measure(text, context)

    assert result["conteo_total_correcto"] is True
    assert result["conteo_nuevos_correcto"] is True
