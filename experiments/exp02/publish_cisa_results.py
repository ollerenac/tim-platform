#!/usr/bin/env python3
"""Publish EXP-02 tables and SVGs from the verified results JSON only."""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import math
import random
from pathlib import Path
from statistics import mean
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[2]
RESULTS_RELATIVE = "experiments/exp02/cisa-evidence/results.v2.json"
REPORT_RELATIVE = "experiments/exp02/RESULTS-CISA-STIX.md"
FIGURE_DIR_RELATIVE = "experiments/exp02/cisa-evidence/figures"
PRIMARY_TYPES = ("indicator", "attack-pattern", "malware", "threat-actor", "vulnerability")
TYPE_LABELS = {
    "indicator": "Indicador",
    "attack-pattern": "Patrón ATT&CK",
    "malware": "Malware",
    "threat-actor": "Actor",
    "vulnerability": "Vulnerabilidad",
}


def _percentile(values: Sequence[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def bootstrap_mean(values: Sequence[float], *, seed: int, samples: int) -> dict[str, float]:
    """Reanalyze document rows using the experiment's frozen bootstrap method."""
    generator = random.Random(seed)
    estimates = [mean(generator.choice(values) for _ in values) for _ in range(samples)]
    return {
        "estimate": mean(values),
        "lower": _percentile(estimates, 0.025),
        "upper": _percentile(estimates, 0.975),
    }


def load_publication_data(results_path: Path | None = None) -> dict[str, Any]:
    path = results_path or ROOT / RESULTS_RELATIVE
    raw = path.read_bytes()
    results = json.loads(raw)
    integrity = results["integrity"]
    if (
        results.get("schema_version") != 2
        or results.get("experiment") != "exp02-cisa-structural-similarity"
        or integrity.get("documents") != 24
        or integrity.get("successful_runs") != 72
        or integrity.get("repetitions_per_document") != 3
        or integrity.get("opencti_writes") != 0
        or len(results.get("per_document", {})) != 24
        or len(results.get("runs", [])) != 72
    ):
        raise ValueError("results.v2.json no conserva el contrato EXP-02 verificado")

    seed = int(results["method"]["bootstrap_seed"])
    samples = int(results["method"]["bootstrap_samples"])
    document_rows = list(results["per_document"].values())
    overall: dict[str, Any] = {}
    for metric in ("cosine", "cisa_recall", "jaccard"):
        values = [
            row["scores"]["overall"]["equivalence_aware"][metric]
            for row in document_rows
            if row["scores"]["overall"]["equivalence_aware"][metric] is not None
        ]
        overall[metric] = bootstrap_mean(values, seed=seed, samples=samples)

    # The primary interval is part of the verified result and therefore takes
    # precedence over a publication-time replay of its bootstrap.
    overall["cosine"] = dict(results["primary"]["confidence_interval_95"])
    overall["cosine"]["estimate"] = results["primary"][
        "structural_cosine_macro_by_document"
    ]

    by_type = {}
    for entity_type in PRIMARY_TYPES:
        values = results["macro_by_document"][entity_type]["equivalence_aware"]
        intervals = results["confidence_intervals_by_type"][entity_type][
            "equivalence_aware"
        ]
        by_type[entity_type] = {
            metric: {
                "estimate": values[metric],
                "lower": intervals[metric]["lower"],
                "upper": intervals[metric]["upper"],
                "documents": values[f"documents_with_{metric}"],
            }
            for metric in ("cosine", "cisa_recall", "jaccard")
        }

    totals = {
        "citations_localized": sum(row["citations"]["localized"] for row in results["runs"]),
        "citations_total": sum(row["citations"]["total"] for row in results["runs"]),
        "raw_entities": sum(row["raw_to_final"]["v2_entities"]["raw"] for row in results["runs"]),
        "final_entities": sum(row["raw_to_final"]["v2_entities"]["kept"] for row in results["runs"]),
        "raw_relationships": sum(row["raw_to_final"]["v2_relationships"]["raw"] for row in results["runs"]),
        "final_relationships": sum(row["raw_to_final"]["v2_relationships"]["kept"] for row in results["runs"]),
        "raw_comparable": sum(row["raw_to_final"]["raw_comparable_entities"] for row in results["runs"]),
        "final_comparable": sum(row["raw_to_final"]["final_comparable_entities"] for row in results["runs"]),
        "matched": sum(row["scores"]["overall"]["equivalence_aware"]["counts"]["matched"] for row in results["runs"]),
        "cisa_only": sum(row["scores"]["overall"]["equivalence_aware"]["counts"]["cisa_only"] for row in results["runs"]),
        "tim_only_unassessed": results["diagnostics"]["tim_only_unassessed"],
    }
    if totals["citations_localized"] != totals["citations_total"]:
        raise ValueError("las citas finales no conservan localización completa")

    stability = dict(results["stability"]["document_median_pairwise_jaccard"])
    return {
        "results_sha256": hashlib.sha256(raw).hexdigest(),
        "freeze_sha256": integrity["freeze_sha256"],
        "model": integrity["model"],
        "provider": integrity["provider"],
        "aws_region": integrity["aws_region"],
        "documents": integrity["documents"],
        "runs": integrity["successful_runs"],
        "repetitions": integrity["repetitions_per_document"],
        "opencti_writes": integrity["opencti_writes"],
        "seed": seed,
        "samples": samples,
        "overall": overall,
        "by_type": by_type,
        "stability": stability,
        "citations": dict(results["citations"]["confidence_interval_95"]),
        "totals": totals,
        "relationships": results["relationships"],
        "diagnostic_population_counts": results["diagnostic_population_counts"],
    }


def _f(value: float) -> str:
    return f"{value:.3f}".replace(".", ",")


def _n(value: int) -> str:
    return f"{value:,}".replace(",", ".")


def interval(metric: dict[str, Any]) -> str:
    return f"{_f(metric['estimate'])} [{_f(metric['lower'])}; {_f(metric['upper'])}]"


def report_markdown(data: dict[str, Any]) -> str:
    rows = []
    for entity_type in PRIMARY_TYPES:
        item = data["by_type"][entity_type]
        rows.append(
            f"| {TYPE_LABELS[entity_type]} | {item['cosine']['documents']} | "
            f"{interval(item['cosine'])} | {interval(item['cisa_recall'])} | "
            f"{interval(item['jaccard'])} |"
        )
    totals = data["totals"]
    relation = data["relationships"]
    gate = relation["gate"]
    return f"""# EXP-02 — Similitud estructural CISA/STIX

<!-- exp02-source-sha256:{data['results_sha256']} -->

Este informe se deriva exclusivamente de `cisa-evidence/results.v2.json`. El STIX oficial de CISA es una referencia oficial parcial, no una verdad absoluta ni una anotación exhaustiva de la prosa.

## Protocolo ejecutado

Se procesaron {data['documents']} avisos CISA con {data['repetitions']} repeticiones por documento: {data['runs']} salidas finales. Claude Haiku 4.5 operó mediante {data['provider']} en `{data['aws_region']}`. La ruta experimental registró {data['opencti_writes']} escrituras en OpenCTI.

El prompt activo es `SYSTEM_PROMPT_V21` de `services/intel-extractor/extractor.py`. Solicita JSON con `entities`, `relationships` y `campaign_summary`; cada objeto estructural incluye valor, tipo, cita literal y página, y cada relación referencia dos entidades.

TIM localiza las citas en el texto y descarta entidades sin cita y relaciones sin cita o sin extremos conservados. La puntuación compara las entidades finales de tipos primarios con el STIX CISA canónico y anclado al PDF.

## Resultado principal

| Métrica macro por documento | Estimación e IC 95 % |
|---|---:|
| Coseno estructural | **{interval(data['overall']['cosine'])}** |
| Recall de la referencia CISA | {interval(data['overall']['cisa_recall'])} |
| Jaccard estructural | {interval(data['overall']['jaccard'])} |

Los intervalos usan *bootstrap* de {data['samples']} remuestras con el documento como unidad y semilla {data['seed']}. Coseno es la métrica primaria; recall y Jaccard son reanálisis reproducibles de las 24 filas documentales del resultado verificado.

## Resultado por tipo

| Tipo | Documentos evaluables | Coseno [IC 95 %] | Recall CISA [IC 95 %] | Jaccard [IC 95 %] |
|---|---:|---:|---:|---:|
{chr(10).join(rows)}

Los extremos de vulnerabilidad (n=1) y actor (n=2) no permiten generalizar. Los indicadores presentan la mayor evidencia transversal: coseno {interval(data['by_type']['indicator']['cosine'])} en 24 documentos.

## Estabilidad, citas y filtro

La mediana documental del Jaccard entre las tres repeticiones fue {interval(data['stability'])}. Se localizaron {_n(totals['citations_localized'])}/{_n(totals['citations_total'])} citas finales, tasa {interval(data['citations'])}.

El filtro redujo entidades v2.1 {_n(totals['raw_entities'])} → {_n(totals['final_entities'])}, relaciones {_n(totals['raw_relationships'])} → {_n(totals['final_relationships'])} y entidades comparables {_n(totals['raw_comparable'])} → {_n(totals['final_comparable'])}.

En las 72 repeticiones se acumularon `matched={_n(totals['matched'])}`, `cisa_only={_n(totals['cisa_only'])}` y `tim_only_unassessed={_n(totals['tim_only_unassessed'])}`. El último grupo no se interpreta como falso positivo porque CISA no agota el documento.

## Relaciones y alcance

Las relaciones permanecen exploratorias: el corpus aportó {gate['support']['documents']} documentos y {gate['support']['grounded_relations']} relaciones CISA ancladas, por debajo de la compuerta de {gate['requirements']['documents']} documentos y {gate['requirements']['grounded_relations']} relaciones. Hubo {relation['candidate_matches_across_repetitions']} coincidencias candidatas y {relation['tim_relation_additions_disagreement']} adiciones TIM sin acuerdo con la referencia parcial.

El experimento demuestra concordancia estructural medible y trazabilidad literal en este corpus. No demuestra verdad factual, equivalencia o superioridad respecto de analistas humanos, utilidad operacional ni persistencia en OpenCTI.

## Integridad

- SHA-256 de `results.v2.json`: `{data['results_sha256']}`
- SHA-256 del freeze v3: `{data['freeze_sha256']}`
- Modelo: `{data['model']}`
"""


def _metadata(data: dict[str, Any], figure: str, values: dict[str, Any]) -> str:
    payload = {
        "figure": figure,
        "results_sha256": data["results_sha256"],
        "values": values,
    }
    return html.escape(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def structural_svg(data: dict[str, Any]) -> str:
    metrics = [("Coseno", "cosine", "#345995"), ("Recall CISA", "cisa_recall", "#2E8B57"), ("Jaccard", "jaccard", "#D97706")]
    values = {key: data["overall"][key] for _, key, _ in metrics}
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="650" viewBox="0 0 1100 650">',
        f'<metadata id="exp02-source">{_metadata(data, "cisa-structural-metrics", values)}</metadata>',
        '<rect width="1100" height="650" fill="white"/>',
        '<text x="550" y="48" text-anchor="middle" font-family="sans-serif" font-size="26" font-weight="700">EXP-02 · Similitud estructural macro por documento</text>',
        '<text x="550" y="80" text-anchor="middle" font-family="sans-serif" font-size="16">24 avisos · 3 repeticiones · IC 95 % bootstrap por documento</text>',
    ]
    for tick in range(6):
        x = 185 + tick * 160
        parts.append(f'<line x1="{x}" y1="120" x2="{x}" y2="510" stroke="#dddddd"/>')
        parts.append(f'<text x="{x}" y="535" text-anchor="middle" font-family="sans-serif" font-size="15">{tick/5:.1f}</text>')
    for index, (label, key, color) in enumerate(metrics):
        y = 180 + index * 120
        item = data["overall"][key]
        lower = 185 + item["lower"] * 800
        upper = 185 + item["upper"] * 800
        estimate = 185 + item["estimate"] * 800
        parts.extend([
            f'<text x="165" y="{y+7}" text-anchor="end" font-family="sans-serif" font-size="18">{label}</text>',
            f'<line x1="{lower:.1f}" y1="{y}" x2="{upper:.1f}" y2="{y}" stroke="#222" stroke-width="4"/>',
            f'<line x1="{lower:.1f}" y1="{y-12}" x2="{lower:.1f}" y2="{y+12}" stroke="#222" stroke-width="3"/>',
            f'<line x1="{upper:.1f}" y1="{y-12}" x2="{upper:.1f}" y2="{y+12}" stroke="#222" stroke-width="3"/>',
            f'<circle cx="{estimate:.1f}" cy="{y}" r="13" fill="{color}" stroke="#111"/>',
            f'<text x="{upper+14:.1f}" y="{y+6}" font-family="sans-serif" font-size="16">{interval(item)}</text>',
        ])
    parts.extend([
        '<text x="550" y="585" text-anchor="middle" font-family="sans-serif" font-size="15">Referencia CISA oficial parcial; las adiciones TIM no se clasifican como falsos positivos.</text>',
        '</svg>',
    ])
    return "\n".join(parts) + "\n"


def stability_svg(data: dict[str, Any]) -> str:
    values = {
        "stability": data["stability"],
        "citations": data["citations"],
        "raw_entities": data["totals"]["raw_entities"],
        "final_entities": data["totals"]["final_entities"],
        "raw_relationships": data["totals"]["raw_relationships"],
        "final_relationships": data["totals"]["final_relationships"],
    }
    t = data["totals"]
    entity_rate = t["final_entities"] / t["raw_entities"]
    relation_rate = t["final_relationships"] / t["raw_relationships"]
    parts = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="1100" height="650" viewBox="0 0 1100 650">',
        f'<metadata id="exp02-source">{_metadata(data, "cisa-document-stability", values)}</metadata>',
        '<rect width="1100" height="650" fill="white"/>',
        '<text x="550" y="48" text-anchor="middle" font-family="sans-serif" font-size="26" font-weight="700">EXP-02 · Repetibilidad, citas y filtro determinista</text>',
        '<text x="550" y="80" text-anchor="middle" font-family="sans-serif" font-size="16">Tres repeticiones por cada uno de los 24 documentos</text>',
        '<rect x="70" y="125" width="960" height="120" rx="12" fill="#EEF4FA" stroke="#345995"/>',
        '<text x="100" y="163" font-family="sans-serif" font-size="18" font-weight="700">Estabilidad entre repeticiones</text>',
        f'<text x="100" y="205" font-family="sans-serif" font-size="25">Jaccard mediano: {interval(data["stability"])}</text>',
        '<rect x="70" y="275" width="460" height="235" rx="12" fill="#F0F8F3" stroke="#2E8B57"/>',
        '<text x="100" y="315" font-family="sans-serif" font-size="18" font-weight="700">Citas finales localizadas</text>',
        f'<text x="100" y="360" font-family="sans-serif" font-size="30">{_n(t["citations_localized"])}/{_n(t["citations_total"])}</text>',
        f'<text x="100" y="400" font-family="sans-serif" font-size="17">Tasa e IC 95 %: {interval(data["citations"])}</text>',
        '<text x="100" y="455" font-family="sans-serif" font-size="15">Valida localización literal; no exactitud factual.</text>',
        '<rect x="570" y="275" width="460" height="235" rx="12" fill="#FFF7E8" stroke="#D97706"/>',
        '<text x="600" y="315" font-family="sans-serif" font-size="18" font-weight="700">Efecto raw → final</text>',
        f'<text x="600" y="360" font-family="sans-serif" font-size="22">Entidades: {_n(t["raw_entities"])} → {_n(t["final_entities"])} ({100*entity_rate:.1f} %)</text>',
        f'<text x="600" y="405" font-family="sans-serif" font-size="22">Relaciones: {_n(t["raw_relationships"])} → {_n(t["final_relationships"])} ({100*relation_rate:.1f} %)</text>',
        '<text x="600" y="455" font-family="sans-serif" font-size="15">El filtro exige cita y extremos conservados.</text>',
        '<text x="550" y="585" text-anchor="middle" font-family="sans-serif" font-size="15">72 salidas finales · 0 escrituras en OpenCTI durante el experimento</text>',
        '</svg>',
    ]
    return "\n".join(parts) + "\n"


def write_publication(root: Path = ROOT) -> dict[str, Any]:
    data = load_publication_data(root / RESULTS_RELATIVE)
    report = root / REPORT_RELATIVE
    figures = root / FIGURE_DIR_RELATIVE
    figures.mkdir(parents=True, exist_ok=True)
    report.write_text(report_markdown(data), encoding="utf-8")
    (figures / "cisa-structural-metrics.svg").write_text(structural_svg(data), encoding="utf-8")
    (figures / "cisa-document-stability.svg").write_text(stability_svg(data), encoding="utf-8")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="derive and validate without writing")
    args = parser.parse_args(argv)
    data = load_publication_data()
    if not args.check:
        data = write_publication()
    print(json.dumps({"documents": data["documents"], "runs": data["runs"], "results_sha256": data["results_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
