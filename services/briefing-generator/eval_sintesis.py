#!/usr/bin/env python3
"""
eval_sintesis.py — harness de evaluación del sintetizador (Cap.5 de la tesis).

Mide, sobre un contexto CONGELADO (mismo stats_block para todas las corridas),
K corridas por proveedor, en dos modos:

  raw    — generación directa: una llamada al modelo (_call_llm).
  system — pipeline con control de anclaje (_generate_verified): reintento + anotación.

Métricas por corrida:
  tasa_anclaje        — identificadores anclados / identificadores detectables; N/A si no hay.
  cobertura_nominal   — fracción de nombres de actores+malware mencionados literalmente.
  conteos_correctos   — asociación correcta etiqueta-valor para total, nuevos y ambos.
  palabras, retried (solo system), unanchored.

Uso (dentro del contenedor briefing-generator; mismo comando en VPS y local):
  # 1. congelar contexto desde OpenCTI vivo:
  python eval_sintesis.py --freeze 72 --context /out/ctx-72h.txt
  # 2. correr K corridas (el nombre del argumento CLI es --n):
  python eval_sintesis.py --context /out/ctx-72h.txt --n 10 --mode raw \
      --out /out/runs-$LLM_PROVIDER-raw.jsonl

El proveedor lo decide LLM_PROVIDER (ollama|bedrock) — misma vara, distinto motor.
"""
import argparse
import difflib
import json
import re
import statistics
import sys

from anchor import anchor_stats

EVALUATOR_VERSION = "2.0.0"

_ACTORS_RE = re.compile(r"Tracked threat actors[^:]*:\s*(.+?)\.\n", re.S)
_MALWARE_RE = re.compile(r"Tracked malware families[^:]*:\s*(.+?)\.\n", re.S)
_TOTALS_RE = re.compile(r"(\d+) indicators total \((\d+) newly created")
_MODE_LABELS = {
    "raw": "generación directa",
    "system": "pipeline con control de anclaje",
    "draft": "borrador sin control",
    "verified": "tras control de anclaje",
}

# Un nombre emitido con una letra cambiada («Darkhosel» por Darkhotel) no es una
# omisión: mete en el informe una entidad que la base no contiene. La cobertura
# nominal los mezclaba. 0,75 es el umbral que separa las corrupciones observadas
# —incluida «PittyPig», que a 0,80 se pierde— del ruido; ver test_eval_sintesis.py.
_CORRUPTION_CUTOFF = 0.75

# El prompt de sistema exige «plain professional prose only — no lists, headers
# or markdown». Es una instrucción comprobable sin juicio humano, así que se
# mide: encabezados, negritas y viñetas al principio de línea.
_MARKDOWN_RE = re.compile(r"^\s*#{1,6}\s|\*\*|^\s*[-*]\s+|^\s*\d+\.\s+", re.M)
_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9.\-]{2,}")


def _names(match: re.Match | None) -> list[str]:
    if not match or "none" in match.group(1)[:20]:
        return []
    return [n.strip() for n in match.group(1).split(",") if n.strip()]


def context_entities(context: str) -> list[str]:
    names = _names(_ACTORS_RE.search(context)) + _names(_MALWARE_RE.search(context))
    unique: list[str] = []
    seen: set[str] = set()
    for name in names:
        key = name.casefold()
        if key not in seen:
            seen.add(key)
            unique.append(name)
    return unique


def _is_complete_mention(name: str, text: str) -> bool:
    """Coincidencia literal sin aceptar el nombre dentro de otra palabra."""
    return bool(re.search(rf"(?<!\w){re.escape(name)}(?!\w)", text, re.I))


# Un número puede llegar con separador de millares («1,071»): la comparación se
# hace sobre los dígitos. Sin esto, un total de cuatro cifras no se reconocía
# nunca — las diez salidas del 2026-08-26 informaban «1,071» correctamente y el
# evaluador las puntuaba todas como error.
_SEP_NUMBER = r"\d{1,3}(?:[,.\u00a0]\d{3})+|\d+"
_NUMBER_RE = re.compile(rf"(?<![\d.,])({_SEP_NUMBER})(?![\d.,])")

_NUMBER_WORD_VALUES = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4,
    "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
    "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13,
    "fourteen": 14, "fifteen": 15, "sixteen": 16,
    "seventeen": 17, "eighteen": 18, "nineteen": 19,
    "twenty": 20, "thirty": 30, "forty": 40, "fifty": 50,
    "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90,
}
_NUMBER_WORD_TOKEN = "|".join([*_NUMBER_WORD_VALUES, "hundred", "thousand"])
_NUMBER_WORD_RE = re.compile(
    rf"\b(({_NUMBER_WORD_TOKEN})(?:[\s-]+(?:and[\s-]+)?({_NUMBER_WORD_TOKEN}))*)\b",
    re.I,
)

_INDICATOR_NOUN = (
    r"(?:indicators?(?:\s+of\s+compromise)?|IOCs?|indicadores?|"
    r"entries|artifacts?|entradas|artefactos?)"
)
_NEW_CUE = (
    r"(?:new|newly\s+(?:created|identified|added|detected)|freshly\s+created|"
    r"nuevos?|reci[eé]n\s+(?:creados?|identificados?))"
)
_PREEXISTING_CUE = (
    r"(?:pre-?existing|previously\s+(?:tracked|known|seen)|updates?\s+to|"
    r"re-?updated|preexistentes?|actualizaci[oó]n(?:es)?|ya\s+conocidos?)"
)
_TOTAL_CUE = r"(?:total(?:es)?|overall|in\s+total|en\s+total)"

_ZERO_NEW_PATTERNS = (
    r"\bno\s+(?:new|newly\s+(?:created|identified)|freshly\s+created)"
    r"(?:\s+\w+){0,2}\s+(?:indicators?|IOCs?)\b",
    r"\babsence\s+of\s+(?:any\s+)?"
    r"(?:new|newly\s+(?:created|identified)|freshly\s+created)"
    r"(?:\s+\w+){0,2}\s+(?:indicators?|IOCs?)\b",
    r"\bning[uú]n\s+indicador\s+nuevo\b",
    r"\bno\s+indicators?\s+(?:were\s+)?newly\s+(?:created|identified|added|detected)\b",
    r"\bno\s+new\s+(?:creation|creations|addition|additions|detection|detections)\b",
)

_ZERO_PREEXISTING_PATTERNS = (
    r"\bno\s+pre-?existing\s+indicators?\b",
    r"\bno\s+previously\s+(?:tracked|known|seen)\s+indicators?\b",
)

_ALL_PREEXISTING_RE = re.compile(
    r"\ball(?:\s+\w+){0,4}\s+(?:were\s+)?pre-?existing\b",
    re.I,
)
_ALL_NEW_RE = re.compile(
    r"\ball(?:\s+\w+){0,4}\s+(?:were\s+)?(?:new|newly\s+(?:created|identified|added))\b",
    re.I,
)

_SAMPLE_CONTEXT_RE = re.compile(
    r"\b(?:samples?|sampled|subsets?|muestras?|muestread[oa]s?|subconjuntos?)\b",
    re.I,
)


def _clause_containing(text: str, start: int, end: int) -> str:
    """Devuelve la cláusula simple que rodea una coincidencia numérica."""
    boundaries = ".!?;\n"
    left = max(text.rfind(mark, 0, start) for mark in boundaries) + 1
    right_candidates = [
        position
        for mark in boundaries
        if (position := text.find(mark, end)) != -1
    ]
    right = min(right_candidates) if right_candidates else len(text)
    return text[left:right]


def _is_sample_count(clause: str, candidate: str) -> bool:
    """Distingue un subconjunto numerado de otros usos de la palabra ``top``."""
    if _SAMPLE_CONTEXT_RE.search(clause):
        return True
    return bool(re.search(
        rf"\btop(?:\s+\w+){{0,3}}\s+{re.escape(candidate)}\b",
        clause,
        re.I,
    ))


def _digits(value: str) -> int:
    return int(re.sub(r"[^\d]", "", value))


_BOUNDARY_RE = re.compile(r"[.!?;\n]")


def _window_after(text: str, end: int, words: int = 3) -> str:
    """Las `words` palabras siguientes a la cifra, sin cruzar la cláusula.

    El corte importa: sin él, «187 indicators. No newly created indicators»
    rotulaba 187 como cifra de nuevos con la etiqueta de la frase siguiente.
    """
    tail = text[end:end + 90]
    stop = _BOUNDARY_RE.search(tail)
    return " ".join(tail[: stop.start() if stop else None].split()[:words])


def _window_before(text: str, start: int, words: int = 3) -> str:
    head = text[max(0, start - 90):start]
    boundaries = [m.end() for m in _BOUNDARY_RE.finditer(head)]
    return " ".join(head[boundaries[-1] if boundaries else 0:].split()[-words:])


def _labels_of(text: str, match: re.Match) -> tuple[str, bool] | None:
    """Etiqueta que la prosa asocia a una cifra, y si la asociación es directa.

    Se mira la ventana inmediata en vez de una lista cerrada de plantillas: las
    salidas parafrasean el verbo («observed», «registered», «logged») y una
    lista de verbos convierte cada paráfrasis nueva en falso negativo.

    Devuelve (etiqueta, fuerte). Una cifra rotulada como preexistente es
    candidata *débil* a total: cuando el período no trae altas, total y
    preexistentes coinciden y «187 pre-existing indicators were re-updated» sí
    enuncia el total; pero si el texto rotula alguna cifra de total
    directamente, esa manda y la preexistente no compite.
    """
    after = _window_after(text, match.end())
    before = _window_before(text, match.start())
    around = f"{before} @ {after}"
    clause = _clause_containing(text, match.start(), match.end())
    names_indicator = bool(re.search(_INDICATOR_NOUN, clause, re.I))
    if re.search(_PREEXISTING_CUE, around, re.I):
        return ("preexisting", True) if names_indicator else None
    if re.search(_NEW_CUE, after, re.I) or re.search(
        rf"{_NEW_CUE}(?:\s+{_INDICATOR_NOUN})?\s*[:=]?\s*$", before, re.I
    ):
        # «0 newly created user accounts» no habla de indicadores: la cláusula
        # debe nombrarlos para que la cifra cuente como indicadores nuevos.
        return ("new", True) if names_indicator else None
    if re.search(_TOTAL_CUE, around, re.I) and names_indicator:
        return ("total", True)
    if re.search(rf"^{_INDICATOR_NOUN}", after, re.I):
        return ("total", True)
    return None


def _word_number(value: str) -> int:
    total = 0
    current = 0
    for token in re.split(r"[\s-]+", value.lower()):
        if token == "and":
            continue
        if token in _NUMBER_WORD_VALUES:
            current += _NUMBER_WORD_VALUES[token]
        elif token == "hundred":
            current = max(current, 1) * 100
        elif token == "thousand":
            total += max(current, 1) * 1000
            current = 0
        else:  # protected by _NUMBER_WORD_RE
            raise ValueError(f"palabra numérica no admitida: {token}")
    return total + current


def _number_value(value: str) -> int:
    return _digits(value) if re.search(r"\d", value) else _word_number(value)


def _number_matches(text: str) -> list[re.Match]:
    return sorted(
        [*_NUMBER_RE.finditer(text), *_NUMBER_WORD_RE.finditer(text)],
        key=lambda match: match.start(),
    )


def _count_fidelity(text: str, expected_total: int, expected_new: int) -> tuple[bool, bool]:
    """Reconoce cifras o palabras y permite derivar el total de una partición completa."""
    claims = {"total": set(), "new": set(), "preexisting": set()}
    for match in _number_matches(text):
        candidate = match.group(1)
        labelled = _labels_of(text, match)
        if labelled is None:
            continue
        kind = labelled[0]
        if _is_sample_count(_clause_containing(text, match.start(), match.end()), candidate):
            continue
        claims[kind].add(_number_value(candidate))

    if any(re.search(pattern, text, re.I) for pattern in _ZERO_NEW_PATTERNS):
        claims["new"].add(0)
    if _ALL_PREEXISTING_RE.search(text):
        claims["new"].add(0)
    if any(re.search(pattern, text, re.I) for pattern in _ZERO_PREEXISTING_PATTERNS):
        claims["preexisting"].add(0)
    if _ALL_NEW_RE.search(text):
        claims["preexisting"].add(0)

    expected_preexisting = expected_total - expected_new
    total_ok = claims["total"] == {expected_total}
    new_ok = claims["new"] == {expected_new}
    preexisting_ok = claims["preexisting"] == {expected_preexisting}
    if not claims["total"] and new_ok and preexisting_ok:
        total_ok = True
    return total_ok, new_ok


def name_fidelity(text: str, entities: list[str]) -> dict:
    """Separa el nombre emitido tal cual, el emitido alterado y el ausente.

    La coincidencia literal decide «exacto». Para el resto se busca en el texto
    el token más parecido a la palabra más distintiva del nombre: si existe uno
    suficientemente próximo, el nombre se emitió corrupto; si no, se omitió.
    """
    tokens = {token.strip(".-") for token in _TOKEN_RE.findall(text)}
    known = " ".join(entities)
    exact: list[str] = []
    corrupted: list[tuple[str, str]] = []
    omitted: list[str] = []
    for name in entities:
        if _is_complete_mention(name, text):
            exact.append(name)
            continue
        target = max(name.split(), key=len)
        # Un token que ya es el nombre de otra entidad no cuenta como corrupción de ésta.
        pool = [t for t in tokens if not _is_complete_mention(t, known)]
        near = difflib.get_close_matches(target, pool, n=1, cutoff=_CORRUPTION_CUTOFF)
        if near:
            corrupted.append((name, near[0]))
        else:
            omitted.append(name)
    return {"exactos": exact, "corruptos": corrupted, "omitidos": omitted}


def measure(text: str, context: str) -> dict:
    st = anchor_stats(text, context)
    identifiers_total = st["total_facts"]
    identifiers_anchored = identifiers_total - len(st["unanchored"])
    rate = (
        identifiers_anchored / identifiers_total
        if identifiers_total
        else None
    )
    entities = context_entities(context)
    covered = [e for e in entities if _is_complete_mention(e, text)]
    totals = _TOTALS_RE.search(context)
    if totals:
        total_ok, new_ok = _count_fidelity(
            text,
            expected_total=int(totals.group(1)),
            expected_new=int(totals.group(2)),
        )
    else:
        total_ok = new_ok = None
    counts_joint = total_ok and new_ok if totals else None
    fidelity = name_fidelity(text, entities)
    return {
        "tasa_anclaje": round(rate, 4) if rate is not None else None,
        "identificadores_totales": identifiers_total,
        "identificadores_anclados": identifiers_anchored,
        "unanchored": st["unanchored"],
        "cobertura_nominal": round(len(covered) / len(entities), 4) if entities else None,
        "entidades_mencionadas": len(covered),
        "entidades_contexto": len(entities),
        "nombres_exactos": len(fidelity["exactos"]),
        "nombres_corruptos": len(fidelity["corruptos"]),
        "nombres_omitidos": len(fidelity["omitidos"]),
        "nombres_corruptos_detalle": [
            f"{esperado}->{emitido}" for esperado, emitido in fidelity["corruptos"]
        ],
        "conteo_total_correcto": total_ok,
        "conteo_nuevos_correcto": new_ok,
        "conteos_correctos_conjuntos": counts_joint,
        "palabras": len(text.split()),
        "formato_sin_markdown": not bool(_MARKDOWN_RE.search(text)),
    }


def summarize(runs: list[dict], provider: str, mode: str) -> dict:
    """Agrega corridas sin convertir denominadores vacíos en éxitos."""
    def _mean(key: str):
        vals = [r[key] for r in runs if r.get(key) is not None]
        return round(statistics.mean(vals), 4) if vals else None

    def _sample_std(key: str):
        vals = [r[key] for r in runs if r.get(key) is not None]
        return round(statistics.stdev(vals), 4) if len(vals) > 1 else None

    def _successes_over_evaluable(key: str):
        vals = [r[key] for r in runs if r.get(key) is not None]
        return f"{sum(value is True for value in vals)}/{len(vals)}" if vals else None

    identifiers_total = sum(r["identificadores_totales"] for r in runs)
    identifiers_anchored = sum(r["identificadores_anclados"] for r in runs)
    summary = {
        "provider": provider,
        "mode": mode,
        "modo_ejecucion": _MODE_LABELS[mode],
        "corridas_total": len(runs),
        "corridas_anclaje_evaluables": sum(
            1 for r in runs if r["identificadores_totales"] > 0
        ),
        "identificadores_totales_evaluados": identifiers_total,
        "identificadores_anclados": identifiers_anchored,
        "tasa_anclaje_agregada": (
            round(identifiers_anchored / identifiers_total, 4)
            if identifiers_total
            else None
        ),
        "cobertura_nominal_media": _mean("cobertura_nominal"),
        "cobertura_nominal_std_muestral": _sample_std("cobertura_nominal"),
        "conteo_total_correcto_aciertos_sobre_evaluables":
            _successes_over_evaluable(
                "conteo_total_correcto"
            ),
        "conteo_nuevos_correcto_aciertos_sobre_evaluables":
            _successes_over_evaluable(
                "conteo_nuevos_correcto"
            ),
        "conteos_correctos_conjuntos_aciertos_sobre_evaluables":
            _successes_over_evaluable(
                "conteos_correctos_conjuntos"
            ),
        "palabras_media": _mean("palabras"),
        "formato_sin_markdown_aciertos_sobre_evaluables": _successes_over_evaluable(
            "formato_sin_markdown"
        ),
        "corridas_con_nombre_corrupto": (
            f"{sum(1 for r in runs if r.get('nombres_corruptos'))}/{len(runs)}"
        ),
        "nombres_corruptos_totales": sum(r.get("nombres_corruptos", 0) for r in runs),
        "nombres_omitidos_totales": sum(r.get("nombres_omitidos", 0) for r in runs),
        "nombres_exactos_totales": sum(r.get("nombres_exactos", 0) for r in runs),
    }
    if mode == "system":
        summary["corridas_con_reintento"] = sum(1 for r in runs if r.get("retried"))
    return summary


def _write_jsonl(path: str, rows: list[dict]) -> None:
    with open(path, "w") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def _run_paired(args, context, call_llm, verify_draft, provider) -> int:
    """Mide el MISMO borrador antes y después del control.

    Las series de agosto de 2026 generaban dos poblaciones independientes, así
    que su diferencia no identificaba el efecto del verificador. Aquí cada
    corrida produce un par: el borrador tal como salió del modelo y el texto que
    el control devuelve sobre ese borrador, unidos por el número de corrida.
    """
    drafts, verified = [], []
    for i in range(args.n):
        draft = call_llm(context)
        final, meta = verify_draft(draft, context)
        common = {"run": i + 1, "provider": provider, "par": i + 1}
        before = measure(draft, context)
        before.update(common | {"mode": "draft", "modo_ejecucion": _MODE_LABELS["draft"],
                                "texto": draft})
        after = measure(final, context)
        after.update(common | {"mode": "verified", "modo_ejecucion": _MODE_LABELS["verified"],
                               "texto": final, "retried": meta["retried"]})
        drafts.append(before)
        verified.append(after)
        print(f"[eval] {provider}/par {i+1}/{args.n}: "
              f"anclaje {before['tasa_anclaje']} -> {after['tasa_anclaje']} "
              f"(identificadores {before['identificadores_totales']} -> "
              f"{after['identificadores_totales']}), reintento={meta['retried']}",
              file=sys.stderr)

    if args.out_prefix:
        _write_jsonl(f"{args.out_prefix}-draft.jsonl", drafts)
        _write_jsonl(f"{args.out_prefix}-verified.jsonl", verified)

    resumen = {
        "borrador": summarize(drafts, provider=provider, mode="draft"),
        "verificado": summarize(verified, provider=provider, mode="verified"),
        "pares": len(drafts),
        "pares_con_reintento": sum(1 for r in verified if r.get("retried")),
        "pares_que_el_control_cambio": sum(
            1 for before, after in zip(drafts, verified)
            if before["texto"] != after["texto"]
        ),
    }
    print(json.dumps(resumen, ensure_ascii=False, indent=1))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--context", required=True, help="fichero stats_block congelado")
    ap.add_argument("--freeze", type=int, help="horas de ventana: recolecta de OpenCTI y escribe --context")
    ap.add_argument("--n", type=int, default=10, help="número K de corridas")
    ap.add_argument(
        "--mode",
        choices=["raw", "system", "paired"],
        default="raw",
        help="raw=generación directa; system=pipeline con control; "
             "paired=el mismo borrador antes y después del control",
    )
    ap.add_argument("--out", help="JSONL de corridas (default: stdout solo resumen)")
    ap.add_argument(
        "--out-prefix",
        help="modo paired: escribe <prefijo>-draft.jsonl y <prefijo>-verified.jsonl",
    )
    args = ap.parse_args()

    if args.freeze:
        from opencti_client import build_pycti_client
        from generator import _build_stats_block, _collect_threat_data
        data = _collect_threat_data(build_pycti_client(), args.freeze)
        block = _build_stats_block(data, args.freeze)
        with open(args.context, "w") as fh:
            fh.write(block)
        print(f"[eval] contexto congelado ({len(block)} chars) -> {args.context}", file=sys.stderr)
        return 0

    from config import LLM_PROVIDER
    from generator import _call_llm, _generate_verified, _verify_draft
    context = open(args.context).read()

    if args.mode == "paired":
        return _run_paired(args, context, _call_llm, _verify_draft, LLM_PROVIDER)

    runs = []
    for i in range(args.n):
        if args.mode == "system":
            text, meta = _generate_verified(context)
            m = measure(text, context)
            m["retried"] = meta["retried"]
        else:
            text = _call_llm(context)
            m = measure(text, context)
        m.update({
            "run": i + 1,
            "provider": LLM_PROVIDER,
            "mode": args.mode,
            "modo_ejecucion": _MODE_LABELS[args.mode],
            "texto": text,
        })
        runs.append(m)
        print(f"[eval] {LLM_PROVIDER}/{_MODE_LABELS[args.mode]} corrida {i+1}/{args.n}: "
              f"anclaje={m['tasa_anclaje']} "
              f"cobertura_nominal={m['cobertura_nominal']} "
              f"conteos_conjuntos={m['conteos_correctos_conjuntos']}", file=sys.stderr)

    if args.out:
        with open(args.out, "w") as fh:
            for r in runs:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    resumen = summarize(runs, provider=LLM_PROVIDER, mode=args.mode)
    print(json.dumps(resumen, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
