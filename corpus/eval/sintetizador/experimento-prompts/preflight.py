#!/usr/bin/env python3
"""Comprueba que el experimento es viable ANTES de gastar llamadas al modelo.

No invoca al proveedor: solo consulta OpenCTI y ejercita el evaluador. Si algo
aquí falla, correr las 144 corridas produciría datos que no se pueden
interpretar.

La comprobación central es la última: por cada bloque se fabrica una respuesta
que dice la verdad con sus cifras reales —en formato liso y con separador de
millares— y se exige que el evaluador la puntúe correcta. Esa comprobación
existe porque ya ocurrió lo contrario: el modelo escribía «1,071», la métrica
buscaba «1071» y diez corridas correctas se puntuaron como error.

    docker cp preflight.py tim-briefing-generator-1:/tmp/
    docker exec tim-briefing-generator-1 python /tmp/preflight.py --horas /tmp/horas.json
"""
import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, "/app")

from opencti_client import build_pycti_client          # noqa: E402
import generator as g                                   # noqa: E402
from anchor import _context_identifiers                 # noqa: E402
from eval_sintesis import context_entities, measure     # noqa: E402

CLAUSULA = ("When the data lists indicator values verbatim, cite at least three "
            "of them exactly as written, character for character, so the reader "
            "can act on them; never alter, abbreviate, defang or invent an "
            "indicator value. ")
ENTIDADES_ESPERADAS = 20
ANCLABLES_BASE = 3


def _miles(n: int) -> str:
    return f"{n:,}"


def _respuesta_perfecta(bloque: str, total: int, nuevos: int, con_separador: bool) -> str:
    """Un texto que dice la verdad, en prosa, con las cifras de ese bloque."""
    fmt = _miles if con_separador else str
    entidades = context_entities(bloque)
    identificadores = sorted(v for k, v in _context_identifiers(bloque) if k != "tid")
    previos = total - nuevos
    frases = [
        f"During the reporting period the platform detected {fmt(total)} indicators "
        f"of compromise, comprising {fmt(nuevos)} newly created indicators and "
        f"{fmt(previos)} updates to pre-existing ones."
    ]
    if nuevos == 0:
        frases[0] = (
            f"During the reporting period the platform detected {fmt(total)} indicators "
            f"of compromise. No newly created indicators were recorded, and "
            f"{fmt(previos)} pre-existing indicators were re-updated."
        )
    if entidades:
        frases.append("The knowledge base covers " + ", ".join(entidades) + ".")
    if identificadores:
        frases.append("Observed indicators include " + ", ".join(identificadores[:5]) + ".")
    return " ".join(frases)


def _respuesta_incorrecta(bloque: str, total: int, nuevos: int) -> str:
    return _respuesta_perfecta(bloque, total + 7, nuevos, con_separador=False)


def revisar(client, horas: list[str], curated: list[str]) -> tuple[list[str], dict]:
    errores: list[str] = []
    resumen = {"bloques": 0, "vacios": 0, "anclables_prompt1": set(),
               "anclables_prompt2": [], "entidades": set(), "degenerados": 0,
               "sin_tratamiento": []}

    # Un solo resolve para las 48 horas: repetirlo cuesta nueve consultas por bloque.
    g._resolve_curated_ids = lambda _client: curated

    for etiqueta in horas:
        inicio = datetime.strptime(etiqueta, "%Y-%m-%d %H").replace(tzinfo=timezone.utc)
        hasta = inicio + timedelta(hours=1)
        data = g._collect_threat_data(client, 1, until=hasta)
        total, nuevos = data["total_touched"], data["total_new"]
        if not total:
            resumen["vacios"] += 1
            errores.append(f"{etiqueta}: 0 indicadores; el bloque no lleva tratamiento")
            continue
        resumen["bloques"] += 1

        original = g.IOC_VALUES_IN_PROMPT
        try:
            g.IOC_VALUES_IN_PROMPT = 0
            bloque1 = g._build_stats_block(data, 1, until=hasta)
            g.IOC_VALUES_IN_PROMPT = original
            bloque2 = g._build_stats_block(data, 1, until=hasta)
        finally:
            g.IOC_VALUES_IN_PROMPT = original

        a1, a2 = len(_context_identifiers(bloque1)), len(_context_identifiers(bloque2))
        resumen["anclables_prompt1"].add(a1)
        resumen["anclables_prompt2"].append(a2)
        if a1 != ANCLABLES_BASE:
            errores.append(f"{etiqueta}: el prompt 1 ofrece {a1} anclables, no {ANCLABLES_BASE}")
        if a2 <= a1:
            resumen["sin_tratamiento"].append(etiqueta)
            errores.append(f"{etiqueta}: el prompt 2 no añade anclables ({a2} vs {a1})")
        if hashlib.sha256(bloque1.encode()).hexdigest() == hashlib.sha256(bloque2.encode()).hexdigest():
            errores.append(f"{etiqueta}: los contextos del prompt 1 y 2 son idénticos")

        entidades = context_entities(bloque2)
        resumen["entidades"].add(len(entidades))
        if len(entidades) != ENTIDADES_ESPERADAS:
            errores.append(f"{etiqueta}: {len(entidades)} entidades, se esperaban {ENTIDADES_ESPERADAS}")

        if total == nuevos or total == (total - nuevos):
            resumen["degenerados"] += 1

        # P7: el evaluador debe reconocer una respuesta correcta, en los dos formatos.
        for con_sep in (False, True):
            texto = _respuesta_perfecta(bloque2, total, nuevos, con_sep)
            m = measure(texto, bloque2)
            etiqueta_fmt = "con separador" if con_sep else "sin separador"
            if not m["conteo_total_correcto"]:
                errores.append(f"{etiqueta} ({etiqueta_fmt}): no reconoce el total {total}")
            if not m["conteo_nuevos_correcto"]:
                errores.append(f"{etiqueta} ({etiqueta_fmt}): no reconoce los nuevos {nuevos}")
            if m["cobertura_nominal"] != 1.0:
                errores.append(f"{etiqueta} ({etiqueta_fmt}): cobertura {m['cobertura_nominal']} sobre texto que los nombra todos")
            if m["tasa_anclaje"] is not None and m["tasa_anclaje"] != 1.0:
                errores.append(f"{etiqueta} ({etiqueta_fmt}): anclaje {m['tasa_anclaje']} citando solo del contexto: {m['unanchored']}")

        # P8: y debe rechazar una incorrecta.
        malo = measure(_respuesta_incorrecta(bloque2, total, nuevos), bloque2)
        if malo["conteo_total_correcto"]:
            errores.append(f"{etiqueta}: acepta un total falso ({total + 7})")

    return errores, resumen


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--horas", required=True, help="JSON con la lista de horas 'YYYY-MM-DD HH'")
    args = ap.parse_args()
    horas = json.load(open(args.horas))

    client = build_pycti_client()
    curated = g._resolve_curated_ids(client)
    print(f"identidades curadas resueltas: {len(curated)}", file=sys.stderr)

    sin = g.SYSTEM_PROMPT.replace(CLAUSULA, "")
    if sin == g.SYSTEM_PROMPT:
        print("FALLO P6: la cláusula no coincide literalmente en SYSTEM_PROMPT", file=sys.stderr)
        return 1

    errores, resumen = revisar(client, horas, curated)

    print(f"\nbloques con datos          {resumen['bloques']}/{len(horas)}")
    print(f"bloques vacíos             {resumen['vacios']}")
    print(f"anclables con el prompt 1  {sorted(resumen['anclables_prompt1'])}")
    a2 = resumen["anclables_prompt2"]
    if a2:
        print(f"anclables con el prompt 2  min {min(a2)}, mediana {sorted(a2)[len(a2)//2]}, max {max(a2)}")
    print(f"entidades por bloque       {sorted(resumen['entidades'])}")
    print(f"bloques degenerados        {resumen['degenerados']} (total==nuevos o total==preexistentes)")
    print(f"prompts de sistema         con cláusula {hashlib.sha256(g.SYSTEM_PROMPT.encode()).hexdigest()[:12]}, "
          f"sin cláusula {hashlib.sha256(sin.encode()).hexdigest()[:12]}")

    if errores:
        print(f"\n{len(errores)} problema(s):", file=sys.stderr)
        for e in errores[:30]:
            print("  -", e, file=sys.stderr)
        if len(errores) > 30:
            print(f"  … y {len(errores) - 30} más", file=sys.stderr)
        return 1
    print(f"\nVIABLE: {resumen['bloques']} bloques × 3 prompts = {resumen['bloques'] * 3} corridas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
