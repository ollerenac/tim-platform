#!/usr/bin/env python3
"""Comprueba la integridad estructural de un fichero de resultados.

No juzga si el experimento salió bien: comprueba que los datos permiten
juzgarlo. Correr esto ANTES de mirar ningún resultado — cada fallo que detecta
ha ocurrido de verdad en este proyecto.

    python3 verificar-resultados.py resultados-24h.csv
    python3 verificar-resultados.py --autotest
"""
import argparse
import csv
import sys
from collections import defaultdict

ETAPAS = ("borrador", "verificado")
PROMPTS = ("1", "2", "3")
BLOQUES = 48
ENTIDADES = 20
# Sus indicadores son todos hashes de fichero, clase que el control no cubre:
# el prompt 2 no añade nada anclable y por eso no llevan tratamiento.
SIN_TRATAMIENTO = {"2026-08-09 08", "2026-08-08 19", "2026-08-08 11"}


def _num(row, key):
    value = (row.get(key) or "").strip()
    return None if value == "" else float(value.replace(",", "."))


def verificar(rows: list[dict], bloques: int = BLOQUES) -> list[str]:
    errores: list[str] = []
    esperadas = len(PROMPTS) * bloques * len(ETAPAS)
    if len(rows) != esperadas:
        errores.append(f"se esperaban {esperadas} filas, hay {len(rows)}")

    vistos = defaultdict(list)
    for i, r in enumerate(rows, 2):  # 2 = primera fila de datos con cabecera
        etiqueta = f"fila {i} (prompt {r.get('prompt')}, bloque {r.get('bloque')}, {r.get('etapa')})"
        if r.get("etapa") not in ETAPAS:
            errores.append(f"{etiqueta}: etapa desconocida")
        if r.get("prompt") not in PROMPTS:
            errores.append(f"{etiqueta}: prompt fuera de 1..3")
        vistos[(r.get("prompt"), r.get("bloque"))].append(r.get("etapa"))

        emitidos = _num(r, "identificadores_emitidos")
        anclados = _num(r, "identificadores_anclados")
        tasa = (r.get("tasa_anclaje") or "").strip()
        techo = _num(r, "anclables_en_contexto")

        # El fallo que invalidó la medición anterior: denominador cero convertido en éxito.
        if emitidos == 0 and tasa != "":
            errores.append(f"{etiqueta}: emitidos=0 exige tasa_anclaje vacía, hay {tasa!r}")
        if emitidos and tasa == "":
            errores.append(f"{etiqueta}: emitidos>0 exige tasa_anclaje")
        if emitidos and anclados is not None and anclados > emitidos:
            errores.append(f"{etiqueta}: anclados > emitidos")
        if anclados is not None and techo is not None and anclados > techo:
            errores.append(f"{etiqueta}: anclados ({anclados:.0f}) supera el techo del contexto ({techo:.0f})")
        if emitidos and tasa != "":
            esperada = anclados / emitidos
            if abs(float(tasa.replace(",", ".")) - esperada) > 5e-4:
                errores.append(f"{etiqueta}: tasa_anclaje no coincide con anclados/emitidos")

        partes = [_num(r, c) for c in ("nombres_exactos", "nombres_alterados", "nombres_ausentes")]
        total = _num(r, "entidades_contexto")
        if None not in partes and total is not None and sum(partes) != total:
            errores.append(f"{etiqueta}: exactos+alterados+ausentes={sum(partes):.0f} != entidades_contexto={total:.0f}")
        if total is not None and total != ENTIDADES:
            errores.append(f"{etiqueta}: entidades_contexto={total:.0f}; se esperaban {ENTIDADES}")

        if not (r.get("texto") or "").strip():
            errores.append(f"{etiqueta}: texto vacío")
        if r.get("etapa") == "borrador" and (r.get("reintento") or "").strip():
            errores.append(f"{etiqueta}: reintento solo aplica a la etapa verificado")

    for (prompt, bloque), etapas in sorted(vistos.items()):
        if sorted(etapas) != sorted(ETAPAS):
            errores.append(f"prompt {prompt}, bloque {bloque}: par incompleto {etapas}")

    # Cada bloque tiene que verse con los tres prompts, o deja de ser un bloque.
    por_bloque = defaultdict(set)
    for r in rows:
        por_bloque[r.get("bloque")].add(r.get("prompt"))
    for bloque, prompts in sorted(por_bloque.items()):
        if prompts != set(PROMPTS):
            errores.append(f"bloque {bloque}: visto solo por los prompts {sorted(prompts)}")

    # El tratamiento existe salvo en los bloques de puros hashes, ya conocidos.
    techos = defaultdict(dict)
    for r in rows:
        techos[r.get("bloque")][r.get("prompt")] = _num(r, "anclables_en_contexto")
    for bloque, por_prompt in sorted(techos.items()):
        uno, dos = por_prompt.get("1"), por_prompt.get("2")
        if uno is None or dos is None:
            continue
        if dos <= uno and bloque not in SIN_TRATAMIENTO:
            errores.append(f"bloque {bloque}: el prompt 2 no añade anclables ({dos:.0f} vs {uno:.0f}) y no está en la lista conocida")
        if dos > uno and bloque in SIN_TRATAMIENTO:
            errores.append(f"bloque {bloque}: figura como sin tratamiento pero el prompt 2 añade anclables")

    # El prompt de sistema es constante por condición; el contexto lo es por bloque.
    for prompt in PROMPTS:
        valores = {r.get("prompt_sha256") for r in rows if r.get("prompt") == prompt}
        if len(valores) > 1:
            errores.append(f"prompt {prompt}: prompt_sha256 no es constante ({len(valores)} valores)")
    sp = {p: {r.get("prompt_sha256") for r in rows if r.get("prompt") == p} for p in PROMPTS}
    if sp["1"] and sp["2"] and sp["1"] != sp["2"]:
        errores.append("prompt 1 y prompt 2 deben compartir prompt de sistema: ninguno lleva la cláusula de citar")
    if sp["2"] and sp["3"] and sp["2"] == sp["3"]:
        errores.append("prompt 2 y prompt 3 comparten prompt de sistema: falta la cláusula de citar en el 3")
    for bloque in sorted(techos):
        del_bloque = [r for r in rows if r.get("bloque") == bloque]
        uno = {r.get("contexto_sha256") for r in del_bloque if r.get("prompt") == "1"}
        dos = {r.get("contexto_sha256") for r in del_bloque if r.get("prompt") == "2"}
        tres = {r.get("contexto_sha256") for r in del_bloque if r.get("prompt") == "3"}
        if uno and dos and uno == dos:
            errores.append(f"bloque {bloque}: prompts 1 y 2 comparten contexto; el 1 no debe llevar valores")
        if dos and tres and dos != tres:
            errores.append(f"bloque {bloque}: prompts 2 y 3 deben compartir contexto; solo cambia el prompt de sistema")
    return errores


def _fila(**kwargs):
    base = dict(prompt="1", bloque="2026-08-25 17", etapa="borrador",
                total_periodo="28", nuevos_periodo="28",
                prompt_sha256="sp-a", contexto_sha256="ctx-a", motor="haiku",
                anclables_en_contexto="3", identificadores_emitidos="0",
                identificadores_anclados="0", tasa_anclaje="", no_anclados="",
                entidades_contexto="20", nombres_exactos="14", nombres_alterados="0",
                nombres_ausentes="6", cobertura_nominal="0.7",
                conteo_total_correcto="True", conteo_nuevos_correcto="True",
                conteos_conjunto_correcto="True", cumplimiento_instruccion="False",
                palabras="200", reintento="", texto="un texto")
    base.update(kwargs)
    return base


def autotest() -> int:
    def solo(rows, fragmento):
        errores = verificar(rows, bloques=1)
        return any(fragmento in e for e in errores)

    ok = [_fila(prompt=p, etapa=e, prompt_sha256="sp-a" if p in "12" else "sp-b",
                contexto_sha256="ctx-a" if p == "1" else "ctx-b",
                anclables_en_contexto="3" if p == "1" else "13",
                identificadores_emitidos="0" if p == "1" else "7",
                identificadores_anclados="0" if p == "1" else "7",
                tasa_anclaje="" if p == "1" else "1.0",
                reintento="False" if e == "verificado" else "")
          for p in PROMPTS for e in ETAPAS]
    assert verificar(ok, bloques=1) == [], verificar(ok, bloques=1)

    malo = [dict(r) for r in ok]
    malo[0]["tasa_anclaje"] = "1.0"
    assert solo(malo, "exige tasa_anclaje vacía"), "no detecta el denominador cero convertido en éxito"

    malo = [dict(r) for r in ok]
    malo[0]["nombres_ausentes"] = "5"
    assert solo(malo, "!= entidades_contexto"), "no detecta que las tres clases no sumen"

    malo = [dict(r) for r in ok]
    for r in malo:
        if r["prompt"] == "1":
            r["contexto_sha256"] = "ctx-b"
            r["anclables_en_contexto"] = "13"
    assert solo(malo, "comparten contexto"), "no detecta que el prompt 1 lleve valores"

    malo = [dict(r) for r in ok]
    for r in malo:
        if r["prompt"] == "3":
            r["prompt_sha256"] = "sp-a"
    assert solo(malo, "comparten prompt de sistema"), "no detecta que falte la cláusula en el prompt 3"

    malo = [dict(r) for r in ok]
    malo[2]["identificadores_anclados"] = "99"
    assert solo(malo, "supera el techo"), "no detecta anclados por encima del techo"

    malo = [r for r in ok if r["prompt"] != "3"]
    assert solo(malo, "visto solo por los prompts"), "no detecta un bloque sin los tres prompts"

    malo = [dict(r) for r in ok]
    for r in malo:
        if r["prompt"] in ("2", "3"):
            r["anclables_en_contexto"] = "3"
    assert solo(malo, "no añade anclables"), "no detecta un bloque sin tratamiento fuera de la lista conocida"

    print("autotest OK: ocho comprobaciones")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="?", help="fichero de resultados a comprobar")
    ap.add_argument("--autotest", action="store_true", help="comprueba el comprobador")
    ap.add_argument("-b", "--bloques", type=int, default=BLOQUES,
                    help=f"bloques esperados (por defecto {BLOQUES})")
    args = ap.parse_args()
    if args.autotest:
        return autotest()
    if not args.csv:
        ap.error("indique un CSV o --autotest")
    with open(args.csv, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    errores = verificar(rows, bloques=args.bloques)
    if errores:
        print(f"{len(errores)} problema(s) en {args.csv}:", file=sys.stderr)
        for e in errores[:40]:
            print("  -", e, file=sys.stderr)
        if len(errores) > 40:
            print(f"  … y {len(errores) - 40} más", file=sys.stderr)
        return 1
    print(f"{args.csv}: {len(rows)} filas, estructura correcta")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
