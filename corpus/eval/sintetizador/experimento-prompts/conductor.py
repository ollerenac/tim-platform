#!/usr/bin/env python3
"""Recorre los bloques con los tres prompts y escribe el CSV de resultados.

Cada bloque es una hora natural. Los tres prompts ven el mismo bloque, de modo
que el contenido se cancela dentro de él y la diferencia es atribuible al
prompt. Cada corrida es pareada: se mide el borrador que escribió el modelo y
el texto que devuelve el control aplicado a ESE mismo borrador, no a una
segunda generación.

Las tres condiciones se construyen en memoria; los ficheros del servicio no se
tocan. Alternarlas a mano es donde se pierde una tanda: basta olvidar restaurar
una constante entre condiciones para que el prompt 1 mida en realidad el 2, y el
CSV no lo delataría.

Escribe fila a fila y puede reanudarse: al arrancar lee lo ya hecho y salta esas
combinaciones.

    docker cp conductor.py tim-briefing-generator-1:/tmp/
    docker exec tim-briefing-generator-1 python /tmp/conductor.py \
        --horas /tmp/horas-productivas.json --salida /tmp/resultados.csv
"""
import argparse
import csv
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta

sys.path.insert(0, "/app")

from opencti_client import build_pycti_client          # noqa: E402
import generator as g                                   # noqa: E402
from anchor import _context_identifiers                 # noqa: E402
from eval_sintesis import measure                       # noqa: E402

CLAUSULA = ("When the data lists indicator values verbatim, cite at least three "
            "of them exactly as written, character for character, so the reader "
            "can act on them; never alter, abbreviate, defang or invent an "
            "indicator value. ")

COLUMNAS = [
    "prompt", "bloque", "etapa", "total_periodo", "nuevos_periodo",
    "prompt_sha256", "contexto_sha256", "motor", "anclables_en_contexto",
    "identificadores_emitidos", "identificadores_anclados", "tasa_anclaje",
    "no_anclados", "entidades_contexto", "nombres_exactos", "nombres_alterados",
    "nombres_ausentes", "cobertura_nominal", "conteo_total_correcto",
    "conteo_nuevos_correcto", "conteos_conjunto_correcto",
    "cumplimiento_instruccion", "palabras", "reintento", "texto",
]


class Freno:
    """Reparte las llamadas para no chocar con el límite del proveedor.

    Una tanda que se corta a mitad por un 429 deja bloques a medias, y un bloque
    a medias no sirve: los tres prompts tienen que ver la misma hora.
    """

    def __init__(self, por_minuto: int):
        self.intervalo = 60.0 / por_minuto if por_minuto else 0.0
        self.ultima = 0.0

    def esperar(self) -> None:
        espera = self.intervalo - (time.monotonic() - self.ultima)
        if espera > 0:
            time.sleep(espera)
        self.ultima = time.monotonic()


def _sha(texto: str) -> str:
    return hashlib.sha256(texto.encode()).hexdigest()


def _condiciones(sistema_con: str):
    """(número, valores expuestos, prompt de sistema) para cada condición."""
    sistema_sin = sistema_con.replace(CLAUSULA, "")
    if sistema_sin == sistema_con:
        raise SystemExit("la cláusula no coincide literalmente en SYSTEM_PROMPT")
    return (
        ("1", 0, sistema_sin),
        ("2", 10, sistema_sin),
        ("3", 10, sistema_con),
    )


def _fila(prompt, bloque, etapa, data, contexto, medida, sistema_sha, motor, retried=None):
    return {
        "prompt": prompt,
        "bloque": bloque,
        "etapa": etapa,
        "total_periodo": data["total_touched"],
        "nuevos_periodo": data["total_new"],
        "prompt_sha256": sistema_sha,
        "contexto_sha256": _sha(contexto),
        "motor": motor,
        "anclables_en_contexto": len(_context_identifiers(contexto)),
        "identificadores_emitidos": medida["identificadores_totales"],
        "identificadores_anclados": medida["identificadores_anclados"],
        # Denominador cero deja la celda vacía: no es 0 ni es 1, es indefinida.
        "tasa_anclaje": "" if medida["tasa_anclaje"] is None else medida["tasa_anclaje"],
        "no_anclados": ";".join(medida["unanchored"]),
        "entidades_contexto": medida["entidades_contexto"],
        "nombres_exactos": medida["nombres_exactos"],
        "nombres_alterados": medida["nombres_corruptos"],
        "nombres_ausentes": medida["nombres_omitidos"],
        "cobertura_nominal": medida["cobertura_nominal"],
        "conteo_total_correcto": medida["conteo_total_correcto"],
        "conteo_nuevos_correcto": medida["conteo_nuevos_correcto"],
        "conteos_conjunto_correcto": medida["conteos_correctos_conjuntos"],
        "cumplimiento_instruccion": medida["formato_sin_markdown"],
        "palabras": medida["palabras"],
        "reintento": "" if retried is None else retried,
        "texto": medida.pop("_texto"),
    }


def _hechas(ruta: str) -> set:
    if not os.path.exists(ruta):
        return set()
    with open(ruta, newline="", encoding="utf-8") as fh:
        return {(r["prompt"], r["bloque"]) for r in csv.DictReader(fh)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--horas", required=True)
    ap.add_argument("--salida", required=True)
    ap.add_argument("--por-minuto", type=int, default=8,
                    help="llamadas por minuto; el proveedor admite 10")
    ap.add_argument("--limite-bloques", type=int, help="para una prueba corta")
    args = ap.parse_args()

    horas = json.load(open(args.horas))
    if args.limite_bloques:
        horas = horas[: args.limite_bloques]
    hechas = _hechas(args.salida)
    if hechas:
        print(f"[conductor] reanudando: {len(hechas)} combinaciones ya hechas", file=sys.stderr)

    client = build_pycti_client()
    curated = g._resolve_curated_ids(client)
    g._resolve_curated_ids = lambda _c: curated   # una vez, no nueve por bloque
    condiciones = _condiciones(g.SYSTEM_PROMPT)
    motor = getattr(g, "BEDROCK_MODEL", "") or "desconocido"
    freno = Freno(args.por_minuto)

    nuevo = not os.path.exists(args.salida)
    with open(args.salida, "a", newline="", encoding="utf-8") as fh:
        escritor = csv.DictWriter(fh, fieldnames=COLUMNAS)
        if nuevo:
            escritor.writeheader()

        for indice, bloque in enumerate(horas, 1):
            hasta = datetime.strptime(bloque, "%Y-%m-%d %H").replace(tzinfo=timezone.utc) + timedelta(hours=1)
            data = None
            for numero, valores, sistema in condiciones:
                if (numero, bloque) in hechas:
                    continue
                if data is None:   # una sola recolección por bloque
                    data = g._collect_threat_data(client, 1, until=hasta)
                original_valores, original_sistema = g.IOC_VALUES_IN_PROMPT, g.SYSTEM_PROMPT
                try:
                    g.IOC_VALUES_IN_PROMPT = valores
                    g.SYSTEM_PROMPT = sistema
                    contexto = g._build_stats_block(data, 1, until=hasta)
                    freno.esperar()
                    borrador = g._call_llm(contexto)
                    final, meta = g._verify_draft(borrador, contexto)
                    if meta["retried"]:
                        freno.esperar()   # el control gastó una segunda llamada
                except Exception as exc:
                    print(f"[conductor] {bloque} prompt {numero}: FALLO {type(exc).__name__}: {exc}",
                          file=sys.stderr)
                    continue
                finally:
                    g.IOC_VALUES_IN_PROMPT, g.SYSTEM_PROMPT = original_valores, original_sistema

                sistema_sha = _sha(sistema)
                for etapa, texto, retried in (("borrador", borrador, None),
                                              ("verificado", final, meta["retried"])):
                    medida = measure(texto, contexto)
                    medida["_texto"] = texto
                    escritor.writerow(_fila(numero, bloque, etapa, data, contexto,
                                            medida, sistema_sha, motor, retried))
                fh.flush()
                print(f"[conductor] {indice}/{len(horas)} {bloque} prompt {numero}: "
                      f"emitidos {measure(final, contexto)['identificadores_totales']}, "
                      f"reintento={meta['retried']}", file=sys.stderr)

    print(f"[conductor] terminado -> {args.salida}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
