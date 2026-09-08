#!/usr/bin/env python3
"""Congela los seis contextos del experimento en una sola pasada.

Seis y no tres: cada ventana necesita su bloque con valores (prompts 2 y 3) y
sin valores (prompt 1). Un solo `_collect_threat_data` por ventana, reutilizado
para las dos variantes, de modo que ambas describan exactamente los mismos datos.

Los conectores escriben sin parar: congelar las ventanas en momentos distintos
puede mover la lista de actores y romper la comparabilidad entre condiciones.
Por eso van las seis juntas y el script comprueba al final que las líneas de
entidades coinciden.

Se ejecuta DENTRO del contenedor briefing-generator:
    docker cp congelar-contextos.py tim-briefing-generator-1:/tmp/
    docker exec tim-briefing-generator-1 python /tmp/congelar-contextos.py
"""
import hashlib
import sys

sys.path.insert(0, "/app")

from opencti_client import build_pycti_client          # noqa: E402
import generator as g                                   # noqa: E402
from anchor import _context_identifiers                 # noqa: E402

VENTANAS = (12, 24, 72)
DESTINO = "/tmp"
VARIANTES = (("con-valores", 10), ("sin-valores", 0))


def main() -> int:
    client = build_pycti_client()
    original = g.IOC_VALUES_IN_PROMPT
    bloques = {}
    try:
        for horas in VENTANAS:
            datos = g._collect_threat_data(client, horas)
            for etiqueta, cuantos in VARIANTES:
                g.IOC_VALUES_IN_PROMPT = cuantos
                bloques[(horas, etiqueta)] = g._build_stats_block(datos, horas)
    finally:
        g.IOC_VALUES_IN_PROMPT = original

    print(f"{'fichero':<34} {'sha256':<16} {'anclables':>9}")
    for (horas, etiqueta), bloque in bloques.items():
        ruta = f"{DESTINO}/ctx-{horas}h-{etiqueta}.txt"
        with open(ruta, "w", encoding="utf-8") as fh:
            fh.write(bloque)
        digest = hashlib.sha256(bloque.encode()).hexdigest()
        print(f"{ruta:<34} {digest[:16]} {len(_context_identifiers(bloque)):>9}")

    errores = []
    for campo in ("Tracked threat actors", "Tracked malware families",
                  "ATT&CK techniques tracked"):
        lineas = {
            next((l for l in b.splitlines() if l.startswith(campo)), "")
            for b in bloques.values()
        }
        if len(lineas) != 1:
            errores.append(f"«{campo}» difiere entre contextos ({len(lineas)} variantes)")
    for (horas, etiqueta), bloque in bloques.items():
        tiene = "Highest-confidence indicator values" in bloque
        if tiene != (etiqueta == "con-valores"):
            errores.append(f"ctx-{horas}h-{etiqueta}: línea de valores {'presente' if tiene else 'ausente'} y no debería")

    print()
    if errores:
        print("NO USAR ESTOS CONTEXTOS:", file=sys.stderr)
        for e in errores:
            print("  -", e, file=sys.stderr)
        return 1
    print("Comparables: entidades idénticas en los seis; línea de valores solo donde toca.")
    print("Sacarlos con:  docker cp tim-briefing-generator-1:/tmp/ctx-12h-con-valores.txt .")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
