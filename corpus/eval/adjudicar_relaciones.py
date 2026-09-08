#!/usr/bin/env python3
"""Adjudicar el 0 % de concordancia en relaciones de los tres avisos held-out.

El Capitulo 5 explicaba ese 0 % por desalineacion de NOMBRES: el anexo STIX
nombra extremos que la prosa no menciona, y §3.9 prohibe al extractor
inventarlos. Este script contrasta esa hipotesis en los tres avisos en vez de
extrapolar la de uno, y mide ademas el TIPO de vinculo, que resulta ser la
causa dominante.

Uso:  python3 corpus/eval/adjudicar_relaciones.py
Salida: una seccion por aviso con (a) presencia literal de los extremos en el
documento, (b) co-ocurrencia en una misma frase — que es lo que §3.9 exige
realmente — y (c) reparto de tipos de vinculo en anexo y en la corrida.

ponytail: sin dependencias externas; re-ejecutable desde el repo limpio.
"""
import json
import re
import unicodedata
from pathlib import Path

CASOS = {
    "AA26-097A": ("corpus/aa26-097a/AA26-097A.stix_.json",
                  "corpus/eval/aa26-097a.txt",
                  "corpus/eval/runs/aa26-097a.haiku-heldout-20260824.json"),
    "AA25-239A": ("corpus/aa25-239a/AA25-239A.stix_.json",
                  "corpus/eval/aa25-239a.txt",
                  "corpus/eval/runs/aa25-239a.haiku-heldout-20260824.json"),
    "AA25-203A": ("corpus/aa25-203a/AA25-203A-interlock-stix.json",
                  "corpus/eval/aa25-203a.txt",
                  "corpus/eval/runs/aa25-203a.haiku-heldout-20260824.json"),
}


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", unicodedata.normalize("NFKD", s)).strip().lower()


def nombre_de(obj: dict) -> str | None:
    """Etiqueta comparable de un objeto STIX: name, value o el literal del patron."""
    for clave in ("name", "value"):
        if obj.get(clave):
            return str(obj[clave])
    if obj.get("pattern"):
        literales = re.findall(r"'([^']+)'", obj["pattern"])
        if literales:
            return literales[0]
    return None


def adjudicar(caso: str, stix_path: str, txt_path: str, run_path: str) -> dict:
    stix = json.loads(Path(stix_path).read_text(encoding="utf-8", errors="replace"))
    objetos = stix.get("objects", stix if isinstance(stix, list) else [])
    por_id = {o["id"]: o for o in objetos if isinstance(o, dict) and o.get("id")}

    crudo = Path(txt_path).read_text(encoding="utf-8", errors="replace")
    documento = norm(crudo)
    frases = [norm(f) for f in re.split(r"(?<=[.!?])\s+|\n{2,}", crudo) if f.strip()]

    relaciones = [o for o in objetos if isinstance(o, dict) and o.get("type") == "relationship"]
    ninguno = solo_uno = ambos = sin_resolver = misma_frase = 0
    tipos_anexo: dict[str, int] = {}

    for rel in relaciones:
        tipos_anexo[rel.get("relationship_type")] = tipos_anexo.get(rel.get("relationship_type"), 0) + 1
        extremos = []
        for ref in (rel.get("source_ref"), rel.get("target_ref")):
            obj = por_id.get(ref)
            extremos.append(nombre_de(obj) if obj else None)
        if None in extremos:
            sin_resolver += 1
            continue
        presentes = [norm(e) in documento for e in extremos]
        if all(presentes):
            ambos += 1
        elif any(presentes):
            solo_uno += 1
        else:
            ninguno += 1
        # §3.9 exige que una MISMA frase declare ambos extremos.
        if any(norm(extremos[0]) in f and norm(extremos[1]) in f for f in frases):
            misma_frase += 1

    corrida = json.loads(Path(run_path).read_text(encoding="utf-8", errors="replace"))
    tipos_corrida: dict[str, int] = {}
    for rel in corrida.get("relationships", []):
        tipo = rel.get("relationship_type") or rel.get("type")
        tipos_corrida[tipo] = tipos_corrida.get(tipo, 0) + 1

    return {
        "caso": caso,
        "relaciones_anexo": len(relaciones),
        "ambos_extremos_en_documento": ambos,
        "un_extremo_en_documento": solo_uno,
        "ningun_extremo_en_documento": ninguno,
        "extremo_no_resoluble": sin_resolver,
        "ambos_extremos_en_una_frase": misma_frase,
        "tipos_anexo": dict(sorted(tipos_anexo.items(), key=lambda kv: -kv[1])),
        "tipos_corrida": dict(sorted(tipos_corrida.items(), key=lambda kv: -kv[1])),
    }


def main() -> None:
    for caso, rutas in CASOS.items():
        r = adjudicar(caso, *rutas)
        print(f"\n=== {r['caso']} — {r['relaciones_anexo']} relaciones en el anexo ===")
        print(f"  ambos extremos literales en el documento : {r['ambos_extremos_en_documento']}")
        print(f"  un solo extremo literal                  : {r['un_extremo_en_documento']}")
        print(f"  ningun extremo literal                   : {r['ningun_extremo_en_documento']}")
        print(f"  extremo no resoluble en el anexo         : {r['extremo_no_resoluble']}")
        print(f"  AMBOS extremos en UNA MISMA FRASE (§3.9) : {r['ambos_extremos_en_una_frase']}")
        print(f"  tipos de vinculo del anexo    : {r['tipos_anexo']}")
        print(f"  tipos de vinculo del extractor: {r['tipos_corrida']}")


if __name__ == "__main__":
    main()
