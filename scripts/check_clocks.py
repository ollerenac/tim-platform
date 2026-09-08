#!/usr/bin/env python3
"""Test de admisión de relojes — se corre DESPUÉS de habilitar cada conector.

Un conector de eventos que sella `created` con la fecha de importación, o que
deja `start_time` en el centinela 1970, destruye la edad del dato de forma
irreversible: ningún widget la puede recuperar después. Este script lo detecta
con 50 objetos en vez de con 460.000.

    docker cp scripts/check_clocks.py opencti-7-pilot-worker-1:/tmp/ && \
      docker exec opencti-7-pilot-worker-1 python /tmp/check_clocks.py [Tipo ...]

Veredicto por tipo:
  COLAPSADO  ≥90% de la muestra tiene created==created_at. La fuente no publicó
             fecha propia, o la ingesta la pisó con la suya. Alarma en un feed de
             eventos; en un catálogo, decisión consciente.
  OK         la fuente publica su propia fecha y sobrevivió a la ingesta.

No esperes COLAPSADO en un catálogo por defecto: los tres de la capa 1 (ATT&CK,
geografía, DISARM) dieron OK. Publican su fecha de publicación, que es legítima.

⚠️ La muestra NO es aleatoria: son los primeros N que devuelve la API. El
histograma por año describe la muestra, no el conjunto. El veredicto sí es
fiable porque el colapso de relojes es una propiedad del conector, no del orden.
"""
import json
import os
import sys
import urllib.request
from collections import Counter

SENTINEL = "1970"

# Umbral de colapso. NO puede ser igualdad exacta con el tamaño de la muestra:
# la plataforma que motivó este script tenía 462.630/464.671 = 99,56% de colapso,
# que en una muestra de 200 da ~199 — y `collapsed == len(nodes)` habría dictado
# OK. Falso negativo en el caso canónico. Medido, no supuesto.
COLLAPSE_THRESHOLD = 0.90

# Por tipo: (fragmento GraphQL, campo que lleva la EDAD FUNCIONAL).
#
# El campo de edad no siempre es `created`. Para un Indicator, `created` significa
# "cuándo se redactó esta afirmación" — que al ingerir es siempre ahora, y colapsa
# por diseño. Su ventana de observación va en `valid_from`, que es donde STIX la
# pone. Medir `created` en un Indicator da COLAPSADO sobre datos perfectamente
# fechados: comprobado con 22.275 indicadores de AlienVault cuyo `created` era
# 100% del día de ingesta y cuyo `valid_from` cubría de julio-2024 a julio-2026,
# sin un solo nulo.
TYPES = {
    "Report": ("... on Report { created published }", "created"),
    "Indicator": ("... on Indicator { created valid_from valid_until }", "valid_from"),
    "Malware": ("... on Malware { created }", "created"),
    "Intrusion-Set": ("... on IntrusionSet { created }", "created"),
    "Attack-Pattern": ("... on AttackPattern { created }", "created"),
    "Course-Of-Action": ("... on CourseOfAction { created }", "created"),
    "Tool": ("... on Tool { created }", "created"),
    "Campaign": ("... on Campaign { created first_seen last_seen }", "first_seen"),
    "Vulnerability": ("... on Vulnerability { created }", "created"),
    "Country": ("... on Country { created latitude }", "created"),
    "Region": ("... on Region { created }", "created"),
    "Sector": ("... on Sector { created }", "created"),
    "Organization": ("... on Organization { created }", "created"),
}


def query(gql, variables=None):
    # env leído aquí y no al importar: --demo corre en el host, sin credenciales.
    url = os.environ["OPENCTI_URL"] + "/graphql"
    token = os.environ["OPENCTI_TOKEN"]
    body = json.dumps({"query": gql, "variables": variables or {}}).encode()
    req = urllib.request.Request(
        url, body, {"Content-Type": "application/json", "Authorization": "Bearer " + token}
    )
    return json.loads(urllib.request.urlopen(req).read().decode())


def collapse_verdict(collapsed, sampled):
    """Veredicto por proporción, nunca por igualdad exacta. Ver COLLAPSE_THRESHOLD."""
    if not sampled:
        return "OK"
    return "COLAPSADO" if collapsed / sampled >= COLLAPSE_THRESHOLD else "OK"


def check_objects(entity_type, spec, sample=200):
    fragment, campo_edad = spec
    # entity_type se pide de vuelta para detectar el filtro ignorado (ver abajo).
    gql = (
        "query($t:[String]){ stixCoreObjects(types:$t, first:%d){ pageInfo{globalCount} "
        "edges{node{ entity_type created_at %s }} } }" % (sample, fragment)
    )
    data = query(gql, {"t": [entity_type]})
    if "data" not in data or not data["data"].get("stixCoreObjects"):
        return f"  {entity_type:15s} ERROR {str(data)[:90]}"

    block = data["data"]["stixCoreObjects"]
    total = block["pageInfo"]["globalCount"]
    nodes = [e["node"] for e in block["edges"]]
    if not nodes:
        return f"  {entity_type:15s} total=0"

    # Un tipo que OpenCTI no reconoce NO da error: ignora el filtro y devuelve
    # todo el grafo. Comprobado: un tipo inventado devolvió el total de la
    # plataforma. Sin esta verificación el script reportaría el conjunto entero
    # como si fuera de un solo tipo, que es exactamente la clase de fallo
    # silencioso que viene a cazar.
    intrusos = {n.get("entity_type") for n in nodes if n.get("entity_type") != entity_type}
    if intrusos:
        return (
            f"  {entity_type:15s} ERROR filtro ignorado — la respuesta trae "
            f"{sorted(intrusos)[:4]}. ¿Nombre de tipo mal escrito?"
        )

    # Un campo de edad ausente es peor que uno colapsado: no hay nada que comparar.
    nulos = sum(1 for n in nodes if not n.get(campo_edad))
    collapsed = sum(
        1 for n in nodes if (n.get(campo_edad) or "")[:10] == (n.get("created_at") or "")[:10]
    )
    years = sorted(Counter((n.get(campo_edad) or "NULL")[:4] for n in nodes).items())
    pct = 100.0 * collapsed / len(nodes)
    aviso = f"  ⚠️ {nulos} sin {campo_edad}" if nulos else ""
    return (
        f"  {entity_type:15s} total={total:<8} muestra={len(nodes):<4} "
        f"{campo_edad}==created_at: {collapsed}/{len(nodes)} ({pct:.0f}%)  "
        f"{collapse_verdict(collapsed, len(nodes))}{aviso}\n"
        f"  {'':15s} {campo_edad} por año (solo la muestra): {years}"
    )


# Relaciones que NO tienen "cuándo" por naturaleza: son afirmaciones atemporales,
# no observaciones. Un indicador `indicates` un malware siempre, no durante un
# periodo; una subtécnica lo es siempre; un país está en su región siempre.
# El centinela 1970 en estas es correcto y no debe disparar alarma. Agregarlas con
# las demás da un porcentaje global sin significado: con AlienVault dentro salía
# 96% de centinela, que parecía el desastre de la plataforma anterior y no lo era.
ATEMPORALES = {
    "indicates", "based-on", "subtechnique-of", "located-at", "part-of",
    "derived-from", "revoked-by", "related-to", "has",
}


def check_relationships(sample=500):
    gql = (
        "query{ stixCoreRelationships(first:%d){ pageInfo{globalCount} "
        "edges{node{ relationship_type start_time }} } }" % sample
    )
    data = query(gql)
    if "data" not in data or not data["data"].get("stixCoreRelationships"):
        return f"  {'relaciones':15s} ERROR {str(data)[:90]}"
    block = data["data"]["stixCoreRelationships"]
    total = block["pageInfo"]["globalCount"]
    nodes = [e["node"] for e in block["edges"]]
    if not nodes:
        return f"  {'relaciones':15s} total=0"

    por_tipo = {}
    for n in nodes:
        t = n.get("relationship_type") or "?"
        d = por_tipo.setdefault(t, [0, 0])
        d[0] += 1
        if (n.get("start_time") or "")[:4] == SENTINEL:
            d[1] += 1

    lineas = [f"  {'relaciones':15s} total={total:<8} muestra={len(nodes)} (centinela por tipo)"]
    for t, (n, cent) in sorted(por_tipo.items(), key=lambda kv: -kv[1][0]):
        pct = 100.0 * cent / n
        if t in ATEMPORALES:
            veredicto = "atemporal — el centinela es correcto"
        else:
            veredicto = "ALERTA — la edad del evento se perdió" if pct > 50 else "OK"
        lineas.append(f"  {'':15s}   {t:<18} {cent:>4}/{n:<4} ({pct:3.0f}%)  {veredicto}")
    return "\n".join(lineas)


def main():
    wanted = sys.argv[1:] or list(TYPES)
    unknown = [t for t in wanted if t not in TYPES]
    if unknown:
        sys.exit(f"tipo desconocido: {unknown}. Conocidos: {list(TYPES)}")
    print("=== relojes ===")
    for entity_type in wanted:
        print(check_objects(entity_type, TYPES[entity_type]))
    print(check_relationships())


def demo():
    """Autocomprobación sin plataforma: la lógica de veredicto, aislada."""
    same = [{"created": "2026-08-03T01:00:00Z", "created_at": "2026-08-03T09:00:00Z"}] * 3
    assert all((n["created"] or "")[:10] == (n["created_at"] or "")[:10] for n in same)
    diff = [{"created": "2019-04-01T00:00:00Z", "created_at": "2026-08-03T09:00:00Z"}]
    assert not any((n["created"] or "")[:10] == (n["created_at"] or "")[:10] for n in diff)
    rels = [{"start_time": "1970-01-01T00:00:00Z"}] * 9 + [{"start_time": "2026-08-01T00:00:00Z"}]
    assert 100.0 * sum(1 for r in rels if r["start_time"][:4] == SENTINEL) / len(rels) == 90.0

    # El caso que motivó el script: 462.630/464.671 = 99,56% de colapso. En una
    # muestra de 200 son ~199, y la condición anterior (collapsed == len) dictaba
    # OK. Este assert es la regresión de aquel falso negativo.
    assert collapse_verdict(199, 200) == "COLAPSADO"
    assert collapse_verdict(200, 200) == "COLAPSADO"
    assert collapse_verdict(180, 200) == "COLAPSADO"   # justo en el umbral, 90%
    assert collapse_verdict(179, 200) == "OK"          # justo por debajo
    assert collapse_verdict(0, 200) == "OK"            # MITRE, geografía, DISARM
    assert collapse_verdict(0, 0) == "OK"              # sin muestra, sin division
    print("demo OK")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        demo()
    else:
        main()
