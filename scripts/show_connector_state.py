#!/usr/bin/env python3
"""Muestra el estado grabado de los conectores — el campo que miente cuando falla.

Un conector guarda `last_run` aunque la descarga haya fallado. Con un intervalo de
días, eso lo deja dormido creyéndose al día: badge Active, cola 0, logs en silencio.
Este script expone ese estado para poder desmentirlo.

    docker cp scripts/show_connector_state.py opencti-7-pilot-worker-1:/tmp/ && \
      docker exec opencti-7-pilot-worker-1 python /tmp/show_connector_state.py [filtro]

El filtro es una subcadena del nombre (ej. "MITRE"). Sin filtro, muestra todos los
conectores externos; los internos de la plataforma se omiten.
"""
import datetime
import json
import os
import sys
import urllib.request


def query(gql):
    url = os.environ["OPENCTI_URL"] + "/graphql"
    token = os.environ["OPENCTI_TOKEN"]
    req = urllib.request.Request(
        url, json.dumps({"query": gql}).encode(),
        {"Content-Type": "application/json", "Authorization": "Bearer " + token},
    )
    return json.loads(urllib.request.urlopen(req).read().decode())


def human_last_run(state):
    """last_run es epoch en segundos; devuelve ISO en UTC o una nota de por qué no."""
    if not state:
        return "(sin estado — el conector correrá en su próximo ciclo)"
    try:
        parsed = json.loads(state)
    except (ValueError, TypeError):
        return f"(estado no parseable: {state[:60]})"
    # OpenCTI devuelve la cadena "null" para un conector que aún no ha corrido:
    # json.loads la convierte en None, no en dict.
    if not isinstance(parsed, dict):
        return "(sin estado — el conector correrá en su próximo ciclo)"
    last_run = parsed.get("last_run")
    if not last_run:
        return "(estado sin last_run)"
    stamp = datetime.datetime.fromtimestamp(int(last_run), datetime.timezone.utc)
    return stamp.isoformat()


def main():
    needle = sys.argv[1].lower() if len(sys.argv) > 1 else None
    data = query("{ connectors{ id name connector_type connector_state active } }")
    rows = data["data"]["connectors"]
    for connector in rows:
        # los internos ([TASK], [FILE], [DRAFT]) no tienen estado propio de ingesta
        if not needle and connector["connector_type"] in ("internal",):
            continue
        if needle and needle not in connector["name"].lower():
            continue
        print(f"  {connector['name']}")
        print(f"    id       : {connector['id']}")
        print(f"    activo   : {connector['active']}")
        print(f"    estado   : {connector['connector_state'] or '(vacío)'}")
        print(f"    last_run : {human_last_run(connector['connector_state'])}")


def demo():
    """Autocomprobación sin plataforma: el parseo de estado, aislado."""
    assert human_last_run('{"last_run": 1785796908}').startswith("2026-08-03T22:41:48")
    assert "sin estado" in human_last_run(None)
    assert "sin estado" in human_last_run("")
    assert "sin estado" in human_last_run("null")   # OpenCTI antes de la primera corrida
    assert "sin last_run" in human_last_run("{}")
    assert "no parseable" in human_last_run("no-json")
    print("demo OK")


if __name__ == "__main__":
    if "--demo" in sys.argv:
        demo()
    else:
        main()
