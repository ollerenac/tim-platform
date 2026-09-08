#!/usr/bin/env python3
"""Imprime un objeto en STIX 2.1 canónico, tal como OpenCTI lo exportaría.

Distinto de mirar Elasticsearch: ES guarda el modelo interno de OpenCTI
(internal_id, rel_*.internal_id, i_aliases_ids). Esto reconstruye el STIX.

    docker cp scripts/show_stix.py opencti-7-pilot-worker-1:/tmp/ && \
      docker exec opencti-7-pilot-worker-1 python /tmp/show_stix.py Tool

Sin argumentos usa Tool. Tipos válidos: los de entity_type (Attack-Pattern,
Malware, Intrusion-Set, Tool, Campaign, Course-Of-Action, Identity…).
"""
import json
import os
import sys
import urllib.request


def query(gql, variables=None):
    url = os.environ["OPENCTI_URL"] + "/graphql"
    token = os.environ["OPENCTI_TOKEN"]
    body = json.dumps({"query": gql, "variables": variables or {}}).encode()
    req = urllib.request.Request(
        url, body, {"Content-Type": "application/json", "Authorization": "Bearer " + token}
    )
    return json.loads(urllib.request.urlopen(req).read().decode())


def main():
    entity_type = sys.argv[1] if len(sys.argv) > 1 else "Tool"
    found = query(
        "query($t:[String]){ stixCoreObjects(types:$t, first:1){ "
        "edges{ node{ id entity_type } } } }",
        {"t": [entity_type]},
    )
    edges = found["data"]["stixCoreObjects"]["edges"]
    if not edges:
        sys.exit(f"sin objetos de tipo {entity_type}")

    # Un tipo que OpenCTI no reconoce no da error: ignora el filtro y devuelve
    # cualquier objeto del grafo. Sin esta comprobación, `show_stix.py
    # Course-of-Action` (mal capitalizado) imprimiría un Malware cualquiera como
    # si fuera una mitigación.
    got = edges[0]["node"].get("entity_type")
    if got != entity_type:
        sys.exit(
            f"filtro ignorado: se pidió '{entity_type}' y llegó '{got}'. "
            f"¿Nombre de tipo mal escrito? (ojo: es Course-Of-Action, no Course-of-Action)"
        )

    raw = query(
        "query($i:String!){ stixCoreObject(id:$i){ toStix } }", {"i": edges[0]["node"]["id"]}
    )
    print(json.dumps(json.loads(raw["data"]["stixCoreObject"]["toStix"]), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
