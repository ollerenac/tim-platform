# Walkthrough de conectores nativos de OpenCTI — ingesta de datos

Estudio conector-por-conector de la ingesta en el pilot OpenCTI 7. Para cada conector
verificamos EN VIVO: (1) ¿ingesta?, (2) últimos objetos con su fecha para cotejar en la
fuente, (3) raw-content recibido, (4) qué entidades/relaciones se crearon, (5) veredicto.

Referencia: https://github.com/OpenCTI-Platform/connectors

## Pregunta que motiva el estudio

Los widgets del dashboard OpenCTI ("Most Active Threats", "Most Targeted Victims") no
parecen cambiar. ¿Es porque **no ingestamos bien** (incluso desde conectores estándar),
o porque **la ingesta funciona pero el widget lee una ventana/fecha que no la muestra**?
Este estudio distingue cuál de las dos, con evidencia.

## Categorización de nuestros conectores (en vivo, 2026-07-27)

Query: `{ connectors { name connector_type active } }`

| Tipo | Conectores | ¿Genera IoCs/entidades? |
|------|-----------|-------------------------|
| **EXTERNAL_IMPORT** | AlienVault · CIRCL OSINT (MISP) · CISA KEV · CVE · GreyNoise · MITRE ATT&CK | **Sí — el foco** |
| INTERNAL_ENRICHMENT | IpInfo | Reactivo — enriquece observables existentes, no jala |
| INTERNAL_IMPORT_FILE | CSV Mapper | Solo archivos subidos a mano |
| INTERNAL_INGESTION | Draft validation | Plomería |
| internal | Task processing #0–3 | Plomería (ejecuta background tasks: merges, borrados masivos) |

No hay `internal-export-file` desplegado. El estudio se limita a los **6 EXTERNAL_IMPORT**.

## Qué produce cada external-import (y si mueve los widgets de amenaza)

| Conector | Entidades que crea | ¿Alimenta Most Active Threats / Most Targeted Victims? |
|----------|--------------------|-----|
| **AlienVault** | Intrusion-Set, Malware, Attack-Pattern, Vulnerability, **Sector, Country**, Indicator, Observable + **relaciones targets/uses** | **SÍ** — el único que crea el grafo actor→targets→sector/country |
| CIRCL OSINT (MISP) | Indicators / observables | No directamente |
| CISA KEV | Solo Vulnerabilities | No (sin targeting) |
| CVE | Solo Vulnerabilities | No |
| GreyNoise | Indicators (reputación IP) | No |
| MITRE ATT&CK | Framework de referencia (one-shot; ya importado) | Estático — no cambia en el tiempo |

**Consecuencia:** si los widgets de amenaza/víctima no cambian, el conector a interrogar
primero es **AlienVault** — los demás ni siquiera deberían moverlos.

## Orden de estudio

1. [AlienVault OTX](./01-alienvault.md) — el rico; foco de la duda de widgets. **← hecho** (veredicto: ingesta sana, crea el grafo de targeting)
2. [CIRCL OSINT (MISP)](./02-misp-circl.md) — indicators. **← hecho** (veredicto: sano pero bajo volumen; 0 targeting, no mueve widgets por diseño)
3. [CISA KEV](./03-cisa-kev.md) — vulnerabilities. **← hecho** (veredicto: sano; 1,359 KEV, 0 targeting; enriquece vulns que AlienVault targetea)
4. [CVE / NIST NVD](./04-cve-nvd.md) — vulnerabilities. **← hecho** (veredicto: sano, 88,319 CVEs, catálogo base; 0 targeting)
5. GreyNoise — indicators
6. MITRE ATT&CK — referencia estática

## Cómo reproducir cualquier consulta

Todas las queries van por GraphQL con env in-container (nunca se imprime el token):

```bash
docker exec -i opencti-7-pilot-intel-extractor-1 python3 - <<'EOF'
import os, json, urllib.request
URL=os.environ["OPENCTI_URL"]+"/graphql"; TOK=os.environ["OPENCTI_TOKEN"]
def gql(q,v=None):
    b=json.dumps({"query":q,"variables":v or {}}).encode()
    r=urllib.request.Request(URL,data=b,headers={"Content-Type":"application/json","Authorization":"Bearer "+TOK})
    return json.load(urllib.request.urlopen(r,timeout=60))
# ... tu query ...
EOF
```
