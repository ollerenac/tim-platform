# Conector 3 — CISA KEV (EXTERNAL_IMPORT)

**Fecha del análisis:** 2026-07-27
**Imagen:** `opencti/connector-cisa-known-exploited-vulnerabilities:7.260706.0` (oficial)
**Fuente:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
**Doc de referencia:** https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/cisa-known-exploited-vulnerabilities

## 0. Qué es y cómo funciona

CISA publica el **KEV catalog** (Known Exploited Vulnerabilities) — la lista oficial de CVEs
con explotación confirmada en el mundo real. El conector jala ese JSON, y por cada CVE
crea/actualiza una **Vulnerability** en OpenCTI, firmada por la identidad
"Cybersecurity and Infrastructure Security Agency". Config: `CISA_INTERVAL=7` (días).

## 1. ¿Está ingestando? — SÍ

`connector_state`: `last_update: 2026-07-27T17:00` (hoy).

Huella (autor CISA `3e0f0f32-21e2-44cb-91be-f7c5f474fdfb`):

| Entidad/relación | Conteo |
|---|---:|
| **Vulnerabilities** | **1,359** |
| Reports | 0 |
| rel `related-to` | 689 |
| rel `targets` | **0** |
| rel `uses` | **0** |

Contexto: la plataforma tiene 90,646 Vulnerabilities en total — la enorme mayoría del
connector-cve (autor "NIST NVD"). CISA KEV aporta **1,359**: el subconjunto explotado.

## 2. Últimas 6 KEV (cotejables en el catálogo CISA)

| CVE | Modified | Descripción (de CISA) |
|-----|----------|----------------------|
| CVE-2026-16232 | 2026-07-24 | Check Point SmartConsole improper authentication |
| CVE-2021-3156 | 2026-07-23 | Sudo off-by-one heap overflow (Baron Samedit) |
| CVE-2017-7269 | 2026-07-23 | Microsoft IIS 6.0 WebDAV buffer overflow |
| CVE-2023-43770 | 2026-07-23 | Roundcube Webmail persistent XSS |
| CVE-2021-31755 | 2026-07-23 | Tenda AC11 stack buffer overflow |
| CVE-2023-36036 | 2026-07-22 | Windows Cloud Files Mini Filter Driver EoP |

Son CVEs reales, conocidos y explotados. Las descripciones vienen ricas de CISA.

## 3. Diferencia clave con connector-cve

Ambos crean Vulnerabilities, pero:
- **connector-cve** (NIST NVD): TODOS los CVEs (~90k), catálogo completo, autor "NIST NVD".
- **CISA KEV**: solo los explotados (~1,359), autor CISA. Es una **capa de señal de amenaza**
  sobre el catálogo — "de todos los CVEs, estos se están explotando ahora".

Como los Vulnerability deduplican por nombre (CVE-ID), un mismo CVE puede estar co-firmado:
existe una vez, enriquecido por ambos conectores.

## 4. Integración con el grafo — el detalle bonito

CVE-2023-43770 (Roundcube XSS) aparece en KEV **y** es targeteado por el actor TA458 en el
pulse de AlienVault (§01, Operation RoundPress):

```
TA458 --targets--> CVE-2023-43770   (relación creada por AlienVault)
CVE-2023-43770 = Known Exploited    (marcado por CISA KEV)
```

Es el MISMO nodo Vulnerability, enriquecido por dos conectores independientes. El grafo
está integrado: CISA KEV aporta la señal "explotado" a los CVEs que AlienVault conecta con
actores. **CISA KEV no crea targeting, pero enriquece los nodos que otros sí targetean.**

## 5. VEREDICTO

**Ingesta SANA.** 1,359 KEV al día, descripciones ricas, deduplicadas contra los CVEs de
NVD. **Cero targeting** (0 targets/uses) → no alimenta directamente los widgets de
amenaza/víctima, como se predijo. Su valor: la capa "explotado en la realidad" y ser el
destino de las relaciones `actor --targets--> vulnerability` que sí crea AlienVault.

**Para la duda de widgets:** tercer conector estándar confirmado sano y NO-culpable de
widgets estáticos (por diseño no produce grafo de amenaza; enriquece vulns).

## Reproducir

```graphql
{ connectors { name connector_state } }   # "CISA Known Exploited Vulnerabilities"
# huella: createdBy = 3e0f0f32-21e2-44cb-91be-f7c5f474fdfb (identidad CISA)
query($f: FilterGroup){ vulnerabilities(filters:$f,first:1){ pageInfo{ globalCount } } }  # 1359
```
