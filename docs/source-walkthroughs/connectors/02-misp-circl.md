# Conector 2 — CIRCL OSINT Feed / MISP (EXTERNAL_IMPORT)

**Fecha del análisis:** 2026-07-27
**Imagen:** `opencti/connector-misp-feed:7.260706.0` (oficial Filigran)
**Fuente:** `https://www.circl.lu/doc/misp/feed-osint/` — feed OSINT MISP curado por CIRCL (Luxemburgo)
**Doc de referencia:** https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/misp-feed

## 0. Qué es y cómo funciona

MISP publica **events** (eventos) — cada uno un conjunto de atributos IOC + objetos sobre
un incidente/campaña. El conector jala el feed MISP (formato manifest + JSON por event),
lo convierte a STIX y empuja a RabbitMQ → worker → ES.

Config en nuestro compose:
```
MISP_FEED_URL=https://www.circl.lu/doc/misp/feed-osint/
MISP_FEED_INTERVAL=1440         # cada 24h
MISP_FEED_IMPORT_FROM_DATE=2025-01-01
MISP_FEED_CREATE_REPORTS=true
MISP_FEED_CREATE_INDICATORS=true
MISP_FEED_CREATE_OBSERVABLES=true
```

Un **MISP event → un Report** que contiene los atributos como Indicators + Observables.

## 1. ¿Está ingestando? — SÍ, pero es un feed de BAJO VOLUMEN

`connector_state`: `last_run: 2026-07-27T18:01` (hoy), `last_event: 2026-07-27T16:16`.
Técnicamente sano, corre a diario.

Conteos (autor CIRCL `be7ea26f-a186-4a64-8304-fabfe973d4a5`):

| Entidad/relación | Conteo |
|---|---:|
| Reports (events) | **11** |
| Indicators | **1,478** |
| rel `indicates` | 350 |
| rel `based-on` | 1,306 |
| rel `related-to` | 787 |
| rel **`targets`** | **0** |
| rel **`uses`** | **0** |

**Punto clave:** CIRCL crea muchísimos indicators/observables pero **CERO relaciones de
targeting** (`targets`, `uses`). Es un feed centrado en IOCs, no en el grafo de amenaza.

## 2. Últimos 8 events (para cotejar)

| Publicado | Event | Entidades contenidas |
|-----------|-------|---------------------|
| 2026-06-01 | Phishing Campaign Targeting Hotel Customers in Luxembourg | Indicator×29, Domain×14, Hostname×14, Sector×2, Attack-Pattern×1 |
| 2026-03-13 | KadNap botnet IOC (mainly Asus router) | Indicator×19, IPv4×9, StixFile×6 |
| 2026-02-18 | PFCloud · Bulletproof Hosting · Datacarry Ransomware | Indicator×27, Sector×10, Attack-Pattern×10, StixFile×10, IPv4×3 |
| 2026-02-12 | Fake 7-Zip downloads turning home PCs into proxy nodes | Indicator×16, Hostname×13, StixFile×12, Attack-Pattern×15 |
| 2026-02-01 | "Hanger Bulletin": UAC-0001 (APT28) cyberattacks | Domain×5, StixFile×55 |
| 2026-01-29 | Disrupting the World's Largest Residential Proxy Network | Domain×23, Attack-Pattern×15, StixFile×14 |
| 2025-12-15 | Kunai Analysis Report | Indicator×17, IPv4×10, StixFile×4 |
| 2025-06-20 | Malicious File Creates Network Socket… | Indicator×12, StixFile×4, Text×6 |

Observación: el event más reciente es de **2026-06-01** (~2 meses atrás). No es que el
conector esté roto — CIRCL **publica esporádicamente** (11 events en ~7 meses de historia
importada). Feed curado, alta calidad, baja frecuencia.

## 3. Raw content — mínimo

Las descripciones de los reports son solo el **título del event** ("Phishing Campaign
Targeting Hotel Customers in Luxembourg", "KadNap botnet IOC…"). Los events MISP son
IOC-céntricos, no narrativos — el valor está en los atributos (hashes, dominios, IPs), no
en prosa. Contrasta con AlienVault, cuyos pulses traen descripción rica.

## 4. Detalle — sectores sin targeting

CIRCL sí crea Sectors (p.ej. el event PFCloud trae 10), pero **no los relaciona con un
actor vía `targets`**. Nota sobre dedup de entidades: un Sector como "Finance" es UN nodo
compartido — aparece con 103 relaciones, pero esas vienen de OTROS conectores (AlienVault)
que apuntan al mismo nodo. Un sector propio de CIRCL como "Civil Aviation" tiene **0
relaciones**: nadie lo targetea. Prueba de que CIRCL no genera el grafo actor→víctima.

## 5. VEREDICTO

**Ingesta SANA pero de otra naturaleza.** CIRCL/MISP funciona: corre a diario, importó 11
events → 1,478 indicators + observables. Pero:

1. Es **bajo volumen** (el feed publica esporádicamente; último event 2026-06-01 — no es un
   fallo, es la cadencia de la fuente).
2. Crea **cero relaciones de targeting** → **NO alimenta** "Most Active Threats" ni "Most
   Targeted Victims". Confirma la predicción del README: es un feed de indicators.

**Para la duda de widgets:** segundo conector estándar confirmado como NO-culpable de
widgets estáticos — no porque falle, sino porque por diseño no produce el grafo de amenaza.
Solo AlienVault (de los external-import) lo hace. Refuerza que la causa de "widgets no
cambian" está en el widget, no en la ingesta.

## Reproducir

```graphql
{ connectors { name connector_state } }   # buscar "CIRCL OSINT Feed"
# conteos con createdBy = be7ea26f-a186-4a64-8304-fabfe973d4a5
query($f: FilterGroup){ indicators(filters:$f,first:1){ pageInfo{ globalCount } } }
query($f: FilterGroup){ stixCoreRelationships(filters:$f,first:1){ pageInfo{ globalCount } } }
#   f con relationship_type "targets" → 0, "based-on" → 1306
```
