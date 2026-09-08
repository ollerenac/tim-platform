# Conector 1 — AlienVault OTX (EXTERNAL_IMPORT)

**Fecha del análisis:** 2026-07-27 (stack 21/21 healthy)
**Imagen:** `opencti/connector-alienvault:7.260706.0` (oficial Filigran, sin modificar)
**Doc de referencia:** https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/alienvault

## 0. Qué es y cómo funciona

AlienVault OTX publica **pulses** — informes colaborativos, cada uno un paquete de datos
sobre una amenaza específica. El conector jala esos pulses (pull), los convierte a STIX
2.1 y los empuja a la cola RabbitMQ → el `worker` los consume hacia Elasticsearch.

Mapeo (según la doc oficial): un **Pulse → un Report** que contiene, como `object_refs`,
todas las entidades y relaciones extraídas:

```
Pulse ──► Report (contenedor)
           ├─ Adversary          → Intrusion-Set
           ├─ Malware Families    → Malware
           ├─ Attack IDs          → Attack-Pattern (técnicas ATT&CK)
           ├─ CVE Indicators      → Vulnerability
           ├─ Industries          → Sector (Identity)
           ├─ Targeted Countries  → Country (Location)
           ├─ IPv4/Domain/Hash/…  → Observable + Indicator
           └─ relaciones: IntrusionSet→targets→Sector/Country/Vulnerability,
                          IntrusionSet→uses→Malware/Attack-Pattern,
                          Indicator→indicates→…, Indicator→based-on→Observable
```

## 1. ¿Está ingestando? — SÍ, y creciendo

`connector_state` en vivo:
```
latest_pulse_timestamp: 2026-07-27T08:01:00   ← al día (hoy)
last_run: 1785175336 (epoch)
```

Conteos de lo creado por AlienVault (author id `09c76b67-24e6-4adb-9b51-92f1d63072e8`),
comparados con la medición de hace 2 días (2026-07-25):

| Métrica | 2026-07-25 | 2026-07-27 | Δ |
|---------|-----------:|-----------:|---|
| Reports (pulses) | 129 | **139** | +10 |
| relaciones `targets` | 3,499 | **3,662** | +163 |
| relaciones `uses` | 6,760 | **7,129** | +369 |
| relaciones `indicates` | — | **50,789** | — |
| relaciones `based-on` | — | **2,323** | — |

**Veredicto parcial:** ingesta viva, incremental, y creando relaciones de targeting
(las que alimentan los widgets). No hay síntoma de ingesta rota.

## 2. Últimos 10 pulses (para cotejar en la fuente)

Cada uno cotejable buscando su título en https://otx.alienvault.com y en el blog original.

| Publicado | Pulse | Entidades contenidas (resumen) |
|-----------|-------|-------------------------------|
| 2026-07-25 | Fake Corepack Site Distributes Infostealer and Proxyware | Attack-Pattern×21, Malware×2, Sector×1, Indicator×4, Domain×2 |
| 2026-07-24 | Check Point SmartConsole Authentication Bypass (CVE-2026-16232) | Attack-Pattern×20, IPv4×4, Indicator×4 |
| 2026-07-24 | Security Advisory - July 2026 Security Update | Attack-Pattern×12, IPv4×4, Indicator×4 |
| 2026-07-24 | June 2026 Threat Trend Report on APT Attacks (South Korea) | **Intrusion-Set×1**, Malware×4, Attack-Pattern×20, Domain×2 |
| 2026-07-24 | Ongoing PLC Exploitation Against Critical U.S. Infrastructure | **Intrusion-Set×1**, **Sector×2**, IPv4×11, Indicator×23, Attack-Pattern×20 |
| 2026-07-24 | Intercom-client@7.0.4 Harvesting Github Credentials | **Intrusion-Set×1**, **Sector×1**, Hostname×1 |
| 2026-07-23 | Thailand's Ministry of Finance Targeted With Hermes AI Agent, Hades Implant | Malware×5, **Sector×2**, **Country×1**, Attack-Pattern×16, StixFile×12, IPv4×3 |
| 2026-07-23 | Upgrades MaaS Ecosystem with Modular Tools (TAG-195) | Attack-Pattern×25, Domain×5, StixFile×30 |
| 2026-07-23 | Email threat landscape: Q2 2026 trends | **Sector×11**, Domain×11, Attack-Pattern×20, Indicator×13 |
| 2026-07-23 | Operation RoundPress (TA458 / GRU) | **Intrusion-Set×1**, Malware×1, **Sector×5**, **Country×4**, Attack-Pattern×20, Indicator×12 |

Observación: varios pulses traen el grafo completo (Intrusion-Set + Sector + Country) —
la materia prima exacta de los widgets de amenaza/víctima.

## 3. Raw content — muestra (descripción tal como OpenCTI la recibió)

- **Operation RoundPress:** *"TA458, a Russia-aligned espionage group likely linked to
  GRU, continues exploiting half-click cross-site scripting vulnerabilities in webmail
  platforms to steal sensitive email data…"*
- **Thailand MoF / Hermes AI:** *"Between July 9-13, 2026, three exposed directories on a
  Hong Kong server revealed an ongoing cyber espionage operation targeting Thailand's
  Ministry of Finance… leveraged Hermes, an autonomous AI agent in unattended YOLO mode,
  alongside a custom Go-based implant [Hades]…"*
- **TAG-195 MaaS:** *"Insikt Group identified four new malware families from TAG-195
  (Golden Chickens, Venom Spider)… TinyEgg… ChonkyChicken…"*

Es inteligencia real, reciente y de fuentes reputadas (ESET, AhnLab, Recorded Future,
Microsoft). No es ruido ni relleno.

## 4. Ejemplar en profundidad — TA458 (Operation RoundPress)

El actor `Intrusion-Set: TA458` y sus relaciones salientes REALES en el grafo:

```
TA458 --targets--> Country:       Ukraine
TA458 --targets--> Sector:        Government, Chemical
TA458 --targets--> Vulnerability: CVE-2024-42900, CVE-2025-3929, CVE-2023-43770,
                                  CVE-2026-8496, CVE-2024-42009  (5)
TA458 --uses----->  Attack-Pattern: 12 técnicas (Local Email Collection, T1189,
                                  T1543, T1059.004, T1059.007, …)
TA458 --indicates via Indicators: 10 observables
```

Cotejo con la fuente (ESET "Operation RoundPress"): TA458 = grupo alineado con Rusia (GRU),
webmail zero-days, objetivos gubernamentales de Ucrania. **Coincide.** El conector extrajo
correctamente actor + víctimas (país/sector) + CVEs + técnicas y creó las relaciones.

Detalle menor: algunas Attack-Patterns aparecen con nombre = ID ("T1189", "T1543") —
técnicas nuevas traídas por pulses recientes posteriores al renombrado masivo del 24-jul.
Cosmético; el mismo procedimiento de renombrado las corrige.

## 4b. Ejemplo campo-por-campo — "Fake Corepack Site Distributes Infostealer" (pulse `6a646bc49938f4fb7a0a02f2`)

Caso didáctico para entender EXACTAMENTE qué importa el conector y de dónde sale cada
entidad. Pulse: https://otx.alienvault.com/pulse/6a646bc49938f4fb7a0a02f2 (publicado
2026-07-25).

### ¿Qué formato del pulse importa el conector?

NINGUNO de los exports descargables (CSV / OpenIOC / STIX2.1 / STIX2.0). Esos son para
consumo manual. El conector usa el **SDK oficial `OTXv2` contra la API nativa de OTX** y
trae el **JSON crudo del pulse**:

```python
# alienvault/client.py
from OTXv2 import OTXv2                                    # L9
self.otx = OTXv2(api_key, server=str(base_url))           # L28
pulse_data = self.otx.getsince(timestamp=modified_since, limit=limit)  # L41
```

`getsince(modified_since)` = "dame los pulses suscritos modificados desde esta fecha" —
el mecanismo de pull incremental. Por eso da igual qué formato de descarga elijas tú.

### Estructura del pulse (modelo `models.py`)

El JSON tiene campos fijos; `builder.py` crea una entidad STIX de cada uno:

| Sección en la página OTX | Campo JSON (`Pulse`) | Método `builder.py` | Entidad OpenCTI | En este pulse |
|---|---|---|---|---:|
| **INDUSTRY:** Technology | `industries` | `_create_target_sectors` (L265) | **Sector** | 1 |
| **MALWARE FAMILIES:** OpenShield, Apprunner | `malware_families` | `_create_malwares` (L222) | **Malware** | 2 |
| **ATT&CK IDS:** T1036.005, T1547, … | `attack_ids` | `_create_attack_patterns` (L301) | **Attack-Pattern** | 21 |
| pestaña **Indicators of Compromise (4)** | `indicators[]` | `_create_indicator` (L475) + observable | **Indicator + Observable** | 4 Ind + 2 Domain |
| (ausente) | `adversary` | `_create_intrusion_sets` (L209) | Intrusion-Set | 0 |
| (ausente) | `targeted_countries` | `_create_target_countries` (L288) | Country | 0 |

### Verificación 1:1 en nuestro OpenCTI (query al Report de este pulse)

```
Attack-Pattern: 21 → T1547, T1547.001, T1090, T1059, T1204.002, T1189, …
Malware:         2 → OpenShield, Apprunner
Sector:          1 → Technology
Indicator:       4 → freevpn.win/…, openshield.canatrace.com/…, corepack.org, yakteam.xyz
Domain-Name:     2 → corepack.org, yakteam.xyz
```

**Coincide exactamente con la página de OTX.** Nada perdido, nada inventado.

### La confusión resuelta

Buscar "Attack Pattern" / "Malware" / "Sector" literalmente en la página de OTX no los
encuentra porque **OTX usa su propio vocabulario y el conector lo traduce** a STIX/OpenCTI:

- "INDUSTRY" → **Sector**
- "MALWARE FAMILIES" → **Malware**
- "ATT&CK IDS" (cuéntalos: 21) → **Attack-Pattern**
- pestaña "Indicators of Compromise (4)" → los **4 Indicators** (+ observables Domain-Name/Url)

### Por qué este pulse NO mueve los widgets de amenaza

Este pulse **no trae `adversary` ni `targeted_countries`** → sin Intrusion-Set, sin
relaciones `actor --targets--> sector/país`. Es un pulse de malware/supply-chain sin actor
atribuido. Contrasta con Operation RoundPress (§4), que SÍ trae actor (TA458) y por eso SÍ
genera el grafo de targeting. **Lección:** que un pulse cree Sector/Malware/Attack-Pattern
no implica que cree relaciones de targeting — eso requiere que el pulse declare un
`adversary` y sus objetivos. Los widgets de "Most Active Threats"/"Most Targeted Victims"
solo se alimentan de los pulses del segundo tipo.

## 5. VEREDICTO

**La ingesta de AlienVault es SANA.** Ingesta al día, incremental, y crea el grafo
completo de targeting (3,662 targets + 7,129 uses, creciendo). El ejemplar TA458 prueba
que actor→sector/país/CVE→técnica se materializa correctamente y cotejable con la fuente.

**Por tanto, "los widgets no cambian" NO se explica por ingesta rota en AlienVault.**
Las relaciones que los widgets necesitan SÍ existen y crecen. La causa hay que buscarla
del lado del **widget**: su ventana de fecha / campo temporal / perspectiva. Esto conecta
con el hallazgo previo (quick 260722-859): el dashboard home de OpenCTI 7 es JSX
hardcodeado; el widget "Relationships created" usa `endDate = fin del mes anterior` +
`created_at`, de modo que la actividad del mes en curso queda invisible aunque exista.

**Próximo paso sugerido para cerrar la duda de widgets:** inspeccionar el widget concreto
que "no cambia" — qué relationship_type lee, en qué ventana, con qué date field — en vez
de seguir sospechando de la ingesta. La evidencia dice que la ingesta no es el problema.

## Reproducir este análisis

```graphql
# ¿ingesta? — estado del conector
{ connectors { name connector_state } }

# conteos por AlienVault (createdBy = 09c76b67-24e6-4adb-9b51-92f1d63072e8)
query($f: FilterGroup){ reports(filters:$f,first:1){ pageInfo{ globalCount } } }
query($f: FilterGroup){ stixCoreRelationships(filters:$f,first:1){ pageInfo{ globalCount } } }
#   con f = {mode:and, filters:[{key:"createdBy",values:["09c7..."],mode:or},
#                               {key:"relationship_type",values:["targets"],mode:or}]}

# últimos 10 pulses + entidades contenidas
query($f: FilterGroup){ reports(filters:$f,first:10,orderBy:published,orderMode:desc){
  edges{ node{ name published description objects(first:60){ edges{ node{
    ... on BasicObject{ entity_type } } } } } } } }
```
