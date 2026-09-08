# Lección 2 — `connector-opencti`: el catálogo de referencia

Conector 2 de la capa 1, ejecutado el **2026-08-03** sobre la plataforma reiniciada, justo
después de `connector-mitre`.

El ciclo de habilitación (7 pasos) está en **[Lección 1, §0](01-vocabulario-relojes-y-senales.md)**.
Aquí solo lo propio de este conector.

---

## 1. Qué es y por qué faltaba

`connector-opencti` es la **pareja de `connector-mitre` en el compose de referencia del
vendor**. Carga dos catálogos oficiales:

- `geography.json` — 250 países con latitud/longitud e ISO real, más 22 regiones
- `sectors.json` — 71 sectores con jerarquía

No estaba en el stack. Ese hueco es el que produjo, meses después, un widget "Target
Countries" vacío con la plataforma llena.

### El fallo que provoca su ausencia

Las fuentes que publican victimología crean el país **por su nombre**. El conector de
AlienVault OTX, por ejemplo:

```python
def create_country(name, created_by) -> stix2.Location:
    return stix2.Location(
        id=Location.generate_id(name, "Country"),
        name=name,
        country="ZZ",   # TODO: Country code is required by STIX2!
        ...)            # sin latitude, sin longitude
```

Un país con el ISO en `ZZ` y sin coordenadas **existe pero es inubicable**. Las aristas
`targets → Country` estaban ahí; faltaba la geometría para dibujarlas.

Medición en la plataforma anterior, antes del wipe:

```
países                183
  con lat/long          0     ← cero
  con alias ISO       129     ← 54 inubicables incluso por ISO
```

Y como no había catálogo, aquella plataforma tuvo que **inventar** lo que faltaba: un
script creaba 6 países a mano, parcheaba alias ISO3 sobre 14, y escribía 13 sectores desde
un diccionario de Python. Trabajo manual para reemplazar 18 líneas de compose.

---

## 2. Configuración

```yaml
connector-opencti:
  image: opencti/connector-opencti:7.260706.0
  environment:
    - CONNECTOR_SCOPE=marking-definition,identity,location
    - CONNECTOR_CONFIDENCE_LEVEL=100
    - CONNECTOR_UPDATE_EXISTING_DATA=true
    - CONFIG_SECTORS_FILE_URL=.../datasets/master/data/sectors.json
    - CONFIG_GEOGRAPHY_FILE_URL=.../datasets/master/data/geography.json
    - CONFIG_INTERVAL=7
```

Dos variables merecen atención:

**`CONNECTOR_UPDATE_EXISTING_DATA=true`** — este conector no solo añade: **modifica** lo que
ya existe. Es lo que quieres. Cuando AlienVault cree su "Iran" sin coordenadas, la fusión
por nombre hará que gane la versión con geometría, llegue en el orden que llegue.

**`CONNECTOR_ID`** va literal en el compose, no por `.env`. No es un secreto: es un
identificador de registro. `.env` no se toca en este proyecto.

---

## 3. Ejecución — y un fallo en el propio procedimiento

El paso 3 del ciclo dice: si el I/O de red está plano, el conector está dormido. En esta
ejecución salió plano:

```
770kB / 1.2MB
771kB / 1.2MB
772kB / 1.2MB
```

Pero `connector_state` traía un `last_run` legítimo y la ingesta había funcionado. **La
regla estaba mal.** `geography.json` + `sectors.json` pesan ~1 MB y se descargan en
segundos: el conector había **terminado** antes de la primera medición. MITRE, con 57 MB,
tardaba lo bastante como para verlo en vuelo.

I/O plano significa "no está descargando", y eso tiene dos causas opuestas: **dormido** o
**ya terminó**. El desempate es el conteo de objetos. Corregido en Lección 1, §0.

Resto de la ejecución, limpia: cola drenada, 0 errores, `last_run 2026-08-03T23:49:57Z`.

---

## 4. Qué produjo

```
                antes    después   delta
country              0       250    +250
sector               0        71     +71
region               0        22     +22
organization         1        33     +32
─────────────────────────────────────────
objetos          3.919     4.294    +375
relaciones      23.740    24.086    +346
```

### Regiones — geoesquema de la ONU

```
Africa · Northern Africa · Sub-Saharan Africa
Americas · Northern America · Latin America and the Caribbean
Asia · Central Asia · Eastern Asia · South-eastern Asia · Southern Asia · Middle East
Europe · Eastern Europe · Northern Europe · Southern Europe · Western Europe
Oceania · Australia and New Zealand · Melanesia · Micronesia · Polynesia
```

Jerárquicas: `Northern Africa` cuelga de `Africa`. Permite agregar victimología por región
sin escribir a mano qué país pertenece a cuál.

### Sectores — 71, con vocabulario canónico

```
Agriculture and agribusiness · Logistics · Judicial power (justice) · Mining
Water distribution and supply · Research · Culture · Unknown · …
```

⚠️ **Este vocabulario no coincide con el que inventó la plataforma anterior.** Aquel
seeder escribía "Government Administration", "Financial Services", "Think Tanks". Son dos
taxonomías incompatibles para el mismo eje. Empezar limpio evitó tenerlas conviviendo.

Existe un sector llamado **"Unknown"**, deliberado: da dónde colgar victimología sin sector
identificado, en vez de dejar la relación huérfana o inventar una categoría.

---

## 5. Corrección: sí crea relaciones

El commit original decía *"no crea ninguna relación ni atribuye nada a nadie"*. **La
primera mitad es falsa.** Medido:

```
located-at   266     país → región, región → región
part-of       80     jerarquía de sectores
             ───
             346     = exactamente el delta de relaciones (23.740 → 24.086)
```

La distinción correcta no es *relación sí / relación no*, sino **estructural vs
atribución**:

| | Ejemplo | ¿La crea este conector? |
|---|---|---|
| **Estructural** | `Perú located-at Latin America` | sí, 346 |
| **Atribución** | `APT28 targets Ucrania` | **no, ninguna** |

Las estructurales son geometría del marco: dicen dónde está algo, no quién ataca a quién.
Ninguna afirma nada sobre amenazas. El espíritu de la frase original era correcto; la letra
no. Ya está corregido en el comentario del `docker-compose.yml`.

---

## 6. Verificación específica — la razón de existir del conector

```bash
docker exec opencti-7-pilot-elasticsearch-1 curl -s -H 'Content-Type: application/json' \
  'localhost:9200/opencti_stix_domain_objects/_search' \
  -d '{"size":0,"query":{"term":{"entity_type.keyword":"Country"}},
       "aggs":{"con_geo":{"filter":{"exists":{"field":"latitude"}}}}}'
```

```
total 250   ·   con latitude 245
```

Los 5 sin coordenadas son territorios pequeños, y **sí traen alias ISO**:

```
Curaçao (CUW/CW) · Saint Barthélemy (BLM/BL) · Sint Maarten (SXM/SX)
Saint Martin (MAF/MF) · United States Minor Outlying Islands (UMI/UM)
```

Siguen siendo ubicables en el mini-mapa del HomeDashboard, que cruza `feature.properties.ISO3`
contra `x_opencti_aliases`. Solo faltarían en un mapa por coordenadas.

| | Plataforma anterior | Ahora |
|---|---|---|
| países con lat/long | 0 / 183 | **245 / 250** |
| países con alias ISO | 129 / 183 | 250 / 250 |

---

## 7. Relojes

```
Country    total=250   muestra=200   created==created_at: 0/200   OK
           created por año: [('2023', 200)]
relaciones total=24.086 muestra=500  start_time==1970: 88/500 (18%)  OK
```

Los 250 países declaran `created: 2023` — la fecha de publicación del dataset, no la de
importación. Catálogo con fecha propia, igual que MITRE.

El 18% de centinela 1970 en relaciones es el mismo perfil sano del conector anterior: las
`located-at` y `part-of` no tienen "cuándo" porque un país no empieza a estar en su región
en una fecha.

---

## 8. El mecanismo central: fusión por nombre

Es lo que hace que todo esto funcione sin importar el orden de llegada.

```
Location.generate_id(name, "Country")
```

El identificador STIX se **deriva del nombre**. El "Iran" sin coordenadas que crea OTX y
el "Iran" del catálogo son, para OpenCTI, **la misma entidad**. Se funden, y con
`UPDATE_EXISTING_DATA=true` la resultante conserva la geometría.

Consecuencia práctica: **cargar el catálogo primero no es requisito de corrección, es
requisito de que lo que veas mientras tanto sea cierto.** Si llegara después, las entidades
se fundirían igual — pero durante el intervalo los widgets contarían países inubicables.

El mismo mecanismo aplica a las 32 organizaciones (§9) y a cualquier entidad cuyo ID sea
determinista por nombre.

---

## 9. Las 32 identidades de autor

El conector crea, además de geografía y sectores, un catálogo de **identidades de
procedencia**:

```
MITRE · Filigran · ESET · BAE Systems · Crowdstrike · Mandiant · Fireeye · McAfee
Recorded Future · Telsy · Cylance · Proofpoint · Trendmicro · Kaspersky · Checkpoint
Symantec · RiskIQ · GreyNoise · Nextron Systems · Group-IB · Gatewatcher · Tenzir
CERT-EU · BSI · NCSC-UK · CERT-Bund · CISA · FBI · Europol
New York Times · Washington Post · Malpedia · The Record
```

**No son inteligencia: son el vocabulario de quién dice qué.** Cuando AlienVault publique
algo atribuido a "ESET", se enganchará a esta entidad en vez de crear una segunda.

Conecta directo con la doctrina de procedencia de la plataforma anterior: allí un allowlist
`CURATED_AUTHORS` gobernaba qué autores podían aparecer en briefings y búsqueda semántica,
y nombraba `ESET`, `CIRCL`, `CERT-FR`… pero esas entidades se creaban sobre la marcha, cada
feed a su manera, con variantes de nombre. Ahora existen desde el principio y son canónicas.

---

## 10. Línea base acumulada — capa 1, conectores 1-2

```
attack-pattern     1.514      955 ATT&CK + 559 CAPEC
course-of-action   1.211
malware              851
country              250      245 con lat/long
intrusion-set        185
tool                  97
sector                71
campaign              60
organization          33      1 MITRE + 32 identidades de autor
region                22
──────────────────────────
objetos            4.294
relaciones        24.086      uses 19.983 · mitigates 3.189 · subtechnique-of 541
                              located-at 266 · part-of 80 · attributed-to 27
observables            0
indicadores            0
```

Sigue sin haber un solo observable ni indicador. La capa 1 es marco puro.

---

## 11. Tu turno — comprobación en la UI

Ahora que el catálogo está cargado, mira:

- `Locations → Countries` — ¿aparecen con bandera? La bandera es señal de que el ISO
  resolvió; un país listado **sin** bandera significa que el código sigue en `ZZ`. Es un
  indicador visual de un campo que si no habría que consultar entidad por entidad.
- `Locations → Regions` — abre `Europe` y comprueba que cuelgan los países.
- `Entities → Sectors` — mira la jerarquía de `part-of`.

<!-- TODO (Óscar): anota aquí qué viste. En particular: ¿los 5 países sin coordenadas
     aparecen con bandera igual? Si sí, confirma que ISO y geometría son campos
     independientes y que el mini-mapa depende del primero, no del segundo. -->

---

## Siguiente

`connector-disarm-framework` — TTPs de desinformación de la **DISARM Foundation**
(no de MITRE, pese a copiar la estructura de ATT&CK). Catálogo, ingesta total.

```bash
docker compose up -d connector-disarm-framework
```

Ciclo completo en Lección 1, §0.
