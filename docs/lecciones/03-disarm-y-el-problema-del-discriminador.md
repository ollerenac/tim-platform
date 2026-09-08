# Lección 3 — DISARM, y el problema del discriminador

Conector 3 de la capa 1, ejecutado el **2026-08-03**. Ciclo de habilitación en
**[Lección 1, §0](01-vocabulario-relojes-y-senales.md)**.

La lección real de este conector no es lo que trae, sino lo que rompe: **tres taxonomías
distintas acaban compartiendo un solo `entity_type`**, y el criterio obvio para separarlas
no funciona.

---

## 1. Qué es DISARM

**DISARM** — *Disinformation Analysis and Risk Management*, antes AMITT — es un marco de
TTPs de desinformación de la **DISARM Foundation**.

⚠️ **No es de MITRE**, pese a que:

- copia la estructura de ATT&CK (tácticas, técnicas, subtécnicas, matriz)
- usa identificadores con el mismo formato (`T0155`, `T0155.001`)
- reutiliza los campos personalizados `x_mitre_*` y `x-mitre-tactic`

Es linaje independiente. En la tesis, atribuirlo a MITRE es un error factual.

Fuente: `DISARMFoundation/DISARMframeworks`, fichero `generated_files/DISARM_STIX/DISARM.json`.

---

## 2. Contenido de la fuente vs contenido importado

`CONNECTOR_SCOPE` declara doce tipos:

```
marking-definition, identity, attack-pattern, course-of-action, intrusion-set,
campaign, malware, tool, report, narrative, event, channel
```

Tras la ingesta, `narrative`, `event` y `channel` salieron a **cero**. Parecía un fallo.
No lo es. Contenido real del fichero fuente, medido:

```
attack-pattern        391
relationship          288
x-mitre-tactic         16
identity                1
marking-definition      1
x-mitre-matrix          1
                     ────
                      698 objetos
```

**El scope declara lo que el conector tiene permiso de importar, no lo que la fuente
contiene.** Confundir permiso con contenido lleva a dar por roto un conector sano.

### Contabilidad completa

| En el fichero | Qué pasó | Verificado |
|---|---|---|
| 391 `attack-pattern` | importados | attack-pattern 1.514 → 1.905 |
| 288 `relationship` | importadas | relaciones 24.086 → 24.374 |
| 1 `identity` | importada | organization 33 → 34 (DISARM Foundation) |
| 16 `x-mitre-tactic` | → 16 `Kill-Chain-Phase`, cadena `disarm` | `opencti_stix_meta_objects` |
| 1 `x-mitre-matrix` | no soportado por OpenCTI | — |
| 1 `marking-definition` | fusionada con las existentes | — |

Todo lo del fichero está contabilizado. Nada se perdió en silencio.

---

## 3. El problema: tres taxonomías, un `entity_type`

Tras los tres conectores de catálogo, `Attack-Pattern` contiene:

```
attack-pattern   1.905
```

Un solo contador para tres cosas que no se parecen:

| Taxonomía | Qué describe | Origen |
|---|---|---|
| **ATT&CK** | TTPs de adversario en redes | MITRE |
| **CAPEC** | patrones de ataque a nivel de debilidad de software | MITRE |
| **DISARM** | TTPs de desinformación | DISARM Foundation |

Un widget que muestre "1.905 técnicas" suma peras, manzanas y tornillos.

---

## 4. Dos discriminadores que fallan

### Intento 1 — `x_mitre_id`

Razonamiento: *el campo se llama `x_mitre_id`, luego solo lo tendrá lo de MITRE.*

**Falso.** DISARM reutiliza el campo:

```
T0155      Gated Asset
T0155.001  Password Gated Asset
T0155.007  Encrypted Communication Channel
```

El nombre de un campo es convención, no contrato de origen. DISARM copió la estructura de
ATT&CK y el conector reutilizó el campo tal cual.

### Intento 2 — prefijo `T0`

Razonamiento: *DISARM numera T0xxx, ATT&CK numera T1xxx.*

**También falso.** Medido:

```
x_mitre_id con prefijo T0  →  484
DISARM aportó              →  391
                              ───
diferencia                 →   93
```

Esos 93 son de **ATT&CK ICS**, que usa el rango T0800-T0899:

```
T0810  Data Historian Compromise
T0841  Network Service Scanning
T0850  Role Identification
T0854  Serial Connection Enumeration
```

Filtrar por prefijo `T0` mezcla desinformación con sistemas de control industrial.

---

## 5. El discriminador que funciona: el autor

```bash
docker exec opencti-7-pilot-elasticsearch-1 curl -s -H 'Content-Type: application/json' \
  'localhost:9200/opencti_stix_domain_objects/_search' \
  -d '{"size":0,"query":{"term":{"entity_type.keyword":"Attack-Pattern"}},
       "aggs":{"autor":{"terms":{"field":"rel_created-by.internal_id.keyword","size":10}}}}'
```

```
24c95f54-99d1-4f77-a74f-ce9739a3f0b3   1.513   The MITRE Corporation
70086dbb-91fb-4e23-b5c5-f0fda759e6be     391   DISARM Foundation
```

Y dentro de los de MITRE, `x_mitre_id` sí separa bien:

| Taxonomía | Criterio | Objetos |
|---|---|---|
| **ATT&CK** | autor MITRE **y** con `x_mitre_id` | 955 |
| **CAPEC** | autor MITRE **y** sin `x_mitre_id` | 558 |
| **DISARM** | autor DISARM Foundation | 391 |
| huérfano | sin autor | 1 |

**Regla general:** el identificador puede colisionar entre fuentes; la procedencia no.
Cuando dos catálogos comparten `entity_type`, el discriminador es `created_by_ref`.

Esto conecta con la doctrina de la plataforma anterior — *"la confianza viaja por autor"*,
el allowlist `CURATED_AUTHORS`. Allí el autor gobernaba la **confianza**; aquí gobierna la
**taxonomía**. Mismo campo, dos usos, misma razón: es lo único que no se puede falsificar
por parecido.

---

## 6. Residuo: 1 técnica sin autor

```
T1521.002  Asymmetric Cryptography
```

Una sola, de ATT&CK, que llegó sin `created-by`. Cae fuera de cualquier filtro por
procedencia: no aparece ni como MITRE ni como DISARM.

Es exactamente la clase de objeto que en la plataforma anterior se acumulaba hasta volverse
invisible. Con 4.686 objetos se detecta; con un millón, no. Queda anotada, sin tocar, hasta
que el allowlist vuelva a importar en la capa 2.

```bash
docker exec opencti-7-pilot-elasticsearch-1 curl -s -H 'Content-Type: application/json' \
  'localhost:9200/opencti_stix_domain_objects/_search' \
  -d '{"size":3,"query":{"bool":{"must":[{"term":{"entity_type.keyword":"Attack-Pattern"}}],
       "must_not":[{"exists":{"field":"rel_created-by.internal_id"}}]}},"_source":["name","x_mitre_id"]}'
```

---

## 7. Relojes

```
Attack-Pattern  total=1905   muestra=200   created==created_at: 0/200   OK
                created por año: 2014(43) 2015(7) 2017(14) 2018(5) 2019(8)
                                 2020(41) 2021(8) 2022(6) 2023(1) 2024(55) 2025(5) 2026(7)
relaciones      total=24374  muestra=500   start_time==1970: 95/500 (19%)  OK
```

El pico de 2024 es la fecha de publicación del framework DISARM. El 19% de centinela sigue
el mismo perfil sano de los dos conectores anteriores.

---

## 8. Cadenas de muerte — efecto secundario

Los 16 `x-mitre-tactic` se convirtieron en `Kill-Chain-Phase`. Estado tras los tres
conectores:

```
disarm                    16
mitre-attack              15
mitre-attack-v19          15
mitre-mobile-attack       14
mitre-mobile-attack-v19   14
mitre-ics-attack          12
mitre-ics-attack-v19      12
                         ───
                          98
```

Nota: ATT&CK publica cada cadena **dos veces**, con y sin sufijo de versión
(`mitre-attack` y `mitre-attack-v19`). No es duplicación errónea, es cómo versiona MITRE —
pero un selector de cadena en la UI mostrará las dos.

---

## 9. Línea base acumulada — capa 1, conectores 1-3

```
attack-pattern     1.905      955 ATT&CK + 558 CAPEC + 391 DISARM + 1 huérfano
course-of-action   1.211
malware              851
country              250      245 con lat/long
intrusion-set        185
tool                  97
sector                71
campaign              60
organization          34      MITRE + 32 autores canónicos + DISARM Foundation
region                22
──────────────────────────
objetos            4.686
relaciones        24.374
kill-chain-phase      98
observables            0
indicadores            0
```

Tres conectores, cero observables, cero indicadores. La capa 1 sigue siendo marco puro.

---

## 10. Tu turno

<!-- TODO (Óscar): abre `Techniques → Attack patterns` y filtra por autor.
     ¿La UI te deja separar las tres taxonomías, o tendrás que construir un filtro
     guardado? Anota aquí qué encontraste — de eso depende si los widgets de la capa 2
     pueden confiar en el contador de attack-pattern o necesitan filtro explícito. -->

---

## Siguiente

`connector-cve` — NVD, ~91.000 vulnerabilidades. **El largo de la capa 1**, horas de
ingesta. Ciclo idéntico; conviene lanzarlo cuando puedas dejarlo corriendo.

```bash
docker compose up -d connector-cve
```
