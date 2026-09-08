<!-- Exportado íntegro de la evidencia interna de la fase 17 (17-13-MEDICIONES.md) el 2026-09-03 para que las rutas citadas por el Capítulo 5 resuelvan desde el repositorio público. Contenido sin ediciones. -->
---
phase: 17-reestructurar-y-actualizar-el-cap-tulo-5-trazabilidad-con-ob
plan: 13
type: evidence
corte: 2026-08-26T14:49:12Z (allowlist) / 2026-08-26T14:5xZ (Elasticsearch)
stack: levantado y detenido en la misma sesión; volumen `opencti-7-pilot_esdata-recovery-20260715` (external)
---

# Mediciones para cerrar B5 y B6

Servicios levantados: `elasticsearch`, `redis`, `rabbitmq`, `minio`, `opencti`. Ningún
conector ni feed en marcha, así que el grafo no creció durante la medición. Stack
detenido con `docker compose stop` al terminar; volúmenes intactos.

## B5 — Allowlist: las tres versiones eran incorrectas, cada una por su lado

Medido con la **ruta de producción**, no con una consulta equivalente:
`resolve_author_ids(client, CURATED_AUTHORS)` ejecutada dentro de la imagen
`semantic-engine` con el mismo anchor `*curated-authors` del Compose.

**Corte 2026-08-26T14:49:12Z — resuelven 6 de 9:**

| Nombre configurado | Resuelve | `internal_id` |
|---|---|---|
| AlienVault | sí | `4d8f4b0f-08a4-4ed6-ba13-471b8e804673` |
| The MITRE Corporation | sí | `24c95f54-99d1-4f77-a74f-ce9739a3f0b3` |
| CIRCL | sí | `86847a6f-3caf-4431-9b85-9591b25ebdf6` |
| CERT-FR | sí | `c964926b-ee72-4a9c-b52d-6a1af4162728` |
| ESET | sí | `9d79f2f6-6a62-47d7-8124-0710891fec19` |
| ColCERT (nombre largo) | sí | `fd181c75-7fff-49c6-baab-5a32820824da` |
| `CERT-FR_1510` | **no** | — |
| `Ransom-ISAC` | **no** | — |
| `Centro Nacional de Seguridad Digital (CNSD)` | **no** | — |

**Filtro efectivamente emitido: `createdBy eq [6 ids]`.**

Veredicto sobre las tres versiones en conflicto:

| Fuente | Decía | Estado |
|---|---|---|
| Capítulo §5.5 (L541) | «cuatro de los nueve resuelven: AlienVault, MITRE, CIRCL y ESET» | **Falso.** Resuelven seis; faltaban CERT-FR y ColCERT |
| `HECHOS.md` J5 | «resuelven seis» **y** «la ruta degradada sin filtro es el modo de operación medido» | Conteo correcto, **conclusión falsa**: con 6 ids la lista no está vacía, luego `opencti_client.py:92` sí emite el filtro |
| Código | filtro aplicado sii la lista resuelta no está vacía | Correcto y confirmado en ejecución |

**El dato que le falta a PE-4.** Con el filtro activo sobre esas 6 identidades,
**32.591 de 152.025 indicadores** quedan visibles para el índice semántico: **21,4 %**.
Ese es el alcance real de la superficie del analista, y ninguna de las tres versiones
anteriores lo enunciaba. La conclusión de PE-4 debe apoyarse en esta cifra, no en el
recuento de nombres que resuelven.

## B6 — Los tres totales son tres instantes, no tres definiciones

Composición actual: 12 tipos de core-relación que **suman exactamente** el total
(599.688 el 2026-08-26), luego no existe hueco definicional entre «suma de tipos» y
«total». La hipótesis de tres definiciones queda descartada por construcción.

Retro-conteo por `created_at` sobre el índice `opencti_stix_core_relationships-000001`:

| Cifra publicada | Dónde | Instante que la produce | Retro-conteo |
|---|---|---|---|
| 553.496 | `HECHOS.md` J3 | `2026-08-25T08:49:49Z` (el que J3 declara) | 553.498 (−2) |
| 561.208 | Figura 5.4 / J8 (`EDGE_TOTAL`) | ≈ `2026-08-25T09:09:5xZ` | 561.236 a las 09:10:00 |
| 568.947 | Capítulo L184 | ≈ `2026-08-25T09:49:2xZ` | 568.890 a las 09:49:00 |

**Los 7.739 «sin explicar» son unos 39 minutos de ingesta.** El histograma horario del
25-ago da 32.251 core-relaciones creadas solo en la hora 08:00Z, 14.010 en la 09:00Z y
22.119 en la 10:00Z. A ese ritmo, dos capturas separadas por media hora difieren en
miles. Las tres cifras son correctas **y** mutuamente incompatibles como «el corte del
2026-08-25»: el defecto es la etiqueta, no la aritmética.

Las diferencias de −2 y ±50 frente al retro-conteo se explican por relaciones borradas o
fusionadas después de cada captura; el retro-conteo mira el estado de hoy filtrado por
fecha de creación, no una foto histórica.

## Atribución y «volumen comparable»

Core-relaciones por autor (`rel_created-by`), corte 2026-08-26:

| Autor | Core-relaciones |
|---|---|
| AlienVault | 457.575 |
| (sin identificar) `fae4f55a…` | 37.060 |
| The MITRE Corporation | 23.731 |
| CIRCL | 10.645 |
| `eb3aa6e3…` | 9.995 |
| CERT-FR | 614 |

**AlienVault supera a CIRCL por un factor de 43 en core-relaciones.** La afirmación de
que son «de volumen comparable» no se sostiene bajo esta métrica; solo podría sostenerse
bajo otra declarada explícitamente, y hoy el capítulo compara indicadores, relaciones y
operaciones distintas sin decir cuál usa.

Por escritor (`creator_id`) hay exactamente dos, como declara J4: `50492ac1…` con
458.276 y `88ec0c6a…` con 142.114.

## Consecuencia para el capítulo

- §5.5 y la conclusión de PE-4: reescribir sobre 6/9, filtro activo y cobertura 21,4 %.
- §5.3: fechar cada total al minuto o unificar todos al mismo instante; retirar
  «volumen comparable» o darle métrica declarada.
- `HECHOS.md`: J5 necesita corrección — el conteo vale, la conclusión de ruta degradada no.

---

## Obs-2 — Adjudicación del 0 % de relaciones en los tres held-out

**Fecha de medición:** 2026-08-27. **Script:** `corpus/eval/adjudicar_relaciones.py`
(versionado en git, sin dependencias externas, re-ejecutable desde el repo limpio).
**Insumos:** los tres anexos STIX oficiales, los tres textos de entrada
`corpus/eval/aa2*.txt` y las tres corridas `*.haiku-heldout-20260824.json`.

El capítulo explicaba el 0 % por desalineación de **nombres**, demostrado solo sobre
AA26-097A y extrapolado a los otros dos. La extrapolación no se sostiene.

| Medida | AA26-097A | AA25-239A | AA25-203A |
|---|---:|---:|---:|
| Relaciones en el anexo | 11 | 15 | 25 |
| Ambos extremos literales en el documento | 0 | 0 | **7** |
| Un solo extremo literal | 0 | 2 | 17 |
| Ningún extremo literal | 10 | 12 | **0** |
| **Ambos extremos en una misma frase (lo que §3.9 exige)** | **0** | **0** | **2** |
| Tipo de vínculo dominante en el anexo | `indicates` 10/11 | `indicates` 14/15 | `indicates` 24/25 |
| `indicates` emitidos por el extractor | 21 | **0** | **0** |
| Otros tipos emitidos | `targets` 3, `attributed-to` 1 | `exploits` 5, `uses` 4 | `uses` 13, `targets` 5 |

### Lectura

**La causa dominante no es el nombre: es el tipo de vínculo.** El anexo de los tres
avisos habla casi exclusivamente en `indicates` —el patrón STIX
`indicator --indicates--> actor/malware`, que CISA genera al ensamblar el bundle desde
sus tablas de IOC—. Ese vínculo no es una afirmación de ninguna frase del aviso: ninguna
oración dice «esta IP *indica* HYDROKITTEN». El extractor, atado por §3.9 a lo que una
frase declara, produce los tipos que la prosa sí afirma: `uses`, `targets`, `exploits`,
`attributed-to`. En AA25-239A y AA25-203A emitió **cero** `indicates`, de modo que
ninguna coincidencia era posible con independencia de los nombres.

**Por aviso:**

- **AA26-097A** — la explicación del capítulo **se confirma**. El extractor sí emitió
  el tipo dominante (21 `indicates`), luego el tipo no fue el obstáculo; los extremos
  del anexo (`HYDROKITTEN`, `Cyber Aveng3rs`) no aparecen ni una vez en el texto
  (0/11 en una misma frase, 10/11 sin ningún extremo literal). Causa vinculante: nombres.
- **AA25-239A** — **causa distinta**. Cero `indicates` emitidos frente a 14/15 del
  anexo. Los nombres además faltan (12/15 sin ningún extremo literal), pero el tipo ya
  hacía imposible el emparejamiento.
- **AA25-203A** — la explicación del capítulo **se refuta**. Los nombres estaban
  disponibles: 7 de 25 relaciones tienen **ambos** extremos literales en el documento y
  ninguna carece de los dos. Aun así, 0 % de concordancia, porque el extractor emitió
  cero `indicates` frente a 24/25 del anexo. Causa vinculante: tipo de vínculo.

### Consecuencia para el capítulo

- §5.4.2: sustituir la explicación única por la adjudicación de los tres casos, con el
  tipo de vínculo como causa dominante y el nombre como causa solo en AA26-097A.
- La conclusión de PE-3 no puede seguir diciendo que el 0 % «no es un fallo del
  extractor» sin matiz: mide una **incompatibilidad de convención de modelado** entre el
  anexo y la regla de citación, que es un límite del protocolo de comparación —no una
  exculpación general del extractor ni prueba de que sus relaciones sean correctas.
- La co-ocurrencia en una misma frase (0, 0 y 2 sobre 11, 15 y 25) da un **techo
  estructural** al recall de relaciones contra estos anexos bajo la regla de §3.9: aun
  con un extractor perfecto, la mayoría de las relaciones del anexo son inalcanzables.
