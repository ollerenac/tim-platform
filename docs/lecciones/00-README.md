# Lecciones — aprendizaje de OpenCTI sobre la plataforma reiniciada

Serie de notas escritas mientras se reconstruye el pilot OpenCTI 7 desde cero, conector a
conector, tras el wipe total del **2026-08-03**.

No son documentación de producto. Son notas de aprendizaje: lo que hacía falta saber antes
de romper algo, escrito después de romperlo.

## Índice

| # | Lección | Cubre |
|---|---|---|
| [01](01-vocabulario-relojes-y-senales.md) | Vocabulario STIX, los tres relojes y las señales que mienten | **§0: ciclo de habilitación de un conector** (referenciado por todas las demás) · SDO/SCO/SRO · marco vs evento · Observable ≠ Indicator · `created_at`/`created`/`start_time` · centinela 1970 · arquitectura de ingesta · señales de salud falsas · API vs UI · recetario · rutas de la UI |
| [02](02-connector-opencti-catalogo-de-referencia.md) | `connector-opencti`: el catálogo de referencia | geografía y sectores · fusión por nombre · identidades canónicas de autor · relación estructural vs atribución |
| [03](03-disarm-y-el-problema-del-discriminador.md) | DISARM y el problema del discriminador | scope ≠ contenido · tres taxonomías en un `entity_type` · por qué el ID colisiona y la procedencia no |
| [04](04-connector-cve-y-cierre-de-la-capa-1.md) | `connector-cve` y el cierre de la capa 1 | build local · ventana 2019 · conector que nunca termina · escalado sub-lineal · mensajes ≠ objetos · **§7: por qué el orden de ingesta importa** · **§8: conmutador técnico/funcional** · las 1.601 CVEs sin CVSS |
| [05](05-alienvault-y-la-apertura-de-la-capa-2.md) | AlienVault y la apertura de la capa 2 | tokens que no se pueden copiar · confianza del usuario, no del conector · curar en la fuente · **§3: el campo que lleva la edad** · **§4: agregar tipos heterogéneos** · alias no registrados · **§8: el backfill que muere sin dejar alarma** · un feed es grande *en un eje* |

**Capa 1** (marco de referencia): lecciones 01-04. **Capa 2** (eventos): lección 05 en adelante.

---

## Cómo se verifica lo que hay aquí

Pregunta legítima, y la respuesta honesta necesita distinguir tres cosas que en un
documento se parecen mucho.

### Las tres categorías

**MEDIDO** — sale de una consulta ejecutada contra la plataforma viva. El comando está en
el propio documento; se puede volver a correr y debe dar lo mismo. Los conteos, los
porcentajes, los nombres de campo, las rutas de la UI (extraídas del bundle del frontend,
no de memoria), los contenidos de los ficheros fuente.

> Fiabilidad alta. Si algo cambia, la consulta lo delata.

**INFERIDO** — una explicación causal construida sobre mediciones. *"El conector estaba
dormido porque grabó `last_run` en una corrida fallida"* es inferencia: lo medido son el
`last_run` y el I/O plano; la causalidad la puse yo.

> Fiabilidad media. Falsable, pero no comprobada directamente.

**HEREDADO** — traído de otra fuente sin volver a medir: documentación del vendor, un
commit de otro repositorio, o mi propio conocimiento previo.

> **Fiabilidad baja. Es donde han estado todos los errores.**

### La regla

**Ninguna afirmación heredada entra en una lección sin convertirse en medida.**

Ejemplo de la lección 03: iba a escribir *"DISARM no trae narrativas porque el fichero solo
tiene attack-patterns"*. Eso era inferencia a partir de un cero. Se descargó el fichero
fuente y se contaron sus 698 objetos. Ahora es medición, y de paso apareció información que
la inferencia no daba: los 16 `x-mitre-tactic` que se convirtieron en cadenas de muerte.

---

## Historial de errores — por qué la regla existe

Todo esto ocurrió en la sesión del 2026-08-03. Se documenta porque el patrón importa más
que los casos.

| Afirmación | Categoría | Qué pasó | Corregido en |
|---|---|---|---|
| "Docker no tiene upstream DNS válido" | inferido | Diagnóstico correcto del síntoma, causa equivocada. Sin test. | L01 §9 · `daemon.json` |
| "La red capturó el DNS de la VPN al crearse" | inferido | Segunda hipótesis, también falsa. Recrear la red no arregló nada. | L01 §9 |
| "MITRE dará relojes colapsados (`CATALOGO?`)" | heredado | Salió `OK` en los tres tipos. Los tres catálogos de la capa 1 dieron `OK`. | L01 §2 |
| "I/O de red plano = conector dormido" | inferido | Falso: también significa "ya terminó". Estaba escrito como procedimiento. | L01 §0 paso 3 |
| "`connector-opencti` no crea relaciones" | heredado del commit del lab | Crea 346 (`located-at`, `part-of`). Cierto en espíritu, falso en la letra. | L02 §5 · `docker-compose.yml` |
| "`x_mitre_id` separa MITRE de DISARM" | heredado | DISARM reutiliza el campo. El nombre de un campo no es contrato de origen. | L03 §4 |
| "El prefijo `T0` identifica a DISARM" | inferido | ATT&CK ICS usa T0800-T0899. 93 colisiones. | L03 §4 |
| "`narrative` y `channel` aparecerán" | heredado del `CONNECTOR_SCOPE` | Cero. El scope declara permiso, no contenido. | L03 §2 |

**Ocho errores. Ninguno en una medición; todos en inferencias y herencias.** Las consultas
no se equivocaron ni una vez.

### Segunda tanda — sesiones del 2026-08-04 al 2026-08-07 (capa 2)

| Afirmación | Categoría | Qué pasó | Corregido en |
|---|---|---|---|
| "AlienVault colapsa los relojes: 22.275/22.275" | inferido | La herramienta comparaba `created` contra `created_at` en un `Indicator`, donde la edad vive en `valid_from`. Cero nulos en los 22.275. **Condenó a un conector sano** | L05 §3 · `7f6ebe1` |
| "El 96% de relaciones centinela repite el problema del wipe" | inferido | Agregaba `indicates` (atemporal, 68% del total) con `targets`. El porcentaje medía composición del grafo, no calidad | L05 §4 · `7f6ebe1` |
| "El orden de carga resuelve los duplicados de actores" | heredado de L04 §7 | Resuelve alias **registrados**. Sandworm quedó fracturado en tres entidades | L05 §6 · nota en L04 §7 |
| "8 workers no rinde más que 4" | inferido | Comparaba la curva de AlienVault con la de `connector-cve`. Cargas distintas: 1.029 vs 12.312 msg/min con el mismo worker | L05 §7 |
| "El worker está muerto" | inferido | Un solo contador congelado. Seguía escribiendo Reports | L05 §7 |
| "La cola drena en ~10 horas" | inferido | Dividí cola entre tasa sin comprobar el signo: la cola **crecía** a +2.442/min | L05 §8 |
| "CIRCL empezó a descargar de repente hoy" | inferido | Llevaba trabajando desde el 5-ago. El cursor había avanzado 18 meses | L05 §8 |
| "Hacen falta 200 GB de EBS" | heredado | Cifra de ejemplo sin derivar. El presupuesto medido da ~34 GB mínimo | — (fuera de las lecciones) |

**Ocho más, mismo patrón: cero en mediciones, todos en inferencia o herencia.** Y dos de
ellos —el campo de edad y la agregación heterogénea— habrían justificado borrar la
plataforma por segunda vez.

### Tercera tanda — 2026-08-07, injerto sobre el host AWS

| Afirmación | Categoría | Qué pasó | Corregido en |
|---|---|---|---|
| "Las CVE sin CVSS reaparecerán solas con `CVE_MAINTAIN_DATA=true`" | heredado | Cierto del conector de fábrica; nuestro overlay pide por `pubStartDate`, así que **no vuelve ninguna**. El parche estaba en el propio repositorio | L04 §9 · L05 §11 |
| "Se recuperarán algunas, no las 1.058" | inferido | Misma raíz. Acerté la dirección, fallé mecanismo y magnitud: son cero | L05 §11 |
| "Hacen falta 200 GB de EBS" | heredado | Cifra de ejemplo sin derivar. El presupuesto medido da ~34 GB, y el real 9,2 KB por CVE | — |
| "El disco no cabe: corte en 2,4 h con 57% de los CVEs" | inferido | Proyección lineal tomada en plena divergencia publicación/consumo. Real: **90,6%** antes del corte | — |
| "`Update indexing fail` es benigno" | inferido | Benigno para el dato, **no para el sistema**: 5.500 trazas JSON en 4 h = 1.065 MB de logs sin rotación, que casi tumban la plataforma | — |
| "La historia es el consumidor de disco" | inferido | Hipótesis mía, medida y descartada: 20% del crecimiento de índices. El consumidor eran las `meta_relationships` y, sobre todo, los logs | — |

**Seis más.** Los dos últimos son de la misma familia y merecen nombre propio: *un juicio
correcto sobre una dimensión, extendido sin comprobar a otra*. "No corrompe datos" no
implica "no consume disco"; "crece rápido ahora" no implica "crecerá igual al final".

### Bugs en mis propias herramientas, tanda del 2026-08-07

| Bug | Gravedad | Efecto |
|---|---|---|
| `cve-watch.sh` comprobaba "¿sigue vivo el conector?" antes de que el contenedor existiera | 🔴 | Vio cero, lo interpretó como "ya terminó" y **el vigilante se suicidó a los dos segundos**. Condición de carrera de arranque: se manifiesta como "no pasó nada". Corregido con un flag `visto_vivo` |
| Comprobación de prefijo del token con `\"` dentro de comillas simples | 🟡 | La barra no escapa dentro de `'...'`, el patrón nunca podía coincidir. Dio "prefijo incorrecto" sobre un token válido |
| `truncate` de logs con el test `[ -f ]` sin `sudo` | 🟡 | `/var/lib/docker` es 0710 de root: el test daba falso siempre y **no truncó nada**, informando éxito |

Los tres comparten forma: **la comprobación falla y el fallo se lee como resultado negativo
legítimo**. Un test que no puede pasar nunca es indistinguible de un test que pasa mal.

Los ocho están corregidos **en el punto donde alguien los leería**, no solo en esta tabla.
Un error corregido únicamente en el índice sigue engañando a quien lea la lección suelta:
dos de estos ocho estaban en esa situación hasta que se auditó explícitamente.

### Bugs en las propias herramientas

Auditoría de `scripts/*.py` el 2026-08-03, provocada por un bug encontrado en uso real
(`show_connector_state.py` reventaba con `estado: null`, la cadena que devuelve OpenCTI
para un conector que aún no ha corrido).

| Bug | Gravedad | Efecto |
|---|---|---|
| `check_clocks.py` exigía colapso del 100% (`collapsed == len`) | 🔴 | Con 99,56% real → ~199/200 → veredicto `OK`. **Habría aprobado la plataforma que motivó el script.** |
| Tipo inválido en `stixCoreObjects(types:)` no da error, devuelve todo el grafo | 🔴 | `show_stix.py` no tenía whitelist: imprimía un objeto cualquiera como si fuera del tipo pedido |
| Docstring decía que los catálogos dan `CATALOGO?` | 🟡 | Los tres catálogos de la capa 1 dieron `OK`. Corrección de L01 que no bajó al código |
| Muestra no aleatoria presentada como representativa | 🟡 | `Vulnerability` mostraba `[('2019', 200)]` de un total de 2.273 |
| `check_relationships` sin guarda de error GraphQL | 🟡 | `KeyError` en vez de mensaje |
| `TYPES` cubría 7 tipos de los 10 presentes | 🟡 | Tool, Campaign, Sector, Region, Course-Of-Action, Organization nunca auditados |
| `check_clocks.py` medía la edad en `created` para todos los tipos | 🔴 | En `Indicator` la edad vive en `valid_from`. Veredicto `COLAPSADO` sobre 22.275 indicadores con **cero nulos**. Detectado el 2026-08-04, corregido en `7f6ebe1` (L05 §3) |
| `check_relationships` agregaba todos los tipos en un porcentaje | 🔴 | `indicates` y `based-on` son atemporales por naturaleza (68% del total). Producía un 96% de falsa alarma. Ahora desglosa por `relationship_type` con lista `ATEMPORALES` exenta (L05 §4) |

**`--demo` pasaba con los seis bugs presentes.** Probaba la aritmética del veredicto, no si
el veredicto era correcto — un test que no habría fallado nunca. Los asserts actuales
incluyen el caso de 199/200 como regresión.

Ningún resultado publicado en las lecciones cambió: los tipos auditados estaban todos en
**0% de colapso**, lejísimos del umbral. El bug era un riesgo que nunca llegó a dispararse.

### El fallo silencioso de las consultas

Peligro aparte, de la misma familia que el `connector_state` que miente: **una consulta mal
escrita a Elasticsearch no da error, devuelve un número plausible.** Los tres casos, sus
defensas y por qué se detectaron están en **L01 §6**.

A diferencia de los ocho de arriba, **esta clase de fallo no está resuelta, está mitigada**:
no hay mecanismo que impida escribir una consulta mala. Las defensas son disciplina —
agregar antes que filtrar, y cerrar la contabilidad para que un descuadre delate el error.

---

## Convenciones

- **Cada número lleva su comando.** Si una cifra aparece sin la consulta que la produce,
  es sospechosa.
- **El ciclo de habilitación no se repite.** Vive en la lección 01 §0; las demás lo
  referencian. Si el ciclo cambia, cambia en un solo sitio.
- **Los errores no se borran, se corrigen a la vista.** Cuando una lección contradice a
  otra anterior, la corrección se documenta con lo que se midió. Un documento que solo
  contiene aciertos no enseña dónde está el riesgo.
- **Las secciones "Tu turno" quedan vacías a propósito.** Son para el lector; el hueco que
  encuentre al redactarlas es lo que falta por aclarar.
