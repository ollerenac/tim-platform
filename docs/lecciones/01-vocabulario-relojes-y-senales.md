# Lección 1 — Vocabulario STIX, los tres relojes y las señales que mienten

Notas de aprendizaje de la sesión del **2026-08-03**, la del wipe total y la primera
ingesta limpia (`connector-mitre`). Todo lo que aparece aquí se midió en vivo contra la
plataforma; no hay nada asumido. Los conteos son de esa sesión y sirven como línea base.

Contexto: se borró una plataforma de 1.035.716 objetos por corrupción temporal y de
procedencia, y se reinició la ingesta por capas. Esta lección recoge lo que hacía falta
saber **antes** de aquella ingesta, aprendido a base de romperla.

---

## 0. Procedimiento — ciclo de habilitación de un conector

**Este ciclo se repite idéntico para cada conector.** Las lecciones siguientes lo dan por
sabido y solo documentan lo propio de su conector. Sustituye `$CONN` por el nombre del
servicio en `docker-compose.yml`.

```bash
CONN=connector-opencti      # ← el único valor que cambia entre lecciones
```

### 1 · Levantar solo ese conector

```bash
docker compose up -d $CONN
```

⚠️ **Nunca `COMPOSE_PROFILES=platform docker compose up -d`**: los 34 conectores comparten
el mismo profile y arrancarían todos de golpe. Nombrar el servicio activa su profile
automáticamente (Compose v2) y arrastra solo sus dependencias.

### 2 · Confirmar el registro

`Data → Ingestion → Connectors`. Debe aparecer con estado Active.

Recuerda §4: **Active no significa que funcione.** Solo que hizo handshake.

### 3 · Comprobar que de verdad trabaja

```bash
docker stats --no-stream --format '{{.Name}}\t{{.NetIO}}' opencti-7-pilot-$CONN-1
sleep 20
docker stats --no-stream --format '{{.Name}}\t{{.NetIO}}' opencti-7-pilot-$CONN-1
```

⚠️ **El I/O plano es ambiguo.** Significa "no está descargando", y eso tiene dos causas
opuestas: está dormido, o **ya terminó**. Un conector rápido (`connector-opencti` baja
~1 MB en segundos) sale plano en la primera medición porque acabó antes de que midieras.
Hace falta un segundo dato para desempatar:

```bash
docker exec opencti-7-pilot-elasticsearch-1 curl -s \
  'localhost:9200/opencti_stix_domain_objects/_count'
```

| I/O | Objetos nuevos | Veredicto |
|---|---|---|
| creciendo (MB) | — | descargando, continuar |
| plano | subieron respecto al conector anterior | **ya terminó**, ir al paso 5 |
| plano | sin cambios | **dormido o roto** → paso 3-bis |

### 3-bis · Si está plano: revisar el estado grabado

```bash
docker cp scripts/show_connector_state.py opencti-7-pilot-worker-1:/tmp/
docker exec opencti-7-pilot-worker-1 python /tmp/show_connector_state.py $CONN
```

Si `connector_state` trae un `last_run` de una corrida fallida, el conector se cree al día
y duerme hasta el próximo intervalo. **Resetear el estado:**

- UI: `Data → Ingestion → Connectors → [conector] → reset del estado`
- API: `resetStateConnector(id: "<id-del-conector>")`

Después: `docker compose restart $CONN`

### 4 · Esperar el drenaje

```bash
docker exec opencti-7-pilot-rabbitmq-1 rabbitmqctl list_queues name messages | awk '$2>0'
```

Sin líneas = cola vacía = ingesta terminada. Con 1 worker es lento a propósito: el objetivo
es ver el proceso, no que pase por debajo.

### 5 · Verificar que la corrida fue real

```bash
docker compose logs --since 30m $CONN 2>&1 | grep -c ERROR
docker exec opencti-7-pilot-worker-1 python /tmp/show_connector_state.py $CONN
```

Cero errores y un `last_run` posterior al arranque = corrida legítima.

### 6 · Test de relojes

```bash
docker cp scripts/check_clocks.py opencti-7-pilot-worker-1:/tmp/ && \
  docker exec opencti-7-pilot-worker-1 python /tmp/check_clocks.py <Tipo> <Tipo> ...
```

Los tipos son los que ese conector produce. Veredictos en §2.

### 7 · Anotar la línea base

```bash
docker exec opencti-7-pilot-elasticsearch-1 curl -s -H 'Content-Type: application/json' \
  'localhost:9200/opencti_stix_domain_objects/_search' \
  -d '{"size":0,"aggs":{"t":{"terms":{"field":"entity_type.keyword","size":25}}}}'
```

Cuántos objetos de cada tipo dejó. Es el punto de comparación del siguiente conector — y
la sección "Línea base" de su lección.

### Orden de la capa 1 — marco de referencia

| # | Conector | Qué trae | Coste | Lección |
|---|---|---|---|---|
| 1 | `connector-mitre` | ATT&CK + CAPEC | ~5 min | ésta (§8) |
| 2 | `connector-opencti` | 250 países con lat/long e ISO + árbol de sectores | ~539 objetos | 02 |
| 3 | `connector-disarm-framework` | TTPs de desinformación (DISARM Foundation, **no** MITRE) | pequeño | 03 |
| 4 | `connector-cve` | ~91.000 vulnerabilidades de NVD | **horas** | 04 |

Uno a la vez, ciclo completo antes del siguiente.

---

## 1. Vocabulario: qué es cada cosa

### Las tres familias de STIX 2.1

| Familia | Nombre | Qué es | Ejemplos |
|---|---|---|---|
| **SDO** | STIX Domain Object | Conocimiento: el *qué* y el *quién* | Attack-Pattern, Intrusion-Set, Malware, Tool, Campaign, Report, Indicator |
| **SCO** | STIX Cyber-observable Object | El dato crudo observado | `ipv4-addr`, `domain-name`, `file` (hash), `url` |
| **SRO** | STIX Relationship Object | La arista entre dos objetos | `uses`, `targets`, `mitigates`, `based-on` |

### Marco de referencia vs evento

La distinción más útil de toda la lección. No está en el estándar STIX — es operativa,
pero gobierna qué widget puede mezclar qué.

| | **Marco de referencia** | **Evento** |
|---|---|---|
| Qué aporta | el vocabulario para describir hechos | los hechos |
| Tiene edad propia | no como suceso | sí, es parte del dato |
| Ejemplos | Attack-Pattern, Tool, Malware, Country, Sector | Report, Indicator, Sighting |
| Fuentes | MITRE ATT&CK, CAPEC, DISARM, catálogo de geografía, CVE/NVD | AlienVault OTX, MISP, Abuse.ch, boletines CNSD/ColCERT |
| Ingesta | total, sin ventana de fechas | con ventana **y** test de relojes |

Analogía: el marco es el diccionario, el evento es la noticia. Un widget que cuenta
"actividad reciente" mezclando ambos miente siempre.

**Frontera imperfecta:** `Campaign` vive en el catálogo de MITRE pero trae `first_seen`
y `last_seen` (ej. J-magic, mid-2023 → mid-2024). Es un objeto de marco que describe un
evento. Si construyes un widget que asume la separación limpia, este es el caso que lo
rompe.

### Observable ≠ Indicator

No son el mismo objeto con más campos. Son tipos distintos con propósitos distintos.

| | **Observable** (SCO) | **Indicator** (SDO) |
|---|---|---|
| Afirma | un hecho: "esta IP existe / se vio" | un juicio: "esto es evidencia de actividad maliciosa" |
| Campos clave | `value`, `hashes` | `pattern`, `valid_from`, `valid_until`, `indicator_types` |
| Ejemplo | `ipv4-addr` con `value = "1.2.3.4"` | `pattern = "[ipv4-addr:value = '1.2.3.4']"` |
| Lleva veredicto | no | sí |
| Caduca | no — un hash no caduca | sí — la sospecha sobre él sí |

Se enlazan con una relación explícita: **`Indicator --based-on--> Observable`**.

Que exista un observable **no implica** que se cree su indicador. Depende del conector:
unos publican solo indicadores, otros solo observables, otros ambos. OpenCTI tiene una
opción para generar el observable desde el patrón del indicador — es configuración, no
consecuencia automática.

### "Pulse" es vocabulario de AlienVault, no de STIX

Un *pulse* es el envoltorio de OTX para un reporte de amenaza: IOCs más metadatos. Al
ingerirse se convierte en un **Report** de OpenCTI.

MITRE **no emite pulses**: publica *bundles* STIX — ficheros JSON con objetos y
relaciones. Usar "pulse" fuera de OTX lleva a esperar estructuras que no existen.

---

## 2. Los tres relojes

Todo objeto convive con hasta tres marcas de tiempo, y confundirlas fue la causa raíz de
que la plataforma anterior tuviera que borrarse.

| Reloj | Campo | Qué significa | Quién lo pone |
|---|---|---|---|
| **Técnico** | `created_at` | cuándo entró **a tu** plataforma | OpenCTI, siempre |
| **Funcional** | `created` | cuándo lo publicó **la fuente** | la fuente, si es honesta |
| **De evento** | `start_time` / `valid_from` | cuándo se **observó** la amenaza | la fuente, si lo declara |

### El centinela 1970

Cuando una relación no trae fecha de observación, OpenCTI escribe `1970-01-01` — epoch 0.
No es un cero inocente: cualquier widget que ordene por `start_time` mete esas relaciones
en enero de 1970 y las trata como el evento más antiguo del universo. Las líneas de tiempo
no salen vacías, salen **aplastadas contra el borde izquierdo**.

### Lo que se midió

Plataforma anterior, antes del wipe:

```
created_at → 2026:  464.671 / 464.671 indicadores   (100%, correcto por definición)
created    → 2026:  462.630 / 464.671               (99,6%)
start_time → 1970:  960.864 / 994.343 relaciones    (96,6%)
```

El 99,6% es el hallazgo. **No es que OpenCTI mezclara datos viejos y nuevos: es que las
importaciones masivas destruyeron la edad.** Sellaron `created` con la fecha de
importación. Un pulse de 2019 no llegó diciendo "soy de 2019"; llegó diciendo "soy de hoy".

Y eso es irrecuperable: ninguna configuración de widget reconstruye una fecha que se
perdió en la ingesta. Por eso hubo que borrar en vez de reparar.

Tras la ingesta limpia de MITRE, la misma medida:

```
Attack-Pattern   created==created_at:   0/200   OK
Intrusion-Set    created==created_at:   0/185   OK
Malware          created==created_at:   0/200   OK
relaciones       start_time==1970:     83/500   (17%)   OK
```

Cero colapso en 585 objetos. MITRE publica fechas reales de 2014 a 2026.

### El test de admisión

`scripts/check_clocks.py`. Se corre **después de habilitar cada conector** y antes de
pasar al siguiente. Detecta con 50 objetos lo que con 460.000 es invisible.

```bash
docker cp scripts/check_clocks.py opencti-7-pilot-worker-1:/tmp/ && \
  docker exec opencti-7-pilot-worker-1 python /tmp/check_clocks.py Attack-Pattern Malware
```

Cómo leer el veredicto:

- **`COLAPSADO`** — **≥90%** de la muestra tiene `created == created_at`. La fuente no
  publicó fecha propia, o la ingesta la pisó con la suya. **Alarma** en un feed de eventos;
  en un catálogo, decisión consciente.
- **`OK`** — la fuente publica su fecha propia y sobrevivió a la ingesta.
- **`start_time == 1970` mayoritario** — se perdió la edad del evento. En la capa 1 el
  19% es sano (`mitigates`, `subtechnique-of`, `located-at` y `part-of` no tienen
  "cuándo"). El 96,6% de la plataforma anterior era otra cosa.

⚠️ **No esperes `COLAPSADO` en un catálogo por defecto.** Se predijo para MITRE razonando
que "una técnica no ocurre en una fecha", y salió `OK`: ATT&CK publica fechas de 2014 a
2026. Geografía también (`created: 2023`), y DISARM igual. **Los tres catálogos de la capa 1
dieron `OK`.** El razonamiento confundía *el objeto* con *su ficha*: T1059 no ocurre en una
fecha, pero MITRE sí registra cuándo la publicó.

### Por qué el umbral es 90% y no igualdad exacta

La primera versión del script exigía `collapsed == len(nodes)` — colapso del 100%. Con los
números reales de la plataforma que motivó todo esto:

```
tasa real de colapso   462.630 / 464.671 = 99,56%
en una muestra de 200  ~199 colapsados
condición original     199 == 200  →  False
veredicto que daba     OK
```

**El script habría aprobado la plataforma más colapsada que hemos visto.** Falso negativo
en su razón de existir. El umbral proporcional lo corrige, y `--demo` lleva ese caso exacto
como test de regresión.

Moraleja: un test verde no prueba que la herramienta funcione, solo que su aritmética no
revienta. El dato para probarla estaba medido en la misma sesión y no se usó.

### La muestra no es aleatoria

`first: N` devuelve los primeros que da la API, no una muestra al azar. Se ve claro con un
conector que ingesta cronológicamente:

```
Vulnerability  total=2273  muestra=200  created por año: [('2019', 200)]
```

Los 200 son de 2019 porque `connector-cve` empieza por ahí. **El histograma describe la
muestra, no el conjunto.** El veredicto sí es fiable: el colapso de relojes es propiedad
del conector, no del orden de los resultados.

### Un tipo mal escrito no da error

`stixCoreObjects(types: ["TipoInventado"])` **no falla: ignora el filtro y devuelve todo el
grafo.** Medido:

```
TOTAL sin filtro    6.229
Course-of-Action    6.230   ← filtro ignorado (es Course-Of-Action)
TipoInventado       6.230   ← filtro ignorado
Attack-Pattern      1.905   ← correcto
```

`check_clocks.py` y `show_stix.py` piden `entity_type` de vuelta y abortan si no coincide.
Sin esa comprobación, el script reportaría el grafo entero como si fuera de un solo tipo.

**Regla:** un conector de eventos que no llena el reloj funcional no entra en producción
sin decisión consciente. Se acepta como fuente de enriquecimiento (lookup) o se rechaza
como fuente de inteligencia. Lo que no puede volver a pasar es descubrirlo con 460.000
objetos dentro.

---

## 3. Arquitectura de ingesta: quién escribe

```
conector              descarga y traduce a bundles STIX
   ↓ empuja mensajes
RabbitMQ  cola push_<connector-id>    amortigua el desfase producción/escritura
   ↓ consume
worker                ÚNICO proceso con permiso de escritura
   ↓ llama a la API
opencti (plataforma)  valida, deduplica, resuelve referencias
   ↓ persiste
Elasticsearch         el grafo
```

Cosas que no son obvias:

- **El conector nunca escribe en la base.** Solo empuja mensajes a la cola.
- **El worker es el único camino de escritura**, y ejecuta *todo* lo de escritura: ingesta
  **y** tareas en segundo plano (borrados masivos incluidos). Por eso escalar workers
  acelera una purga.
- **RabbitMQ es infraestructura permanente**, no algo que se "active" por conector. Arranca
  con Elasticsearch, Redis y MinIO.
- **Las colas son durables.** Un apagado no pierde trabajo pendiente: al volver, sigue.
- Escalar workers en borrados es **sub-lineal**: 1→35/min, 4→75, 8→102. El cuello es el
  coste de refs de Reports en Elasticsearch, no la CPU. 8 es el tope útil.

### Un borrado no es un borrado

Una tarea de fondo `DELETE` **encola** a RabbitMQ; los workers ejecutan. Que la tarea diga
`COMPLETED` significa "terminé de encolar", no "terminé de borrar". Se verifica **con un
conteo**, nunca con el estado de la tarea.

---

## 4. Señales que mienten

La lección más cara del día. Ninguna de estas señales es defectuosa: todas son ambiguas, y
las tres primeras fueron consistentes entre sí **y todas equivocadas a la vez**.

| Señal | Por qué no sirve sola |
|---|---|
| Badge **Active** | solo dice que el proceso hizo handshake y está vivo. Un conector puede estar verde durante días fallando cada descarga |
| **Messages 0** | indistinguible entre "aún no empieza", "no hay nada nuevo" y "lleva 5 minutos fallando" |
| **connector_state** | se graba `last_run` **aunque la descarga haya fallado**. Con `INTERVAL=7`, el conector se cree al día y duerme una semana |
| **Logs** | con `CONNECTOR_LOG_LEVEL=error`, silencio significa tanto "todo bien" como "dormido" |
| **I/O de red** | ← la única que no mintió |

### El caso real

`connector-mitre` arrancó con el DNS roto. Falló las 4 descargas, **grabó
`last_run = 22:14:09` igualmente**, y se durmió hasta el 10 de agosto. La UI mostraba
Active, la cola 0, los logs en silencio. Diagnóstico por I/O de red:

```
dormido:      21.7kB → 21.9kB en 20 s     (~200 bytes)
trabajando:   12.2kB → 57.1MB en 25 s
```

**Arreglo:** resetear el estado del conector.
UI: `Data → Ingestion → Connectors → [conector] → reset del estado`.
API: `resetStateConnector(id: "...")`. Después, `docker compose restart <conector>`.

**Paso obligatorio del ciclo:** revisar `connector_state` antes de dar por bueno cualquier
conector nuevo.

---

## 5. Por qué la API y la UI no dicen lo mismo

Ninguna miente. **La API da el estado real; la UI da el estado accionable.** Cuando
difieren, la respuesta suele estar en un filtro del frontend, no en un dato perdido.

### Caso 1 — conectores internos invisibles

La API devuelve 6 conectores internos; la UI muestra 2. Los 4 ocultos son
`[TASK] Internal task processing #0-3`, con `connector_type = "internal"` en minúscula.
En el bundle compilado del frontend está el filtro literal:

```js
connector_type!=="internal").map(...)
```

Los 4 existen, están activos y son los que ejecutan las tareas de fondo. OpenCTI decidió
que no son cosa del operador.

### Caso 2 — conteos distintos

| Fuente | Valor | Qué mide |
|---|---|---|
| API `stixCoreObjects` | 2.035 | objetos STIX de dominio |
| UI "Total number of documents" | 5.31K | **documentos de Elasticsearch**: incluye relaciones, metadatos internos e historial |

No se contradicen. Miden cosas distintas.

### Caso 3 — Elasticsearch no guarda STIX

Lo que hay en ES es el **modelo de almacenamiento interno de OpenCTI**: `internal_id`,
`rel_*.internal_id`, `i_aliases_ids`, `parent_types`. Para ver STIX 2.1 canónico hay que
pedírselo a la plataforma (campo `toStix`), que lo reconstruye.

### Índices de Elasticsearch

```
opencti_stix_domain_objects         SDO
opencti_stix_cyber_observables      SCO
opencti_stix_core_relationships     SRO
opencti_stix_meta_relationships     refs (created-by, marking, external-refs)
opencti_stix_meta_objects           markings, kill chain phases, labels
opencti_internal_objects            usuarios, roles, workspaces, conectores
opencti_history                     historial de cambios
```

**Toda la configuración de OpenCTI vive en Elasticsearch** — dashboards, workspaces,
filtros guardados, usuarios, registro de conectores. No existe separación entre plano de
datos y plano de configuración; por eso no existe un "wipe solo de datos".

---

## 6. Recetario

Comandos verificados en esta sesión.

**STIX 2.1 canónico de un objeto:**
```bash
docker cp scripts/show_stix.py opencti-7-pilot-worker-1:/tmp/
docker exec opencti-7-pilot-worker-1 python /tmp/show_stix.py Intrusion-Set
```

**Documento crudo de Elasticsearch:**
```bash
docker exec opencti-7-pilot-elasticsearch-1 curl -s -H 'Content-Type: application/json' \
  'localhost:9200/opencti_stix_domain_objects/_search?pretty' \
  -d '{"size":1,"query":{"term":{"entity_type.keyword":"Tool"}}}'
```

**Recuento por tipo:**
```bash
docker exec opencti-7-pilot-elasticsearch-1 curl -s -H 'Content-Type: application/json' \
  'localhost:9200/opencti_stix_domain_objects/_search' \
  -d '{"size":0,"aggs":{"t":{"terms":{"field":"entity_type.keyword","size":20}}}}'
```

**Cola pendiente:**
```bash
docker exec opencti-7-pilot-rabbitmq-1 rabbitmqctl list_queues name messages
```

**Estado grabado de un conector** (el campo que miente cuando falla, §4):
```bash
docker cp scripts/show_connector_state.py opencti-7-pilot-worker-1:/tmp/
docker exec opencti-7-pilot-worker-1 python /tmp/show_connector_state.py MITRE
```

**Test de relojes:** ver §2.

### ⚠️ Consultas que fallan en silencio

**Una consulta mal escrita a Elasticsearch no da error: devuelve un número plausible.** Es
la misma familia de peligro que el `connector_state` de §4 — fallo disfrazado de dato.

Los tres casos que ocurrieron de verdad en esta sesión:

| Error | Devolvió | Parecía |
|---|---|---|
| `Course-of-Action` en vez de `Course-Of-Action` | el total sin filtrar (3.919) | un conteo válido |
| `term` sobre `entity_type` sin `.keyword` | 0 hits | "no hay objetos de ese tipo" |
| `prefix` sobre `x_mitre_id` sin `.keyword` | 0 hits | "DISARM no usa IDs T0" |

Los campos de texto están analizados: `term` y `prefix` necesitan el subcampo `.keyword`.
Y la capitalización de `entity_type` no perdona.

**Dos defensas, en orden de preferencia:**

**1 · Agregar antes que filtrar.** Una agregación `terms` **enumera lo que existe**; no
puede devolver el valor equivocado en silencio, porque el nombre no lo pones tú.

```bash
# frágil: si el tipo está mal escrito, resultado engañoso sin aviso
-d '{"query":{"term":{"entity_type.keyword":"Course-of-Action"}}}'

# robusto: te dice qué tipos hay y cuántos de cada uno
-d '{"size":0,"aggs":{"t":{"terms":{"field":"entity_type.keyword","size":50}}}}'
```

**2 · Cerrar la contabilidad.** Si las partes no suman el total observado, el error está en
la consulta, no en los datos. En la lección 03, `391 attack-pattern + 288 relaciones +
1 identidad` tenían que cuadrar con el delta de la ingesta — y cuadraron. Los tres fallos
silenciosos de arriba se cazaron por descuadre, ninguno por sospecha.

---

## 7. Rutas de la UI

Extraídas del bundle del frontend, no de memoria.

| Qué | Ruta |
|---|---|
| Técnicas y subtécnicas | `Techniques → Attack patterns` |
| Mitigaciones | `Techniques → Courses of action` |
| Grupos adversarios | `Threats → Intrusion sets` |
| Malware / Herramientas | `Arsenal → Malwares` / `Arsenal → Tools` |
| Campañas | `Threats → Campaigns` |
| Observables / Indicadores | `Observations → Observables` / `Indicators` |
| Países / Sectores | `Locations → Countries` / `Entities → Sectors` |
| Estado de conectores | `Data → Ingestion → Connectors` |
| Políticas de retención | `Settings → Customization → Retention policies` |

### Sobre las políticas de retención

OpenCTI crea 4 al arrancar, todas a 30 días, todas nunca ejecutadas al inicio. **Ninguna
tiene scope `knowledge`** — sus ámbitos son `file`, `activity`, `workbench` e `history`,
así que no pueden borrar un indicador ni un report.

⚠️ `Global files retention` sí merece revisión antes de la capa 3: con scope `file`,
30 días y filtro vacío, **borra de MinIO cualquier fichero subido con más de 30 días**.
En un laboratorio donde el PDF original *es* la evidencia, eso es una decisión, no un
detalle.

---

## 8. Línea base — `connector-mitre`, 2026-08-03

```
duración            ~5 min con 1 worker
objetos              3.919
relaciones          23.740

attack-pattern       1.514    ← 955 ATT&CK (con x_mitre_id) + 559 CAPEC
course-of-action     1.211
malware                851
intrusion-set          185
tool                    97
campaign                60
organization             1    ← The MITRE Corporation
observables              0
indicadores              0
```

**Cero observables, cero indicadores.** ATT&CK no trae ni una IP ni un hash: es marco puro.

**CAPEC viene incluido.** El conector descarga `stix-capec.json` como una de sus 4 fuentes.
CAPEC es otro catálogo de MITRE, de patrones a nivel de debilidad de software ("Overread
Buffers"), no de TTPs de adversario. Se distinguen por la ausencia de `x_mitre_id`. Son
**dos taxonomías conviviendo** bajo el mismo `entity_type`: un widget que cuente 1.514
"técnicas" está sumando peras y manzanas.

### Campos por tipo

23 campos comunes a todos (`id`, `standard_id`, `entity_type`, `name`, `description`,
`created`, `created_at`, `modified`, `confidence`, `revoked`, `lang`…), más exclusivos:

| Tipo | Exclusivos |
|---|---|
| Attack-Pattern | `x_mitre_id`, `x_mitre_detection`, `x_mitre_platforms`, `x_mitre_permissions_required` |
| Malware | `is_family`, `malware_types`, `capabilities`, `implementation_languages` |
| Intrusion-Set | `goals`, `primary_motivation`, `secondary_motivations`, `resource_level` |
| Tool | `tool_types`, `tool_version` |
| Campaign | `objective`, `first_seen`, `last_seen` |

**Matiz importante:** en el *documento* el campo ausente **no existe** — Elasticsearch no
guarda nulos. Pero en el *mapping del índice* sí está declarado para todos los tipos, que
comparten esquema. Esquema común, documentos dispersos.

Los `x_mitre_*` son *custom properties*: STIX permite extender con prefijo `x_`. OpenCTI
los transporta sin entenderlos — así un formato genérico lleva semántica de una fuente
concreta sin romperse.

---

## 9. Bitácora: cómo se diagnosticó mal dos veces

Vale como método, no como anécdota.

**Síntoma:** `connector-mitre` Active, cola 0, `socket.gaierror: [Errno -3] Try again`.

1. **Primera hipótesis** — Docker sin upstream DNS válido → cambiar `daemon.json`.
   Prescripción correcta, **razonamiento equivocado**. Sin evidencia.
2. **Objeción del usuario:** "tenía una VPN activada y ahora ya no está".
   Segunda hipótesis: la red capturó el DNS de la VPN al crearse → recrear la red.
   **Falló:** tras `down` + `up`, seguía roto.
3. **Test que partió el problema en dos** — un contenedor con `--dns` explícito:
   ```
   --dns 200.48.225.130  → OK      --dns 1.1.1.1 → OK      --dns 8.8.8.8 → OK
   ```
   Egress UDP 53 funciona; el problema es el upstream del resolver embebido.
4. **Causa real:** `/etc/resolv.conf → /run/resolvconf/resolv.conf` (paquete
   `resolvconf`, no el stub de systemd-resolved). Contiene solo `127.0.0.53`. Docker
   descarta loopback por inalcanzable desde contenedor **y se queda sin ningún upstream**.
   La VPN escribía servidores reales ahí: **el problema llevaba meses, la VPN lo tapaba.**

**Lección de método:** la objeción del usuario no acertó la causa, pero forzó a *testear*
en vez de razonar. El test de `--dns` explícito separó "¿no hay red?" de "¿no hay
resolver?" y el resto cayó solo. Una explicación bonita sin test es una hipótesis.

**Segunda trampa, gratis:** `depends_on` solo ordena el arranque en `docker compose up`.
Cuando **reinicia el daemon**, Docker levanta todos los contenedores a la vez y
`restart: unless-stopped` no respeta dependencias. El conector ganó la carrera contra
OpenCTI y murió con `OpenCTI API is not reachable`.

---

## 10. Tu resumen

<!-- TODO (Óscar): escribe aquí, con tus palabras, la distinción marco vs evento y qué
     cambia en la práctica al ingerir cada tipo. 5-10 líneas.

     No es trámite: es el concepto que estabas armando cuando preguntaste si "estas ideas
     entreveradas tienen sentido". Escribirlo tú fija lo que leerlo no fija, y el hueco
     que encuentres al redactarlo es exactamente lo que falta por aclarar. -->

---

## Pendientes que salieron de esta sesión

- [ ] `Global files retention` a 30 días borrará los PDFs originales de MinIO (§7)
- [ ] ATT&CK y CAPEC comparten `entity_type: Attack-Pattern` — separarlos en widgets (§8)
- [ ] Los 34 conectores comparten `profiles: [platform]`: `COMPOSE_PROFILES=platform up -d`
      arranca los 34 de golpe. La ingesta progresiva exige nombrar servicios uno a uno
- [ ] Añadir "revisar `connector_state`" como paso fijo del ciclo por conector (§4)
