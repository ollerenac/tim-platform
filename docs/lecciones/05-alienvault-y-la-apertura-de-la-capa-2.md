# Lección 5 — AlienVault y la apertura de la capa 2

Primer conector de eventos, ejecutado el **2026-08-04**. Ciclo de habilitación en
**[Lección 1, §0](01-vocabulario-relojes-y-senales.md)**.

La capa 1 traía catálogos: marcos de referencia que describen *qué existe*. La capa 2 trae
**eventos**: afirmaciones sobre *qué está pasando*. El cambio de naturaleza rompe tres
herramientas que funcionaban bien contra catálogos, y esta lección documenta las tres
roturas antes que el conector.

Incluye además un accidente del **2026-08-05** que no estaba previsto y acabó siendo el
hallazgo más útil de la serie: un conector que arrancó un backfill, murió a mitad, y metió
30.753 observables sin dejar una sola señal (§8).

> **Fechas de medición.** Las cifras de §1 a §7 se midieron el 3 y 4 de agosto contra la
> plataforma viva. Las de §8 a §10, el 7 de agosto. La plataforma está apagada desde
> entonces: los comandos son re-ejecutables, pero **no se han vuelto a correr**. Cada
> bloque lleva su fecha.

---

## 1. La cuenta de servicio: un token que no se puede copiar

El wipe del 2026-08-03 se llevó por delante algo que no estaba en la lista de daños: **las
cuentas de servicio de los conectores viven en Elasticsearch**, igual que el resto de la
configuración de OpenCTI. Al borrar el índice desapareció la cuenta de AlienVault, y con
ella la validez de su token.

El primer intento fue el obvio: recuperar el token viejo del `.env` y volver a usarlo.

**No funciona, y el motivo importa.** OpenCTI 7 genera los tokens en el servidor y no acepta
fijar su valor desde fuera. No hay campo donde pegar un token existente; sólo hay un botón
que emite uno nuevo. Un token de otra plataforma —o de la misma plataforma antes de un
wipe— es papel mojado.

> Consecuencia operativa: **el `.env` no es portable entre despliegues.** Las claves de API
> de terceros sí; los tokens de OpenCTI, no. Al migrar a otro host hay que recrear las
> cuentas a mano.

### Confianza 80, y por qué no admin

La cuenta se recreó como `connector-alienvault@tim.local`, grupo `Connectors`, **nivel de
confianza 80**, sin capacidad `Bypass`.

La tentación es usar el token de admin: ya existe, funciona, y ahorra cinco minutos. Es un
error caro, y éste es el mecanismo:

**La confianza de un objeto sale del usuario dueño del token, no de
`CONNECTOR_CONFIDENCE_LEVEL`.** Esa variable existe y se puede poner a 30, pero OpenCTI
resuelve los conflictos de escritura con la confianza del *usuario*.

Con un token de admin, AlienVault escribe a confianza 100 — **empata con MITRE**. Y cuando
dos fuentes empatan, gana la última que escribe. AlienVault nombra sus attack-patterns con
el identificador pelado, así que los `T1095` de OTX sobrescriben los nombres de ATT&CK:

```
antes   Non-Application Layer Protocol
después T1095
```

Esas son las *"12 técnicas basura"* que arrastraba la plataforma anterior, y el mecanismo
estuvo sin identificar hasta esta sesión.

**Verificado tras la ingesta (2026-08-04):** los 185 intrusion-sets de MITRE quedaron
intactos. Ninguno reescrito, ninguno renombrado. La cuenta a 80 hizo su trabajo.

---

## 2. Curar en la fuente, no filtrar después

Antes de arrancar el conector se auditó la cuenta de OTX. El resultado desmontó una
suposición cómoda.

**Medido el 2026-08-04:**

```
cuenta ollerenac
suscripciones declaradas          0
pulses en /pulses/subscribed  8.868
```

`subscriber_count = 0` y aun así el endpoint devuelve 8.868 pulses. La cuenta arrastraba
suscripciones que la UI no mostraba como tales. **Un contador a cero no significa que no
entre nada.**

Al perfilar la ventana desde 2026-03-01 aparecieron dos publishers dominantes y un tercero
suelto. El interesante:

```
publisher   pr0viehh
un pulse    43.706 IOCs
```

Cuarenta y tres mil indicadores en **un solo pulse**. Sin curar, ese pulse por sí solo
habría multiplicado por dos el volumen de la plataforma entera.

### La decisión, y por qué el allowlist no bastaba

El sistema ya tiene un `CURATED_AUTHORS` que gobierna qué autores entran en el briefing y
en la búsqueda semántica. La tentación era dejar entrar todo y filtrar en la salida.

No sirve, por dos razones medidas:

1. **El allowlist no impide que los objetos entren.** Gobierna briefing y semantic, no la
   ingesta. Los 43.706 IOCs estarían en el grafo igualmente.
2. **Los widgets nativos de OpenCTI no conocen el allowlist.** El dashboard, los conteos y
   los mapas cuentan todo lo que hay en la plataforma.

Se curó en el origen: el usuario des-suscribió `pr0viehh`, `whatda77` y un pulse suelto de
`FNTuncer` desde la propia OTX.

**Ventana final (2026-08-04): 755 pulses, 100% del publisher oficial `AlienVault`.**

> **Doctrina.** Curar en la fuente, no filtrar después. Un filtro de salida deja el dato
> dentro del grafo, dentro de los conteos y dentro de los widgets — sólo lo esconde del
> camino que tú controlas.

---

## 3. ⚠️ Caso de estudio: el veredicto de relojes depende del campo, no del conector

Éste es el error más instructivo de la serie, porque **la herramienta funcionaba
correctamente y aun así condenaba a un conector sano.**

`check_clocks.py` corrió sobre la plataforma recién ingerida y devolvió:

```
Indicator   COLAPSADO   22.275 / 22.275   (100%)
```

Colapso total. Veredicto: AlienVault no fecha nada. La conclusión encajaba con la historia
previa —la plataforma anterior se borró por un 96,6% de fechas centinela— y por eso mismo
no levantó sospecha. **Un resultado que confirma lo que ya temes no se audita.**

### La causa

El script comparaba `created` contra `created_at`. En un Indicator esos dos campos
significan cosas distintas:

| Campo | Qué significa | Al ingerir |
|---|---|---|
| `created_at` | cuándo lo escribió esta plataforma | ahora |
| `created` | cuándo se **redactó la afirmación** | ahora, también |
| **`valid_from`** | **desde cuándo el indicador es válido** | **la fecha real del pulse** |

En un Indicator, `created` no lleva la edad. Lleva el momento en que alguien afirmó el
indicador — que al ingerir de un feed es siempre el instante de la ingesta. Comparar esos
dos campos da colapso **por construcción**, mida lo que mida el conector.

La edad vive en `valid_from`. Y estaba intacta:

```
Indicator.valid_from     julio-2024 → julio-2026
nulos                    0
```

**Cero nulos en 22.275 indicadores.** El conector fechaba perfectamente. La herramienta
miraba el campo equivocado.

### La corrección

Corregido en `7f6ebe1`. El mapa `TYPES` de `check_clocks.py` ahora declara **qué campo
lleva la edad para cada tipo**:

| Tipo | Campo de edad |
|---|---|
| `Indicator` | `valid_from` |
| `Campaign` | `first_seen` |
| resto | `created` |

Lección de método: **un veredicto sobre el tiempo necesita saber qué campo lleva el tiempo
en ese tipo.** No hay un campo universal de edad en STIX, y elegir mal condena a un
conector sano con un número perfectamente plausible.

Es el tercer bug del mismo patrón en las herramientas propias (ver
[00-README](00-README.md#bugs-en-las-propias-herramientas)): **un test que sólo ha visto
datos enfermos no reconoce los sanos.**

---

## 4. ⚠️ Caso de estudio: no agregar relaciones de tipos distintos en un porcentaje

Segundo error, mismo día, y produjo una cifra que pedía a gritos borrar la plataforma otra
vez.

La medición inicial sobre las relaciones dio:

```
relaciones con start_time centinela 1970    96%
```

Noventa y seis por ciento. Prácticamente idéntico al **96,6%** que motivó el wipe de la
plataforma anterior. La conclusión inmediata —*"volvemos a estar donde estábamos"*— era
falsa.

### La causa

El desglose por tipo de relación:

```
total de relaciones                442.330
   de ellas, `indicates`           299.460   (68%)
```

**`indicates` no tiene "cuándo" por naturaleza.** Expresa que un indicador señala a una
amenaza; no es un hecho que ocurra en una ventana temporal. Lo mismo pasa con `based-on`.
Que su `start_time` sea el centinela de 1970 no es un defecto: es que ese campo no aplica.

Sumar `indicates` con `targets` en un porcentaje único mezcla relaciones que **pueden**
llevar fecha con relaciones que **no pueden** llevarla. El 96% no medía calidad de datos;
medía la proporción de relaciones atemporales en el grafo.

### El veredicto real, ya desglosado

Con el desglose por tipo y las atemporales exentas de alarma:

| Qué | Campo | Centinela | Veredicto |
|---|---|---|---|
| `Indicator` | `valid_from` | 0/200 (0%) | ✅ OK |
| `Report` | `created` | 0/200 (0%) | ✅ OK |
| `targets` | `start_time` | **100%** | 🔴 ALERTA — 11.204 relaciones |
| `uses` | `start_time` | **64%** | 🔴 ALERTA — las de MITRE sí tienen |

**AlienVault aprueba en objetos y suspende en aristas.** Ése es el veredicto honesto, y no
se parece ni al "COLAPSADO" del §3 ni al "96%" de aquí.

Corregido en `7f6ebe1`: `check_relationships` bucketiza por `relationship_type` y mantiene
una lista `ATEMPORALES` exenta.

Lección de método: **un porcentaje sobre una población heterogénea no significa nada.**
Antes de agregar, pregunta si todos los miembros podían haber tenido el valor que estás
midiendo. Si no podían, no pertenecen al denominador.

---

## 5. `targets` sin fecha bloquea el conmutador funcional

La alerta de §4 no es cosmética. Tiene una consecuencia directa sobre lo que la plataforma
puede mostrar.

`targets` es la relación que alimenta la victimología: qué actor ataca a qué país, a qué
sector, en qué periodo. Es lo que llena el mapa y los widgets de "amenazas por región".

La [Lección 4 §8](04-connector-cve-y-cierre-de-la-capa-1.md) documentó el conmutador
técnico/funcional de OpenCTI. Recordatorio:

| Modo | Filtra por | Qué responde |
|---|---|---|
| **Technical Date** | `created_at` | *"¿qué entró en mi plataforma en este periodo?"* |
| **Functional Date** | `start_time` | *"¿qué ocurrió en el mundo en este periodo?"* |

Con `targets` al 100% de centinela, **en modo funcional el mapa de países saldría vacío**:
las 11.204 relaciones tienen `start_time` en 1970 y quedan fuera de cualquier ventana
razonable.

**Decisión (2026-08-04): Date Reference se queda en Technical Date.** Medida, no intuida.
No es la preferencia "correcta" en abstracto — es la única que produce widgets no vacíos
con los datos que hay.

> Y es reversible: el día que un conector aporte `targets` bien fechados, se vuelve a
> evaluar. La decisión está atada a una medición, no a un gusto.

---

## 6. La resolución por alias cubre menos de lo que dice la Lección 4 §7

La [Lección 4 §7](04-connector-cve-y-cierre-de-la-capa-1.md) argumentó que cargar el marco
de referencia primero permite a OpenCTI resolver alias: cuando un feed trae "Sofacy",
la plataforma lo reconoce como APT28 porque MITRE registró ese alias.

**Ese argumento es correcto pero está incompleto, y esta sesión lo mide.**

Tras la ingesta (2026-08-04):

```
intrusion-sets totales      390
   de MITRE                 185   ← intactos
   nuevos de AlienVault     205
```

Los 185 de MITRE sobrevivieron: la cuenta a confianza 80 hizo su trabajo (§1). Pero los 205
nuevos no son 205 actores legítimos. Una muestra:

```
'Sandworm'                            alias: None                  ← duplica a MITRE
'Sandworm Team'                       alias: [ELECTRUM, …, APT44]  ← el de MITRE
'APT-C-13, Sandworm, FROZENBARENTS'   alias: None                  ← texto libre como nombre
'hackerbot-claw', 'nhattuanbl'                                     ← parecen usuarios de OTX
'UNC6691', 'SloppyLemming', 'Dust Specter'                         ← plausibles, no en ATT&CK
```

**Sandworm quedó fracturado en tres entidades distintas.**

### Por qué no se disparó la resolución

Porque **MITRE no registra "Sandworm" a secas como alias de "Sandworm Team"**. Registra
`ELECTRUM`, `Telebots`, `IRON VIKING`, `APT44` y algunos más — pero no la forma corta que
usa medio mundo en prosa.

La resolución por alias funciona sobre **alias registrados**. No hace nada contra:

| Caso | Ejemplo | Por qué falla |
|---|---|---|
| Variante no registrada | `Sandworm` vs `Sandworm Team` | el alias corto no está en ATT&CK |
| Texto libre como nombre | `APT-C-13, Sandworm, FROZENBARENTS` | tres nombres en un campo `name` |
| Actor ausente de ATT&CK | `UNC6691`, `SloppyLemming` | no hay contra qué resolver |
| Ruido del feed | `hackerbot-claw`, `nhattuanbl` | no son actores |

> **Corrección a la Lección 4 §7.** Cargar el marco primero resuelve los alias
> *registrados*, y eso sigue siendo razón suficiente para el orden de ingesta. Pero **no es
> un mecanismo de deduplicación de actores.** El orden correcto reduce los duplicados; no
> los elimina. Queda trabajo manual de curación que ningún orden de carga evita.

**Decisión pendiente:** clasificar los 205 en tres cubos — adversarios legítimos ausentes de
ATT&CK, duplicados de entidades de MITRE bajo otro nombre, y ruido. Es la decisión de
calidad de datos de la capa 2 y sigue abierta.

---

## 7. Escalado: la curva sólo vale dentro de la misma carga

Durante el backfill se midió el drenaje a tres tamaños de flota.

**Medido el 2026-08-04, carga AlienVault:**

| Workers | msg/min | Factor |
|---|---|---|
| 1 | 1.029 | — |
| 4 | 1.491 | ×1,45 |
| 8 | 2.310 | ×2,24 |

Sub-lineal, sin techo aún a 8. Multiplicar por ocho la flota multiplica por 2,24 el
rendimiento.

### ⚠️ El error: comparar curvas entre conectores

Durante la sesión afirmé que *"8 workers no rinde más que 4"* comparando estas cifras con
las de `connector-cve` de la lección anterior. **La comparación no era válida**, y el
2026-08-07 apareció el dato que lo demuestra sin lugar a dudas:

```
mismo worker (1), misma plataforma, misma configuración

AlienVault       1.029 msg/min
CIRCL OSINT     12.312 msg/min      ← doce veces más
```

**Doce veces**, con la flota idéntica. Un mensaje no es una unidad de trabajo constante:

| Conector | Mensajes por objeto | Naturaleza del mensaje |
|---|---|---|
| `connector-cve` | ~2 | vulnerabilidad plana, pocas aristas |
| `connector-alienvault` | ~9 | pulse con reports, indicadores y relaciones |
| `connector-misp-feed` | — | observables sueltos, muchos ya existentes |

> **Doctrina.** Las curvas de escalado sólo se comparan **dentro de la misma carga**.
> "2.310 msg/min" no es un número de la plataforma, es un número del par
> (plataforma, conector). Llevarlo a otro conector produce conclusiones falsas con
> aritmética correcta.

---

## 8. ⚠️ Caso de estudio: un backfill que muere a mitad no deja ninguna alarma

Esto no estaba planificado. Ocurrió el **2026-08-05** y se descubrió el **2026-08-07**.

### Lo que pasó

`connector-misp-feed` (CIRCL OSINT Feed) se creó el 5-ago a las 03:06:34, arrancó su primer
backfill, y la plataforma se apagó a mitad. Al volver a levantarla dos días después, la
cola tenía 575.406 mensajes de ese conector y un solo worker.

La pregunta natural fue *"¿por qué de repente ahora y no cuando lo levanté?"*. La respuesta
medida es que **no fue de repente**:

```
contenedor creado    2026-08-05T03:06:34
cursor guardado      last_event: 2026-07-14T19:00:18
ventana configurada  MISP_FEED_IMPORT_FROM_DATE=2025-01-01
```

El cursor había avanzado desde enero-2025 hasta julio-2026. **Recorrió casi dieciocho meses
de CIRCL antes de morir.** Trabajó, y nadie lo vio.

### Por qué nadie lo vio

Tres señales que deberían haber avisado, y por qué ninguna avisó:

| Señal | Por qué falló |
|---|---|
| Logs de error | **No hubo error.** El conector hizo su trabajo hasta que lo pararon |
| La cola de RabbitMQ | Nadie la miró entre las 03:06 del 5-ago y el apagado |
| El checkpoint de la sesión | Escrito el **4-ago a las 12:59** — catorce horas *antes* de que el conector existiera. Decía "cola 0, 5 conectores", y era cierto cuando se escribió |

El conector salió con código 137 (SIGKILL tras agotar el plazo de SIGTERM), que en la lista
de contenedores es indistinguible de cualquier otro conector ocupado.

### Lo que sí lo delató

Contar objetos contra la línea base:

```
                  checkpoint 4-ago      medido 7-ago        delta
observables            24.542              55.295         +30.753
indicadores            24.548              53.880         +29.332
reports                   758               1.240            +482
```

**Treinta mil observables entraron sin que nadie lo supiera.** El único método que lo
detectó fue la contabilidad — el mismo que ya salvó las lecciones 01 §6 y 04 §3.

### El error de medición que cometí encima

Al ver 619.169 mensajes en cola y ~1.029 msg/min de drenaje, afirmé *"unas 10 horas"*. Diez
minutos después:

```
t0     598.149
t+30s  599.370      →  +2.442/min NETO, mientras el worker drenaba
```

**La cola estaba creciendo, no drenando.** El conector publicaba a ~3.500/min contra
~1.029/min de consumo. Mi estimación asumía una cola fija; con un productor activo más
rápido que el consumidor, no hay tiempo de drenaje: hay divergencia.

Lección de método: **antes de dividir una cola entre una tasa, comprueba el signo de la
derivada.** Dos lecturas separadas treinta segundos cuestan nada y distinguen "se vacía en
diez horas" de "no se vacía nunca".

### La regla operativa

> **Un conector que arranca un backfill y se interrumpe deja el sistema en un estado que
> parece limpio.** El cursor queda a medias, la cola muere con el broker o persiste sin que
> nadie la mire, y al siguiente arranque el trabajo parece empezar "de repente".
>
> La única defensa es **anotar el conteo de objetos antes de habilitar un conector**, y
> volver a contarlo después. Es el paso que faltaba en el ciclo de la
> [Lección 1 §0](01-vocabulario-relojes-y-senales.md).

Y el multiplicador estaba en la propia configuración:

```
MISP_FEED_CREATE_REPORTS=true          MISP_FEED_CREATE_OBSERVABLES=true
MISP_FEED_CREATE_INDICATORS=true       MISP_FEED_CREATE_OBJECT_OBSERVABLES=true
MISP_FEED_CREATE_TAGS_AS_LABELS=true
```

Cada atributo de un evento MISP se convierte en observable **y** en indicador **y** en el
objeto-observable **y** en sus etiquetas **y** en las relaciones que los unen. CIRCL no es
un feed roto: es un feed denso con todos los interruptores abiertos.

---

## 9. Un feed no es "grande": es grande en un eje

El accidente de §8 regaló una comparación que de otro modo habría costado una sesión
montar: dos feeds de la capa 2 sobre la misma plataforma, medidos el mismo día.

**Medido el 2026-08-07:**

| | AlienVault OTX | CIRCL OSINT |
|---|---|---|
| Observables aportados | 24.542 | ~30.753 |
| Indicadores | 24.548 | ~29.332 |
| Reports | 758 | ~482 |
| **Intrusion-sets** | **205** | **2** |
| Drenaje (1 worker) | 1.029 msg/min | 12.312 msg/min |

Volumen comparable en IOCs. **Cien veces menos atribución.**

Los intrusion-sets de la plataforma pasaron de 390 a 392 mientras entraban treinta mil
observables: CIRCL aporta indicadores prácticamente sin decir de quién son.

> **Doctrina nueva.** "Feed grande" no significa nada. Hay que preguntar **grande en qué
> eje**: volumen de IOCs, densidad de atribución, cobertura temporal, o riqueza de
> relaciones. Un feed puede ser masivo en uno y estéril en otro, y la decisión de
> habilitarlo depende de cuál necesitas.

Corolario práctico, y **inferido, no medido**: si lo que falta en la plataforma es
atribución, añadir feeds tipo CIRCL no la mejora — sólo aumenta el coste de ingesta y
dificulta la curación de actores. Está sin comprobar porque exigiría medir el grafo con y
sin CIRCL.

Corolario para §6, éste sí medido: **la decisión sobre los 205 intrusion-sets de AlienVault
sigue siendo limpia.** El temor era que CIRCL hubiera contaminado la atribución y hubiera
que desenredar tres fuentes. Aportó 2 actores. La clasificación pendiente sigue siendo un
problema de una sola fuente.

---

## 10. Línea base — apertura de la capa 2

**Medido el 2026-08-07**, antes de apagar la plataforma. Incluye capa 1 completa, AlienVault
curado, y lo que CIRCL y GreyNoise metieron sin supervisión el 5-ago.

```
Stix-Domain-Object       310.638
Stix-Cyber-Observable     59.981
Indicator                 58.565
Report                     1.243
Intrusion-Set                392
Malware                    1.976
Attack-Pattern             1.931
Vulnerability            243.782
relaciones               500.708
cola pendiente           260.493
version                7.260706.0
```

Copia en `.planning/estado-local-20260807.md`.

### Residuos anotados, sin tocar

- **260.493 mensajes en cola.** Persisten en el volumen `rabbitmqdata` y reanudan el
  drenaje al volver a levantar. Decidir entonces si CIRCL entra en la capa 2 o se purgan.
- **`targets` al 100% de centinela** (§5). Bloquea el modo funcional.
- **205 intrusion-sets sin clasificar** (§6).
- **`connector-misp-feed`, `misp-feed-certfr` y `greynoise-feed` parados** el 7-ago, a la
  espera de decidir su configuración.

---

## 11. Tu turno

**a) Cierra la predicción de las CVEs.** La [Lección 4 §9](04-connector-cve-y-cierre-de-la-capa-1.md)
dejó abierta una decisión: las CVEs sin CVSS que el conector descarta *"reaparecerán solas
cuando NVD las analice y `CVE_MAINTAIN_DATA=true` las recoja"*.

Predicción a falsar, escrita **antes** de medir: se recuperarán **algunas, no las 1.058**.
El bucle de mantenimiento consulta por `lastModified`, así que recogerá las que NVD haya
puntuado desde la última ejecución — días de trabajo del NIST, no el atraso histórico. Las
CVEs de 2019-2024 que NVD analizó antes de que arrancáramos tienen `lastModified` viejo y no
volverán solas nunca.

> **Resuelta el 2026-08-07, y la predicción era falsa.** No hizo falta la plataforma: se
> resolvió leyendo el código, que es más barato y más concluyente.
>
> La predicción decía "algunas". La respuesta es **cero**. El razonamiento estaba construido
> sobre el conector **de fábrica**, y nuestro overlay cambia `_update_cve_params` de
> `lastModStartDate` a `pubStartDate`. Las cinco llamadas del fichero pasan por ese helper,
> incluida `_maintain_data`. El bucle de mantenimiento no pregunta por CVEs *modificadas*
> sino por CVEs *publicadas* desde la última corrida, así que una CVE de 2021 puntuada
> mañana no entra en ninguna ventana futura.
>
> Acerté la dirección ("no todas") y fallé el mecanismo y la magnitud. Y el error es de
> categoría **heredada**: predije sobre el comportamiento documentado del conector oficial
> sin comprobar que el nuestro lo había cambiado — teniendo el parche en nuestro propio
> repositorio.
>
> Corregido también en [Lección 4 §9](04-connector-cve-y-cierre-de-la-capa-1.md), que es
> donde alguien leería la afirmación original.

El ejercicio sigue en pie, pero cambia de pregunta. Ya no es *"¿vuelven solas?"* —no— sino
**¿cuántas faltan hoy?**: contar `Vulnerability` tras un tirón histórico completo y
contrastar contra NVD con `noRejected` por ventana, como en §3 de la lección 4. Con eso se
decide entre parchear `_filter_cvss` o aceptar el hueco por escrito.

**b) Clasifica los 205.** Consulta de partida, filtrando por autor para excluir a MITRE:

```bash
docker exec opencti-7-pilot-elasticsearch-1 curl -s -H 'Content-Type: application/json' \
  'localhost:9200/opencti_stix_domain_objects/_search' \
  -d '{"size":50,"query":{"bool":{
       "must":[{"term":{"entity_type.keyword":"Intrusion-Set"}}],
       "must_not":[{"term":{"rel_created-by.internal_id.keyword":"24c95f54-99d1-4f77-a74f-ce9739a3f0b3"}}]}},
       "_source":["name","aliases"]}'
```

Tres cubos: legítimos ausentes de ATT&CK, duplicados de MITRE bajo otro nombre, y ruido.

**c) Verifica el signo antes de dividir.** Sobre cualquier cola, dos lecturas separadas
treinta segundos antes de estimar un tiempo de drenaje. Es el error de §8 y cuesta nada
evitarlo.

---

## Siguiente

La capa 2 queda **abierta, no cerrada**. Faltan los feeds de observables
(`urlhaus`, `malwarebazaar`, `abuseipdb`, `cisa-kev`, `first-epss`), los enriquecedores
(`hygiene`, `google-dns`, `ipinfo`, `virustotal`, `shodan`) y la decisión sobre CIRCL.

Dos avisos heredados de esta sesión para cuando se retomen:

1. **Los enriquecedores consultan una API por cada observable.** Con 59.981 observables en
   la plataforma y claves de plan gratuito en VirusTotal y Shodan, correrlos desatendidos
   agota la cuota en horas.
2. **Aplica el §1 a todos los feeds, no sólo a AlienVault.** La cuenta a confianza 80 se
   creó para OTX, pero el riesgo de pisar los nombres de MITRE es idéntico para
   `urlhaus`, `malwarebazaar` y `misp-feed`. Es el mismo mecanismo sin resolver.
