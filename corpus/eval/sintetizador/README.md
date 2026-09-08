# Artefactos heredados de evaluacion del sintetizador

`runs-haiku-raw.jsonl` y `runs-haiku-system.jsonl` contienen diez salidas por
modo obtenidas con un contexto congelado. Los nombres historicos `raw` y
`system` se interpretan como **generacion directa** y **pipeline con control de
anclaje**, respectivamente.

Las veinte salidas tienen cero identificadores detectables (IPv4, dominio, URL,
CVE o T-ID). La implementacion anterior convertia ese denominador vacio en una
tasa de anclaje de 1,0. Ese valor queda invalidado: al reanalizar los textos, la
tasa correcta es `N/A` (0 identificadores anclados de 0 evaluables). Por tanto,
estos archivos no demuestran ausencia de fabricaciones ni anclaje perfecto.

El campo historico `totales_citados` comprobaba solo que ambos numeros
aparecieran en cualquier lugar del texto. Debe sustituirse por la asociacion
numero--etiqueta que implementa `../../../services/briefing-generator/eval_sintesis.py`:
acierto del total de indicadores, acierto de indicadores nuevos y acierto
conjunto, siempre informados como `x_m/K_m`: aciertos sobre corridas
evaluables para la métrica `m`.

Los textos originales se conservan para reanalisis reproducible. No deben
editarse ni emplearse como si hubieran sido generados otra vez con el evaluador
corregido. Una nueva comparacion entre modos debera guardar el mismo borrador
antes y despues del control para estimar su efecto de forma pareada.

## Reanalisis del PoC tabular

El verificador inicial del commit `08584bd` informo 21/23 en la primera corrida
y 23/23 en la segunda. Esos cocientes son evidencia historica, no resultados
intercambiables con la metrica actual: aceptaban subcadenas, aplicaban reglas de
dominio distintas y comprobaban los conteos con otra regla.

Con coincidencia exacta por tipo, host de URL reconocido como dominio o IPv4 y
una lista congelada de sufijos, los artefactos conservados dan los resultados
siguientes. Los nombres de archivo terminados en un TLD registrado, como
`loader.py`, permanecen como candidatos léxicamente ambiguos:

Los dos reportes tabulares se reanalizan exclusivamente contra
`contexto-72h.json` (SHA-256
`687437fb2bb61f769f2959dfa58a5953985c078952b1bbf26db10be3a47f4300`).
Ese JSON es el contexto estructurado que originó `reporte-72h-corrida1.md` y
`reporte-72h.md`. El archivo `ctx-72h.txt` pertenece únicamente a las dos
series de prosa de 10+10 salidas descritas más adelante.

| Artefacto | Anclados/evaluables | Tasa | Residuos lexicos |
|---|---:|---:|---|
| `reporte-72h-corrida1.md` | 21/23 | 0.9130 | URL raiz `agenticsora.com/`; URL `aone-cli...` |
| `reporte-72h.md` | 22/22 | 1.0000 | ninguno |

Como control de procedencia, el contexto correcto reproduce **21/23** y
**22/22**. Si se aplica erróneamente `ctx-72h.txt` a esos reportes tabulares,
los resultados caen a **3/23** y **3/22**. Esta divergencia confirma que los
dos contextos no son intercambiables y no autoriza una nueva corrida del
proveedor.

La adjudicacion contra el contexto distingue los dos residuos de la primera
corrida: `aone-cli...` altera el identificador fuente y es la fabricacion
observada; la URL raiz `agenticsora.com/` resume un origen presente solo mediante
URLs con ruta, por lo que no es coincidencia literal pero tampoco prueba por si
sola una falsedad. Los totales 187/0 se evalúan aparte y no forman parte de esos
denominadores.

## Reanalisis con el evaluador corregido (2026-08-22)

Se aplicaron `measure()` y `summarize()` al campo `texto` de cada registro, con
`ctx-72h.txt` como contexto congelado:

| Resultado | Generacion directa | Pipeline con control |
|---|---:|---:|
| Corridas evaluables para anclaje | 0/10 | 0/10 |
| Identificadores anclados/evaluables | 0/0 | 0/0 |
| Tasa de anclaje lexico | N/A | N/A |
| Tocadas/nuevas/conjunto correctos | 10/10 · 10/10 · 10/10 | 10/10 · 10/10 · 10/10 |
| Cobertura nominal (media ± DE muestral) | 0.7100 ± 0.2355 | 0.5800 ± 0.3011 |
| Reintentos | — | 0 |

El reanalisis no invoca al LLM ni altera los JSONL; recalcula solamente las
medidas sobre las salidas almacenadas.

## Tanda pareada con identificadores expuestos (2026-08-26)

La tanda de agosto midió un control que no podía activarse: `_build_stats_block`
agregaba los indicadores por tipo y cantidad y nunca enviaba sus valores al
modelo, de modo que el verificador de anclaje operaba sobre un conjunto vacío.
Corregido el prompt —diez valores literales de los indicadores de mayor
confianza, con su tipo, y la instrucción de citar al menos tres tal cual—, el
contexto vivo pasó de tres identificadores comprobables a trece.

Los artefactos son `ctx-pareado-20260826.txt` (el bloque congelado tal como lo
recibe el modelo), `runs-haiku-pareado-borrador.jsonl` y
`runs-haiku-pareado-verificado.jsonl`. Cada par comparte el número de corrida:
el borrador es la salida directa del modelo y el verificado es el resultado de
aplicar el control **a ese mismo borrador**, no a una segunda generación. Esa
es la diferencia con las series de agosto, cuyas dos poblaciones independientes
no permitían atribuir ninguna diferencia al verificador.

| Resultado | Borrador | Tras el control |
|---|---:|---:|
| Corridas evaluables para anclaje | 10/10 | 10/10 |
| Identificadores anclados/evaluables | 68/68 | 68/68 |
| Tasa de anclaje léxico | 1.0000 | 1.0000 |
| Tocadas/nuevas/conjunto correctos | 10/10 · 10/10 · 10/10 | 10/10 · 10/10 · 10/10 |
| Cobertura nominal (media ± DE muestral) | 0.8550 ± 0.2565 | 0.8550 ± 0.2565 |
| Nombres exactos/alterados/ausentes | 171 / 0 / 29 | 171 / 0 / 29 |
| Prosa sin markdown | 0/10 | 0/10 |
| Reintentos | — | 0 |
| Borradores alterados por el control | — | 0/10 |

Las dos columnas coinciden porque ningún borrador llevaba identificadores sin
respaldo: el control se ejerció sobre los 68, no halló residuos y no reintentó.
Los cero reintentos son aquí un resultado, no la identidad que eran en agosto.
La capacidad correctiva del verificador sigue sin ponerse a prueba, porque
requeriría borradores con residuos.

### Corrección del evaluador

La asociación número–etiqueta se comprobaba con una lista cerrada de plantillas
y no admitía separador de millares. Las diez salidas informan «1,071 indicators
of compromise, comprising 807 newly created» y todas se puntuaban como error en
el total. La comprobación se rehízo sobre la cláusula que rodea a cada cifra;
la adjudicación manual de las diez confirma el resultado corregido, y la tanda
de agosto conserva exactamente sus valores previos —esa invariancia se verifica
en `test_eval_sintesis.py` y en el generador de la Figura 5.6—.
