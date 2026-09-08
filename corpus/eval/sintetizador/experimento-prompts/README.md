# Experimento de prompts del sintetizador

Mide qué tiene que contener el prompt para que el verificador de anclaje pueda
llegar a ejercerse, separando dos cambios que hasta ahora iban juntos: exponer
los valores de los indicadores y pedir explícitamente que se citen.

## Las tres condiciones de prompt

| Condición | Línea de valores en el bloque de datos | Cláusula de citar en el prompt de sistema |
|---|---|---|
| **Prompt 1 — solo recuentos** | no | no |
| **Prompt 2 — con valores** | sí | no |
| **Prompt 3 — con valores y petición de citarlos** | sí | sí |

La línea de valores es la que produce `_build_stats_block` cuando
`IOC_VALUES_IN_PROMPT > 0`:

```
Highest-confidence indicator values, verbatim: www.racon.online (Hostname),
77.73.135.34 (IPv4-Addr), …
```

La cláusula que distingue el prompt 3 del 2 es este fragmento literal de
`SYSTEM_PROMPT`, que hay que quitar entero para producir el prompt 2:

> When the data lists indicator values verbatim, cite at least three of them
> exactly as written, character for character, so the reader can act on them;
> never alter, abbreviate, defang or invent an indicator value.

## Los bloques

Cada **bloque** es una hora natural en la que la plataforma registró actividad de
fuentes curadas. Los tres prompts ven el mismo bloque, de modo que el contenido
se cancela dentro de él: la diferencia entre prompt 1 y prompt 2 en una misma
hora es atribuible solo al prompt.

Medido contra la plataforma el 2026-08-26 sobre 21 días (504 horas), por el
camino de producción con la lista de fuentes curadas: **48 horas con al menos un
indicador**, 31 con diez o más. Los feeds curados no gotean, descargan en
ráfagas. Ventanas fijas más largas no sirven para variar el material: por encima
de 24 h la muestra se toma de los 50 indicadores más recientemente actualizados
y deja de cambiar.

Los bloques se definen por `updated_at`, que es lo que hace producción, así que
incluyen horas de pura re-actualización sin altas nuevas.

### Lo que el preflight midió sobre los 48 bloques

| | |
|---|---|
| Anclables con el prompt 1 | **3 en los 48** — las tres técnicas ATT&CK; línea base constante |
| Anclables con el prompt 2 | de 3 a 23, mediana 10 — el experimento trae dentro una curva de dosis |
| Entidades vigiladas | **20 en los 48**, así que la cobertura nominal es comparable |
| Bloques sin tratamiento | **3**: `2026-08-09 08`, `2026-08-08 19`, `2026-08-08 11`. Sus indicadores son todos hashes de fichero, y el control de anclaje no cubre esa clase. Se conservan marcados, no se excluyen |
| Bloques degenerados para conteos | **30 de 48**: el total coincide con los nuevos o con los preexistentes, así que la métrica no distingue una etiqueta de otra |

## Condiciones de ejecución

Verificado el 2026-08-26: el código del contenedor es idéntico al del
repositorio, de modo que lo medido es lo versionado.

| Fichero | md5 en `tim-briefing-generator-1` y en el repositorio |
|---|---|
| `services/briefing-generator/generator.py` | `2fc7470f246643efd1f1618f45a05da6` |
| `services/briefing-generator/anchor.py` | `2577325921e6e831feb23c03eb711c09` |
| `services/briefing-generator/eval_sintesis.py` | `d5f4497183838debb6478b00a5571dcd` |

Repetir la comprobación si se reconstruye la imagen:

```bash
ssh -i ~/.ssh/tim-opencti.pem ubuntu@98.89.215.208 \
  'docker exec tim-briefing-generator-1 md5sum /app/generator.py /app/anchor.py /app/eval_sintesis.py'
```

El contenedor **no tiene `/out`**. Los ficheros de trabajo van a `/tmp` y se
sacan con `docker cp`.

## Ficheros

Duplicar `plantilla-resultados.csv` una vez por ventana:

- `resultados-12h.csv`
- `resultados-24h.csv`
- `resultados-72h.csv`

Cada uno recibe las tres condiciones de prompt: 3 × 20 corridas × 2 etapas =
**120 filas**, más la cabecera.

## Diccionario de columnas

### Identificación

| Columna | Valores | Notas |
|---|---|---|
| `prompt` | `1`, `2`, `3` | La variable independiente |
| `bloque` | `2026-08-25 17` | La hora natural medida |
| `etapa` | `borrador`, `verificado` | Dos filas por bloque y prompt |
| `total_periodo` | entero | Indicadores tocados en esa hora |
| `nuevos_periodo` | entero | De ésos, los creados en esa hora |

La terna `prompt` + `bloque` + `etapa` identifica cada fila sin ambigüedad.

`borrador` es lo que escribió el modelo; `verificado`, lo que quedó tras pasar
el control **sobre ese mismo texto**. El efecto del control es la diferencia
dentro del par, nunca entre grupos.

### Procedencia

| Columna | Notas |
|---|---|
| `prompt_sha256` | Hash del texto exacto del prompt de sistema usado |
| `contexto_sha256` | Hash del bloque de datos congelado |
| `motor` | Identificador del modelo, p. ej. `us.anthropic.claude-haiku-4-5-20251001-v1:0` |
| `anclables_en_contexto` | Identificadores distintos presentes en el bloque: el techo de la condición |

`contexto_sha256` difiere entre el prompt 1 y los prompts 2/3 dentro de la misma
ventana. No es un error: el prompt 1 se define por no llevar la línea de
valores. `anclables_en_contexto` vale 3 con el prompt 1, y 4 (12 h) o 13
(24 h y 72 h) con los prompts 2 y 3.

### Anclaje

| Columna | Definición |
|---|---|
| `identificadores_emitidos` | Identificadores distintos que menciona el texto, \|I(y)\| |
| `identificadores_anclados` | De ésos, los que están en el bloque, \|I(y) ∩ I(C)\| |
| `tasa_anclaje` | anclados / emitidos, ecuación de §2.9 |
| `no_anclados` | Lista literal de los que no aparecen, separados por `;` |

**Si `identificadores_emitidos` es 0, `tasa_anclaje` va vacía.** No es 0 ni es 1:
es una división por cero. El modelo no acertó ni falló, no dijo nada
comprobable. La implementación anterior escribía 1,0 en ese caso, y por eso
veinte corridas figuraban como «anclaje perfecto» sin haber citado nada.

`no_anclados` no es opcional. Un identificador sin anclar puede ser una
invención o una variante legítima —una URL raíz derivada de otra con ruta—, y
eso lo decide una persona leyendo.

### Nombres

| Columna | Definición |
|---|---|
| `entidades_contexto` | Nombres que podría mencionar: **20** en las nueve condiciones (10 actores + 10 familias) |
| `nombres_exactos` | Emitidos carácter por carácter |
| `nombres_alterados` | Emitidos con una variante próxima: `Darkhosel` por `Darkhotel` |
| `nombres_ausentes` | No mencionados |
| `cobertura_nominal` | exactos / entidades_contexto |

Las tres clases suman siempre `entidades_contexto`. Si no suman, la medición
está rota. La separación importa: un nombre ausente deja el informe incompleto;
uno alterado mete en él una entidad que la base no contiene.

### Conteos

| Columna | Definición |
|---|---|
| `conteo_total_correcto` | ¿Dice el total del período junto a lo que cuenta? |
| `conteo_nuevos_correcto` | ¿Dice cuántos son nuevos junto a lo que cuenta? |
| `conteos_conjunto_correcto` | Las dos a la vez |

No basta con que el número aparezca: tiene que estar pegado a su etiqueta. En la
ventana de 72 h el total tiene cuatro cifras y el modelo escribe `1,071` con
separador de millares; una comprobación que busque `1071` literal produce veinte
falsos negativos.

### Resto

| Columna | Definición |
|---|---|
| `cumplimiento_instruccion` | ¿Libre de encabezados, negritas, viñetas y listas numeradas? El prompt lo exige |
| `palabras` | Longitud de la salida |
| `reintento` | ¿Disparó el control una segunda llamada? Solo tiene sentido en `etapa = verificado` |
| `texto` | La salida completa, literal, entrecomillada |

`texto` es obligatorio: sin él no se puede volver a medir cuando el evaluador
cambie, y va a cambiar. Puede contener saltos de línea mientras el campo vaya
entre comillas dobles.

## Reglas de agregación

1. **Nunca promediar `tasa_anclaje` entre corridas.** Una corrida con 1/1 y otra
   con 0/8 no dan «50 % de media»: dan 1 de 9. Sumar numeradores y denominadores.
2. **Nunca convertir `x/20` en porcentaje pelado.** Con K=20, un 20/20 tiene
   intervalo de confianza aproximado [0,83; 1]; no es «100 %».
3. **Las 120 filas de un fichero son 60 pares, no 120 observaciones
   independientes.** Cuando el control no reintenta, las dos etapas de un par
   son el mismo texto.

## Objetos sin anclar

El control de anclaje es un control **léxico**: comprueba que cada identificador
del informe aparezca literalmente en el bloque que el modelo recibió. No dictamina
veracidad, así que un identificador sin anclar **no se etiqueta aquí como
fabricación**: se reporta como objeto sin anclar y se deja a revisión humana, que
es para lo que el control existe.

Lo que sí es objetivo, porque lo decide el propio pipeline, es qué pasó después:
si el reintento dejó el informe limpio o si el objeto persistió y el informe se
publicó con la nota visible.

| Prompt | Bloque | Etapa | Objeto sin anclar | Frase del informe |
|---|---|---|---|---|
| 2 | `2026-08-08 20` | borrador | `dominio:backblazeb2.com` | Notable indicators in the sample include domains associated with cloud storage infrastructure (backblazeb2.com subdom… |
| 2 | `2026-08-09 15` | borrador | `dominio:gu.cc` | gu.cc`, `. |
| 2 | `2026-08-10 08` | borrador | `dominio:wel1.ru` | The indicators consist primarily of hostnames associated with the domain wel1.ru, including four subdomains prefixed … |
| 2 | `2026-08-24 09` | borrador | `ipv4:104.253.0.0` | com, including a mail server endpoint, three file hashes, and 18 IPv4 addresses distributed across the 104.253.0.0/16… |
| 2 | `2026-08-24 09` | verificado | `ipv4:104.253.0.0` | com, including a mail server endpoint, three executable file hashes, and eighteen IP addresses spanning the 104.253.0… |
| 2 | `2026-08-24 12` | borrador | `dominio:megadancer.top` | fun, and megadancer.top. |
| 3 | `2026-08-08 16` | borrador | `dominio:sedaliareality.net` | net, sedaliareality.net, idrci. |
| 3 | `2026-08-08 21` | borrador | `url:https://apple-online.shop/MSTeamsSetup.exe` | exe and https://apple-online.shop/MSTeamsSetup.exe. |
| 3 | `2026-08-08 21` | borrador | `url:https://apple-online.shop/MicrosoftEdgeSetup.exe` | The malicious URLs distribute files mimicking legitimate Microsoft software: https://apple-online.shop/MicrosoftEdgeS… |
| 3 | `2026-08-08 21` | verificado | `url:https://apple-online.shop/MSTeamsSetup.exe` | exe and https://apple-online.shop/MSTeamsSetup.exe, both spoofing legitimate Microsoft products to facilitate social … |
| 3 | `2026-08-08 21` | verificado | `url:https://apple-online.shop/MicrosoftEdgeSetup.exe` | The highest-confidence indicators identified include two URLs hosting executable installers at https://apple-online.s… |
| 3 | `2026-08-24 09` | borrador | `ipv4:104.253.0.0` | com and associated mail server, along with 18 IPv4 addresses primarily within the 104.253.0.0/16 range. |
| 3 | `2026-08-24 12` | borrador | `url:http://megadancer.top/home/eng10` | fun/home/voteCZ03, and http://megadancer.top/home/eng10. |
| 3 | `2026-08-24 12` | verificado | `url:http://megadancer.top/home/eng10` | fun/home/voteCZ03, and http://megadancer.top/home/eng10. |

De los **9 bloques en que el control saltó**, en **6** el segundo
borrador quedó sin objetos sin anclar y en **3** persistieron y el informe salió
marcado para revisión. Las etapas `borrador` y `verificado` de un mismo bloque
permiten ver el antes y el después de cada caso.

Cuatro formas recurrentes, descritas sin adjudicarlas:

- **Prefijo de red presentado como dirección.** `104.253.0.0` dentro de «18 IPv4
  addresses spanning the 104.253.0.0/16 range». El informe describe un rango; el
  detector ve una IPv4 que no está en el bloque.
- **Dominio raíz derivado de sus subdominios.** `wel1.ru`, `backblazeb2.com`. Los
  subdominios sí están en el bloque; el dominio padre no aparece literalmente.
- **URL con ruta distinta de la del bloque.** El anfitrión está en los datos, la
  ruta concreta no. Son los tres casos que persistieron tras el reintento.
- **Fragmento truncado.** `gu.cc` aparece cortado en medio de una enumeración.
