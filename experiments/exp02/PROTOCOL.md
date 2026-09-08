# Protocolo fijo de EXP-02 CISA/STIX v3

## Objetivo

Medir hasta qué punto el Extractor Documental de TIM reproduce la estructura
CTI contenida en una referencia STIX oficial parcial de CISA cuando procesa el
texto del aviso correspondiente con Claude Haiku 4.5 mediante Amazon Bedrock.

El experimento mide concordancia estructural observable. No estima una verdad
absoluta del PDF, no evalúa exhaustivamente los hechos adicionales de TIM y no
compara TIM con el desempeño de un analista humano.

## Unidades experimentales

La selección congelada contiene exactamente 24 pares PDF/STIX finales obtenidos
de CISA. Tres pares adicionales son reservas y dos fueron rechazados. El orden,
las identidades, los PDF, los STIX, los textos convertidos y las referencias
canónicas se ligan mediante SHA-256.

Cada documento final tiene tres repeticiones independientes bajo la misma
configuración, para un total de 72 llamadas de extracción. Un reintento técnico
se conserva como attempt distinto y nunca sustituye ni borra un intento previo.

## Configuración del modelo

- Proveedor: Amazon Bedrock.
- Modelo: `us.anthropic.claude-haiku-4-5-20251001-v1:0`.
- Región: `us-east-1`.
- Autenticación: rol IAM de la instancia mediante IMDS.
- Prompt: `SYSTEM_PROMPT_V21`, SHA-256
  `8731ecb15b5fecbeccab3b9e155fad95038a9c12e798492359a2d6c3ca0fc2d2`.
- Fuente: `advisory`.
- Límite: 32 000 tokens de salida para las extracciones finales.
- Variables prohibidas: clave Anthropic directa y token OpenCTI no vacío.
- Escrituras OpenCTI: cero.
- Ritmo máximo: ocho inicios en cualquier ventana de 60 segundos.

El prompt y el comportamiento productivo de `extractor.py` permanecen sin
cambios durante el experimento.

## Salida capturada

Cada extracción exitosa conserva:

- texto JSON crudo de Haiku;
- entidades y relaciones v2 crudas;
- estadísticas de citas y uso del modelo;
- salida CTI final validada por TIM;
- entidades y relaciones finales;
- identificadores de documento y repetición;
- huellas de input, referencia, freeze y attempt; y
- tiempo transcurrido, proveedor, modelo, región y `opencti_writes=0`.

JSON inválido, salida incompleta o error Bedrock produce un attempt fallido, no
un conjunto CTI vacío ni una identidad final exitosa.

## Hechos comparables

Una entidad comparable se representa como:

```text
(canonical_type, indicator_subtype, canonical_value)
```

Los tipos primarios son `indicator`, `attack-pattern`, `threat-actor`,
`malware` y `vulnerability`. `intrusion-set` CISA se proyecta a
`threat-actor`. Los tipos de contexto `country`, `sector` y `technology` se
informan fuera del score primario.

Una relación comparable se representa como:

```text
(relationship_type, canonical_source_entity, canonical_target_entity)
```

Solo se consideran `uses`, `targets`, `exploits`, `indicates` y
`attributed-to` cuando ambos extremos son comparables. Las relaciones se
informan separadamente y permanecen exploratorias cuando su soporte oficial es
escaso.

## Matching automático

El matcher acepta, en este orden:

1. valor exacto normalizado;
2. IOC, CVE o ATT&CK ID exacto;
3. alias declarado en el STIX o la salida; y
4. equivalencia controlada congelada.

El matching es determinista y uno-a-uno. Cada match recibe una identidad de
comparación común solo para construir la intersección. Los hechos originales se
preservan.

Dos nombres del mismo tipo sin regla automática permanecen diferentes. Se
cuentan como `unresolved_nominal_pairs`, reducen conservadoramente la similitud
y no requieren adjudicación.

## Métricas

Para cada documento, repetición, tipo y alcance se construyen conjuntos binarios
de hechos canónicos CISA y TIM.

```text
cosine     = |CISA ∩ TIM| / sqrt(|CISA| × |TIM|)
CISA_recall = |CISA ∩ TIM| / |CISA|
Jaccard     = |CISA ∩ TIM| / |CISA ∪ TIM|
```

El coseno equivalence-aware es la métrica principal. Recall CISA y Jaccard son
complementarias. La coincidencia exacta se informa como sensibilidad.

Cuando CISA contiene hechos y TIM queda vacío, las tres métricas valen cero.
Cuando el alcance CISA está vacío, el resultado es `not_evaluable`. Los hechos
solo TIM son `tim_only_unassessed`; participan en los denominadores de coseno y
Jaccard, pero no se llaman falsos positivos.

Primero se calcula la media aritmética de las tres repeticiones de cada
documento. Después se calcula la media aritmética de los 24 documentos. El
intervalo del 95 % usa 10 000 remuestreos de documentos completos con seed
`20260830`.

La estabilidad se informa mediante los tres Jaccard por pares entre
repeticiones. También se informan localización de citas, cambios raw→final,
resultados por tipo y conteos matched/CISA-only/TIM-only-unassessed.

## Ausencia de gates humanos

El protocolo v3 no requiere workbooks, anotadores, revisores, práctica,
adjudicación nominal, revisión de adiciones ni validación manual de relaciones.
Los diagnósticos automáticos pueden conservar muestras de diferencias, pero no
bloquean scoring, verificación ni redacción.

## Integridad y secuencia

El freeze v2 existente se conserva sin cambios como evidencia histórica del
diseño supersedido. No autoriza ninguna llamada nueva.

Antes de Bedrock se crea `freeze.v3.json`, `freeze.v3.sha256` y
`execution-manifest.v3.json`. V3 liga especificación, selección, documentos,
referencias, prompt, modelo, código, reglas, semillas, agregación y ausencia de
gates humanos.

La secuencia obligatoria es:

1. todas las pruebas locales pasan;
2. `finalize` crea v3 una sola vez;
3. `verify --stage pre-run` confirma cero outputs v3;
4. `smoke` realiza una llamada Bedrock de diez tokens;
5. `run-all` completa las 72 identidades;
6. `score` escribe `results.v2.json`; y
7. `verify --stage complete` recompone y compara toda la evidencia offline.

Cambiar un input, referencia, prompt, regla o archivo de código ligado después
del freeze invalida la ejecución y exige una versión de freeze nueva. Ningún
artefacto final se sobrescribe.

## Interpretación permitida

Se puede afirmar el grado observado de similitud estructural, la recuperación
de hechos CISA, diferencias por tipo, estabilidad, localización de citas y
cantidad de información TIM adicional no evaluada.

No se puede afirmar que CISA sea verdad absoluta, que todo hecho solo TIM sea
incorrecto, que coseno sea correlación o precisión factual, ni que TIM iguale o
supere a un analista humano.
