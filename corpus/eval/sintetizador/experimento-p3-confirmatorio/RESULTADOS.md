# EXP PE-5 — Experimento confirmatorio del sintetizador con prompt fijo P3

**Fecha de ejecución:** 2026-09-02
**Identificador de análisis:** `PE-5-confirmatory-fixed-P3-remeasurement`
**Estado:** cerrado; salidas congeladas y reanálisis 2.0 versionado.

## Pregunta

PE-5: ¿el sintetizador conserva los conteos del bloque de datos y permite
auditar los identificadores que emite? El prompt de producción P3 se congela
(no es una comparación de prompts) y se pregunta si el comportamiento observado
en la evaluación exploratoria previa se repite con entradas no usadas para
elegirlo.

## Diseño

- Unidad experimental: bloque horario, capturado una vez; las tres repeticiones
  reciben exactamente el mismo texto.
- **Estrato confirmatorio:** 21 bloques productivos nuevos (horas completas
  2026-07-01 → 2026-09-02, excluidas las 48 usadas en la selección de P3).
- **Estrato de replicación:** 27 bloques del corpus anterior, elegidos por regla
  SHA-256 con semilla `pe5-confirmatory-fixed-p3-v1`. No se mezcla con el
  estrato nuevo en la conclusión principal.
- Motor: Claude Haiku 4.5 (`us.anthropic.claude-haiku-4-5-20251001-v1:0`) vía
  Amazon Bedrock, ejecutado desde el VPS de AWS. Cero escrituras en OpenCTI.
- 48 bloques × 3 repeticiones = 144 llamadas iniciales; 12 reintentos del
  verificador de anclaje → **156 llamadas reales**; 288 mediciones
  (borrador + informe final por corrida); 0 fallos.

## Resultados principales (estrato confirmatorio, informe final)

| Métrica | Valor |
|---|---:|
| Identificadores anclados / emitidos | **340/340** (tasa 1,0000) en 61/63 salidas evaluables |
| Salidas sin denominador (`N/A` 0/0) | 2/63 |
| Total y nuevos correctos, casos discriminantes válidos | **24/24** (8 bloques) |
| Total y nuevos correctos, criterio estricto | 54/63 (13 de 21 bloques eran casos límite) |
| Cita de ≥3 valores anclados, casos evaluables | 49/51 |
| Jaccard mediano entre repeticiones | 0,625 |
| Prosa sin marcado | 2/63 |

Replicación (final): anclaje 359/363 (0,9890); el control redujo residuos de 17
a 4 ocurrencias (`wel1.ru` y una URL repetida en las tres corridas de un
bloque), todos con advertencia visible; discriminantes 15/15 en 5 bloques
válidos; Jaccard mediano 0,6667.

Diseño de conteos agrupado: 13 bloques discriminantes válidos, 31 en el límite,
4 con partición imposible (nuevos > total; calidad de entrada histórica, no
evidencia del modelo).

## Reanálisis 2.0

El evaluador original dependía de dígitos y no derivaba el total desde una
partición completa; Haiku escribió cifras en palabras («four»). La versión
2.0.0 de `eval_sintesis.py` reconoce esas expresiones y volvió a medir los
textos congelados. Los textos originales no fueron editados
(`raw_outputs_modified: false`).

## Límites

- El anclaje es léxico (IPv4, dominios, URL, CVE, ATT&CK) y no acredita verdad
  semántica; hashes, nombres propios y relaciones quedan fuera del detector.
- El resultado discriminante se apoya en 8 bloques confirmatorios.
- P3 no ordena repetir total y nuevos: los cocientes miden fidelidad observada,
  no obediencia a una cláusula del prompt.
- Sin lectores humanos: no se afirma legibilidad. Un solo motor.
- Los 27 bloques de replicación no son evidencia reservada.

## Integridad y procedencia

- `analysis.v2.json` SHA-256:
  `9a17da9c08190848585a0da75209086d2837cbc62f6d4d7c8cd9b28b5fc53e10`
  (registrado en el freeze del Capítulo 5, revisión 2026-09-02).
- Evaluador 2.0.0 (`services/briefing-generator/eval_sintesis.py`):
  `599c7e8fe48668f1a64959b16fdb50d208299c62cce3df861706c86fcef652cc`.
- Prompt P3: `cb009b2122c61993c91d6c18bb60adf9a6b0ff3b957c136f58ed7ab4724316d3`.
- Resultados crudos: `run/results.jsonl` + `run/contexts/` (48 contextos
  congelados); manifiesto en `SHA256SUMS`; ejecución en `full-run.log`.
- Selección de estratos: `plan.json`; totales de ejecución en
  `verification.json`.

## Uso aguas abajo

- Tesis: §5.6 (Tabla 5.16, Figuras 5.7 y 5.8) y veredicto PE-5
  «parcialmente validada».
- Figuras `c5-05-sintetizador-anclaje` y `c5-06-sintetizador-exigencias`
  derivan de `analysis.v2.json`.
- Mejoras derivadas (§5.6.4): detector de hashes, coherencia nuevos ⊆ total en
  el bloque de datos, control determinista de formato, adjudicación humana
  futura.
