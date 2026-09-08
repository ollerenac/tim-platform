# EXP-02 — Similitud estructural CISA/STIX

<!-- exp02-source-sha256:2ba6c5cba92bbb288d79bad05692712f59f8cb34c55054312ec1f48eb64d056b -->

Este informe se deriva exclusivamente de `cisa-evidence/results.v2.json`. El STIX oficial de CISA es una referencia oficial parcial, no una verdad absoluta ni una anotación exhaustiva de la prosa.

## Protocolo ejecutado

Se procesaron 24 avisos CISA con 3 repeticiones por documento: 72 salidas finales. Claude Haiku 4.5 operó mediante bedrock en `us-east-1`. La ruta experimental registró 0 escrituras en OpenCTI.

El prompt activo es `SYSTEM_PROMPT_V21` de `services/intel-extractor/extractor.py`. Solicita JSON con `entities`, `relationships` y `campaign_summary`; cada objeto estructural incluye valor, tipo, cita literal y página, y cada relación referencia dos entidades.

TIM localiza las citas en el texto y descarta entidades sin cita y relaciones sin cita o sin extremos conservados. La puntuación compara las entidades finales de tipos primarios con el STIX CISA canónico y anclado al PDF.

## Resultado principal

| Métrica macro por documento | Estimación e IC 95 % |
|---|---:|
| Coseno estructural | **0,642 [0,555; 0,720]** |
| Recall de la referencia CISA | 0,571 [0,480; 0,660] |
| Jaccard estructural | 0,487 [0,402; 0,569] |

Los intervalos usan *bootstrap* de 10000 remuestras con el documento como unidad y semilla 20260830. Coseno es la métrica primaria; recall y Jaccard son reanálisis reproducibles de las 24 filas documentales del resultado verificado.

## Resultado por tipo

| Tipo | Documentos evaluables | Coseno [IC 95 %] | Recall CISA [IC 95 %] | Jaccard [IC 95 %] |
|---|---:|---:|---:|---:|
| Indicador | 24 | 0,800 [0,698; 0,889] | 0,805 [0,692; 0,902] | 0,709 [0,589; 0,818] |
| Patrón ATT&CK | 23 | 0,411 [0,304; 0,520] | 0,248 [0,157; 0,350] | 0,245 [0,154; 0,347] |
| Malware | 6 | 0,101 [0,000; 0,267] | 0,069 [0,000; 0,186] | 0,059 [0,000; 0,161] |
| Actor | 2 | 0,000 [0,000; 0,000] | 0,000 [0,000; 0,000] | 0,000 [0,000; 0,000] |
| Vulnerabilidad | 1 | 1,000 [1,000; 1,000] | 1,000 [1,000; 1,000] | 1,000 [1,000; 1,000] |

Los extremos de vulnerabilidad (n=1) y actor (n=2) no permiten generalizar. Los indicadores presentan la mayor evidencia transversal: coseno 0,800 [0,698; 0,889] en 24 documentos.

## Estabilidad, citas y filtro

La mediana documental del Jaccard entre las tres repeticiones fue 0,745 [0,512; 0,877]. Se localizaron 3.952/3.952 citas finales, tasa 1,000 [1,000; 1,000].

El filtro redujo entidades v2.1 7.075 → 3.952, relaciones 1.671 → 149 y entidades comparables 6.110 → 4.262.

En las 72 repeticiones se acumularon `matched=3.421`, `cisa_only=1.751` y `tim_only_unassessed=841`. El último grupo no se interpreta como falso positivo porque CISA no agota el documento.

## Relaciones y alcance

Las relaciones permanecen exploratorias: el corpus aportó 2 documentos y 5 relaciones CISA ancladas, por debajo de la compuerta de 8 documentos y 20 relaciones. Hubo 0 coincidencias candidatas y 81 adiciones TIM sin acuerdo con la referencia parcial.

El experimento demuestra concordancia estructural medible y trazabilidad literal en este corpus. No demuestra verdad factual, equivalencia o superioridad respecto de analistas humanos, utilidad operacional ni persistencia en OpenCTI.

## Integridad

- SHA-256 de `results.v2.json`: `2ba6c5cba92bbb288d79bad05692712f59f8cb34c55054312ec1f48eb64d056b`
- SHA-256 del freeze v3: `3df6770702f52e18a3b9b64d05de4e3b1477734fd77af3e0cce89adb301db4c7`
- Modelo: `us.anthropic.claude-haiku-4-5-20251001-v1:0`
