# EXP-02: similitud estructural CISA/STIX

EXP-02 evalúa el Extractor Documental de TIM enviando a Claude Haiku 4.5 por
Amazon Bedrock el texto de avisos CISA y comparando la salida CTI final con el
STIX oficial que acompaña cada aviso.

La referencia CISA es oficial pero parcial. No se considera verdad absoluta ni
una anotación exhaustiva del PDF. Por esa razón, EXP-02 mide **concordancia
estructural**, no exactitud factual ni equivalencia con un analista humano.

## Corpus congelado

Los manifiestos de `cisa-intake/` registran 29 pares historicos
`document.pdf` / `reference.stix.json`:

- 24 documentos finales;
- 3 reservas; y
- 2 rechazados por las reglas de elegibilidad.

Esta exportación conserva las referencias STIX, los manifiestos, las salidas y
las métricas. Los PDF y los `input.txt` completos no se redistribuyen; sus URL
y SHA-256 permanecen en `cisa-evidence/selection-manifest.v1.json`. Cada
documento final se procesó tres veces: 24 × 3 = 72 extracciones.

## Flujo evaluado

1. El runner carga el `input.txt` congelado correspondiente al PDF.
2. `services/intel-extractor/extractor.py` envía el texto a Bedrock con
   `SYSTEM_PROMPT_V21`.
3. Haiku devuelve JSON CTI con entidades, relaciones y `campaign_summary`.
4. TIM valida citas literales, normaliza, deduplica y conserva tanto la salida
   cruda como la salida final.
5. El scorer canonicaliza la referencia CISA y la salida TIM, aplica matching
   automático uno-a-uno y calcula las métricas.

El prompt productivo no se modifica para el experimento. La ruta autorizada es:

- proveedor `bedrock`;
- modelo `us.anthropic.claude-haiku-4-5-20251001-v1:0`;
- región `us-east-1`;
- autenticación IAM/IMDS;
- `ANTHROPIC_API_KEY=`; y
- `OPENCTI_TOKEN=` con `opencti_writes=0`.

## Comparación automática

Los tipos primarios son `indicator`, `attack-pattern`, `threat-actor`,
`malware` y `vulnerability`. `country`, `sector` y `technology` se conservan
como contexto fuera de la métrica principal.

Las coincidencias admitidas son valor exacto normalizado, identificador técnico
exacto, alias declarado y equivalencia controlada congelada. El emparejamiento
es uno-a-uno. Un par nominal no resuelto queda como diferencia conservadora y
se registra en diagnósticos; no se envía a una persona ni bloquea el scoring.

La métrica principal es el coseno estructural binario:

```text
cosine = |CISA ∩ TIM| / sqrt(|CISA| × |TIM|)
```

Se informan además `CISA_recall` y Jaccard. Los hechos solo TIM se etiquetan
`tim_only_unassessed`, nunca falsos positivos. Un alcance sin hechos CISA
comparables es `not_evaluable`.

No se requieren workbooks, anotadores, revisores, adjudicación manual ni
revisión humana de adiciones.

## Secuencia operativa v3

Desde `experiments/exp02`:

```bash
python3 -m pytest -q
PYTHONPATH=src:../../services/intel-extractor \
  LLM_PROVIDER=bedrock AWS_REGION=us-east-1 \
  BEDROCK_MODEL=us.anthropic.claude-haiku-4-5-20251001-v1:0 \
  ANTHROPIC_API_KEY= OPENCTI_TOKEN= \
  python3 -m exp02.cisa_cli finalize --evidence cisa-evidence
PYTHONPATH=src python3 -m exp02.cisa_cli verify \
  --evidence cisa-evidence --stage pre-run
```

`finalize` crea de forma exclusiva:

- `freeze.v3.json`;
- `freeze.v3.sha256`; y
- `execution-manifest.v3.json`.

El freeze v3 liga los 24 pares, referencias, prompt, modelo, especificación,
código, reglas, semillas y ausencia de gates humanos. Los artefactos v2 se
preservan como historia y no autorizan llamadas nuevas.

Después del pre-run se ejecutan, dentro del contenedor aislado del extractor:

```bash
python3 -m exp02.cisa_cli smoke --evidence /exp02/cisa-evidence
python3 -m exp02.cisa_cli run-all --evidence /exp02/cisa-evidence
```

El runner limita los inicios a ocho por minuto, conserva cada attempt y solo
materializa una identidad final cuando la salida está completa. `run-all`
reanuda identidades faltantes sin sobrescribir evidencia.

Finalmente:

```bash
PYTHONPATH=src python3 -m exp02.cisa_cli score --evidence cisa-evidence
PYTHONPATH=src python3 -m exp02.cisa_cli verify \
  --evidence cisa-evidence --stage complete
```

El resultado autoritativo es `cisa-evidence/results.v2.json`. La verificación
`complete` recompone offline las métricas desde las 72 salidas y exige igualdad
canónica con el resultado guardado.

## Artefactos históricos

`ANNOTATION-GUIDE.md`, `PRACTICE-ANSWER-KEY.md`, `practice/` y los módulos de
workbooks pertenecen al diseño anterior. Se preservan para trazabilidad, pero no
son entradas, gates ni evidencia necesaria del protocolo CISA/STIX v3.

El contrato metodológico público se resume en `PROTOCOL.md` y queda ligado por
los manifiestos `freeze.v3.json` y `execution-manifest.v3.json`.
