# PE-1 Platform Startup and Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ejecutar y documentar tres ciclos controlados de reactivación de la plataforma y de integración PDF→extractor→OpenCTI para sustentar PE-1.

**Architecture:** Un ejecutor Python coordina los scripts canónicos existentes, captura inventario sin secretos, conserva cada repetición y agrega un veredicto. Las funciones puras validan inventario, resultados y manifiesto; las operaciones Docker permanecen en una frontera inyectable y siempre terminan con `compose stop`.

**Tech Stack:** Python 3.10, `pytest`, Docker Compose, scripts operativos existentes y JSON con SHA-256.

**Spec:** `experiments/pe1-platform-integration/PROTOCOL.md`

## Global Constraints

- Objetivo único: `local-gpu`.
- Tres repeticiones completas y no sobrescribibles.
- PDF y huella exactos definidos en el protocolo.
- Nunca ejecutar `docker compose down`, `down -v` ni borrar volúmenes.
- El volumen recuperado de Elasticsearch se conserva.
- Los registros no contienen secretos ni valores de IOC.
- Una repetición fallida se conserva y hace fallar el resultado agregado.

---

### Task 1: Contratos puros del ejecutor

**Files:**
- Create: `experiments/pe1-platform-integration/run_pe1.py`
- Create: `experiments/pe1-platform-integration/tests/test_run_pe1.py`

**Interfaces:**
- Consumes: salida JSON por línea de `docker compose ps` y estados de `docker inspect`.
- Produces: `parse_compose_ps(raw)`, `assess_inventory(expected, rows, states)`, `aggregate_summaries(summaries)` y `build_manifest(root, output)`.

- [ ] **Step 1: Write the failing tests**

Crear pruebas que exijan 39 servicios, distingan 38 sondas de un servicio sin
sonda, rechacen `OOMKilled`, rechacen una repetición fallida y comprueben las
huellas de todos los artefactos del manifiesto.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest experiments/pe1-platform-integration/tests/test_run_pe1.py -q`

Expected: FAIL porque `run_pe1.py` todavía no existe.

- [ ] **Step 3: Write the minimal implementation**

Implementar las cuatro funciones con validación cerrada: entradas ausentes,
duplicadas o mal formadas producen `ExperimentError`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest experiments/pe1-platform-integration/tests/test_run_pe1.py -q`

Expected: PASS.

### Task 2: Ciclo seguro y captura de evidencia

**Files:**
- Modify: `experiments/pe1-platform-integration/run_pe1.py`
- Modify: `experiments/pe1-platform-integration/tests/test_run_pe1.py`

**Interfaces:**
- Consumes: `scripts/bootstrap-platform.sh`, `scripts/compose-target.sh` y `scripts/capture-pe1-local-evidence.py`.
- Produces: `run_cycle(number, config, command_runner)` y un `summary.json` por repetición.

- [ ] **Step 1: Write the failing tests**

Usar un ejecutor de comandos controlado que reproduzca respuestas completas de
Compose. Comprobar el resultado observable: archivos creados, veredicto y
detención final, incluida la ruta de error.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest experiments/pe1-platform-integration/tests/test_run_pe1.py -q`

Expected: FAIL porque `run_cycle` no existe.

- [ ] **Step 3: Write the minimal implementation**

Ejecutar *bootstrap*, capturar inventario, invocar la captura existente, validar
su JSON y detener los contenedores en `finally`. Escribir cada archivo mediante
reemplazo atómico y rechazar directorios de repetición ya poblados.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest experiments/pe1-platform-integration/tests/test_run_pe1.py -q`

Expected: PASS.

### Task 3: CLI, cierre y ejecución real

**Files:**
- Modify: `experiments/pe1-platform-integration/run_pe1.py`
- Modify: `experiments/pe1-platform-integration/tests/test_run_pe1.py`
- Generate: `experiments/pe1-platform-integration/runs/rep-{1,2,3}/*`
- Generate: `experiments/pe1-platform-integration/ENVIRONMENT.json`
- Generate: `experiments/pe1-platform-integration/RESULTS.json`
- Generate: `experiments/pe1-platform-integration/RESULTS.md`
- Generate: `experiments/pe1-platform-integration/MANIFEST.json`

**Interfaces:**
- Consumes: `--target local-gpu`, `--pdf`, `--repetitions 3` y `--output-root`.
- Produces: código cero solo si las seis condiciones aprueban y el manifiesto verifica todos los artefactos.

- [ ] **Step 1: Write the failing CLI tests**

Comprobar que se rechazan otra huella, otro número de repeticiones, un destino
con resultados previos y cualquier objetivo distinto de `local-gpu`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest experiments/pe1-platform-integration/tests/test_run_pe1.py -q`

Expected: FAIL por ausencia de la CLI completa.

- [ ] **Step 3: Implement and run the experiment**

Run: `python3 experiments/pe1-platform-integration/run_pe1.py --target local-gpu --pdf corpus/aa26-204a/CSA_RUSSIA_PHISHING_TARGET_ZIMBRA.pdf --repetitions 3 --output-root experiments/pe1-platform-integration`

Expected: tres resúmenes conservados, `RESULTS.json` con veredicto agregado y la plataforma detenida al final.

- [ ] **Step 4: Verify artifacts offline**

Run: `python3 experiments/pe1-platform-integration/run_pe1.py --verify --output-root experiments/pe1-platform-integration`

Expected: `MANIFEST OK` y código cero.

### Task 4: Reestructuración académica de §5.2

La reestructuración consumió `PROTOCOL.md`, `RESULTS.json`, `ENVIRONMENT.json` y
`MANIFEST.json`, y produjo una respuesta a PE-1 limitada a los resultados
observados. Los archivos de trabajo y validadores académicos internos no forman
parte de esta exportación pública; la tesis resultante está disponible como
`tesis/tesis.pdf` en la raíz del repositorio.
