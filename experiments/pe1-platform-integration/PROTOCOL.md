# Protocolo PE-1 — arranque e integración de la plataforma

## Pregunta

¿La configuración `local-gpu` puede reactivar los 39 servicios desde sus
contenedores detenidos, alcanzar el estado operativo esperado y completar un
recorrido verificable desde un PDF conocido hasta un reporte en OpenCTI?

## Hipótesis

En tres repeticiones, la plataforma alcanzará 39/39 servicios en ejecución: 38
con su sonda satisfecha y `connector-opencti` en ejecución sin sonda declarada.
No habrá servicios reiniciándose ni estados `OOMKilled`.

En cada repetición, el mismo PDF terminará con un trabajo `complete`. El
`report_id` devuelto por el extractor identificará un reporte recuperable en
OpenCTI con indicadores y relaciones.

## Unidad y condiciones

La unidad experimental es un ciclo compuesto por una reactivación de la
plataforma y una importación documental. Se ejecutarán tres ciclos numerados.

El objetivo es `local-gpu`. El proveedor será Ollama y el modelo generativo será
`llama3.2:3b`. La entrada será
`corpus/aa26-204a/CSA_RUSSIA_PHISHING_TARGET_ZIMBRA.pdf`, cuya huella SHA-256
esperada es `97805a057e1217acdf8a1c21f3852994c550b2b9fe094af270bd1bb6e24e8c76`.

Los contenedores y volúmenes existentes se conservan. Cada ciclo empieza con los
contenedores detenidos y termina con `docker compose stop`. No se permite
`down`, `down -v`, eliminación de volúmenes ni sustitución del volumen de
Elasticsearch recuperado.

## Procedimiento

1. Confirmar que existen exactamente 39 servicios declarados y que el PDF
   coincide con la huella congelada.
2. Ejecutar `scripts/bootstrap-platform.sh local-gpu` y medir el tiempo hasta que
   termine su verificación funcional.
3. Capturar el inventario mediante `docker compose ps` y el estado de cada
   contenedor mediante `docker inspect`.
4. Ejecutar `scripts/capture-pe1-local-evidence.py` con el PDF congelado.
5. Verificar la identidad del trabajo y del reporte mediante la API de OpenCTI.
6. Conservar resultados y registros de la repetición y detener los contenedores.

## Criterios de aceptación

La condición de arranque aprueba si el *bootstrap* termina con código cero, los
39 servicios están en ejecución, 38 sondas están satisfechas, el único servicio
sin sonda es `connector-opencti` y ningún contenedor está reiniciándose ni fue
marcado `OOMKilled`.

La condición de integración aprueba si la captura conserva la huella del PDF,
el proveedor y el modelo declarados, el trabajo termina como `complete`, el
`report_id` coincide con el reporte recuperado y este contiene al menos un
indicador y una relación `indicates`.

El experimento aprueba únicamente si las dos condiciones aprueban en las tres
repeticiones. Las fallas se conservan y no se sustituyen silenciosamente.

## Resultados que no autoriza

El protocolo no demuestra instalación desde un equipo vacío, creación de
volúmenes nuevos, disponibilidad continua, SLA, tolerancia a fallos, capacidad
máxima ni calidad semántica de los objetos extraídos.

Las verificaciones generales de `tim-check.sh` recorren contratos de varios
servicios. La entrada documental trazada solo recorre extractor y OpenCTI; no se
afirma que ese mismo documento atraviese el índice semántico o el sintetizador.

## Artefactos

Cada repetición conserva `bootstrap.log`, `inventory.json`,
`integration.json`, `capture.log`, `stop.log` y `summary.json`. El cierre genera
`ENVIRONMENT.json`, `RESULTS.json`, `RESULTS.md` y `MANIFEST.json`.
