# EXP-01 — Protocolo reproducible

## Interfaz experimental

El protocolo utiliza tres límites públicos: la CLI de EXP-01, la API/cola pública de OpenCTI y el paquete de evidencias final. No consulta directamente Elasticsearch para decidir el resultado.

## Invariantes de aceptación

- La línea base de cada condición contiene 0 objetos marcados `TIMEXP-EXP01`.
- La importación normal recupera 9/9 objetos, 10/10 hechos relacionales y 17/17 hechos de procedencia.
- El replay exacto conserva los mismos IDs canónicos y no produce duplicados.
- Con el worker detenido hay 1 mensaje listo, 0 consumidores, trabajo `progress` y grafo experimental vacío.
- Al reiniciar el worker el trabajo llega a `complete`, la cola converge a 0 mensajes listos y el puntaje vuelve a ser perfecto.

## Ejecución automatizada de una réplica

Primero se detiene cualquier instancia experimental que ocupe `127.0.0.1:18080`. Luego:

```bash
python3 experiments/exp01/replicate.py --replica 2
python3 experiments/exp01/replicate.py --replica 3 --leave-running
```

`--dry-run` imprime la secuencia sin modificar Docker. Cada réplica crea dos proyectos Compose nuevos:

- `timexp_exp01_rN_normal`
- `timexp_exp01_rN_interrupted`

Los proyectos se detienen sin eliminar contenedores, redes ni volúmenes. `--leave-running` conserva la última condición interrumpida disponible para inspección.

## Condición normal

1. Crear una plataforma fresca y esperar seis servicios saludables.
2. Exportar la línea base.
3. Enviar el fixture como un único mensaje y esperar `complete`.
4. Exportar por la API pública y puntuar contra el oráculo.
5. Reenviar el mismo fixture, verificar el mismo SHA-256 y repetir exportación/puntuación.
6. Detener la plataforma conservando sus recursos.

## Condición interrumpida

1. Crear otra plataforma fresca y exportar su línea base.
2. Detener únicamente el worker.
3. Encolar el fixture.
4. Registrar trabajo, cola y grafo antes del reinicio.
5. Reiniciar únicamente el worker y esperar el estado `complete`.
6. Conservar una lectura inmediata de la cola y esperar, con un límite de 30 segundos, hasta observar 0 mensajes listos, 0 no reconocidos y al menos 1 consumidor.
7. Exportar y puntuar el grafo.
8. Detener la plataforma o conservarla para inspección.

La espera de cola es por condición y no por un `sleep` fijo. RabbitMQ actualiza las estadísticas de administración con una cadencia propia; por eso el estado `complete` del trabajo y una lectura instantánea de la API de administración pueden diferir durante unos segundos sin que exista un mensaje lógico pendiente.

## Cadena de evidencia

Los snapshots, estados de trabajo, estados de cola y puntajes se guardan en `runs/replica-N/`. `summaries/replica-N.json` contiene el resultado de cada réplica y `AGGREGATE.json` consolida las tres. `MANIFEST.json` se genera al final y fija tamaño y SHA-256 de cada artefacto.
