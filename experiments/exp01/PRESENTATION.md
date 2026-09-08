# EXP-01 — Guion de presentación para capítulo 5 y sustentación

## Afirmación central

En tres ejecuciones aisladas, la implementación importó íntegramente el grafo STIX ensayado, no creó duplicados ante un replay exacto y procesó correctamente un mensaje que había quedado pendiente mientras el worker estaba detenido.

## Orden recomendado en el capítulo 5

1. **Pregunta.** ¿La implementación conserva el significado del grafo y recupera trabajo pendiente, o sólo reporta que el proceso terminó?
2. **Diseño.** Mostrar el fixture conocido, el oráculo independiente y las tres condiciones: normal, replay e interrupción.
3. **Manipulación experimental.** Explicar que cada réplica usa plataformas y volúmenes limpios; en la interrupción sólo se apaga el worker.
4. **Resultados.** Presentar primero `3/3 réplicas PASS` y `9/9 condiciones puntuadas PASS`; después mostrar la tabla de tiempos como información descriptiva secundaria.
5. **Evidencia del mecanismo.** Mostrar la transición `cola 1 / consumidor 0 / grafo vacío` a `cola 0 / consumidor 1 / grafo completo`.
6. **Conclusión y límites.** Afirmar preservación, idempotencia y recuperación para el caso ensayado; reservar confiabilidad estadística, volumen y utilidad analítica para experimentos posteriores.

## Material principal

- **Figura 5.x — Resumen de EXP-01.** Flujo experimental, condiciones y resultado agregado de las tres réplicas. Archivo: `figures/exp01-summary.svg`.
- **Figura 5.y — Evidencia visual en OpenCTI.** Reporte reconstruido después de reiniciar el worker en la réplica 3. Archivo: `figures/opencti-exp01-report.png`.
- **Tabla 5.x — Resultados por réplica.** Usar la primera tabla de `RESULTS.md`.
- **Tabla 5.y — Transición durante la interrupción.** Usar la segunda tabla de `RESULTS.md`.

## Relato breve para la sustentación

“No confiamos en que OpenCTI dijera simplemente ‘complete’. Construimos un grafo cuyo contenido conocíamos y después lo exportamos para compararlo contra un oráculo. Lo hicimos tres veces. En cada ejecución importamos normalmente, reenviamos exactamente lo mismo para buscar duplicados y apagamos el worker antes de enviar el mensaje. Con el worker apagado vimos el mensaje pendiente y el grafo vacío; al encenderlo, el mensaje se consumió y apareció el grafo completo. Las nueve evaluaciones recuperaron todos los objetos, relaciones y hechos de procedencia, sin duplicados. Por tanto, para este caso controlado demostramos preservación semántica, idempotencia y recuperación de cola; todavía no afirmamos confiabilidad productiva ni rendimiento a escala.”

## Respuesta si preguntan por la anomalía de la réplica 3

La primera lectura administrativa de RabbitMQ se tomó antes de su siguiente ciclo de actualización de métricas. Se conservó esa muestra, se comprobó la configuración de 5 segundos y se cambió el arnés para esperar la condición observable de cola drenada con un límite de 30 segundos. El grafo y el trabajo ya habían aprobado; la corrección elimina una carrera del instrumento de medición, no oculta un fallo de importación.

## Frontera de las conclusiones

Se puede afirmar: “EXP-01 demuestra repetidamente el mecanismo bajo las condiciones ensayadas”. No se debe afirmar todavía: “el sistema nunca pierde información”, “tolera cualquier caída”, “escala a producción” o “mejora el trabajo del analista”.
