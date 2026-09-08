# Evidencia — migración del despliegue AWS a objetivos de perfiles

**Fecha:** 2026-08-27T07:16–07:38Z · **Host:** VPS AWS `<HOST_INTERNO>` (sin GPU, 31 GiB RAM) ·
**Proyecto Compose:** `tim` en `~/tim` · **Commits aplicados:** `bc04677` + `9a62ab6` + `ebf030b`
(compose + overrides + scripts; **imágenes de servicio no reconstruidas**).
Sin valores secretos en este documento: credenciales generadas en el VPS y almacenadas
solo en su `.env` (chmod 600) y `.kibana.htpasswd` (hash apr1).

## Estado ANTES (2026-08-27T07:16Z)

| Ítem | Valor |
|---|---|
| Commit desplegado | `b8ddbc4` (2026-08-07) + parches manuales de servicio |
| Contenedores | 37 Up; `tim-ollama-1` y `tim-semantic-engine-1` en **Created** (nunca arrancados: la reserva NVIDIA de la base no resolvía en un host sin GPU) |
| soc-dashboard | **restarting**, 3.858 reinicios — nginx: `host not found in upstream "semantic-engine"` |
| `.kibana.htpasswd` | **directorio vacío** root-owned (artefacto de bind-mount a ruta inexistente) |
| `certs/` | solo README — sin TLS |
| `.env` | sin `KIBANA_USER`/`KIBANA_PASSWORD` |
| Grafo (línea base) | core-relaciones **611.444** · dominio **539.382** · observables **121.838** |
| Volúmenes | tim_{esdata,esbackups,redisdata,rabbitmqdata,miniodata,ollamadata,chromadata,briefingsdata,extractordata} |

Conclusión del estado previo: búsqueda semántica y dashboard **nunca operativos** en AWS.

## Procedimiento aplicado

1. Respaldo en `~/tim/backup-preperfiles-20260827/` (compose, 8 scripts, `ps -a`, config renderizada).
2. Retirado el directorio-artefacto `.kibana.htpasswd`; generado hash apr1 + credencial en `.env` (no impresa).
3. Certificados autofirmados `certs/localhost{,-key}.pem` (el 443 solo liga a 127.0.0.1; acceso por túnel SSH).
4. Copiados base + `docker-compose.aws.yml` + `docker-compose.local-gpu.yml` + scripts.
5. `up -d --dry-run`: plan verificado — **1 solo Recreate (ollama)**, 36 servicios intactos.
6. Fases: ollama CPU → `init-models.sh aws` (nomic-embed-text, 274 MB) → `up -d --wait` → recreación forzada solo de soc-dashboard (su contenedor viejo arrastraba el montaje directorio-vs-fichero).
7. Hallazgo medido: con el grafo AWS, `indicator.list` de 100 dispara `DATABASE_ERROR «Find direct ids fail»` (OpenCTI 7, ~454 ids directos/lote); 50 itera estable (8 páginas por la ruta de producción). Fijado `OPENCTI_PAGE_SIZE=50` en el override aws (`ebf030b`).
8. htpasswd a 644: el worker nginx (uid 101) no leía el 600 de uid 1000.

Sin `down`, sin `down -v`, sin tocar volúmenes, redes, secretos existentes ni recursos AWS.

## Estado DESPUÉS (2026-08-27T07:37Z)

| Comprobación | Resultado |
|---|---|
| Inventario | **PASS** — 39 en ejecución: 38 con healthcheck satisfecho, 1 sin healthcheck (`connector-opencti`, nombrado) |
| Contratos entre servicios | **PASS** — feeds (12), MITRE activo, semantic ready+index+search, briefing stats, extractor stats, Kibana available |
| `tim-check.sh aws` | **READY** — verify-uis.mjs **SKIPPED explícito** (sin node en el VPS); UI verificada por contratos HTTP + curl autenticado |
| MITRE | `mitre_work=complete (28242/28242)`, colas a 0 |
| Dashboard | `https://localhost/` → 200 autenticado, `<title>SOC Dashboard</title>`; 401 sin credencial; reinicios=0 |
| Kibana | `/api/status` → 200 autenticado; 401 sin credencial |
| Búsqueda semántica | no vacía (`q=ransomware` → resultados con score y enlace a OpenCTI); índice **en carga**: 632 indexados y subiendo (embeddings CPU) |
| Proveedores efectivos | extractor `bedrock`/haiku · briefing `bedrock` · semantic `OPENCTI_PAGE_SIZE=50`, `nomic-embed-text` |
| Grafo (sin regresión) | core **611.444** (=) · dominio **539.401** (+19, ingesta viva) · observables **121.838** (=) |
| Volúmenes | los 9 presentes; `tim_esdata`+`tim_esbackups` adjuntos a elasticsearch |
| Servicios NO recreados | opencti (2026-08-10), elasticsearch (08-10), worker (08-10), intel-extractor (08-19), briefing-generator (08-26, `generator.py` md5 `e0d5207e…` intacto) |
| Recreados | ollama, semantic-engine, soc-dashboard — los tres `running healthy`, reinicios=0 |
| Llamadas pagadas a modelos | **ninguna** (solo embeddings Ollama locales y descarga del modelo) |

## Reversión

`~/tim/backup-preperfiles-20260827/` conserva compose y scripts previos. Restaurarlos y
`docker compose --profile platform --profile feeds --profile semantic --profile briefings
--profile dashboard up -d` devuelve el estado anterior (incluidos sus dos `Created` y el
dashboard en bucle, que era el punto de partida). Los volúmenes no se tocan en ninguna
dirección. Los arreglos de host (htpasswd, certs, credencial en `.env`) son aditivos y
compatibles con la definición vieja.

## Verificación viva del objetivo local-gpu (añadida 2026-08-27, misma fecha)

Con autorización del usuario se levantó el piloto local completo por el flujo canónico
`bootstrap-platform.sh local-gpu` y se detuvo al terminar. Resultado: **READY (local-gpu)**
— 39 servicios (38 healthcheck satisfecho + `connector-opencti` sin sonda, nombrado),
contratos HTTP completos, ambos modelos Ollama presentes con reserva NVIDIA activa
(RTX 3050), MITRE `complete (28242/28242)`, y los dos flujos Chromium de UI en PASS
(SOC Dashboard con cinco vistas y búsqueda semántica; Kibana autenticado). Volumen
`opencti-7-pilot_esdata-recovery-20260715` verificado antes de arrancar e intacto después.

Tres hallazgos de la corrida, ninguno regresión de los perfiles:

1. **Work MITRE huérfano** del apagón del 08-25 (`progress 0/0` eterno) bloqueaba la
   puerta de `verify-platform`; remedio canónico `retry-mitre-import.sh --force`
   (ciclo nuevo completo, 28.242/28.242, sin borrar datos).
2. **Bug real del refactor, cazado y corregido** (`79e10fd`): `retry-mitre-import.sh`
   invocaba `--profile connectors` solo, que ya no resuelve `opencti` (perfil `core`).
   Barrido posterior: ninguna otra invocación mono-perfil con dependencias cruzadas.
3. **Estado Kibana perdido por el volumen de recuperación**: `esdata-recovery-20260715`
   restauró `opencti_*` pero no los data views de `.kibana` (0 data views), así que
   Kibana mostraba la pantalla de primer arranque y el flujo Chromium fallaba de forma
   reproducible. Reaprovisionado el data view operativo `opencti_history*` vía API;
   el flujo pasó. Condición preexistente del volumen, no de los perfiles.

## Límites de esta evidencia
- El backfill semántico en AWS seguía en curso al cierre (632 indexados); la operatividad
  verificada es servicio+índice+búsqueda, no cobertura completa del inventario.
- verify-uis.mjs (chequeo JS de la UI) no corrió en el VPS por ausencia de node — salto
  explícito y declarado; equivalente HTTP cubierto.
- Este documento es evidencia técnica de despliegue; **no** modifica la narrativa de PE-1
  del Capítulo 5 ni incorpora resultados nuevos a la tesis.
