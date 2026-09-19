# Despliegue por objetivos — perfiles Compose

TIM se despliega en un único entorno: un nodo de AWS sin GPU, con Amazon Bedrock
como único proveedor generativo. La búsqueda semántica y el piloto local con GPU
(`local-gpu`, Ollama) se retiraron el 2026-09-19; la última revisión que los
contiene es la etiqueta git `pre-fase3-evidencia`.

## Vocabulario

- **Servicio**: unidad desplegable declarada en Docker Compose.
- **Contenedor**: instancia en ejecución de un servicio.
- **Módulo**: parte interna del código de un servicio.
- **Capa**: agrupación arquitectónica (§3.x de la tesis).
- **Perfil**: grupo de activación de servicios para un escenario operativo.
  Un perfil **no** es un módulo independiente: `briefings` sin `core` no
  funciona, y Compose no activa perfiles por dependencia.

## Perfiles

| Perfil | Servicios | Razón de la frontera |
|---|---|---|
| `core` | elasticsearch, kibana, redis, rabbitmq, minio, opencti, worker (7) | Plataforma base: sin esto no hay OpenCTI. Kibana queda aquí porque la observabilidad del índice es parte de operar la plataforma y el verificador la exige |
| `connectors` | los 25 `connector-*` | Ingesta de catálogos y fuentes; separables de la plataforma para diagnóstico y para `core-only` |
| `feeds` | feed-orchestrator | Capacidad funcional: orquestación de feeds propios |
| `extractor` | intel-extractor | Capacidad funcional: extracción documental (generativa, Bedrock) |
| `briefings` | briefing-generator | Capacidad funcional: síntesis ejecutiva (generativa, Bedrock) |
| `dashboard` | soc-dashboard | Frontera de presentación; nginx resuelve los upstreams de feeds/briefings/extractor/kibana por petición (resolver de Docker), así que arranca aunque un backend esté caído |

Total: 7+25+1+1+1+1 = **36 servicios**.

## Objetivos

| Objetivo | Fichero | Perfiles | Uso |
|---|---|---|---|
| `aws` | `docker-compose.yml` | los 6 | Despliegue completo |
| `core-only` | `docker-compose.yml` | `core` | Plataforma OpenCTI sin servicios funcionales (diagnóstico) |

No hay overlays. El proveedor generativo no es configuración: `intel-extractor` y
`briefing-generator` llevan Bedrock fijado en el código (`LLM_PROVIDER = "bedrock"`)
y se autentican con el rol IAM de la instancia, sin claves en disco. Solo
`AWS_REGION` y `BEDROCK_MODEL` son ajustables por entorno.

## Comandos

```bash
# renderizar/operar un objetivo (compose-target.sh imprime el comando completo)
$(./scripts/compose-target.sh aws) config --quiet
$(./scripts/compose-target.sh aws) up -d --wait

# arranque ordenado (ATT&CK primero) y verificación funcional
./scripts/bootstrap-platform.sh aws

# gate de readiness (inventario + contratos + UI)
./scripts/tim-check.sh aws
```

El despliegue llega al nodo por `git pull` en `~/tim`; después,
`$(./scripts/compose-target.sh aws) up -d --build --remove-orphans` reconstruye
solo las imágenes cuyo código cambió. `--remove-orphans` no retira un servicio que
siga definido bajo un perfil inactivo: hay que pararlo de forma explícita.

El nombre `bootstrap-platform.sh` se conserva por compatibilidad como nombre
propio de la herramienta; no designa un perfil Compose.

`tim-check.sh` es un gate de **régimen**: exige los umbrales del grafo ATT&CK
(relaciones `uses` incluidas) pero no una cola MITRE vacía, porque cada ciclo
del conector reimporta los mismos objetos y la ocupa durante horas. La cola a
cero y el work `complete` solo los exige el arranque inicial
(`verify-platform.sh`, llamado por `bootstrap-platform.sh`).

`tim-check.sh` y `verify-service-contracts.py` **fallan con uso explícito** si
no se les da objetivo. El verificador distingue en su veredicto: servicios con
healthcheck satisfecho, servicios `running` sin healthcheck (nombrados), y
rechaza detenidos, `unhealthy`, `restarting` y OOMKilled.

## Pruebas

- `scripts/test-verify-service-contracts.py` — unitarias del verificador
  (objetivos, comando compose, veredicto de inventario, resolver de nginx, gate
  MITRE de régimen).
- `scripts/test-compose-targets.py` — aceptación con `docker compose config`:
  render válido por objetivo, ninguna reserva de GPU, inventario esperado,
  dependencias resueltas, servicios generativos sin conmutador de proveedor,
  volúmenes preservados.

```bash
python3 -m pytest scripts/test-verify-service-contracts.py scripts/test-compose-targets.py -q
```

## Histórico: migración del VPS AWS (2026-08-27) y reversión

Sección histórica: describe la organización por overlays `aws`/`local-gpu`, ya retirada.

Estado previo registrado (commit desplegado `b8ddbc4`, proyecto Compose `tim`
en `~/tim`): 37 contenedores Up, `tim-ollama-1` y `tim-semantic-engine-1` en
`Created` desde el despliegue —la reserva NVIDIA de la base impedía arrancar
ollama en un host sin GPU y semantic-engine quedaba bloqueado tras él— y
`tim-soc-dashboard-1` en bucle de reinicio (3.858 reinicios: nginx no resolvía
el upstream `semantic-engine`). Línea base del grafo antes de migrar:
611.444 core-relaciones, 539.382 objetos de dominio, 121.838 observables.

Procedimiento aplicado: respaldo de `docker-compose.yml` y scripts en el VPS,
copia de la base nueva + overrides + scripts, `up -d` del objetivo `aws` sin
recrear servicios sanos (`--no-recreate` implícito al no cambiar sus
definiciones), descarga de `nomic-embed-text`, verificación con
`tim-check.sh aws`. Sin `down`, sin tocar volúmenes, sin recrear los
servicios generativos en ejecución.

**Reversión**: los ficheros previos quedan en `~/tim/backup-preperfiles-<fecha>/`.
Solo después de restaurar esa configuración anterior se ejecutaba `docker compose --profile platform --profile feeds --profile semantic --profile briefings --profile dashboard up -d`; este comando histórico no corresponde al Compose vigente. <!-- historical-topology-command -->
La operación devolvía el estado anterior exacto, con sus dos servicios
`Created` y el dashboard en bucle, que era el estado de partida. Los volúmenes
no se tocan en ninguna dirección.
