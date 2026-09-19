# Despliegue por objetivos — perfiles Compose y matriz AWS/local

Vigente desde 2026-08-27. Sustituye la organización anterior de perfiles
(`platform`/`feeds`/`semantic`/`briefings`/`dashboard`), en la que `platform`
mezclaba plataforma base, servicios funcionales y la reserva GPU de Ollama.

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
| `core` | elasticsearch, kibana, redis, rabbitmq, minio, opencti, worker (7) | Plataforma base: sin esto no hay OpenCTI. Kibana queda aquí porque la observabilidad del índice es parte de operar la plataforma y el verificador la exige en todos los objetivos completos |
| `connectors` | los 25 `connector-*` | Ingesta de catálogos y fuentes; separables de la plataforma para diagnóstico y para `core-only` |
| `feeds` | feed-orchestrator | Capacidad funcional: orquestación de feeds propios |
| `extractor` | intel-extractor | Capacidad funcional: extracción documental (generativa; proveedor conmutable) |
| `briefings` | briefing-generator | Capacidad funcional: síntesis ejecutiva (generativa; proveedor conmutable) |
| `dashboard` | soc-dashboard | Frontera de presentación; nginx resuelve los upstreams de feeds/briefings/extractor/kibana por petición (resolver de Docker), así que arranca aunque un backend esté caído |
| `inference` | ollama | Backend de generación local; solo lo activa `local-gpu`. **La reserva GPU no está aquí**: es un atributo de hardware del objetivo, no del servicio, y vive en `docker-compose.local-gpu.yml` |

Total: 7+25+1+1+1+1 = **36 servicios** en `aws`; `local-gpu` añade `ollama`
(37). La búsqueda semántica (`semantic-engine`, `chromadb`, perfil `semantic`)
se retiró el 2026-09-19; sus volúmenes en despliegues previos se eliminan a
mano tras validar.

## Matriz de objetivos

| Objetivo | Ficheros | Perfiles | Extractor | Sintetizador | Ollama | Modelos exigidos |
|---|---|---|---|---|---|---|
| `aws` | base + `docker-compose.aws.yml` | los 6 | Bedrock (fijado) | Bedrock (fijado) | no se despliega | — |
| `local-gpu` | base + `docker-compose.local-gpu.yml` | los 6 + `inference` | Ollama (fijado) | Ollama (fijado) | GPU, generación | `llama3.2:3b` |
| `core-only` | base | `core` | — | — | — | — |

Los proveedores de `aws` están **fijados en el override**, no heredados de
variables: el objetivo define la semántica y cambiarla exige editar un fichero
versionado.

En `local-gpu`, tanto el extractor como el sintetizador usan
`llama3.2:3b` para generación.

## Comandos

```bash
# renderizar/operar un objetivo (compose-target.sh imprime el comando completo)
$(./scripts/compose-target.sh aws) config --quiet
$(./scripts/compose-target.sh aws) up -d --wait
$(./scripts/compose-target.sh local-gpu) up -d --wait

# arranque ordenado (ATT&CK primero) y verificación funcional
./scripts/bootstrap-platform.sh local-gpu

# gate de readiness (inventario + contratos + UI)
./scripts/tim-check.sh aws

# solo modelos (únicamente local-gpu)
./scripts/init-models.sh local-gpu
```

El nombre `bootstrap-platform.sh` se conserva por compatibilidad como nombre
propio de la herramienta; no designa un perfil Compose.

`tim-check.sh` es un gate de **régimen**: exige los umbrales del grafo ATT&CK
(relaciones `uses` incluidas) pero no una cola MITRE vacía, porque cada ciclo
del conector reimporta los mismos objetos y la ocupa durante horas. La cola a
cero y el work `complete` solo los exige el arranque inicial
(`verify-platform.sh`, llamado por `bootstrap-platform.sh`).

`tim-check.sh` y `verify-service-contracts.py` **fallan con uso explícito** si
no se les da objetivo. El verificador ahora distingue en su veredicto:
servicios con healthcheck satisfecho, servicios `running` sin healthcheck
(nombrados), y rechaza detenidos, `unhealthy`, `restarting` y OOMKilled.

## Pruebas

- `scripts/test-verify-service-contracts.py` — unitarias del verificador
  (objetivos, comando compose, veredicto de inventario, modelos por objetivo).
- `scripts/test-compose-targets.py` — aceptación con `docker compose config`:
  render válido por objetivo, sin NVIDIA ni ollama en aws, NVIDIA solo en
  ollama en local-gpu, inventario esperado, dependencias resueltas,
  proveedores por objetivo, volúmenes preservados.

```bash
python3 -m pytest scripts/test-verify-service-contracts.py scripts/test-compose-targets.py -q
```

## Migración del VPS AWS (2026-08-27) y reversión

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
