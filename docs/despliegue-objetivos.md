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
  Un perfil **no** es un módulo independiente: `semantic` sin `core` e
  `inference` no funciona, y Compose no activa perfiles por dependencia.

## Perfiles

| Perfil | Servicios | Razón de la frontera |
|---|---|---|
| `core` | elasticsearch, kibana, redis, rabbitmq, minio, opencti, worker (7) | Plataforma base: sin esto no hay OpenCTI. Kibana queda aquí porque la observabilidad del índice es parte de operar la plataforma y el verificador la exige en todos los objetivos completos |
| `connectors` | los 25 `connector-*` | Ingesta de catálogos y fuentes; separables de la plataforma para diagnóstico y para `core-only` |
| `feeds` | feed-orchestrator | Capacidad funcional: orquestación de feeds propios |
| `extractor` | intel-extractor | Capacidad funcional: extracción documental (generativa; proveedor conmutable) |
| `semantic` | chromadb, semantic-engine | Capacidad funcional: búsqueda semántica. ChromaDB solo sirve a este carril |
| `briefings` | briefing-generator | Capacidad funcional: síntesis ejecutiva (generativa; proveedor conmutable) |
| `dashboard` | soc-dashboard | Frontera de presentación; nginx exige resolver los upstreams de feeds/semantic/briefings/extractor/kibana |
| `inference` | ollama | Backend de inferencia local compartido (embeddings siempre; generación solo en local-gpu). **La reserva GPU no está aquí**: es un atributo de hardware del objetivo, no del servicio, y vive en `docker-compose.local-gpu.yml` |

Total: 7+25+1+1+2+1+1+1 = **39 servicios**, los mismos de antes; nombres de
servicios y volúmenes intactos.

### Por qué Ollama no tiene un perfil «gpu-local»

El mismo servicio sirve a los dos objetivos: en AWS embebe en CPU
(`nomic-embed-text`, ~0,3 GB) y en el piloto embebe y genera con GPU. Separar
dos servicios habría duplicado el volumen `ollamadata` (los modelos
descargados) y cambiado el nombre del contenedor que semantic-engine resuelve.
La diferencia real es de hardware, y Compose tiene un mecanismo exacto para
eso: un override que añade `deploy.resources.reservations` solo donde existe
el dispositivo.

## Matriz de objetivos

| Objetivo | Ficheros | Perfiles | Extractor | Sintetizador | Ollama | Modelos exigidos |
|---|---|---|---|---|---|---|
| `aws` | base + `docker-compose.aws.yml` | los 8 | Bedrock (fijado) | Bedrock (fijado) | CPU, solo embeddings | `nomic-embed-text` |
| `local-gpu` | base + `docker-compose.local-gpu.yml` | los 8 | Ollama (fijado) | Ollama (fijado) | GPU, embeddings + generación | `nomic-embed-text`, `llama3.2:3b` |
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

# solo modelos
./scripts/init-models.sh aws
```

El nombre `bootstrap-platform.sh` se conserva por compatibilidad como nombre
propio de la herramienta; no designa un perfil Compose.

`tim-check.sh` y `verify-service-contracts.py` **fallan con uso explícito** si
no se les da objetivo. El verificador ahora distingue en su veredicto:
servicios con healthcheck satisfecho, servicios `running` sin healthcheck
(nombrados), y rechaza detenidos, `unhealthy`, `restarting` y OOMKilled.

## Pruebas

- `scripts/test-verify-service-contracts.py` — unitarias del verificador
  (objetivos, comando compose, veredicto de inventario, modelos por objetivo).
- `scripts/test-compose-targets.py` — aceptación con `docker compose config`:
  render válido por objetivo, sin NVIDIA en aws, NVIDIA solo en ollama en
  local-gpu, inventario esperado, dependencias resueltas, proveedores por
  objetivo, volúmenes preservados.

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
