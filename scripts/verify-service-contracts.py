#!/usr/bin/env python3
"""Read-only functional checks for a TIM Compose deployment target.

Uso: verify-service-contracts.py <aws|core-only>

Cada objetivo declara sus perfiles y sus ficheros Compose. Compose NO activa
perfiles por dependencia: el conjunto completo se habilita explícitamente aquí.
"""

from __future__ import annotations

import base64
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

# Perfiles de un despliegue completo: capacidad funcional separada de la
# plataforma base (core). No hay inferencia local: la generación va a Bedrock.
FULL_PROFILES = (
    "core",
    "connectors",
    "feeds",
    "extractor",
    "briefings",
    "dashboard",
)

TARGETS = {
    "aws": {
        "profiles": FULL_PROFILES,
        "compose_files": ("docker-compose.yml",),
        "functional": True,
    },
    "core-only": {
        "profiles": ("core",),
        "compose_files": ("docker-compose.yml",),
        # Sin feeds/briefings/dashboard no hay contratos funcionales
        # que ejercitar: solo inventario.
        "functional": False,
    },
}


def resolve_target(name: str) -> dict:
    if name not in TARGETS:
        print(f"  FAIL objetivo desconocido: {name!r}; opciones: {', '.join(sorted(TARGETS))}")
        raise SystemExit(1)
    return TARGETS[name]


def parse_target(argv: list[str]) -> str:
    if len(argv) != 1:
        print(
            "uso: verify-service-contracts.py <aws|core-only>\n"
            "  aws       — despliegue completo; la generación va a Amazon Bedrock\n"
            "  core-only — plataforma OpenCTI sin servicios funcionales",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return argv[0]


def compose_command(target: str) -> list[str]:
    spec = resolve_target(target)
    cmd = ["docker", "compose"]
    for f in spec["compose_files"]:
        cmd += ["-f", f]
    for profile in spec["profiles"]:
        cmd += ["--profile", profile]
    return cmd


# Fijado por main() según el objetivo; default seguro para import en tests.
COMPOSE = compose_command("aws")
SSL_CONTEXT = ssl._create_unverified_context()
MAX_DIAGNOSTIC_BODY_BYTES = 2048


def _bounded_body(body: bytes | str, redactions: tuple[str, ...] = ()) -> str:
    if isinstance(body, str):
        raw = body.encode()
    else:
        raw = body
    clipped = raw[:MAX_DIAGNOSTIC_BODY_BYTES]
    text = " ".join(clipped.decode("utf-8", errors="replace").split())
    for secret in redactions:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    if len(raw) > MAX_DIAGNOSTIC_BODY_BYTES:
        text += " [truncated]"
    return text


class ServiceContractError(ValueError):
    """Actionable, credential-free failure at a read-only service contract."""

    def __init__(
        self,
        service: str,
        method: str,
        url: str,
        *,
        status: int | None = None,
        body: str = "",
        failure: str = "",
    ) -> None:
        self.service = service
        self.method = method
        self.url = url
        self.endpoint = urllib.parse.urlsplit(url).path
        self.status = status
        self.body = body
        self.failure = failure

        detail = f"HTTP {status}" if status is not None else failure or "request failed"
        if failure and status is not None:
            detail += f" ({failure})"
        if body:
            detail += f"; body={body}"
        super().__init__(f"{service} {method} {url}: {detail}")


def load_env() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in (ROOT / ".env").read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("'\"")
    return values


def run(*args: str) -> str:
    result = subprocess.run(
        [*args], cwd=ROOT, check=True, text=True, capture_output=True
    )
    return result.stdout


def compose(*args: str) -> str:
    return run(*COMPOSE, *args)


def fail(message: str) -> None:
    print(f"  FAIL {message}")
    raise SystemExit(1)


def passed(message: str) -> None:
    print(f"  PASS {message}")


def request_json(
    url: str,
    auth: str | None = None,
    timeout: int = 90,
    *,
    service: str,
):
    headers = {"Accept": "application/json"}
    if auth:
        headers["Authorization"] = auth
    request = urllib.request.Request(url, headers=headers)
    method = request.get_method()
    redactions = (auth,) if auth else ()

    try:
        with urllib.request.urlopen(request, context=SSL_CONTEXT, timeout=timeout) as response:
            content_type = response.headers.get_content_type()
            body = response.read()
            diagnostic_body = _bounded_body(body, redactions)
            if response.status != 200:
                raise ServiceContractError(
                    service,
                    method,
                    url,
                    status=response.status,
                    body=diagnostic_body,
                )
            if content_type not in ("application/json", "application/taxii+json"):
                raise ServiceContractError(
                    service,
                    method,
                    url,
                    status=response.status,
                    body=diagnostic_body,
                    failure=f"unexpected content type {content_type}",
                )
            try:
                return json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ServiceContractError(
                    service,
                    method,
                    url,
                    status=response.status,
                    body=diagnostic_body,
                    failure=f"invalid JSON: {exc}",
                ) from exc
    except urllib.error.HTTPError as exc:
        raise ServiceContractError(
            service,
            method,
            url,
            status=exc.code,
            body=_bounded_body(exc.read(MAX_DIAGNOSTIC_BODY_BYTES + 1), redactions),
        ) from exc
    except urllib.error.URLError as exc:
        raise ServiceContractError(
            service,
            method,
            url,
            failure=f"transport error: {exc.reason}",
        ) from exc


def verify_unauthorized(url: str, service: str) -> None:
    try:
        urllib.request.urlopen(url, context=SSL_CONTEXT, timeout=10)
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return
        raise ServiceContractError(
            service,
            "GET",
            url,
            status=exc.code,
            body=_bounded_body(exc.read(MAX_DIAGNOSTIC_BODY_BYTES + 1)),
            failure="expected unauthenticated rejection with HTTP 401",
        ) from exc
    except urllib.error.URLError as exc:
        raise ServiceContractError(
            service,
            "GET",
            url,
            failure=f"transport error: {exc.reason}",
        ) from exc
    raise ServiceContractError(
        service,
        "GET",
        url,
        status=200,
        failure="endpoint accepted an unauthenticated request; expected HTTP 401",
    )


class InventoryVerdict:
    """Estado de la flota separando lo que cada evidencia realmente acredita:
    healthcheck satisfecho ≠ running sin sonda. El gate 17-07 encontró el
    mensaje «39 healthy» pasando con 38 sondas y un servicio sin declarar."""

    def __init__(self) -> None:
        self.healthy: list[str] = []
        self.no_healthcheck: list[str] = []
        self.bad: list[str] = []

    def summary(self) -> str:
        total = len(self.healthy) + len(self.no_healthcheck)
        msg = (
            f"{total} servicios en ejecución: {len(self.healthy)} con healthcheck "
            f"satisfecho, {len(self.no_healthcheck)} en ejecución sin healthcheck"
        )
        if self.no_healthcheck:
            msg += f" ({', '.join(self.no_healthcheck)})"
        return msg


def inventory_verdict(expected: set[str], rows: dict, inspections: dict) -> InventoryVerdict:
    verdict = InventoryVerdict()
    for service in sorted(expected):
        row = rows.get(service)
        if row is None:
            verdict.bad.append(f"{service}=missing")
            continue
        state = row.get("State")
        health = row.get("Health")
        if state != "running" or (health and health != "healthy"):
            verdict.bad.append(f"{service}={state}/{health or 'no-healthcheck'}")
            continue
        inspected = inspections.get(service, {})
        if inspected.get("OOMKilled"):
            verdict.bad.append(f"{service}=oom-killed")
            continue
        if inspected.get("Restarting"):
            verdict.bad.append(f"{service}=restarting")
            continue
        (verdict.healthy if health else verdict.no_healthcheck).append(service)
    return verdict


def verify_compose() -> None:
    expected = set(compose("config", "--services").split())
    rows = {
        row["Service"]: row
        for row in (json.loads(line) for line in compose("ps", "-a", "--format", "json").splitlines() if line)
    }
    inspections = {}
    for service in expected & set(rows):
        container_id = compose("ps", "-q", service).strip()
        if container_id:
            inspections[service] = json.loads(run("docker", "inspect", container_id))[0]["State"]

    verdict = inventory_verdict(expected, rows, inspections)
    if verdict.bad:
        fail("unready services: " + ", ".join(verdict.bad))
    passed(verdict.summary())


def verify_contracts(env: dict[str, str]) -> None:
    required = ("KIBANA_USER", "KIBANA_PASSWORD")
    missing = [key for key in required if not env.get(key)]
    if missing:
        fail("missing .env values: " + ", ".join(missing))

    token = base64.b64encode(
        f"{env['KIBANA_USER']}:{env['KIBANA_PASSWORD']}".encode()
    ).decode()
    auth = f"Basic {token}"

    verify_unauthorized("https://localhost/", "SOC Dashboard")
    verify_unauthorized("http://localhost:5602/", "Kibana")
    passed("SOC Dashboard and Kibana reject unauthenticated access")

    feeds = request_json(
        "https://localhost/api/feeds/feeds/status", auth, service="feed-orchestrator"
    )["feeds"]
    names = {item.get("name") for item in feeds}
    # 12 desde 2026-07-25: "otx" retirado 07-22 (P0.1); "digitalside" retirado 07-25
    # (host caído desde 07-07, nunca ingirió).
    if len(feeds) != 12 or len(names) != 12:
        fail(f"feed contract expected 12 unique sources, got {len(feeds)}/{len(names)}")
    invalid = sorted({item.get("status") for item in feeds} - {"ok", "running", "error", "never_run"})
    if invalid:
        fail(f"feed contract has invalid statuses: {invalid}")

    connectors = request_json(
        "https://localhost/api/feeds/connectors/status", auth, service="feed-orchestrator"
    )["connectors"]
    if not any(item.get("name") == "MITRE ATT&CK" and item.get("active") for item in connectors):
        fail("MITRE ATT&CK is absent or inactive in connector status")

    recent = request_json(
        "https://localhost/api/feeds/feeds/recent?limit=1",
        auth,
        service="feed-orchestrator",
    )
    if not isinstance(recent.get("iocs"), list):
        fail("recent IOC contract is malformed")

    briefing = request_json(
        "https://localhost/api/briefings/stats",
        auth,
        timeout=120,
        service="briefing-generator",
    )
    if not isinstance(briefing.get("ioc_count_24h"), int) or not isinstance(
        briefing.get("top_techniques"), list
    ):
        fail("briefing/OpenCTI integration contract is malformed")

    extractor = request_json(
        "https://localhost/api/extractor/stats", auth, service="intel-extractor"
    )
    collector = request_json(
        "https://localhost/api/extractor/collector/status",
        auth,
        service="intel-extractor",
    )
    if not isinstance(extractor, dict) or not isinstance(collector.get("sources"), list):
        fail("extractor/collector integration contract is malformed")

    kibana = request_json(
        "http://localhost:5602/api/status",
        auth,
        timeout=60,
        service="Kibana",
    )
    level = ((kibana.get("status") or {}).get("overall") or {}).get("level")
    if level != "available":
        fail(f"Kibana reports overall level {level!r}")

    errors = sorted(item["name"] for item in feeds if item.get("status") == "error")
    passed("cross-service data contracts work")
    if errors:
        print(f"  WARN external feed errors do not invalidate service readiness: {', '.join(errors)}")
    passed("Kibana API status is available")


def main(argv: list[str] | None = None) -> None:
    global COMPOSE
    target = parse_target(sys.argv[1:] if argv is None else argv)
    spec = resolve_target(target)
    COMPOSE = compose_command(target)

    print(f"[tim-check] Service inventory (target: {target})")
    try:
        env = load_env()
        verify_compose()
        if spec["functional"]:
            print("[tim-check] Functional contracts")
            verify_contracts(env)
        else:
            print(f"  SKIP functional contracts: el objetivo {target} no los declara")
    except (KeyError, OSError, ValueError, subprocess.CalledProcessError, urllib.error.URLError) as exc:
        fail(str(exc))


if __name__ == "__main__":
    main()
