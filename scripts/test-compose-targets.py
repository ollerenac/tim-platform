#!/usr/bin/env python3
"""Aceptación de los objetivos de despliegue: cada uno debe renderizar con
`docker compose config` y respetar su contrato de hardware y dependencias.

Requiere docker CLI y el .env del repositorio (los mismos requisitos que
cualquier arranque real). No levanta contenedores.
"""

from __future__ import annotations

import importlib.util
import subprocess
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

SCRIPT = Path(__file__).with_name("verify-service-contracts.py")
SPEC = importlib.util.spec_from_file_location("verify_service_contracts", SCRIPT)
contracts = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(contracts)


def _render(target: str) -> dict:
    cmd = contracts.compose_command(target) + ["config", "--format", "json"]
    # --format json esquiva la coerción de tipos de YAML; PyYAML lee JSON también.
    result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        raise AssertionError(
            f"`docker compose config` falló para el objetivo {target}:\n{result.stderr[-2000:]}"
        )
    return yaml.safe_load(result.stdout)


def _gpu_reservations(config: dict) -> list[str]:
    hits = []
    for name, svc in config.get("services", {}).items():
        devices = (
            (svc.get("deploy") or {}).get("resources", {}).get("reservations", {}).get("devices")
        ) or []
        for device in devices:
            if device.get("driver") == "nvidia":
                hits.append(name)
    return hits


class ComposeTargetRenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not (ROOT / ".env").is_file():
            raise unittest.SkipTest(".env ausente: estos tests renderizan la configuración real")
        cls.aws = _render("aws")
        cls.core_only = _render("core-only")

    def test_all_targets_render(self):
        for cfg in (self.aws, self.core_only):
            self.assertIn("services", cfg)

    # El despliegue es un nodo sin GPU: ninguna reserva de dispositivo en ningún servicio.
    def test_no_service_reserves_a_gpu(self):
        self.assertEqual(_gpu_reservations(self.aws), [])

    def test_inventory_per_target(self):
        aws_services = set(self.aws["services"])
        self.assertEqual(len(aws_services), 36)
        for svc in ("soc-dashboard", "opencti", "intel-extractor", "briefing-generator"):
            self.assertIn(svc, aws_services)
        for svc in ("ollama", "semantic-engine", "chromadb"):
            self.assertNotIn(svc, aws_services)
        self.assertEqual(
            set(self.core_only["services"]),
            {"elasticsearch", "kibana", "redis", "rabbitmq", "minio", "opencti", "worker"},
        )

    def test_full_target_resolves_all_dependencies(self):
        services = self.aws["services"]
        for name, svc in services.items():
            for dep, spec in (svc.get("depends_on") or {}).items():
                if isinstance(spec, dict) and spec.get("required") is False:
                    continue
                self.assertIn(
                    dep, services,
                    f"{name} depende de {dep}, ausente en el objetivo renderizado",
                )

    # El proveedor está fijado en el código de cada servicio (Bedrock): Compose ya no
    # lo conmuta ni le pasa configuración de un LLM local o de la API directa.
    def test_generative_services_carry_no_provider_switch(self):
        for service in ("intel-extractor", "briefing-generator"):
            env = self.aws["services"][service]["environment"]
            self.assertIn("BEDROCK_MODEL", env)
            for retired in ("LLM_PROVIDER", "OLLAMA_URL", "OLLAMA_MODEL", "ANTHROPIC_API_KEY"):
                self.assertNotIn(retired, env, f"{service} aún recibe {retired}")

    def test_volume_names_are_preserved(self):
        volumes = self.aws.get("volumes", {})
        for vol in ("esdata", "redisdata", "rabbitmqdata", "miniodata",
                    "briefingsdata", "extractordata"):
            self.assertIn(vol, volumes)
        for retired in ("chromadata", "ollamadata"):
            self.assertNotIn(retired, volumes)


if __name__ == "__main__":
    unittest.main()
