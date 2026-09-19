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
        cls.local_gpu = _render("local-gpu")
        cls.core_only = _render("core-only")

    # 1-2: cada objetivo renderiza una configuración válida
    def test_all_targets_render(self):
        for cfg in (self.aws, self.local_gpu, self.core_only):
            self.assertIn("services", cfg)

    # 3: AWS sin reserva NVIDIA
    def test_aws_render_has_no_nvidia_reservation(self):
        self.assertEqual(_gpu_reservations(self.aws), [])

    # 4: local-gpu conserva la reserva NVIDIA en ollama
    def test_local_gpu_render_reserves_nvidia_for_ollama(self):
        self.assertEqual(_gpu_reservations(self.local_gpu), ["ollama"])

    # 5: inventario esperado por objetivo
    def test_inventory_per_target(self):
        aws_services = set(self.aws["services"])
        self.assertEqual(len(aws_services), 36)
        for svc in ("soc-dashboard", "opencti", "intel-extractor", "briefing-generator"):
            self.assertIn(svc, aws_services)
        for svc in ("ollama", "semantic-engine", "chromadb"):
            self.assertNotIn(svc, aws_services)
        self.assertEqual(set(self.local_gpu["services"]), aws_services | {"ollama"})
        core = set(self.core_only["services"])
        self.assertEqual(
            core,
            {"elasticsearch", "kibana", "redis", "rabbitmq", "minio", "opencti", "worker"},
        )

    # 10: dependencias completas de dashboard, feeds y briefings
    def test_full_targets_resolve_all_dependencies(self):
        for cfg in (self.aws, self.local_gpu):
            services = cfg["services"]
            for name, svc in services.items():
                for dep, spec in (svc.get("depends_on") or {}).items():
                    if isinstance(spec, dict) and spec.get("required") is False:
                        continue
                    self.assertIn(
                        dep, services,
                        f"{name} depende de {dep}, ausente en el objetivo renderizado",
                    )

    # proveedor generativo por objetivo (defaults del render, sin leer secretos)
    def test_generative_providers_are_fixed_per_target(self):
        for service in ("intel-extractor", "briefing-generator"):
            aws_env = self.aws["services"][service]["environment"]
            local_env = self.local_gpu["services"][service]["environment"]
            self.assertEqual(aws_env.get("LLM_PROVIDER"), "bedrock")
            self.assertEqual(local_env.get("LLM_PROVIDER"), "ollama")
        self.assertIn(
            "ollama",
            self.local_gpu["services"]["intel-extractor"]["depends_on"],
        )

    def test_volume_names_are_preserved(self):
        for cfg in (self.aws, self.local_gpu):
            for vol in ("esdata", "redisdata", "rabbitmqdata", "miniodata",
                        "briefingsdata", "extractordata"):
                self.assertIn(vol, cfg.get("volumes", {}))
            self.assertNotIn("chromadata", cfg.get("volumes", {}))
        # `compose config` poda los volúmenes sin servicio activo: ollamadata
        # solo se renderiza donde corre ollama (perfil inference).
        self.assertIn("ollamadata", self.local_gpu["volumes"])
        self.assertNotIn("ollamadata", self.aws["volumes"])


if __name__ == "__main__":
    unittest.main()
