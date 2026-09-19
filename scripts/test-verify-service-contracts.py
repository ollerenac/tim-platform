#!/usr/bin/env python3
"""Offline regressions for TIM HTTP contract diagnostics and deployment targets."""

from __future__ import annotations

import importlib.util
import io
import json
import re
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("verify-service-contracts.py")
SPEC = importlib.util.spec_from_file_location("verify_service_contracts", SCRIPT)
contracts = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(contracts)


class FakeHeaders:
    def __init__(self, content_type: str = "application/json") -> None:
        self.content_type = content_type

    def get_content_type(self) -> str:
        return self.content_type


class FakeResponse:
    def __init__(self, payload, status: int = 200, content_type: str = "application/json") -> None:
        self.status = status
        self.headers = FakeHeaders(content_type)
        self._body = io.BytesIO(json.dumps(payload).encode())

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        return False

    def read(self, amount: int = -1) -> bytes:
        return self._body.read(amount)


def http_error(
    status: int,
    body: bytes = b"Internal Server Error",
    url: str = "https://localhost/api/feeds/feeds/status",
) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url,
        status,
        "simulated failure",
        FakeHeaders("text/plain"),
        io.BytesIO(body),
    )


class ServiceContractTests(unittest.TestCase):
    url = "https://localhost/api/feeds/feeds/status"
    auth = "Basic do-not-print-this-secret"

    def test_http_500_diagnostic_names_service_endpoint_status_and_body(self):
        with patch.object(contracts.urllib.request, "urlopen", side_effect=http_error(500)):
            with self.assertRaises(contracts.ServiceContractError) as caught:
                contracts.request_json(self.url, self.auth, service="feed-orchestrator")

        message = str(caught.exception)
        self.assertIn("feed-orchestrator", message)
        self.assertIn("/api/feeds/feeds/status", message)
        self.assertIn("500", message)
        self.assertIn("Internal Server Error", message)
        self.assertNotIn(self.auth, message)
        self.assertNotIn("do-not-print-this-secret", message)

    def test_nginx_resolves_every_upstream_at_request_time(self):
        """A literal host in proxy_pass is resolved once at startup: nginx then
        refuses to start with a backend down and keeps a stale IP after it
        restarts (VPS 2026-09-19). Every proxy must go through a variable."""
        nginx = (Path(__file__).resolve().parents[1] / "services/dashboard/nginx.conf").read_text()
        self.assertIn("resolver 127.0.0.11", nginx)
        self.assertNotIn("/api/semantic/", nginx)
        targets = re.findall(r"^\s*proxy_pass\s+(\S+);", nginx, re.M)
        self.assertEqual(len(targets), 4)
        for target in targets:
            self.assertTrue(target.startswith("$"), f"proxy_pass {target} is resolved at startup")


    def test_mitre_queue_is_fatal_only_at_bootstrap(self):
        """The readiness gate runs against a platform that ingests continuously:
        a MITRE re-import leaves its queue busy for hours. Only the bootstrap
        poller may require an empty queue and a complete work."""
        scripts = Path(__file__).resolve().parent
        self.assertIn(
            'check_mitre_relationships.sh" --steady-state',
            (scripts / "tim-check.sh").read_text(),
        )
        self.assertNotIn("--steady-state", (scripts / "verify-platform.sh").read_text())
        checker = (scripts / "check_mitre_relationships.sh").read_text()
        self.assertIn('failed+=("${pending[@]}")', checker)


class TargetSelectionTests(unittest.TestCase):
    """Objetivos de despliegue: aws (sin GPU, Bedrock), local-gpu (Ollama+NVIDIA), core-only."""

    def test_target_registry_declares_three_targets(self):
        self.assertEqual(set(contracts.TARGETS), {"aws", "local-gpu", "core-only"})

    def test_aws_target_covers_full_stack_without_inference(self):
        aws = contracts.TARGETS["aws"]["profiles"]
        for profile in ("core", "connectors", "feeds", "extractor", "briefings", "dashboard"):
            self.assertIn(profile, aws)
        self.assertNotIn("inference", aws)
        self.assertNotIn("semantic", aws)
        self.assertIn("inference", contracts.TARGETS["local-gpu"]["profiles"])

    def test_aws_target_uses_aws_override_and_local_gpu_uses_gpu_override(self):
        self.assertEqual(
            contracts.TARGETS["aws"]["compose_files"],
            ("docker-compose.yml", "docker-compose.aws.yml"),
        )
        self.assertEqual(
            contracts.TARGETS["local-gpu"]["compose_files"],
            ("docker-compose.yml", "docker-compose.local-gpu.yml"),
        )

    def test_core_only_target_is_base_platform_without_functional_contracts(self):
        core = contracts.TARGETS["core-only"]
        self.assertEqual(core["profiles"], ("core",))
        self.assertEqual(core["compose_files"], ("docker-compose.yml",))
        self.assertFalse(core["functional"])

    def test_ollama_models_differ_by_target(self):
        self.assertEqual(contracts.TARGETS["aws"]["ollama_models"], ())
        self.assertEqual(contracts.TARGETS["local-gpu"]["ollama_models"], ("llama3.2:3b",))
        self.assertEqual(contracts.TARGETS["core-only"]["ollama_models"], ())

    def test_compose_command_names_every_profile_and_file(self):
        cmd = contracts.compose_command("aws")
        self.assertEqual(cmd[:2], ["docker", "compose"])
        for profile in contracts.TARGETS["aws"]["profiles"]:
            self.assertIn(profile, cmd)
        self.assertIn("docker-compose.aws.yml", cmd)
        self.assertNotIn("docker-compose.local-gpu.yml", cmd)

    def test_unknown_target_is_rejected_with_options(self):
        with self.assertRaisesRegex(SystemExit, "1"):
            contracts.resolve_target("staging")

    def test_missing_target_is_rejected_with_usage(self):
        with self.assertRaisesRegex(SystemExit, "2"):
            contracts.parse_target([])


class InventoryVerdictTests(unittest.TestCase):
    """El mensaje final no debe llamar healthy a un servicio sin healthcheck."""

    def _rows(self, **overrides):
        rows = {
            "opencti": {"Service": "opencti", "State": "running", "Health": "healthy"},
            "worker": {"Service": "worker", "State": "running", "Health": "healthy"},
            "connector-opencti": {"Service": "connector-opencti", "State": "running", "Health": ""},
        }
        rows.update(overrides)
        return rows

    def test_summary_separates_healthy_from_no_healthcheck(self):
        verdict = contracts.inventory_verdict(
            expected={"opencti", "worker", "connector-opencti"},
            rows=self._rows(),
            inspections={},
        )
        self.assertEqual(verdict.healthy, ["opencti", "worker"])
        self.assertEqual(verdict.no_healthcheck, ["connector-opencti"])
        self.assertEqual(verdict.bad, [])
        message = verdict.summary()
        self.assertNotRegex(message, r"3 .*healthy")
        self.assertIn("2 con healthcheck satisfecho", message)
        self.assertIn("1 en ejecución sin healthcheck", message)
        self.assertIn("connector-opencti", message)

    def test_missing_service_is_rejected(self):
        verdict = contracts.inventory_verdict(
            expected={"opencti", "worker", "connector-opencti", "kibana"},
            rows=self._rows(),
            inspections={},
        )
        self.assertIn("kibana=missing", verdict.bad)

    def test_stopped_unhealthy_restarting_and_oom_are_rejected(self):
        rows = self._rows(
            opencti={"Service": "opencti", "State": "exited", "Health": ""},
            worker={"Service": "worker", "State": "running", "Health": "unhealthy"},
        )
        verdict = contracts.inventory_verdict(
            expected={"opencti", "worker", "connector-opencti"},
            rows=rows,
            inspections={"connector-opencti": {"OOMKilled": False, "Restarting": True}},
        )
        self.assertIn("opencti=exited/no-healthcheck", verdict.bad)
        self.assertIn("worker=running/unhealthy", verdict.bad)
        self.assertIn("connector-opencti=restarting", verdict.bad)

    def test_oom_killed_is_rejected(self):
        verdict = contracts.inventory_verdict(
            expected={"opencti", "worker", "connector-opencti"},
            rows=self._rows(),
            inspections={"opencti": {"OOMKilled": True, "Restarting": False}},
        )
        self.assertIn("opencti=oom-killed", verdict.bad)


if __name__ == "__main__":
    unittest.main()
