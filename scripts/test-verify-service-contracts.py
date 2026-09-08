#!/usr/bin/env python3
"""Offline regressions for TIM HTTP contract diagnostics and semantic readiness."""

from __future__ import annotations

import importlib.util
import io
import json
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
    url: str = "https://localhost/api/semantic/search?q=malware&n_results=3",
) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        url,
        status,
        "simulated failure",
        FakeHeaders("text/plain"),
        io.BytesIO(body),
    )


class ServiceContractTests(unittest.TestCase):
    url = "https://localhost/api/semantic/search?q=malware&n_results=3"
    ready_url = "https://localhost/api/semantic/ready"
    auth = "Basic do-not-print-this-secret"

    def test_http_500_diagnostic_names_service_endpoint_status_and_body(self):
        with patch.object(contracts.urllib.request, "urlopen", side_effect=http_error(500)):
            with self.assertRaises(contracts.ServiceContractError) as caught:
                contracts.request_json(self.url, self.auth, service="semantic-engine")

        message = str(caught.exception)
        self.assertIn("semantic-engine", message)
        self.assertIn("/api/semantic/search", message)
        self.assertIn("500", message)
        self.assertIn("Internal Server Error", message)
        self.assertNotIn(self.auth, message)
        self.assertNotIn("do-not-print-this-secret", message)

    def test_semantic_readiness_waits_through_503_then_returns_ready_json(self):
        expected = {"status": "ready", "attempts": 1, "error": None}
        waits = []
        with patch.object(
            contracts.urllib.request,
            "urlopen",
            side_effect=[
                http_error(503, b'{"status":"warming"}', self.ready_url),
                FakeResponse(expected),
            ],
        ) as opener:
            result = contracts.wait_for_semantic_ready(
                self.ready_url,
                self.auth,
                attempts=3,
                sleep=lambda seconds: waits.append(seconds),
            )

        self.assertEqual(result, expected)
        self.assertEqual(opener.call_count, 2)
        self.assertEqual(waits, [contracts.SEMANTIC_RETRY_DELAY_SECONDS])

    def test_semantic_readiness_exhaustion_raises_last_enriched_error(self):
        errors = [
            http_error(503, f"warming {number}".encode(), self.ready_url)
            for number in range(1, 4)
        ]
        waits = []
        with patch.object(contracts.urllib.request, "urlopen", side_effect=errors) as opener:
            with self.assertRaises(contracts.ServiceContractError) as caught:
                contracts.wait_for_semantic_ready(
                    self.ready_url,
                    self.auth,
                    attempts=3,
                    sleep=lambda seconds: waits.append(seconds),
                )

        self.assertEqual(opener.call_count, 3)
        self.assertEqual(len(waits), 2)
        self.assertEqual(caught.exception.status, 503)
        self.assertIn("warming 3", str(caught.exception))

    def test_semantic_readiness_does_not_retry_401(self):
        waits = []
        with patch.object(
            contracts.urllib.request, "urlopen", side_effect=http_error(401, b"Unauthorized")
        ) as opener:
            with self.assertRaises(contracts.ServiceContractError) as caught:
                contracts.wait_for_semantic_ready(
                    self.ready_url,
                    self.auth,
                    attempts=3,
                    sleep=lambda seconds: waits.append(seconds),
                )

        self.assertEqual(opener.call_count, 1)
        self.assertEqual(waits, [])
        self.assertEqual(caught.exception.status, 401)

    def test_semantic_proxy_timeout_exceeds_functional_client_budget(self):
        nginx = (Path(__file__).resolve().parents[1] / "services/dashboard/nginx.conf").read_text()
        semantic_location = nginx.split("location /api/semantic/ {", 1)[1].split("}", 1)[0]

        self.assertIn("proxy_read_timeout 130s;", semantic_location)

    def test_semantic_index_waits_for_positive_progress(self):
        waits = []
        with patch.object(
            contracts,
            "request_json",
            side_effect=[
                {"status": "fetching", "indexed": 0, "total": 0},
                {"total_indexed": 0},
                {"status": "indexing", "indexed": 32, "total": 315440},
                {"total_indexed": 32},
            ],
        ) as request:
            stats = contracts.wait_for_semantic_index(
                "https://localhost/api/semantic/health",
                "https://localhost/api/semantic/stats",
                self.auth,
                attempts=3,
                sleep=lambda seconds: waits.append(seconds),
            )

        self.assertEqual(stats["total_indexed"], 32)
        self.assertEqual(request.call_count, 4)
        self.assertEqual(waits, [contracts.SEMANTIC_INDEX_RETRY_DELAY_SECONDS])

    def test_semantic_index_error_is_immediately_fatal(self):
        with patch.object(
            contracts,
            "request_json",
            return_value={"status": "error", "indexed": 0, "total": 0},
        ) as request:
            with self.assertRaisesRegex(ValueError, "status error"):
                contracts.wait_for_semantic_index(
                    "https://localhost/api/semantic/health",
                    "https://localhost/api/semantic/stats",
                    self.auth,
                    attempts=3,
                    sleep=lambda seconds: None,
                )

        self.assertEqual(request.call_count, 1)

    def test_semantic_search_must_be_nonempty(self):
        with self.assertRaisesRegex(ValueError, "no results"):
            contracts.validate_semantic_search({"results": [], "count": 0})

        contracts.validate_semantic_search(
            {"results": [{"value": "example.test", "score": 0.9}], "count": 1}
        )



class TargetSelectionTests(unittest.TestCase):
    """Objetivos de despliegue: aws (sin GPU, Bedrock), local-gpu (Ollama+NVIDIA), core-only."""

    def test_target_registry_declares_three_targets(self):
        self.assertEqual(set(contracts.TARGETS), {"aws", "local-gpu", "core-only"})

    def test_aws_target_profiles_cover_full_stack_with_inference(self):
        aws = contracts.TARGETS["aws"]
        for profile in ("core", "connectors", "feeds", "extractor", "semantic", "briefings", "dashboard", "inference"):
            self.assertIn(profile, aws["profiles"])

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
        self.assertEqual(contracts.TARGETS["aws"]["ollama_models"], ("nomic-embed-text",))
        self.assertEqual(
            contracts.TARGETS["local-gpu"]["ollama_models"],
            ("nomic-embed-text", "llama3.2:3b"),
        )
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
