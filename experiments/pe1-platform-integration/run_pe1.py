#!/usr/bin/env python3
"""Ejecutor y verificador del experimento PE-1 de plataforma e integración."""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


PDF_SHA256 = "97805a057e1217acdf8a1c21f3852994c550b2b9fe094af270bd1bb6e24e8c76"
SOURCE_PATHS = (
    "docker-compose.yml",
    "docker-compose.local-gpu.yml",
    "scripts/bootstrap-platform.sh",
    "scripts/tim-check.sh",
    "scripts/verify-service-contracts.py",
    "scripts/capture-pe1-local-evidence.py",
)


class ExperimentError(RuntimeError):
    """El experimento no puede continuar sin romper su protocolo."""


def parse_compose_ps(raw: str) -> dict[str, dict[str, Any]]:
    """Convierte la salida JSON de Compose en filas únicas por servicio."""
    stripped = raw.strip()
    if not stripped:
        return {}
    try:
        decoded = json.loads(stripped)
        items = decoded if isinstance(decoded, list) else [decoded]
    except json.JSONDecodeError:
        items = []
        for line in stripped.splitlines():
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ExperimentError("docker compose ps devolvió JSON inválido") from exc
    rows: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("Service"), str):
            raise ExperimentError("docker compose ps devolvió una fila inválida")
        service = item["Service"]
        if service in rows:
            raise ExperimentError(f"servicio duplicado en docker compose ps: {service}")
        rows[service] = item
    return rows


def assess_inventory(
    expected_services: Iterable[str],
    rows: dict[str, dict[str, Any]],
    states: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Evalúa el inventario exacto definido por el protocolo PE-1."""
    expected = sorted(set(expected_services))
    issues: list[str] = []
    if len(expected) != 39:
        issues.append(f"expected-count={len(expected)}")
    unexpected = sorted(set(rows) - set(expected))
    missing = sorted(set(expected) - set(rows))
    issues.extend(f"{service}=unexpected" for service in unexpected)
    issues.extend(f"{service}=missing" for service in missing)

    running = 0
    healthy = 0
    without_healthcheck: list[str] = []
    for service in expected:
        row = rows.get(service)
        if row is None:
            continue
        state = row.get("State")
        health = row.get("Health") or ""
        if state != "running":
            issues.append(f"{service}={state or 'unknown'}")
            continue
        running += 1
        if health == "healthy":
            healthy += 1
        elif health:
            issues.append(f"{service}=health-{health}")
        else:
            without_healthcheck.append(service)
        inspected = states.get(service)
        if not isinstance(inspected, dict):
            issues.append(f"{service}=inspect-missing")
            continue
        if inspected.get("OOMKilled") is True:
            issues.append(f"{service}=oom-killed")
            continue
        if inspected.get("Restarting") is True:
            issues.append(f"{service}=restarting")
            continue

    if without_healthcheck != ["connector-opencti"]:
        issues.append(
            "without-healthcheck=" + ",".join(without_healthcheck)
        )
    if healthy != 38:
        issues.append(f"healthy-count={healthy}")

    return {
        "accepted": not issues,
        "expected": len(expected),
        "running": running,
        "healthy": healthy,
        "without_healthcheck": without_healthcheck,
        "issues": issues,
    }


def aggregate_summaries(summaries: list[dict[str, Any]]) -> dict[str, Any]:
    """Agrega tres repeticiones sin ocultar ninguna condición fallida."""
    startup_times = [
        float(item["startup"]["duration_s"])
        for item in summaries
        if item["startup"].get("accepted") is True
    ]
    integration_times = [
        float(item["integration"]["processing_time_s"])
        for item in summaries
        if item["integration"].get("accepted") is True
    ]
    startup_passed = sum(item["startup"].get("accepted") is True for item in summaries)
    integration_passed = sum(
        item["integration"].get("accepted") is True for item in summaries
    )
    repetitions = len(summaries)
    identities = [item.get("repetition") for item in summaries]
    accepted = (
        repetitions == 3
        and identities == [1, 2, 3]
        and startup_passed == 3
        and integration_passed == 3
    )
    return {
        "accepted": accepted,
        "repetitions": repetitions,
        "startup_passed": startup_passed,
        "integration_passed": integration_passed,
        "startup_mean_s": round(statistics.mean(startup_times), 2)
        if startup_times
        else None,
        "integration_mean_s": round(statistics.mean(integration_times), 2)
        if integration_times
        else None,
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def build_manifest(root: Path, output: Path) -> dict[str, Any]:
    """Sella todos los archivos regulares salvo el propio manifiesto."""
    root = root.resolve()
    output = output.resolve()
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.resolve() == output:
            continue
        if "__pycache__" in path.parts or path.suffix == ".pyc" or path.suffix == ".tmp":
            continue
        files[path.relative_to(root).as_posix()] = _sha256(path)
    manifest = {"algorithm": "sha256", "files": files}
    _write_json(output, manifest)
    return manifest


def verify_manifest(root: Path, manifest_path: Path) -> dict[str, Any]:
    """Verifica las huellas declaradas y rechaza archivos probatorios extra."""
    root = root.resolve()
    manifest_path = manifest_path.resolve()
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExperimentError("manifiesto ausente o inválido") from exc
    if manifest.get("algorithm") != "sha256" or not isinstance(manifest.get("files"), dict):
        raise ExperimentError("estructura del manifiesto inválida")
    declared = manifest["files"]
    for relative, expected in declared.items():
        path = root / relative
        if not path.is_file():
            raise ExperimentError(f"falta el artefacto {relative}")
        if _sha256(path) != expected:
            raise ExperimentError(f"deriva detectada en {relative}")
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and path.resolve() != manifest_path
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".tmp"}
    }
    if actual != set(declared):
        missing = sorted(actual - set(declared))
        stale = sorted(set(declared) - actual)
        raise ExperimentError(
            f"membresía del manifiesto distinta; sin declarar={missing}; ausentes={stale}"
        )
    return {"verified": len(declared)}


def prepare_config(
    *,
    target: str,
    pdf: Path,
    repetitions: int,
    output_root: Path,
    compose: list[str],
    expected_pdf_sha256: str = PDF_SHA256,
) -> dict[str, Any]:
    """Congela los parámetros ejecutables y rechaza cualquier deriva del protocolo."""
    if target != "local-gpu":
        raise ExperimentError("el protocolo solo permite el objetivo local-gpu")
    if repetitions != 3:
        raise ExperimentError("el protocolo exige exactamente tres repeticiones")
    if not pdf.is_file() or _sha256(pdf) != expected_pdf_sha256:
        raise ExperimentError("la huella del PDF no coincide con el protocolo")
    if not compose or compose[:2] != ["docker", "compose"]:
        raise ExperimentError("comando Compose inválido")
    output_root = output_root.resolve()
    final_outputs = ("ENVIRONMENT.json", "RESULTS.json", "RESULTS.md", "MANIFEST.json")
    populated_runs = [
        path
        for path in (output_root / "runs").glob("rep-*")
        if path.is_dir() and any(path.iterdir())
    ]
    if any((output_root / name).exists() for name in final_outputs) or populated_runs:
        raise ExperimentError("el destino contiene resultados previos")
    return {
        "target": target,
        "pdf": pdf.resolve(),
        "pdf_sha256": expected_pdf_sha256,
        "repetitions": repetitions,
        "output_root": output_root,
        "compose": compose,
        "capture_timeout_s": 1800,
        "command_timeout_s": 1800,
    }


def _write_log(path: Path, completed: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = (completed.stdout or "") + (completed.stderr or "")
    path.write_text(content, encoding="utf-8")


def _invoke(command_runner, command: list[str], timeout_s: int):
    return command_runner(
        command,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )


def _require_success(completed: Any, context: str) -> str:
    if completed.returncode != 0:
        raise ExperimentError(f"falló {context} con código {completed.returncode}")
    return completed.stdout or ""


def _capture_inventory(
    compose: list[str], command_runner, timeout_s: int
) -> dict[str, Any]:
    expected_raw = _require_success(
        _invoke(command_runner, compose + ["config", "--services"], timeout_s),
        "compose config --services",
    )
    expected = [line.strip() for line in expected_raw.splitlines() if line.strip()]
    rows_raw = _require_success(
        _invoke(
            command_runner,
            compose + ["ps", "-a", "--format", "json"],
            timeout_s,
        ),
        "compose ps",
    )
    rows = parse_compose_ps(rows_raw)
    ids_raw = _require_success(
        _invoke(command_runner, compose + ["ps", "-q"], timeout_s),
        "compose ps -q",
    )
    container_ids = [line.strip() for line in ids_raw.splitlines() if line.strip()]
    if len(container_ids) != len(expected):
        raise ExperimentError(
            f"compose ps -q devolvió {len(container_ids)} contenedores; se esperaban {len(expected)}"
        )
    inspect_raw = _require_success(
        _invoke(command_runner, ["docker", "inspect", *container_ids], timeout_s),
        "docker inspect",
    )
    try:
        inspections = json.loads(inspect_raw)
    except json.JSONDecodeError as exc:
        raise ExperimentError("docker inspect devolvió JSON inválido") from exc
    states: dict[str, dict[str, Any]] = {}
    if not isinstance(inspections, list):
        raise ExperimentError("docker inspect devolvió una estructura inválida")
    for inspection in inspections:
        if not isinstance(inspection, dict):
            raise ExperimentError("docker inspect devolvió un elemento inválido")
        labels = (inspection.get("Config") or {}).get("Labels") or {}
        service = labels.get("com.docker.compose.service")
        state = inspection.get("State")
        if not isinstance(service, str) or not isinstance(state, dict):
            raise ExperimentError("docker inspect no identifica servicio y estado")
        if service in states:
            raise ExperimentError(f"docker inspect duplicó el servicio {service}")
        states[service] = state
    result = assess_inventory(expected, rows, states)
    result["services"] = expected
    return result


def validate_integration(evidence: dict[str, Any], expected_pdf_sha256: str) -> dict[str, Any]:
    """Valida el recorrido PDF→extractor→reporte OpenCTI sin puntuar contenido."""
    provider = evidence.get("provider") or {}
    source = evidence.get("source") or {}
    job = evidence.get("job") or {}
    opencti = evidence.get("opencti") or {}
    accepted = (
        evidence.get("schema") == "pe1-local-extractor-evidence/v2"
        and evidence.get("target") == "local-gpu"
        and provider.get("name") == "ollama"
        and provider.get("model") == "llama3.2:3b"
        and source.get("sha256") == expected_pdf_sha256
        and job.get("status") == "complete"
        and isinstance(job.get("report_id"), str)
        and bool(job.get("report_id"))
        and opencti.get("report_found") is True
        and opencti.get("report_id") == job.get("report_id")
        and isinstance(opencti.get("indicator_count"), int)
        and opencti.get("indicator_count", 0) > 0
        and isinstance(opencti.get("relationship_count"), int)
        and opencti.get("relationship_count", 0) > 0
    )
    return {
        "accepted": accepted,
        "processing_time_s": float(job.get("processing_time_s") or 0.0),
        "job_id": job.get("job_id"),
        "report_id": job.get("report_id"),
        "indicator_count": opencti.get("indicator_count", 0),
        "relationship_count": opencti.get("relationship_count", 0),
    }


def run_cycle(
    number: int,
    config: dict[str, Any],
    *,
    command_runner=subprocess.run,
    clock=time.monotonic,
) -> dict[str, Any]:
    """Ejecuta una repetición y conserva el resultado incluso cuando falla."""
    root = Path(config["output_root"])
    run_dir = root / "runs" / f"rep-{number}"
    if run_dir.exists() and any(run_dir.iterdir()):
        raise ExperimentError(f"la repetición {number} ya contiene evidencia")
    run_dir.mkdir(parents=True, exist_ok=True)
    compose = list(config["compose"])
    timeout_s = int(config["command_timeout_s"])
    startup: dict[str, Any] = {"accepted": False, "duration_s": 0.0}
    integration: dict[str, Any] = {
        "accepted": False,
        "processing_time_s": 0.0,
    }
    errors: list[str] = []

    try:
        started = clock()
        bootstrap = _invoke(
            command_runner,
            ["./scripts/bootstrap-platform.sh", config["target"]],
            timeout_s,
        )
        duration = round(clock() - started, 3)
        _write_log(run_dir / "bootstrap.log", bootstrap)
        startup["duration_s"] = duration
        startup["bootstrap_exit_code"] = bootstrap.returncode
        if bootstrap.returncode != 0:
            errors.append(f"bootstrap-exit={bootstrap.returncode}")
        else:
            inventory = _capture_inventory(compose, command_runner, timeout_s)
            _write_json(run_dir / "inventory.json", inventory)
            startup.update(inventory)

        if startup.get("accepted") is True:
            integration_path = run_dir / "integration.json"
            capture = _invoke(
                command_runner,
                [
                    sys.executable,
                    "scripts/capture-pe1-local-evidence.py",
                    "--target",
                    config["target"],
                    "--pdf",
                    str(config["pdf"]),
                    "--output",
                    str(integration_path),
                    "--timeout",
                    str(config["capture_timeout_s"]),
                ],
                int(config["capture_timeout_s"]) + 120,
            )
            _write_log(run_dir / "capture.log", capture)
            if capture.returncode != 0 or not integration_path.is_file():
                errors.append(f"capture-exit={capture.returncode}")
            else:
                try:
                    evidence = json.loads(integration_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError as exc:
                    raise ExperimentError("integration.json contiene JSON inválido") from exc
                integration = validate_integration(evidence, config["pdf_sha256"])
                if integration["accepted"] is not True:
                    errors.append("integration-contract-rejected")
    except (ExperimentError, OSError, subprocess.SubprocessError) as exc:
        errors.append(str(exc))
    finally:
        try:
            stopped = _invoke(command_runner, compose + ["stop"], timeout_s)
            _write_log(run_dir / "stop.log", stopped)
            shutdown = {"accepted": stopped.returncode == 0, "exit_code": stopped.returncode}
            if stopped.returncode != 0:
                errors.append(f"stop-exit={stopped.returncode}")
        except (OSError, subprocess.SubprocessError) as exc:
            shutdown = {"accepted": False, "exit_code": None}
            errors.append(f"stop-error={exc}")

    summary = {
        "repetition": number,
        "accepted": (
            startup.get("accepted") is True
            and integration.get("accepted") is True
            and shutdown.get("accepted") is True
        ),
        "startup": startup,
        "integration": integration,
        "shutdown": shutdown,
        "errors": errors,
    }
    _write_json(run_dir / "summary.json", summary)
    return summary


def _run_checked(command: list[str]) -> str:
    completed = subprocess.run(command, capture_output=True, text=True, timeout=60)
    if completed.returncode != 0:
        raise ExperimentError(f"falló el comando de preflight: {' '.join(command)}")
    return completed.stdout.strip()


def resolve_compose(target: str) -> list[str]:
    command = shlex.split(_run_checked(["./scripts/compose-target.sh", target]))
    if command[:2] != ["docker", "compose"]:
        raise ExperimentError("compose-target.sh devolvió un comando inválido")
    return command


def _safe_volume_name(env_path: Path = Path(".env")) -> str | None:
    if not env_path.is_file():
        return None
    for line in env_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("ESDATA_VOLUME_NAME="):
            return line.split("=", 1)[1]
    return None


def _environment(config: dict[str, Any]) -> dict[str, Any]:
    sources = {}
    for relative in SOURCE_PATHS:
        path = Path(relative)
        if not path.is_file():
            raise ExperimentError(f"falta la fuente ejecutable {relative}")
        sources[relative] = _sha256(path)
    return {
        "schema": "pe1-platform-environment/v1",
        "captured_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "target": config["target"],
        "repetitions": config["repetitions"],
        "source": {
            "path": Path(config["pdf"]).as_posix(),
            "sha256": config["pdf_sha256"],
        },
        "compose_project": "opencti-7-pilot",
        "elasticsearch_volume": _safe_volume_name(),
        "scope": "reactivación con contenedores y volúmenes existentes",
        "git_commit": _run_checked(["git", "rev-parse", "HEAD"]),
        "source_sha256": sources,
    }


def _results_markdown(results: dict[str, Any]) -> str:
    rows = []
    evaluable_integrations = 0
    for item in results["runs"]:
        startup_accepted = item["startup"]["accepted"] is True
        integration_accepted = item["integration"]["accepted"] is True
        if not startup_accepted:
            integration = "No evaluable"
            processing = indicators = relationships = "—"
        else:
            evaluable_integrations += 1
            integration = "Aprobado" if integration_accepted else "No aprobado"
            processing = f'{float(item["integration"]["processing_time_s"]):.3f}'
            indicators = str(item["integration"].get("indicator_count", 0))
            relationships = str(item["integration"].get("relationship_count", 0))
        rows.append(
            "| {rep} | {startup} | {duration:.3f} | {integration} | {processing} | "
            "{indicators} | {relationships} |".format(
                rep=item["repetition"],
                startup="Aprobado" if startup_accepted else "No aprobado",
                duration=float(item["startup"]["duration_s"]),
                integration=integration,
                processing=processing,
                indicators=indicators,
                relationships=relationships,
            )
        )
    verdict = "APROBADO" if results["accepted"] else "NO APROBADO"
    return "\n".join(
        [
            "# Resultados PE-1 — arranque e integración",
            "",
            f"**Veredicto agregado:** {verdict}.",
            "",
            "| Repetición | Arranque | Tiempo hasta READY (s) | Integración | Procesamiento (s) | Indicadores | Relaciones |",
            "|---:|---|---:|---|---:|---:|---:|",
            *rows,
            "",
            f"Arranque: {results['aggregate']['startup_passed']}/3. "
            f"Integración: {results['aggregate']['integration_passed']}/3 ciclos planeados "
            f"y {results['aggregate']['integration_passed']}/{evaluable_integrations} ciclos evaluables.",
            "",
            "El tiempo de arranque mide una reactivación con volúmenes existentes. "
            "No representa una instalación desde cero.",
            "",
        ]
    )


def _close_results(root: Path, summaries: list[dict[str, Any]]) -> dict[str, Any]:
    aggregate = aggregate_summaries(summaries)
    results = {
        "schema": "pe1-platform-results/v1",
        "accepted": aggregate["accepted"],
        "aggregate": aggregate,
        "runs": summaries,
        "evidence": {
            "protocol": "PROTOCOL.md",
            "environment": "ENVIRONMENT.json",
            "manifest": "MANIFEST.json",
        },
        "limitations": [
            "reactivación con contenedores y volúmenes existentes",
            "un host, un objetivo, un modelo y un documento",
            "la entrada trazada recorre extractor y OpenCTI",
            "no evalúa calidad semántica, disponibilidad ni capacidad máxima",
        ],
    }
    _write_json(root / "RESULTS.json", results)
    (root / "RESULTS.md").write_text(_results_markdown(results), encoding="utf-8")
    build_manifest(root, root / "MANIFEST.json")
    verify_manifest(root, root / "MANIFEST.json")
    return results


def rebuild_results(root: Path) -> dict[str, Any]:
    """Recalcula resultados derivados desde las tres repeticiones conservadas."""
    root = root.resolve()
    for required in ("PROTOCOL.md", "ENVIRONMENT.json"):
        if not (root / required).is_file():
            raise ExperimentError(f"falta el artefacto requerido {required}")
    summaries = []
    for number in range(1, 4):
        path = root / "runs" / f"rep-{number}" / "summary.json"
        try:
            summary = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ExperimentError(f"resumen inválido de la repetición {number}") from exc
        if summary.get("repetition") != number:
            raise ExperimentError(f"identidad inválida de la repetición {number}")
        summaries.append(summary)
    return _close_results(root, summaries)


def execute_experiment(
    config: dict[str, Any],
    *,
    command_runner=subprocess.run,
) -> dict[str, Any]:
    root = Path(config["output_root"])
    _write_json(root / "ENVIRONMENT.json", _environment(config))
    summaries = [
        run_cycle(number, config, command_runner=command_runner)
        for number in range(1, config["repetitions"] + 1)
    ]
    return _close_results(root, summaries)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=["local-gpu"])
    parser.add_argument("--pdf", type=Path)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.verify:
            verified = verify_manifest(args.output_root, args.output_root / "MANIFEST.json")
            print(f"MANIFEST OK: {verified['verified']} archivos")
            return 0
        if args.target is None or args.pdf is None:
            raise ExperimentError("--target y --pdf son obligatorios para ejecutar")
        compose = resolve_compose(args.target)
        config = prepare_config(
            target=args.target,
            pdf=args.pdf,
            repetitions=args.repetitions,
            output_root=args.output_root,
            compose=compose,
        )
        results = execute_experiment(config)
        print(json.dumps({"accepted": results["accepted"]}, sort_keys=True))
        return 0 if results["accepted"] else 1
    except (ExperimentError, OSError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
