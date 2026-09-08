#!/usr/bin/env python3
"""Capture sanitized evidence for one PE1 local-GPU PDF extraction."""

from __future__ import annotations

import __future__
import argparse
import hashlib
import json
import marshal
import re
import shlex
import subprocess
import sys
import time
import types
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path


ENDPOINT = "http://127.0.0.1:8004"
EXPECTED_PROVIDER = {
    "LLM_PROVIDER": "ollama",
    "OLLAMA_MODEL": "llama3.2:3b",
}
PENDING_JOB_STATUSES = {"queued", "processing"}
CAPTURE_TOOL_PATH = "scripts/capture-pe1-local-evidence.py"
TOOLING_STAGES = ("capture_submission", "final_report_read")
FULL_COMMIT_RE = re.compile(r"[0-9a-f]{40}")

REPORT_READ_SCRIPT = r'''
import json, os, sys
from pycti import OpenCTIApiClient

report_id = sys.argv[1]
client = OpenCTIApiClient(os.environ["OPENCTI_URL"], os.environ["OPENCTI_TOKEN"])
report = client.report.read(id=report_id)
if not report:
    print(json.dumps({"found": False, "id": report_id}))
    raise SystemExit(0)
objects = report.get("objects") or []
if isinstance(objects, dict):
    nodes = [edge.get("node") or {} for edge in objects.get("edges", [])]
else:
    nodes = [node or {} for node in objects]
indicator_ids = [
    n.get("id") for n in nodes
    if n.get("id") and (
        n.get("entity_type") == "Indicator"
        or (n.get("standard_id") or "").startswith("indicator--")
    )
]
attack_pattern_ids = [
    n.get("id") for n in nodes
    if n.get("id") and (
        n.get("entity_type") == "Attack-Pattern"
        or (n.get("standard_id") or "").startswith("attack-pattern--")
    )
]
relationship_ids = set()
for indicator_id in indicator_ids:
    for attack_pattern_id in attack_pattern_ids:
        matches = client.stix_core_relationship.list(
            fromId=indicator_id,
            toId=attack_pattern_id,
            relationship_type="indicates",
            first=10,
        ) or []
        for rel in matches:
            if (
                rel.get("relationship_type") == "indicates"
                and (rel.get("from") or {}).get("id") == indicator_id
                and (rel.get("to") or {}).get("id") == attack_pattern_id
            ):
                relationship_ids.add(rel.get("standard_id") or rel.get("id"))
print(json.dumps({
    "found": True,
    "id": report.get("id"),
    "standard_id": report.get("standard_id"),
    "name": report.get("name"),
    "object_count": len(nodes),
    "indicator_count": len(indicator_ids),
    "relationship_count": len({x for x in relationship_ids if x}),
}))
'''


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, capture_output=True, text=True)


def _load_json(raw: str, context: str) -> dict:
    try:
        payload = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"respuesta JSON inválida de {context}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"respuesta JSON inválida de {context}")
    return payload


def _last_json_object(raw: str, context: str) -> dict:
    """Parse the final JSON line while ignoring non-sensitive client log lines."""
    for line in reversed(raw.splitlines()):
        if line.lstrip().startswith("{"):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                return payload
    raise RuntimeError(f"respuesta JSON inválida de {context}")


def compose_command(target: str) -> list[str]:
    completed = _run(["./scripts/compose-target.sh", target])
    command = shlex.split(completed.stdout)
    if not command:
        raise RuntimeError("compose-target.sh no devolvió un comando")
    return command


def effective_provider(compose: list[str]) -> dict[str, str]:
    container_id = _run(compose + ["ps", "-q", "intel-extractor"]).stdout.strip()
    if not container_id or "\n" in container_id:
        raise RuntimeError("intel-extractor no tiene un contenedor único en ejecución")
    inspected = _run(
        [
            "docker",
            "inspect",
            container_id,
            "--format",
            "{{json .Config.Env}}",
        ]
    )
    try:
        entries = json.loads(inspected.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("docker inspect devolvió un entorno inválido") from exc
    if not isinstance(entries, list):
        raise RuntimeError("docker inspect devolvió un entorno inválido")
    environment = dict(
        entry.split("=", 1)
        for entry in entries
        if isinstance(entry, str) and "=" in entry
    )
    return {
        key: environment[key]
        for key in ("LLM_PROVIDER", "OLLAMA_MODEL")
        if key in environment
    }


def require_local_provider(provider: dict[str, str]) -> None:
    if provider.get("LLM_PROVIDER") != EXPECTED_PROVIDER["LLM_PROVIDER"]:
        raise RuntimeError("proveedor rechazado: se requiere ollama")
    if provider.get("OLLAMA_MODEL") != EXPECTED_PROVIDER["OLLAMA_MODEL"]:
        raise RuntimeError("modelo rechazado: se requiere llama3.2:3b")


def submit_pdf(endpoint: str, pdf: Path) -> str:
    boundary = f"----pe1-{uuid.uuid4().hex}"
    safe_name = pdf.name.replace('"', "_").replace("\r", "_").replace("\n", "_")
    body = b"".join(
        [
            f"--{boundary}\r\n".encode(),
            (
                'Content-Disposition: form-data; name="file"; '
                f'filename="{safe_name}"\r\n'
            ).encode(),
            b"Content-Type: application/pdf\r\n\r\n",
            pdf.read_bytes(),
            f"\r\n--{boundary}--\r\n".encode(),
        ]
    )
    request = urllib.request.Request(
        f"{endpoint.rstrip('/')}/extract",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        payload = _load_json(response.read().decode(), "/extract")
    job_id = payload.get("job_id")
    if not isinstance(job_id, str) or not job_id.strip():
        raise RuntimeError("/extract no devolvió un job_id válido")
    return job_id


def poll_job(
    endpoint: str,
    job_id: str,
    timeout_s: int,
    interval_s: float = 5.0,
) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        request = urllib.request.Request(
            f"{endpoint.rstrip('/')}/jobs/{job_id}", method="GET"
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            job = _load_json(response.read().decode(), f"/jobs/{job_id}")
        if job.get("job_id") != job_id:
            raise RuntimeError("identidad del job no coincide con la consulta")
        status = job.get("status")
        if status == "complete":
            return job
        if status == "failed":
            raise RuntimeError("job fallido; detalle externo omitido")
        if status not in PENDING_JOB_STATUSES:
            raise RuntimeError("estado desconocido del job")
        if time.monotonic() >= deadline:
            raise RuntimeError(f"timeout esperando el job tras {timeout_s} s")
        time.sleep(interval_s)


def read_report(compose: list[str], report_id: str) -> dict:
    completed = _run(
        compose
        + [
            "exec",
            "-T",
            "intel-extractor",
            "python3",
            "-c",
            REPORT_READ_SCRIPT,
            report_id,
        ]
    )
    return _last_json_object(completed.stdout, "OpenCTI")


def validate_tooling_provenance(tooling: dict) -> dict:
    if not isinstance(tooling, dict) or set(tooling) != set(TOOLING_STAGES):
        raise RuntimeError("procedencia de herramientas incompleta o no permitida")
    sanitized = {}
    for stage in TOOLING_STAGES:
        entry = tooling.get(stage)
        if not isinstance(entry, dict) or set(entry) != {"path", "commit"}:
            raise RuntimeError("procedencia de herramientas ambigua")
        if entry.get("path") != CAPTURE_TOOL_PATH:
            raise RuntimeError("procedencia de herramientas fuera del allowlist")
        commit = entry.get("commit")
        if not isinstance(commit, str) or FULL_COMMIT_RE.fullmatch(commit) is None:
            raise RuntimeError("procedencia de herramientas requiere commits completos")
        sanitized[stage] = {"path": CAPTURE_TOOL_PATH, "commit": commit}
    return sanitized


def _canonical_fingerprint_value(value):
    if value is None:
        return ("none",)
    if type(value) is bool:
        return ("bool", value)
    if type(value) is int:
        return ("int", value)
    if type(value) is float:
        return ("float", value)
    if type(value) is complex:
        return ("complex", value.real, value.imag)
    if type(value) is str:
        return ("str", value.encode("utf-8"))
    if type(value) is bytes:
        return ("bytes", value)
    if value is Ellipsis:
        return ("ellipsis",)
    if isinstance(value, types.CodeType):
        return ("code", _canonical_code(value))
    if isinstance(value, re.Pattern):
        return (
            "regex",
            _canonical_fingerprint_value(value.pattern),
            value.flags,
        )
    if isinstance(value, tuple):
        return ("tuple", tuple(_canonical_fingerprint_value(item) for item in value))
    if isinstance(value, list):
        return ("list", tuple(_canonical_fingerprint_value(item) for item in value))
    if isinstance(value, (set, frozenset)):
        items = [_canonical_fingerprint_value(item) for item in value]
        return (type(value).__name__, tuple(sorted(items, key=repr)))
    if isinstance(value, dict):
        items = [
            (
                _canonical_fingerprint_value(key),
                _canonical_fingerprint_value(item),
            )
            for key, item in value.items()
        ]
        return ("dict", tuple(sorted(items, key=repr)))
    raise RuntimeError("valor no permitido en la huella del script")


def _canonical_code(code: types.CodeType) -> tuple:
    return (
        code.co_argcount,
        getattr(code, "co_posonlyargcount", 0),
        code.co_kwonlyargcount,
        code.co_nlocals,
        code.co_stacksize,
        code.co_flags,
        code.co_code,
        _canonical_fingerprint_value(code.co_consts),
        _canonical_fingerprint_value(code.co_names),
        _canonical_fingerprint_value(code.co_varnames),
        _canonical_fingerprint_value(code.co_filename),
        _canonical_fingerprint_value(code.co_name),
        _canonical_fingerprint_value(getattr(code, "co_qualname", code.co_name)),
        code.co_firstlineno,
        getattr(code, "co_linetable", b""),
        getattr(code, "co_lnotab", b""),
        getattr(code, "co_exceptiontable", b""),
        _canonical_fingerprint_value(code.co_freevars),
        _canonical_fingerprint_value(code.co_cellvars),
    )


def _fingerprint_module_code(module_code: types.CodeType) -> str:
    return hashlib.sha256(marshal.dumps(_canonical_code(module_code))).hexdigest()


def _module_compile_flags(module_code: types.CodeType) -> int:
    recognized = sum(
        getattr(__future__, name).compiler_flag
        for name in __future__.all_feature_names
    )
    return module_code.co_flags & recognized


def source_tool_fingerprint(source: str, filename: str | None = None) -> str:
    """Compile and fingerprint a committed blob without executing it."""
    loaded_filename = LOADED_MODULE_CODE.co_filename
    if filename is not None and filename != loaded_filename:
        raise RuntimeError("filename del blob no coincide con el módulo cargado")
    try:
        module_code = compile(
            source,
            loaded_filename,
            "exec",
            flags=_module_compile_flags(LOADED_MODULE_CODE),
            dont_inherit=True,
            optimize=sys.flags.optimize,
        )
    except (SyntaxError, ValueError, TypeError) as exc:
        raise RuntimeError("blob del script inválido o no compilable") from exc

    return _fingerprint_module_code(module_code)


def tool_revision() -> str:
    """Return the exact committed revision of this capture/read script."""
    status = _run(
        [
            "git",
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            CAPTURE_TOOL_PATH,
        ]
    ).stdout.strip()
    if status:
        raise RuntimeError("script de captura sin revisión limpia y auditable")
    revision = _run(
        ["git", "log", "-1", "--format=%H", "--", CAPTURE_TOOL_PATH]
    ).stdout.strip()
    if FULL_COMMIT_RE.fullmatch(revision) is None:
        raise RuntimeError("no se pudo resolver la revisión del script de captura")
    committed_source = _run(
        ["git", "show", f"{revision}:{CAPTURE_TOOL_PATH}"]
    ).stdout
    committed_fingerprint = source_tool_fingerprint(
        committed_source,
        LOADED_MODULE_CODE.co_filename,
    )
    if committed_fingerprint != LOADED_TOOL_FINGERPRINT:
        raise RuntimeError("la revisión resuelta no coincide con el script cargado")
    return revision


def require_tool_revision(expected: str) -> None:
    """Fail closed when the loaded capture script no longer matches its pin."""
    if tool_revision() != expected:
        raise RuntimeError("la revisión del script cambió durante la captura")


def validate_result(job: dict, report: dict) -> dict:
    job_id = job.get("job_id")
    if not isinstance(job_id, str) or not job_id:
        raise RuntimeError("resultado rechazado: falta la identidad del job consultado")
    expected_name = f"pdf-upload-{job_id[:8]}"
    if report.get("name") != expected_name:
        raise RuntimeError(
            "resultado rechazado: la referencia documental del reporte no coincide"
        )
    accepted = (
        job.get("status") == "complete"
        and bool(job.get("report_id"))
        and job.get("iocs_extracted", 0) > 0
        and report.get("found") is True
        and report.get("id") == job.get("report_id")
        and report.get("indicator_count", 0) > 0
        and report.get("relationship_count", 0) > 0
    )
    if not accepted:
        raise RuntimeError(
            "resultado rechazado: no satisface el contrato integrado "
            "de reporte, indicadores y relaciones"
        )
    return {
        "job_id": job_id,
        "report_id": job["report_id"],
        "document_reference": report["name"],
        "indicator_count": report["indicator_count"],
        "relationship_count": report["relationship_count"],
    }


def build_evidence(
    captured_at: str,
    target: str,
    provider: dict,
    source_path: Path,
    job: dict,
    report: dict,
    tooling: dict,
) -> dict:
    validate_result(job, report)
    tooling = validate_tooling_provenance(tooling)
    return {
        "schema": "pe1-local-extractor-evidence/v2",
        "captured_at": captured_at,
        "target": target,
        "provider": {
            "name": provider["LLM_PROVIDER"],
            "model": provider["OLLAMA_MODEL"],
        },
        "source": {
            "path": source_path.as_posix(),
            "sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        },
        "job": {
            key: job[key]
            for key in (
                "job_id",
                "status",
                "report_id",
                "iocs_extracted",
                "techniques_found",
                "processing_time_s",
            )
        },
        "opencti": {
            "report_found": report["found"],
            "report_id": report["id"],
            "standard_id": report["standard_id"],
            "document_reference": report["name"],
            "object_count": report["object_count"],
            "indicator_count": report["indicator_count"],
            "relationship_count": report["relationship_count"],
        },
        "tooling": tooling,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture sanitized PE1 local extractor evidence"
    )
    parser.add_argument("--target", required=True, choices=["local-gpu"])
    parser.add_argument("--pdf", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=1800)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if not args.pdf.is_file():
            raise RuntimeError(f"PDF ausente: {args.pdf.as_posix()}")
        if args.timeout <= 0:
            raise RuntimeError("--timeout debe ser positivo")

        compose = compose_command(args.target)
        provider = effective_provider(compose)
        require_local_provider(provider)

        pinned_revision = tool_revision()
        job_id = submit_pdf(ENDPOINT, args.pdf)
        job = poll_job(ENDPOINT, job_id, args.timeout)
        report_id = job.get("report_id")
        if not isinstance(report_id, str) or not report_id:
            raise RuntimeError("job completo sin report_id")
        require_tool_revision(pinned_revision)
        report = read_report(compose, report_id)
        require_tool_revision(pinned_revision)
        accepted = validate_result(job, report)

        evidence = build_evidence(
            captured_at=datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            target=args.target,
            provider=provider,
            source_path=args.pdf,
            job=job,
            report=report,
            tooling={
                "capture_submission": {
                    "path": CAPTURE_TOOL_PATH,
                    "commit": pinned_revision,
                },
                "final_report_read": {
                    "path": CAPTURE_TOOL_PATH,
                    "commit": pinned_revision,
                },
            },
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({"status": "accepted", **accepted}, sort_keys=True))
        return 0
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except (OSError, subprocess.CalledProcessError, urllib.error.URLError):
        print("ERROR: fallo externo durante la captura", file=sys.stderr)
        return 1


LOADED_MODULE_CODE = sys._getframe().f_code
LOADED_TOOL_FINGERPRINT = _fingerprint_module_code(LOADED_MODULE_CODE)


if __name__ == "__main__":
    raise SystemExit(main())
