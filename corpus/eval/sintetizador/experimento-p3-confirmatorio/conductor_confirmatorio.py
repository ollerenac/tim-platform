#!/usr/bin/env python3
"""Ejecuta P3 sin alterar el servicio y conserva cada entrada y salida.

El proceso usa el prompt de producción cargado por ``generator.py``. No edita
ese módulo ni su configuración. Los resultados se escriben uno por uno y una
segunda invocación omite las corridas ya terminadas.
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCHEMA_VERSION = 1
PROMPT_ID = "P3-production"
HOUR_FORMAT = "%Y-%m-%d %H"


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _utc_now():
    return datetime.now(timezone.utc).isoformat()


def _atomic_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def _atomic_json(path, value):
    _atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _append_jsonl(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _validate_plan(hours, repetitions):
    if not hours:
        raise ValueError("el plan no contiene bloques horarios")
    if not isinstance(repetitions, int) or repetitions < 1:
        raise ValueError("repetitions debe ser un entero positivo")
    if len(hours) != len(set(hours)):
        raise ValueError("el plan contiene bloques duplicados")
    for block in hours:
        try:
            parsed = datetime.strptime(block, HOUR_FORMAT)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"bloque horario inválido: {block!r}") from exc
        if parsed.strftime(HOUR_FORMAT) != block:
            raise ValueError(f"bloque horario no canónico: {block!r}")


def discover_productive_hours(count_updated, since, until, limit, excluded=None, progress=None):
    """Select the latest non-empty complete hours without seeing LLM outputs."""
    if limit < 1:
        raise ValueError("limit debe ser positivo")
    try:
        start = datetime.strptime(since, HOUR_FORMAT).replace(tzinfo=timezone.utc)
        end = datetime.strptime(until, HOUR_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise ValueError("since y until deben usar YYYY-MM-DD HH") from exc
    if start >= end:
        raise ValueError("since debe ser anterior a until")

    excluded = set(excluded or ())
    selected = []
    summary = {"inspected": 0, "productive": 0, "excluded_productive": 0, "selected": 0}
    cursor = end - timedelta(hours=1)
    while cursor >= start and len(selected) < limit:
        block = cursor.strftime(HOUR_FORMAT)
        count = count_updated(block)
        if not isinstance(count, int) or count < 0:
            raise RuntimeError(f"recuento inválido para {block}: {count!r}")
        summary["inspected"] += 1
        if count:
            summary["productive"] += 1
            if block in excluded:
                summary["excluded_productive"] += 1
            else:
                selected.append(block)
                summary["selected"] = len(selected)
        if progress:
            progress(dict(summary, block=block, updated=count))
        cursor -= timedelta(hours=1)
    return selected, summary


def build_mixed_plan(confirmatory_hours, exploratory_hours, total_blocks, seed):
    """Combine all unseen blocks with a hash-selected replication subset."""
    _validate_plan(confirmatory_hours, 1)
    _validate_plan(exploratory_hours, 1)
    if set(confirmatory_hours) & set(exploratory_hours):
        raise ValueError("los estratos confirmatorio y exploratorio se solapan")
    if not seed:
        raise ValueError("la semilla de selección no puede estar vacía")
    replication_count = total_blocks - len(confirmatory_hours)
    if replication_count < 0 or replication_count > len(exploratory_hours):
        raise ValueError("total_blocks no puede satisfacerse con los bloques disponibles")

    ranked = sorted(exploratory_hours, key=lambda block: _sha256(f"{seed}|{block}"))
    replication_hours = ranked[:replication_count]
    all_hours = list(confirmatory_hours) + replication_hours
    ordered = sorted(all_hours, key=lambda block: _sha256(f"{seed}|order|{block}"))
    strata = {
        **{block: "confirmatory" for block in confirmatory_hours},
        **{block: "replication" for block in replication_hours},
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "selection_rule": "all confirmatory blocks plus lowest SHA-256 ranks from exploratory blocks",
        "selection_seed": seed,
        "total_blocks": total_blocks,
        "hours": ordered,
        "strata": strata,
        "confirmatory_hours": list(confirmatory_hours),
        "replication_hours": replication_hours,
    }


def _context_paths(output_dir, block):
    slug = block.replace(" ", "T")
    root = Path(output_dir) / "contexts"
    return root / f"{slug}.txt", root / f"{slug}.json"


def _load_frozen_context(output_dir, block):
    text_path, meta_path = _context_paths(output_dir, block)
    if not text_path.exists() and not meta_path.exists():
        return None
    if not text_path.exists() or not meta_path.exists():
        raise RuntimeError(f"contexto congelado incompleto para {block}")
    context = text_path.read_text(encoding="utf-8")
    record = json.loads(meta_path.read_text(encoding="utf-8"))
    if record.get("context_sha256") != _sha256(context):
        raise RuntimeError(f"hash del contexto congelado no coincide para {block}")
    return context, record


def freeze_context(output_dir, block, context, metadata):
    """Write a block once; a changed snapshot can never replace it silently."""
    text_path, meta_path = _context_paths(output_dir, block)
    record = {
        "schema_version": SCHEMA_VERSION,
        "block": block,
        "context_sha256": _sha256(context),
        "source": metadata,
    }
    frozen = _load_frozen_context(output_dir, block)
    if frozen is not None:
        old_context, old_record = frozen
        if old_context != context or old_record != record:
            raise RuntimeError(f"contexto congelado no coincide para {block}")
        return old_record
    _atomic_text(text_path, context)
    _atomic_json(meta_path, record)
    return record


def _protocol(hours, repetitions, backend, strata):
    extra = getattr(backend, "protocol_metadata", None)
    return {
        "schema_version": SCHEMA_VERSION,
        "experiment": "PE-5-confirmatory-fixed-P3",
        "prompt_id": PROMPT_ID,
        "hours": list(hours),
        "strata": strata,
        "repetitions": repetitions,
        "provider": backend.provider,
        "model": backend.model,
        "region": backend.region,
        "system_prompt": backend.system_prompt,
        "prompt_sha256": _sha256(backend.system_prompt),
        "ioc_values_in_prompt": backend.ioc_values_in_prompt,
        "inference_parameters_sent": {"max_tokens": 2000},
        "runtime": extra() if callable(extra) else {},
    }


def _freeze_protocol(output_dir, protocol):
    path = Path(output_dir) / "protocol.json"
    if path.exists():
        frozen = json.loads(path.read_text(encoding="utf-8"))
        if frozen != protocol:
            raise RuntimeError("protocolo congelado no coincide con la reanudación")
        return
    _atomic_json(path, protocol)


def _read_results(path):
    path = Path(path)
    if not path.exists():
        return []
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"results.jsonl inválido en línea {line_number}") from exc
    keys = [(row.get("block"), row.get("repetition")) for row in rows]
    if len(keys) != len(set(keys)):
        raise RuntimeError("results.jsonl contiene corridas duplicadas")
    return rows


def _summary(rows, total, failures=0):
    return {
        "completed": len(rows),
        "total": total,
        "retries": sum(bool(row.get("verifier", {}).get("retried")) for row in rows),
        "failures": failures,
    }


def _json_value(value):
    """Normalize tuples and other JSON-compatible containers before comparison."""
    return json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True))


def verify_artifacts(output_dir, measure=None, require_complete=False):
    """Verify hashes, run keys, stage metrics, and protocol consistency."""
    output_dir = Path(output_dir)
    protocol_path = output_dir / "protocol.json"
    if not protocol_path.exists():
        raise RuntimeError("falta protocol.json")
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    if protocol.get("prompt_sha256") != _sha256(protocol.get("system_prompt", "")):
        raise RuntimeError("el hash del prompt no coincide")
    hours = protocol.get("hours", [])
    repetitions = protocol.get("repetitions")
    _validate_plan(hours, repetitions)
    strata = protocol.get("strata", {})
    if set(strata) != set(hours):
        raise RuntimeError("el protocolo no etiqueta todos los estratos")

    rows = _read_results(output_dir / "results.jsonl")
    expected = len(hours) * repetitions
    if require_complete and len(rows) != expected:
        raise RuntimeError(f"corrida incompleta: {len(rows)}/{expected}")

    for row in rows:
        block = row.get("block")
        repetition = row.get("repetition")
        if block not in hours or repetition not in range(1, repetitions + 1):
            raise RuntimeError(f"clave de corrida fuera del protocolo: {(block, repetition)!r}")
        if row.get("stratum") != strata[block]:
            raise RuntimeError(f"estrato incorrecto para {block}")
        if row.get("prompt_sha256") != protocol["prompt_sha256"]:
            raise RuntimeError(f"prompt incorrecto en {(block, repetition)!r}")
        if row.get("provider") != protocol.get("provider") or row.get("model") != protocol.get("model"):
            raise RuntimeError(f"motor incorrecto en {(block, repetition)!r}")

        context, context_record = _load_frozen_context(output_dir, block)
        if row.get("context_sha256") != context_record["context_sha256"]:
            raise RuntimeError(f"contexto incorrecto en {(block, repetition)!r}")
        if row.get("source") != context_record.get("source"):
            raise RuntimeError(f"metadatos de entrada incorrectos en {(block, repetition)!r}")
        retried = bool(row.get("verifier", {}).get("retried"))
        if row.get("llm_calls") != 1 + int(retried):
            raise RuntimeError(f"conteo de llamadas incorrecto en {(block, repetition)!r}")

        for stage in ("draft", "final"):
            value = row.get(stage, {})
            text = value.get("text", "")
            if not isinstance(text, str) or not text.strip():
                raise RuntimeError(f"texto {stage} vacío en {(block, repetition)!r}")
            if measure is not None:
                recalculated = _json_value(measure(text, context))
                if recalculated != value.get("metrics"):
                    raise RuntimeError(
                        f"métricas almacenadas no coinciden en {(block, repetition, stage)!r}"
                    )

    context_files = list((output_dir / "contexts").glob("*.txt"))
    if require_complete and len(context_files) != len(hours):
        raise RuntimeError(f"contextos incompletos: {len(context_files)}/{len(hours)}")
    return {
        "blocks": len(hours),
        "contexts": len(context_files),
        "completed": len(rows),
        "expected": expected,
        "stage_measurements": len(rows) * 2,
        "retries": sum(bool(row.get("verifier", {}).get("retried")) for row in rows),
        "llm_calls": sum(row.get("llm_calls", 0) for row in rows),
    }


def run_confirmatory(
    hours,
    repetitions,
    output_dir,
    backend,
    progress=None,
    max_new_runs=None,
    strata=None,
):
    """Run a resumable fixed-P3 experiment through an injected backend."""
    _validate_plan(hours, repetitions)
    if max_new_runs is not None and max_new_runs < 1:
        raise ValueError("max_new_runs debe ser positivo")
    if strata is None:
        strata = {block: "unspecified" for block in hours}
    if set(strata) != set(hours):
        raise ValueError("strata debe etiquetar exactamente todos los bloques")
    if not set(strata.values()) <= {"confirmatory", "replication", "unspecified"}:
        raise ValueError("strata contiene una etiqueta desconocida")
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    protocol = _protocol(hours, repetitions, backend, strata)
    _freeze_protocol(output_dir, protocol)

    result_path = output_dir / "results.jsonl"
    rows = _read_results(result_path)
    completed = {(row["block"], row["repetition"]) for row in rows}
    total = len(hours) * repetitions
    failures = 0
    new_runs = 0
    context_cache = {}
    report = progress or (lambda _state: None)
    report(_summary(rows, total, failures))

    for block in hours:
        for repetition in range(1, repetitions + 1):
            key = (block, repetition)
            if key in completed:
                continue
            if max_new_runs is not None and new_runs >= max_new_runs:
                report(_summary(rows, total, failures))
                return _summary(rows, total, failures)

            try:
                if block not in context_cache:
                    frozen = _load_frozen_context(output_dir, block)
                    if frozen is None:
                        context, source = backend.collect_context(block)
                        context_record = freeze_context(output_dir, block, context, source)
                    else:
                        context, context_record = frozen
                    context_cache[block] = (context, context_record)
                context, context_record = context_cache[block]

                started_at = _utc_now()
                draft = backend.generate(context)
                final, verifier = backend.verify(draft, context)
                row = {
                    "schema_version": SCHEMA_VERSION,
                    "status": "completed",
                    "prompt_id": PROMPT_ID,
                    "prompt_sha256": protocol["prompt_sha256"],
                    "context_sha256": context_record["context_sha256"],
                    "block": block,
                    "stratum": strata[block],
                    "repetition": repetition,
                    "provider": backend.provider,
                    "model": backend.model,
                    "started_at_utc": started_at,
                    "completed_at_utc": _utc_now(),
                    "llm_calls": 2 if verifier.get("retried") else 1,
                    "source": context_record["source"],
                    "draft": {"text": draft, "metrics": backend.measure(draft, context)},
                    "final": {"text": final, "metrics": backend.measure(final, context)},
                    "verifier": verifier,
                }
                _append_jsonl(result_path, row)
                rows.append(row)
                completed.add(key)
                new_runs += 1
            except Exception as exc:
                failures += 1
                _append_jsonl(
                    output_dir / "errors.jsonl",
                    {
                        "schema_version": SCHEMA_VERSION,
                        "status": "failed",
                        "block": block,
                        "repetition": repetition,
                        "failed_at_utc": _utc_now(),
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                )
            report(_summary(rows, total, failures))

    return _summary(rows, total, failures)


class RateLimiter:
    def __init__(self, calls_per_minute):
        self.interval = 60.0 / calls_per_minute if calls_per_minute else 0.0
        self.last_call = 0.0

    def wait(self):
        remaining = self.interval - (time.monotonic() - self.last_call)
        if remaining > 0:
            time.sleep(remaining)
        self.last_call = time.monotonic()


class ProductionBackend:
    """Thin boundary around the already deployed briefing implementation."""

    def __init__(self, calls_per_minute):
        sys.path.insert(0, "/app")
        import anthropic
        import generator as generator_module
        from eval_sintesis import measure
        from opencti_client import build_pycti_client

        self.g = generator_module
        self._measure = measure
        self._anthropic_version = anthropic.__version__
        self.provider = self.g.LLM_PROVIDER
        self.model = self.g.BEDROCK_MODEL
        self.region = self.g.AWS_REGION
        self.system_prompt = self.g.SYSTEM_PROMPT
        self.ioc_values_in_prompt = self.g.IOC_VALUES_IN_PROMPT
        if self.provider != "bedrock":
            raise RuntimeError(f"el proveedor activo no es Bedrock: {self.provider}")
        if self.ioc_values_in_prompt != 10:
            raise RuntimeError("P3 requiere exactamente diez valores de IOC en el contexto")

        self.client = build_pycti_client()
        curated = self.g._resolve_curated_ids(self.client)
        self.curated = curated
        self.g._resolve_curated_ids = lambda _client: curated

        limiter = RateLimiter(calls_per_minute)
        raw_call = self.g._call_llm

        def paced_call(stats_block, feedback=""):
            limiter.wait()
            return raw_call(stats_block, feedback)

        # Process-local only: this also paces the verifier's possible retry.
        self.g._call_llm = paced_call

    def protocol_metadata(self):
        hashes = {}
        for name in ("generator.py", "anchor.py", "eval_sintesis.py"):
            path = Path("/app") / name
            hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        return {
            "anthropic_sdk": self._anthropic_version,
            "python": sys.version.split()[0],
            "code_sha256": hashes,
        }

    def collect_context(self, block):
        start = datetime.strptime(block, HOUR_FORMAT).replace(tzinfo=timezone.utc)
        until = start + timedelta(hours=1)
        data = self.g._collect_threat_data(self.client, 1, until=until)
        if not data.get("total_touched"):
            raise RuntimeError(f"el bloque {block} no contiene indicadores actualizados")
        context = self.g._build_stats_block(data, 1, until=until)
        return context, {
            "window_start_utc": start.isoformat(),
            "window_end_utc": until.isoformat(),
            "total_touched": data.get("total_touched"),
            "total_new": data.get("total_new"),
            "indicator_sample_size": len(data.get("indicators", [])),
            "actor_sample_size": len(data.get("actors", [])),
            "malware_sample_size": len(data.get("malware", [])),
            "campaign_sample_size": len(data.get("campaigns", [])),
            "attack_pattern_sample_size": len(data.get("attack_patterns", [])),
        }

    def count_updated(self, block):
        start = datetime.strptime(block, HOUR_FORMAT).replace(tzinfo=timezone.utc)
        until = start + timedelta(hours=1)
        filters = self.g._make_updated_at_filter(1, self.curated, until)
        page = self.client.indicator.list(first=1, withPagination=True, filters=filters)
        return int(page["pagination"]["globalCount"])

    def generate(self, context):
        return self.g._call_llm(context)

    def verify(self, draft, context):
        return self.g._verify_draft(draft, context)

    def measure(self, text, context):
        return self._measure(text, context)


def _print_progress(state):
    print(
        "PROGRESS "
        f"{state['completed']}/{state['total']} "
        f"retries={state['retries']} failures={state['failures']}",
        file=sys.stderr,
        flush=True,
    )


def _print_discovery(state):
    if state["inspected"] == 1 or state["inspected"] % 24 == 0 or state["updated"]:
        print(
            "SCAN "
            f"inspected={state['inspected']} productive={state['productive']} "
            f"selected={state['selected']} block={state['block']} updated={state['updated']}",
            file=sys.stderr,
            flush=True,
        )


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser("discover")
    discover.add_argument("--since", required=True)
    discover.add_argument("--until", required=True)
    discover.add_argument("--limit", type=int, default=48)
    discover.add_argument("--exclude-json")
    discover.add_argument("--output", required=True)

    mix = subparsers.add_parser("mix")
    mix.add_argument("--confirmatory", required=True)
    mix.add_argument("--exploratory", required=True)
    mix.add_argument("--total-blocks", type=int, default=48)
    mix.add_argument("--seed", required=True)
    mix.add_argument("--output", required=True)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--output-dir", required=True)
    verify.add_argument("--allow-partial", action="store_true")

    run = subparsers.add_parser("run")
    run.add_argument("--plan", required=True, help="JSON producido por el subcomando mix")
    run.add_argument("--output-dir", required=True)
    run.add_argument("--repetitions", type=int, default=3)
    run.add_argument("--calls-per-minute", type=int, default=8)
    run.add_argument("--max-new-runs", type=int)
    args = parser.parse_args()

    if args.command == "discover":
        backend = ProductionBackend(0)
        excluded = set()
        if args.exclude_json:
            excluded = set(json.loads(Path(args.exclude_json).read_text(encoding="utf-8")))
        hours, summary = discover_productive_hours(
            count_updated=backend.count_updated,
            since=args.since,
            until=args.until,
            limit=args.limit,
            excluded=excluded,
            progress=_print_discovery,
        )
        _atomic_json(args.output, hours)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "rule": "latest productive complete hours, descending UTC; exploratory blocks excluded",
            "since": args.since,
            "until": args.until,
            "limit": args.limit,
            "excluded": sorted(excluded),
            "hours": hours,
            "summary": summary,
        }
        _atomic_json(str(args.output) + ".manifest.json", manifest)
        print(json.dumps(summary, sort_keys=True))
        return 0 if len(hours) == args.limit else 2

    if args.command == "mix":
        confirmatory = json.loads(Path(args.confirmatory).read_text(encoding="utf-8"))
        exploratory = json.loads(Path(args.exploratory).read_text(encoding="utf-8"))
        plan = build_mixed_plan(
            confirmatory_hours=confirmatory,
            exploratory_hours=exploratory,
            total_blocks=args.total_blocks,
            seed=args.seed,
        )
        _atomic_json(args.output, plan)
        print(json.dumps({
            "confirmatory": len(plan["confirmatory_hours"]),
            "replication": len(plan["replication_hours"]),
            "total": len(plan["hours"]),
        }, sort_keys=True))
        return 0

    if args.command == "verify":
        sys.path.insert(0, "/app")
        from eval_sintesis import measure

        summary = verify_artifacts(
            args.output_dir,
            measure=measure,
            require_complete=not args.allow_partial,
        )
        print(json.dumps(summary, sort_keys=True))
        return 0

    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    hours = plan["hours"]
    backend = ProductionBackend(args.calls_per_minute)
    summary = run_confirmatory(
        hours=hours,
        repetitions=args.repetitions,
        output_dir=args.output_dir,
        backend=backend,
        progress=_print_progress,
        max_new_runs=args.max_new_runs,
        strata=plan["strata"],
    )
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["completed"] == summary["total"] and not summary["failures"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
