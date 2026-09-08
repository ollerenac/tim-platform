"""Dedicated command surface for CISA/STIX evaluation evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from .cisa_intake import freeze_selection
from .cisa_execution import finalize_execution, verify_execution, write_pilot
from .cisa_reference import build_references
from .cisa_runner import load_runtime, run_all, run_once, run_smoke, seal_execution
from .cisa_score import (
    ScoreIntegrityError,
    score_experiment,
    write_score_artifacts,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="exp02-cisa")
    commands = parser.add_subparsers(dest="command", required=True)
    freeze = commands.add_parser("freeze", help="admit and freeze CISA PDF/STIX pairs")
    freeze.add_argument("--intake", required=True, type=Path)
    freeze.add_argument("--evidence", required=True, type=Path)
    freeze.add_argument("--cutoff-utc", required=True)
    freeze.add_argument("--final-count", type=int, default=24)
    reference = commands.add_parser("build-reference", help="canonicalize frozen official CISA STIX")
    reference.add_argument("--evidence", required=True, type=Path)
    seal = commands.add_parser("seal", help="write the immutable CISA Bedrock execution manifest")
    seal.add_argument("--evidence", required=True, type=Path)
    pilot = commands.add_parser("pilot", help="write the four-document historical comparator diagnostic")
    pilot.add_argument("--evidence", required=True, type=Path)
    finalize = commands.add_parser("finalize", help="write immutable schema-v2 pre-run evidence")
    finalize.add_argument("--evidence", required=True, type=Path)
    verify = commands.add_parser("verify", help="fail-closed verification of schema-v2 execution evidence")
    verify.add_argument("--evidence", required=True, type=Path)
    verify.add_argument("--stage", required=True, choices=("pre-run", "complete"))
    smoke = commands.add_parser("smoke", help="perform the single guarded Bedrock smoke call")
    smoke.add_argument("--evidence", required=True, type=Path)
    run_one = commands.add_parser("run-one", help="perform one immutable CISA extraction")
    run_one.add_argument("--evidence", required=True, type=Path)
    run_one.add_argument("--code", required=True)
    run_one.add_argument("--repetition", required=True, type=int)
    run_all = commands.add_parser("run-all", help="resume all missing CISA extraction identities")
    run_all.add_argument("--evidence", required=True, type=Path)
    score = commands.add_parser("score", help="score the complete immutable CISA evaluation")
    score.add_argument("--evidence", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "score":
        try:
            result = score_experiment(args.evidence)
            summary = write_score_artifacts(args.evidence, result)
        except (
            FileExistsError,
            OSError,
            ValueError,
            json.JSONDecodeError,
            ScoreIntegrityError,
        ) as error:
            print(str(error), file=sys.stderr)
            return 2
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
        return 0
    if args.command == "build-reference":
        try:
            references = build_references(args.evidence)
        except (FileExistsError, OSError, ValueError, json.JSONDecodeError) as error:
            print(str(error), file=sys.stderr)
            return 2
        print(json.dumps({"final": len(references), "reference": "reference"}, sort_keys=True))
        return 0
    if args.command in {"pilot", "verify"}:
        try:
            result = write_pilot(args.evidence) if args.command == "pilot" else verify_execution(
                args.evidence, stage=args.stage
            )
        except (FileExistsError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
            print(str(error), file=sys.stderr)
            return 2
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    if args.command in {"seal", "finalize", "smoke", "run-one", "run-all"}:
        try:
            runtime = load_runtime()
            if args.command == "seal":
                result = seal_execution(args.evidence, runtime)
            elif args.command == "finalize":
                result = finalize_execution(args.evidence, runtime)
            elif args.command == "smoke":
                result = run_smoke(args.evidence, runtime)
            elif args.command == "run-one":
                result = run_once(args.evidence, args.code, args.repetition, runtime)
            else:
                result = run_all(args.evidence, runtime)
        except (FileExistsError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
            print(str(error), file=sys.stderr)
            return 2
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        if isinstance(result, dict) and result.get("status") == "error":
            return 1
        return 0
    if args.final_count != 24:
        print("CISA evaluation requires exactly 24 final documents", file=sys.stderr)
        return 2
    try:
        manifest = freeze_selection(
            args.intake, args.evidence, args.cutoff_utc, final_count=args.final_count,
        )
    except (FileExistsError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps({
        "candidates": len(manifest["documents"]) + len(manifest["reserve"]) + len(manifest["rejected"]),
        "final": len(manifest["documents"]),
        "reserve": len(manifest["reserve"]),
        "rejected": len(manifest["rejected"]),
        "manifest": "selection-manifest.v1.json",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
