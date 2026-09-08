"""Regresiones de las convenciones matemáticas publicadas en §2.9."""
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]


def _run_score(run_path: Path, reference_path: Path, source_path: Path) -> str:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "corpus/eval/score.py"),
            str(run_path),
            str(reference_path),
            str(source_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def test_score_reports_citation_rate_na_when_no_objects_are_emitted(tmp_path):
    """Sin instancias objeto–cita, la tasa no puede presentarse como 0/0."""
    run_path = tmp_path / "run.json"
    reference_path = tmp_path / "reference.json"
    source_path = tmp_path / "source.txt"
    run_path.write_text(json.dumps({"entities": [], "relationships": []}))
    reference_path.write_text(json.dumps({"objects": []}))
    source_path.write_text("")

    output = _run_score(run_path, reference_path, source_path)

    assert "Citas localizadas: N/A (0/0) contra el texto" in output


def test_score_reports_precision_na_when_the_extractor_emits_no_items():
    output = _run_score(
        ROOT / "corpus/eval/runs/aa26-204a.haiku-devrun-20260818.json",
        ROOT / "corpus/aa26-204a/AA26-204A.stix_.json",
        ROOT / "corpus/eval/aa26-204a.txt",
    )

    indicator_line = next(
        line for line in output.splitlines() if line.startswith("indicator")
    )
    assert "N/A" in indicator_line


def test_score_lists_relationship_disagreements_for_manual_adjudication():
    output = _run_score(
        ROOT / "corpus/eval/runs/aa26-204a.v2.1.json",
        ROOT / "corpus/aa26-204a/AA26-204A.stix_.json",
        ROOT / "corpus/eval/aa26-204a.txt",
    )

    assert "P_STIX" in output
    assert "R_STIX" in output
    assert "F1_STIX" in output
    assert "FP_STIX (indicator) — ausentes del anexo; adjudicar contra la prosa:" in output
    assert "FP_STIX (rel) — ausentes del anexo; adjudicar contra la prosa:" in output
    assert "Fuera del alcance de STIX" in output
    assert "Fuera del alcance del GT" not in output


def test_versioned_builders_reproduce_their_artifacts(tmp_path):
    (tmp_path / "runs").mkdir()

    for version in ("20", "21"):
        subprocess.run(
            [sys.executable, str(ROOT / f"corpus/eval/build_run_v{version}.py")],
            cwd=tmp_path,
            check=True,
            capture_output=True,
            text=True,
        )
        dotted = f"2.{version[-1]}"
        generated = tmp_path / "runs" / f"aa26-204a.v{dotted}.json"
        versioned = ROOT / "corpus/eval/runs" / generated.name
        assert generated.read_bytes() == versioned.read_bytes()
