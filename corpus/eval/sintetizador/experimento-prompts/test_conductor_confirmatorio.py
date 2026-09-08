import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).with_name("conductor_confirmatorio.py")
SPEC = importlib.util.spec_from_file_location("conductor_confirmatorio", SCRIPT)
cc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cc)


class FakeBackend:
    provider = "bedrock"
    model = "haiku-fixed"
    region = "us-east-1"
    system_prompt = "PROMPT P3 FIJO"
    ioc_values_in_prompt = 10

    def __init__(self):
        self.collected = []
        self.generated = []

    def collect_context(self, block):
        self.collected.append(block)
        return (
            f"contexto exacto {block}",
            {"total_touched": 7, "total_new": 2},
        )

    def generate(self, context):
        self.generated.append(context)
        return f"borrador {len(self.generated)} para {context}"

    def verify(self, draft, context):
        return draft + " verificado", {"retried": len(self.generated) == 2}

    def measure(self, text, context):
        return {"palabras": len(text.split()), "contexto": context}


def _records(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_run_freezes_one_context_per_block_and_records_every_repetition(tmp_path):
    """Catches recollecting a block for every repetition or losing a measured stage."""
    backend = FakeBackend()
    progress = []

    summary = cc.run_confirmatory(
        hours=["2026-09-02 10", "2026-09-02 11"],
        repetitions=2,
        output_dir=tmp_path,
        backend=backend,
        progress=progress.append,
        strata={
            "2026-09-02 10": "confirmatory",
            "2026-09-02 11": "replication",
        },
    )

    assert summary == {"completed": 4, "total": 4, "retries": 1, "failures": 0}
    assert backend.collected == ["2026-09-02 10", "2026-09-02 11"]
    assert len(backend.generated) == 4
    assert progress[-1] == summary

    rows = _records(tmp_path / "results.jsonl")
    assert {(r["block"], r["repetition"]) for r in rows} == {
        ("2026-09-02 10", 1),
        ("2026-09-02 10", 2),
        ("2026-09-02 11", 1),
        ("2026-09-02 11", 2),
    }
    assert all(r["prompt_id"] == "P3-production" for r in rows)
    assert {r["block"]: r["stratum"] for r in rows} == {
        "2026-09-02 10": "confirmatory",
        "2026-09-02 11": "replication",
    }
    assert all(r["draft"]["text"].startswith("borrador") for r in rows)
    assert all(r["final"]["text"].endswith("verificado") for r in rows)
    assert sum(r["llm_calls"] for r in rows) == 5

    contexts = sorted((tmp_path / "contexts").glob("*.txt"))
    assert len(contexts) == 2
    assert {p.read_text() for p in contexts} == {
        "contexto exacto 2026-09-02 10",
        "contexto exacto 2026-09-02 11",
    }


def test_resume_does_not_repeat_completed_model_calls(tmp_path):
    """Catches charging Bedrock again for run keys already durably recorded."""
    first = FakeBackend()
    cc.run_confirmatory(
        hours=["2026-09-02 10"],
        repetitions=2,
        output_dir=tmp_path,
        backend=first,
    )
    second = FakeBackend()

    summary = cc.run_confirmatory(
        hours=["2026-09-02 10"],
        repetitions=2,
        output_dir=tmp_path,
        backend=second,
    )

    assert summary == {"completed": 2, "total": 2, "retries": 1, "failures": 0}
    assert second.collected == []
    assert second.generated == []
    assert len(_records(tmp_path / "results.jsonl")) == 2


def test_freeze_context_refuses_to_overwrite_different_input(tmp_path):
    """Catches mixing two OpenCTI snapshots under the same hourly block label."""
    first = cc.freeze_context(
        tmp_path,
        "2026-09-02 10",
        "contexto original",
        {"total_touched": 7, "total_new": 2},
    )
    same = cc.freeze_context(
        tmp_path,
        "2026-09-02 10",
        "contexto original",
        {"total_touched": 7, "total_new": 2},
    )

    assert same == first
    with pytest.raises(RuntimeError, match="contexto congelado no coincide"):
        cc.freeze_context(
            tmp_path,
            "2026-09-02 10",
            "contexto cambiado",
            {"total_touched": 8, "total_new": 3},
        )


def test_protocol_refuses_prompt_or_plan_drift_on_resume(tmp_path):
    """Catches silently resuming a confirmatory run with a changed protocol."""
    backend = FakeBackend()
    cc.run_confirmatory(
        hours=["2026-09-02 10"],
        repetitions=1,
        output_dir=tmp_path,
        backend=backend,
    )
    changed = FakeBackend()
    changed.system_prompt = "PROMPT MODIFICADO"

    with pytest.raises(RuntimeError, match="protocolo congelado no coincide"):
        cc.run_confirmatory(
            hours=["2026-09-02 10"],
            repetitions=1,
            output_dir=tmp_path,
            backend=changed,
        )


@pytest.mark.parametrize("hours", [[], ["malformada"], ["2026-09-02 10"] * 2])
def test_invalid_hour_plans_are_rejected_before_any_call(tmp_path, hours):
    """Catches empty, malformed, or duplicate plans reaching the model."""
    backend = FakeBackend()

    with pytest.raises(ValueError):
        cc.run_confirmatory(
            hours=hours,
            repetitions=3,
            output_dir=tmp_path,
            backend=backend,
        )

    assert backend.generated == []


def test_discovery_selects_most_recent_productive_unseen_hours():
    """Catches reusing exploratory blocks or admitting zero-activity hours."""
    counts = {
        "2026-09-02 10": 4,
        "2026-09-02 11": 0,
        "2026-09-02 12": 8,
        "2026-09-02 13": 3,
    }
    inspected = []

    selected, summary = cc.discover_productive_hours(
        count_updated=lambda block: inspected.append(block) or counts[block],
        since="2026-09-02 10",
        until="2026-09-02 14",
        limit=2,
        excluded={"2026-09-02 12"},
    )

    assert selected == ["2026-09-02 13", "2026-09-02 10"]
    assert inspected == ["2026-09-02 13", "2026-09-02 12", "2026-09-02 11", "2026-09-02 10"]
    assert summary == {
        "inspected": 4,
        "productive": 3,
        "excluded_productive": 1,
        "selected": 2,
    }


def test_mixed_plan_uses_all_new_blocks_and_hash_selects_replication_blocks():
    """Catches cherry-picking old blocks or mislabeling the confirmatory stratum."""
    plan = cc.build_mixed_plan(
        confirmatory_hours=["2026-09-02 10", "2026-09-02 11"],
        exploratory_hours=[
            "2026-08-01 01",
            "2026-08-01 02",
            "2026-08-01 03",
            "2026-08-01 04",
        ],
        total_blocks=4,
        seed="pe5-fixed",
    )

    assert set(plan["hours"]) == {
        "2026-09-02 10",
        "2026-09-02 11",
        "2026-08-01 01",
        "2026-08-01 04",
    }
    assert plan["confirmatory_hours"] == ["2026-09-02 10", "2026-09-02 11"]
    assert set(plan["replication_hours"]) == {"2026-08-01 01", "2026-08-01 04"}
    assert {plan["strata"][h] for h in plan["confirmatory_hours"]} == {"confirmatory"}
    assert {plan["strata"][h] for h in plan["replication_hours"]} == {"replication"}


def test_verify_artifacts_recomputes_both_stages_from_frozen_context(tmp_path):
    """Catches accepting stored metrics that no longer match text and context."""
    backend = FakeBackend()
    cc.run_confirmatory(
        hours=["2026-09-02 10"],
        repetitions=2,
        output_dir=tmp_path,
        backend=backend,
    )

    summary = cc.verify_artifacts(tmp_path, measure=backend.measure, require_complete=True)

    assert summary == {
        "blocks": 1,
        "contexts": 1,
        "completed": 2,
        "expected": 2,
        "stage_measurements": 4,
        "retries": 1,
        "llm_calls": 3,
    }

    rows = _records(tmp_path / "results.jsonl")
    rows[0]["draft"]["metrics"]["palabras"] = 999
    (tmp_path / "results.jsonl").write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n"
    )
    with pytest.raises(RuntimeError, match="métricas almacenadas no coinciden"):
        cc.verify_artifacts(tmp_path, measure=backend.measure, require_complete=True)
