"""
test_eval_extraction.py — live-LLM eval harness for IOC extraction quality (EXT-01).

Runs the real extract_from_text() path (chunk -> LLM -> refang -> dedup) over the
labeled corpus in tests/eval_corpus/ and scores precision/recall/F1 per IOC type
and per doc format via tests/eval_scoring.py.

Run commands (pytest.ini sets `addopts = -m "not llm_eval"`, so a bare run stays
offline-green and this module is deselected by default):

  offline default (harness deselected):
      cd services/intel-extractor && python3 -m pytest -q

  live eval (needs Ollama — run inside the compose network):
      docker compose --profile extractor exec intel-extractor python -m pytest -m llm_eval tests/ -q

Passing `-m llm_eval` on the command line overrides the addopts exclusion.

Outputs: a per-type x per-format P/R/F1 table on the terminal and
tests/eval_corpus/last_run.json (gitignored) with per-doc predicted/gold sets
and the aggregates.

Regression gate: test_eval_gate reads tests/eval_corpus/baseline.json, whose
shape is exactly eval_scoring.aggregate() output
({"per_type": {...}, "per_format": {...}}). The baseline is committed by plan
11-03 after the post-refang capture; until then the gate skips.
"""
import json
import pathlib
import re

import pytest

try:
    import requests
    import extractor as _extractor
    from extractor import build_stix_pattern, extract_from_text
    from config import OLLAMA_URL
    from ioc_fanger import fang
    from tests.eval_scoring import aggregate, score
    _IMPORT_OK = True
except ImportError:
    _IMPORT_OK = False

pytestmark = [
    pytest.mark.llm_eval,
    pytest.mark.skipif(not _IMPORT_OK, reason="extractor not importable"),
]

CORPUS = pathlib.Path(__file__).parent / "eval_corpus"
BASELINE = CORPUS / "baseline.json"

# ATT&CK-ID-shaped token, sub-techniques included (EXT-05)
_ATTACK_ID_RE = re.compile(r"(?i)\bT\d{4}(?:\.\d{3})?\b")


def _ollama_up() -> bool:
    try:
        return requests.get(f"{OLLAMA_URL}/api/tags", timeout=2).ok
    except Exception:
        return False


def _print_table(agg: dict) -> None:
    print("\n== IOC extraction eval ==")
    for section in ("per_format", "per_type"):
        print(f"-- {section} --")
        print(f"{'bucket':<24}{'tp':>4}{'fp':>4}{'fn':>4}{'prec':>8}{'rec':>8}{'f1':>8}")
        for bucket, m in sorted(agg[section].items()):
            print(
                f"{bucket:<24}{m['tp']:>4}{m['fp']:>4}{m['fn']:>4}"
                f"{m['precision']:>8.3f}{m['recall']:>8.3f}{m['f1']:>8.3f}"
            )


@pytest.fixture(scope="module")
def eval_run():
    """Run the whole corpus through extract_from_text ONCE; both tests share the result."""
    if not _ollama_up():
        pytest.skip(
            "Ollama unreachable — run inside compose: "
            "docker compose --profile extractor exec intel-extractor python -m pytest -m llm_eval tests/ -q"
        )

    docs: list[dict] = []
    # Record raw technique dicts (name + description) per doc for the EXT-05 gate:
    # the extract_from_text seam only exposes lowercased names, so wrap call_llm —
    # delegating to the real one — to capture the full LLM output without extra calls.
    real_call_llm = _extractor.call_llm
    current_techniques: list[dict] = []

    def recording_call_llm(*args, **kwargs):
        result = real_call_llm(*args, **kwargs)
        current_techniques.extend(result.get("techniques", []))
        return result

    _extractor.call_llm = recording_call_llm
    try:
        for txt_path in sorted(CORPUS.glob("*.txt")):
            gold_doc = json.loads((CORPUS / f"{txt_path.stem}.expected.json").read_text())
            text = txt_path.read_text()
            current_techniques.clear()
            extraction = extract_from_text(text, source_type=gold_doc["format"])
            # Count as predicted only what would become a real indicator (EXT-02)
            predicted = {
                (ioc["type"], ioc["value"])
                for ioc in extraction["unique_iocs"]
                if build_stix_pattern(ioc["type"], ioc["value"]) is not None
            }
            gold = {(ioc["type"], ioc["value"]) for ioc in gold_doc["iocs"]}
            docs.append({
                "stem": txt_path.stem,
                "format": gold_doc["format"],
                "text": text,
                "predicted": predicted,
                "gold": gold,
                "techniques": list(current_techniques),
            })
    finally:
        _extractor.call_llm = real_call_llm

    aggregates = aggregate(docs)
    _print_table(aggregates)
    (CORPUS / "last_run.json").write_text(json.dumps({
        "per_doc": {
            d["stem"]: {
                "predicted": sorted(map(list, d["predicted"])),
                "gold": sorted(map(list, d["gold"])),
            }
            for d in docs
        },
        "aggregates": aggregates,
    }, indent=2) + "\n")
    return {"docs": docs, "aggregates": aggregates}


def test_eval_report(eval_run):
    """Reporting vehicle (11-03 baseline capture): every corpus doc produced a result."""
    assert len(eval_run["docs"]) == 24
    for d in eval_run["docs"]:
        assert isinstance(d["predicted"], set), f"{d['stem']}: no result"


def test_eval_gate(eval_run):
    """Regression gate — armed once 11-03 commits tests/eval_corpus/baseline.json."""
    if not BASELINE.exists():
        pytest.skip("baseline not captured yet (11-03)")
    baseline = json.loads(BASELINE.read_text())
    agg = eval_run["aggregates"]
    docs = {d["stem"]: d for d in eval_run["docs"]}

    # EXT-03: advisory extraction must not regress
    assert agg["per_format"]["advisory"]["f1"] >= baseline["per_format"]["advisory"]["f1"]

    # Success criterion 3: blog/report recall must not drop below baseline
    assert agg["per_format"]["blog"]["recall"] >= baseline["per_format"]["blog"]["recall"]
    assert agg["per_format"]["report"]["recall"] >= baseline["per_format"]["report"]["recall"]

    # EXT-02: the all-defanged doc must be fully recovered
    defanged = docs["bulletin_06_defanged"]
    assert score(defanged["predicted"], defanged["gold"])["recall"] == 1.0

    # Success criterion 4: zero hallucinated IOCs on the IOC-empty blog
    assert len(docs["blog_06_empty"]["predicted"]) == 0, (
        f"empty-blog FPs: {sorted(docs['blog_06_empty']['predicted'])}"
    )

    # EXT-05: no ATT&CK-ID-shaped token in a predicted technique name OR description
    # unless that literal appears in the source doc
    for d in eval_run["docs"]:
        doc_upper = d["text"].upper()
        for tech in d["techniques"]:
            for field in (tech.get("name", ""), tech.get("description", "")):
                for m in _ATTACK_ID_RE.finditer(str(field)):
                    assert m.group(0).upper() in doc_upper, (
                        f"{d['stem']}: hallucinated ATT&CK id {m.group(0)!r} in {field!r}"
                    )

    # Pitfall 6 grounding: every predicted value must appear in the refanged source doc
    for d in eval_run["docs"]:
        fanged = fang(d["text"])
        for ioc_type, value in d["predicted"]:
            assert value in fanged, f"{d['stem']}: ungrounded prediction {ioc_type}:{value}"
