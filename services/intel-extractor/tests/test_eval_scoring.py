"""
Unit tests for the pure eval scorer (EXT-01 measurement core) + corpus lint.

Offline by design: eval_scoring has no third-party imports and no LLM calls.
The corpus lint proves eval_corpus/ integrity (research Pitfall 8) without
touching the LLM: gold values are canonical, docs are single-chunk, and the
two mandatory hard cases exist.
"""
import json
import pathlib

import pytest

from tests.eval_scoring import aggregate, score

try:
    from extractor import _IOC_VALUE_RE
    from ioc_fanger import fang
    _IMPORT_OK = True
except ImportError:
    _IMPORT_OK = False

_skip = pytest.mark.skipif(not _IMPORT_OK, reason="extractor not importable")

CORPUS = pathlib.Path(__file__).parent / "eval_corpus"
FORMATS = {"advisory", "blog", "bulletin", "report"}


def _load_corpus():
    """Return [(stem, text, gold_dict)] for every doc in the corpus."""
    out = []
    for txt in sorted(CORPUS.glob("*.txt")):
        sidecar = CORPUS / f"{txt.stem}.expected.json"
        gold = json.loads(sidecar.read_text()) if sidecar.exists() else None
        out.append((txt.stem, txt.read_text(), gold))
    return out


# ── score() ──────────────────────────────────────────────────────────────────

def test_score_perfect_match():
    gold = {("ip", "192.0.2.1"), ("domain", "evil.example")}
    result = score(set(gold), gold)
    assert result == {"tp": 2, "fp": 0, "fn": 0, "precision": 1.0, "recall": 1.0, "f1": 1.0}


def test_score_empty_gold_empty_predicted_is_perfect():
    """No predictions on empty gold = perfect (empty-blog hard case)."""
    result = score(set(), set())
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["tp"] == result["fp"] == result["fn"] == 0


def test_score_empty_gold_nonempty_predicted_counts_fp():
    result = score({("ip", "192.0.2.9")}, set())
    assert result["fp"] == 1
    assert result["precision"] < 1.0
    assert result["precision"] == 0.0
    # recall on empty gold stays perfect (nothing to find)
    assert result["recall"] == 1.0


def test_score_mixed():
    predicted = {("ip", "192.0.2.1"), ("ip", "198.51.100.2"), ("url", "http://c2.example/x")}
    gold = {("ip", "192.0.2.1"), ("domain", "evil.example")}
    result = score(predicted, gold)
    assert result["tp"] == 1
    assert result["fp"] == 2
    assert result["fn"] == 1
    assert result["precision"] == pytest.approx(1 / 3)
    assert result["recall"] == pytest.approx(0.5)
    assert result["f1"] == pytest.approx(2 * (1 / 3) * 0.5 / ((1 / 3) + 0.5))


# ── aggregate() ──────────────────────────────────────────────────────────────

def test_aggregate_known_answer():
    """Two synthetic docs with hand-computed per-type and per-format P/R/F1 (micro-average)."""
    per_doc = [
        {
            "format": "advisory",
            "predicted": {("ip", "192.0.2.1"), ("ip", "198.51.100.2")},
            "gold": {("ip", "192.0.2.1"), ("domain", "evil.example")},
        },
        {
            "format": "blog",
            "predicted": {("ip", "203.0.113.3"), ("domain", "evil.example")},
            "gold": {("ip", "203.0.113.3")},
        },
    ]
    result = aggregate(per_doc)

    # per_type — ip: tp=2, fp=1, fn=0 → p=2/3, r=1.0, f1=0.8
    ip = result["per_type"]["ip"]
    assert (ip["tp"], ip["fp"], ip["fn"]) == (2, 1, 0)
    assert ip["precision"] == pytest.approx(2 / 3)
    assert ip["recall"] == pytest.approx(1.0)
    assert ip["f1"] == pytest.approx(0.8)

    # per_type — domain: tp=0, fp=1, fn=1 → p=0, r=0, f1=0
    dom = result["per_type"]["domain"]
    assert (dom["tp"], dom["fp"], dom["fn"]) == (0, 1, 1)
    assert dom["precision"] == 0.0
    assert dom["recall"] == 0.0
    assert dom["f1"] == 0.0

    # per_format — advisory: tp=1, fp=1, fn=1 → p=0.5, r=0.5, f1=0.5
    adv = result["per_format"]["advisory"]
    assert (adv["tp"], adv["fp"], adv["fn"]) == (1, 1, 1)
    assert adv["f1"] == pytest.approx(0.5)

    # per_format — blog: tp=1, fp=1, fn=0 → p=0.5, r=1.0, f1=2/3
    blog = result["per_format"]["blog"]
    assert (blog["tp"], blog["fp"], blog["fn"]) == (1, 1, 0)
    assert blog["precision"] == pytest.approx(0.5)
    assert blog["recall"] == pytest.approx(1.0)
    assert blog["f1"] == pytest.approx(2 / 3)


def test_aggregate_empty_doc_list():
    result = aggregate([])
    assert result == {"per_type": {}, "per_format": {}}


# ── corpus lint (offline, unmarked — guards research Pitfall 8) ──────────────

def test_corpus_lint_pairing_and_counts():
    """Every .txt has a sidecar and vice versa; 24 docs, 6 per format."""
    txt_stems = {p.stem for p in CORPUS.glob("*.txt")}
    sidecar_stems = {p.name.removesuffix(".expected.json") for p in CORPUS.glob("*.expected.json")}
    assert txt_stems == sidecar_stems
    assert len(txt_stems) == 24

    per_format: dict = {}
    for _, _, gold in _load_corpus():
        assert gold is not None
        assert gold["format"] in FORMATS
        per_format[gold["format"]] = per_format.get(gold["format"], 0) + 1
    assert per_format == {f: 6 for f in FORMATS}


@_skip
def test_corpus_lint_gold_values_canonical():
    """Every gold value is stored canonical: type is supported and value passes _IOC_VALUE_RE."""
    for stem, _, gold in _load_corpus():
        for ioc in gold["iocs"]:
            assert ioc["type"] in _IOC_VALUE_RE, f"{stem}: unsupported gold type {ioc['type']!r}"
            assert _IOC_VALUE_RE[ioc["type"]].match(ioc["value"]), (
                f"{stem}: gold value {ioc['value']!r} fails {ioc['type']} shape — not canonical"
            )


def test_corpus_lint_no_routable_infrastructure():
    """Gold IPs are RFC 5737 documentation ranges only; domains/urls/emails use .example."""
    for stem, _, gold in _load_corpus():
        for ioc in gold["iocs"]:
            v = ioc["value"]
            if ioc["type"] == "ip":
                assert v.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), f"{stem}: routable IP {v}"
            elif ioc["type"] in ("domain", "url", "email"):
                assert ".example" in v, f"{stem}: non-.example value {v}"


@_skip
def test_corpus_lint_gold_grounded_in_doc():
    """Every gold value appears in fang(doc_text) — guards labeling typos and keeps grounding valid."""
    for stem, text, gold in _load_corpus():
        fanged = fang(text)
        for ioc in gold["iocs"]:
            assert ioc["value"] in fanged, f"{stem}: gold {ioc['value']!r} not found in refanged doc"


@_skip
def test_corpus_lint_defanged_hard_case():
    """bulletin_06_defanged: EVERY IOC defanged — canonical value absent raw, present after fang()."""
    text = (CORPUS / "bulletin_06_defanged.txt").read_text()
    gold = json.loads((CORPUS / "bulletin_06_defanged.expected.json").read_text())
    assert "hxxp" in text
    assert len(gold["iocs"]) > 0
    fanged = fang(text)
    for ioc in gold["iocs"]:
        assert ioc["value"] not in text, f"canonical {ioc['value']!r} appears raw — doc not fully defanged"
        assert ioc["value"] in fanged, f"{ioc['value']!r} not recoverable via fang()"


def test_corpus_lint_empty_blog_hard_case():
    """blog_06_empty: IOC-empty narrative blog with an empty gold array."""
    gold = json.loads((CORPUS / "blog_06_empty.expected.json").read_text())
    assert gold["format"] == "blog"
    assert gold["iocs"] == []


def test_corpus_lint_gitignore_covers_last_run():
    assert "last_run.json" in (CORPUS / ".gitignore").read_text()
