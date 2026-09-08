"""
eval_scoring.py — Pure scoring functions for the IOC extraction eval (EXT-01).

Set-based per-doc TP/FP/FN, micro-averaged P/R/F1 per IOC type and per doc
format. No third-party imports, no LLM calls — fully verified offline.
"""
from collections import defaultdict


def _prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 1.0  # no predictions on empty gold = perfect precision
    r = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": f1}


def score(predicted: set, gold: set) -> dict:
    """Score one doc: predicted vs gold sets of (type, value) pairs."""
    tp = len(predicted & gold)
    fp = len(predicted - gold)
    fn = len(gold - predicted)
    return _prf(tp, fp, fn)


def aggregate(per_doc: list) -> dict:
    """
    Roll up per-doc results into micro-averaged P/R/F1 buckets.

    per_doc: list of {"format": str, "predicted": set[(type, value)], "gold": set[(type, value)]}
    Returns {"per_type": {ip: {...}, ...}, "per_format": {advisory: {...}, ...}} —
    tp/fp/fn summed within each bucket BEFORE computing P/R/F1 (micro-average).
    """
    type_counts: dict = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    fmt_counts: dict = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

    for doc in per_doc:
        doc_score = score(doc["predicted"], doc["gold"])
        for k in ("tp", "fp", "fn"):
            fmt_counts[doc["format"]][k] += doc_score[k]

        pred_by_type: dict = defaultdict(set)
        gold_by_type: dict = defaultdict(set)
        for pair in doc["predicted"]:
            pred_by_type[pair[0]].add(pair)
        for pair in doc["gold"]:
            gold_by_type[pair[0]].add(pair)
        for t in set(pred_by_type) | set(gold_by_type):
            type_score = score(pred_by_type[t], gold_by_type[t])
            for k in ("tp", "fp", "fn"):
                type_counts[t][k] += type_score[k]

    return {
        "per_type": {t: _prf(**c) for t, c in type_counts.items()},
        "per_format": {f: _prf(**c) for f, c in fmt_counts.items()},
    }
