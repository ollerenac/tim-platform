"""Regression tests for the frozen four-document Bedrock evaluation scorer."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).with_name("score_runs.py")
SPEC = importlib.util.spec_from_file_location("cert_real_score_runs", MODULE_PATH)
score_runs = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(score_runs)


def test_normalize_entity_uses_defang_case_and_exact_attack_id():
    assert score_runs.normalize_entity(
        {"type": "indicator", "value": "HXXPS://Evil[.]Example/a"}
    ) == ("indicator", "https://evil.example/a")
    assert score_runs.normalize_entity(
        {"type": "malware", "value": "Málware X"}
    ) == ("malware", "malware x")
    assert score_runs.normalize_entity(
        {"type": "attack-pattern", "value": "Process Discovery [T1057]"}
    ) == ("attack-pattern", "T1057")


def test_prediction_sets_represent_flat_output_and_explicit_relationships():
    output = {
        "accepted_iocs": [{"type": "domain", "value": "evil[.]example"}],
        "exploited_cves": ["cve-2026-1234"],
        "technique_keywords": ["Process Discovery [T1057]"],
        "malware_families": ["Example RAT"],
        "threat_actors": [],
        "targeted_sectors": [],
        "targeted_countries": [],
        "victim_technologies": [],
        "v2_entities": [
            {"id": "e1", "type": "malware", "value": "Example RAT", "quote": "Example RAT uses Process Discovery"},
            {"id": "e2", "type": "attack-pattern", "value": "Process Discovery [T1057]", "quote": "Example RAT uses Process Discovery"},
        ],
        "v2_relationships": [
            {"source": "e1", "type": "uses", "target": "e2", "quote": "Example RAT uses Process Discovery"}
        ],
    }

    predicted = score_runs.prediction_sets(output)

    assert predicted["entities"] == {
        ("indicator", "evil.example"),
        ("vulnerability", "cve-2026-1234"),
        ("attack-pattern", "T1057"),
        ("malware", "example rat"),
    }
    assert predicted["relationships"] == {
        ("malware", "example rat", "uses", "attack-pattern", "T1057")
    }
    assert predicted["invalid_endpoint_relationships"] == 0


def test_relationship_with_missing_endpoint_is_counted_and_not_scored():
    predicted = score_runs.prediction_sets(
        {
            "accepted_iocs": [],
            "exploited_cves": [],
            "technique_keywords": [],
            "malware_families": [],
            "threat_actors": [],
            "targeted_sectors": [],
            "targeted_countries": [],
            "victim_technologies": [],
            "v2_entities": [{"id": "e1", "type": "malware", "value": "X", "quote": "X"}],
            "v2_relationships": [{"source": "e1", "type": "uses", "target": "missing", "quote": "X"}],
        }
    )

    assert predicted["relationships"] == set()
    assert predicted["invalid_endpoint_relationships"] == 1


def test_score_run_reports_exact_metrics_and_citation_localization():
    expected = {
        "entities": [
            {"id": "g1", "type": "malware", "value": "Example RAT", "quote": "Example RAT"},
            {"id": "g2", "type": "country", "value": "Peru", "quote": "targets Peru"},
        ],
        "relationships": [
            {"source": "g1", "type": "targets", "target": "g2", "quote": "Example RAT targets Peru"}
        ],
    }
    run = {
        "document": "doc",
        "repetition": 1,
        "elapsed_seconds": 2.5,
        "model_output": {
            "accepted_iocs": [],
            "exploited_cves": [],
            "technique_keywords": [],
            "malware_families": ["Example RAT"],
            "threat_actors": [],
            "targeted_sectors": [],
            "targeted_countries": [],
            "victim_technologies": [],
            "v2_entities": [
                {"id": "e1", "type": "malware", "value": "Example RAT", "quote": "Example RAT"}
            ],
            "v2_relationships": [],
        },
    }

    result = score_runs.score_run(run, expected, "Example RAT targets Peru")

    assert result["entities"]["counts"] == {"tp": 1, "fp": 0, "fn": 1}
    assert result["entities"]["precision"] == 1.0
    assert result["entities"]["recall"] == 0.5
    assert result["indicators"]["counts"] == {"tp": 0, "fp": 0, "fn": 0}
    assert result["knowledge_entities"]["counts"] == {"tp": 1, "fp": 0, "fn": 1}
    assert result["relationships"]["counts"] == {"tp": 0, "fp": 0, "fn": 1}
    assert result["citations"] == {"localized": 1, "total": 1, "rate": 1.0}


def test_citations_are_located_against_the_refanged_production_input():
    result = score_runs._citation_metrics(
        {
            "v2_entities": [
                {"quote": "Contacted https://evil.example/path"}
            ],
            "v2_relationships": [],
        },
        "Contacted hxxps://evil[.]example/path",
    )

    assert result == {"localized": 1, "total": 1, "rate": 1.0}


def test_aggregate_sums_three_repetitions_before_computing_metrics():
    rows = [
        {"entities": {"counts": {"tp": 2, "fp": 0, "fn": 0}}, "indicators": {"counts": {"tp": 1, "fp": 0, "fn": 0}}, "knowledge_entities": {"counts": {"tp": 1, "fp": 0, "fn": 0}}, "relationships": {"counts": {"tp": 1, "fp": 0, "fn": 0}}, "citations": {"localized": 2, "total": 2}},
        {"entities": {"counts": {"tp": 1, "fp": 1, "fn": 1}}, "indicators": {"counts": {"tp": 1, "fp": 0, "fn": 0}}, "knowledge_entities": {"counts": {"tp": 0, "fp": 1, "fn": 1}}, "relationships": {"counts": {"tp": 0, "fp": 0, "fn": 1}}, "citations": {"localized": 1, "total": 2}},
        {"entities": {"counts": {"tp": 0, "fp": 0, "fn": 2}}, "indicators": {"counts": {"tp": 0, "fp": 0, "fn": 1}}, "knowledge_entities": {"counts": {"tp": 0, "fp": 0, "fn": 1}}, "relationships": {"counts": {"tp": 0, "fp": 1, "fn": 1}}, "citations": {"localized": 0, "total": 0}},
    ]

    aggregate = score_runs.aggregate_scores(rows)

    assert aggregate["entities"]["counts"] == {"tp": 3, "fp": 1, "fn": 3}
    assert aggregate["entities"]["precision"] == pytest.approx(0.75)
    assert aggregate["entities"]["recall"] == pytest.approx(0.5)
    assert aggregate["indicators"]["counts"] == {"tp": 2, "fp": 0, "fn": 1}
    assert aggregate["knowledge_entities"]["counts"] == {"tp": 1, "fp": 1, "fn": 2}
    assert aggregate["relationships"]["counts"] == {"tp": 1, "fp": 1, "fn": 2}
    assert aggregate["citations"] == {"localized": 3, "total": 4, "rate": 0.75}
