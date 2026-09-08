import hashlib
import json
import math
from pathlib import Path

import pytest

from exp02.cisa_score import (
    ScoreIntegrityError,
    bootstrap_ci,
    bootstrap_ratio_ci,
    canonicalize_prediction,
    citation_localization,
    deterministic_type_sample,
    macro_recall,
    pairwise_jaccard,
    raw_to_final_effect,
    relationship_design_gate,
    score_experiment,
    score_entity_type,
    structural_metrics,
)
from exp02.cisa_reference import CanonicalEntity
from exp02.cisa_reference import CanonicalRelation


def entity(
    canonical_type: str,
    value: str,
    *,
    object_id: str,
    aliases: tuple[str, ...] = (),
    indicator_subtype: str | None = None,
) -> CanonicalEntity:
    return CanonicalEntity(
        document_id="AA00-001A",
        canonical_type=canonical_type,
        canonical_value=value,
        source_value=value,
        source_object_id=object_id,
        aliases=aliases,
        reference_origin="test",
        grounded_in_pdf=True,
        grounding_value=value,
        indicator_subtype=indicator_subtype,
    )


EQUIVALENCES = {
    "schema_version": 1,
    "frozen_before_final_runs": True,
    "groups": [["China", "People's Republic of China", "PRC"]],
}


def test_structural_metrics_use_binary_set_formulas():
    """Replacing set denominators with text similarity or pooled rates would change all three values."""
    metrics = structural_metrics(tp=2, cisa_only=2, tim_only=1)

    assert metrics["status"] == "evaluated"
    assert metrics["cosine"] == pytest.approx(2 / math.sqrt(4 * 3))
    assert metrics["cisa_recall"] == pytest.approx(0.5)
    assert metrics["jaccard"] == pytest.approx(0.4)
    assert metrics["counts"] == {
        "matched": 2,
        "cisa_only": 2,
        "tim_only_unassessed": 1,
    }


def test_structural_metrics_mark_empty_cisa_scope_not_evaluable():
    """Treating an absent CISA comparison scope as zero would bias the document macro."""
    metrics = structural_metrics(tp=0, cisa_only=0, tim_only=3)

    assert metrics == {
        "status": "not_evaluable",
        "cosine": None,
        "cisa_recall": None,
        "jaccard": None,
        "counts": {
            "matched": 0,
            "cisa_only": 0,
            "tim_only_unassessed": 3,
        },
    }


def test_macro_recall_is_mean_of_document_recalls():
    """Pooling entity counts instead would overweight the second document."""
    rows = [{"recall": 1.0}, {"recall": 0.25}]

    assert macro_recall(rows) == pytest.approx(0.625)


def test_stability_uses_all_three_pairwise_jaccard_values():
    """Comparing only adjacent repetitions would omit one required pair."""
    runs = [{"a", "b"}, {"a", "b"}, {"a"}]

    assert pairwise_jaccard(runs) == pytest.approx([1.0, 0.5, 0.5])


def test_bootstrap_is_reproducible_and_resamples_whole_documents():
    """Changing the seed or sampling entity instances would change the frozen CI."""
    documents = [0.0, 1.0, 1.0]

    first = bootstrap_ci(documents, seed=20260830, samples=10_000)
    second = bootstrap_ci(documents, seed=20260830, samples=10_000)

    assert first == second
    assert first["unit"] == "document"
    assert first["samples"] == 10_000
    assert first["estimate"] == pytest.approx(2 / 3)


def test_stability_bootstrap_uses_the_document_median_estimator():
    """A mean interval labelled as median would change the stability conclusion."""
    interval = bootstrap_ci([0.0, 0.0, 1.0], seed=20260830, samples=100, statistic="median")

    assert interval["statistic"] == "median"
    assert interval["estimate"] == 0.0


def test_citation_bootstrap_resamples_document_aggregate_ratio():
    """Averaging document rates would give 0.5 instead of the entity-weighted 1/101."""
    interval = bootstrap_ratio_ci([(1, 1), (0, 100)], seed=20260830, samples=100)

    assert interval["unit"] == "document"
    assert interval["statistic"] == "aggregate_ratio"
    assert interval["estimate"] == pytest.approx(1 / 101)


def test_citation_bootstrap_keeps_zero_entity_documents_and_marks_undefined_resamples():
    """Dropping zero-denominator documents would change the frozen 24-document bootstrap population."""
    interval = bootstrap_ratio_ci([(1, 1), (0, 0)], seed=20260830, samples=100)
    all_zero = bootstrap_ratio_ci([(0, 0), (0, 0)], seed=20260830, samples=100)

    assert interval["population_documents"] == 2
    assert interval["undefined_resamples"] > 0
    assert all_zero["population_documents"] == 2
    assert all_zero["estimate"] is None
    assert all_zero["undefined_resamples"] == 100


def test_exact_and_equivalence_accounting_are_separate_and_one_to_one():
    """Counting a technical-id match as exact would erase the declared distinction."""
    reference = [
        entity(
            "attack-pattern", "PowerShell", object_id="reference--1", aliases=("T1059.001",)
        ),
        entity("attack-pattern", "WMI", object_id="reference--2", aliases=("T1047",)),
    ]
    prediction = [
        entity(
            "attack-pattern",
            "Command and Scripting Interpreter [T1059.001]",
            object_id="prediction--1",
            aliases=("T1059.001",),
        ),
        entity("attack-pattern", "Invented technique", object_id="prediction--2"),
    ]

    score = score_entity_type(reference, prediction, EQUIVALENCES)

    assert score["exact"]["counts"] == {
        "matched": 0,
        "cisa_only": 2,
        "tim_only_unassessed": 2,
    }
    assert score["equivalence_aware"]["counts"] == {
        "matched": 1,
        "cisa_only": 1,
        "tim_only_unassessed": 1,
    }
    assert score["equivalence_aware"]["cisa_recall"] == pytest.approx(0.5)
    assert score["equivalence_aware"]["cosine"] == pytest.approx(0.5)
    assert score["matches"][0]["layer"] == "technical-id"


def test_unresolved_nominal_pair_is_a_nonblocking_conservative_difference():
    """Excluding unresolved names would silently restore the removed human gate."""
    score = score_entity_type(
        [entity("malware", "KnownWare", object_id="reference--1")],
        [entity("malware", "AdditionalWare", object_id="prediction--1")],
        EQUIVALENCES,
    )

    assert "false_positive" not in json.dumps(score).casefold()
    assert score["equivalence_aware"]["counts"] == {
        "matched": 0,
        "cisa_only": 1,
        "tim_only_unassessed": 1,
    }
    assert score["equivalence_aware"]["cosine"] == 0.0
    assert score["unresolved_nominal_pairs"] == 1
    assert len(score["pending_equivalences"]) == 1
    assert score["reference_interpretation"] == "official_cisa_stix_is_partial"


def test_technical_indicator_mismatches_are_definitive_without_cartesian_review():
    """Different canonical IPs cannot be aliases, so no human pair queue is justified."""
    score = score_entity_type(
        [
            entity(
                "indicator",
                "203.0.113.7",
                object_id="reference--1",
                indicator_subtype="ip",
            )
        ],
        [
            entity(
                "indicator",
                "198.51.100.8",
                object_id="prediction--1",
                indicator_subtype="ip",
            )
        ],
        EQUIVALENCES,
    )

    assert score["pending_equivalences"] == []
    assert score["equivalence_aware"]["counts"] == {
        "matched": 0,
        "cisa_only": 1,
        "tim_only_unassessed": 1,
    }
    assert score["pending_scope"] == "automatic_diagnostic_only_nonblocking"


def test_one_prediction_adapter_keeps_raw_and_final_views_distinct():
    """Using final harvested fields in the raw view would hide TIM's post-model effect."""
    raw = canonicalize_prediction(
        "AA00-001A",
        {
            "raw_v2_entities": [
                {
                    "id": "e1",
                    "type": "malware",
                    "value": "RawWare",
                    "aliases": [],
                    "quote": "RawWare appeared.",
                }
            ],
            "raw_v2_relationships": [],
        },
        stage="raw",
    )
    final = canonicalize_prediction(
        "AA00-001A",
        {
            "unique_iocs": [{"type": "ip", "value": "203.0.113.7"}],
            "accepted_iocs": [{"type": "ip", "value": "203.0.113.7"}],
            "technique_keywords": [],
            "threat_actors": [],
            "targeted_sectors": [],
            "malware_families": [],
            "targeted_countries": [],
            "exploited_cves": ["CVE-2026-12345"],
            "victim_technologies": [],
            "campaign_summary": "",
            "v2_entities": [],
            "v2_relationships": [],
        },
        stage="final",
    )

    assert {(row.canonical_type, row.canonical_value) for row in raw.entities} == {
        ("malware", "RawWare")
    }
    assert {(row.canonical_type, row.canonical_value) for row in final.entities} == {
        ("indicator", "203.0.113.7"),
        ("vulnerability", "CVE-2026-12345"),
    }


def test_prediction_adapter_preserves_wildcard_domain_semantics():
    """Removing the wildcard would create a different indicator than CISA's pattern."""
    final = canonicalize_prediction(
        "AA00-001A",
        {
            "unique_iocs": [{"type": "domain", "value": "*.Example.COM"}],
            "accepted_iocs": [{"type": "domain", "value": "*.Example.COM"}],
            "technique_keywords": [],
            "threat_actors": [],
            "targeted_sectors": [],
            "malware_families": [],
            "targeted_countries": [],
            "exploited_cves": [],
            "victim_technologies": [],
            "campaign_summary": "",
            "v2_entities": [],
            "v2_relationships": [],
        },
        stage="final",
    )

    assert final.entities[0].canonical_value == "*.example.com"


def test_final_prediction_scores_only_shape_accepted_iocs():
    """A citation-valid v2 indicator must not bypass TIM's final IOC shape gate."""
    final = canonicalize_prediction(
        "AA00-001A",
        {
            "unique_iocs": [{"type": "ip", "value": "203.0.113.7"}],
            "accepted_iocs": [],
            "technique_keywords": [],
            "threat_actors": [],
            "targeted_sectors": [],
            "malware_families": [],
            "targeted_countries": [],
            "exploited_cves": [],
            "victim_technologies": [],
            "campaign_summary": "",
            "v2_entities": [
                {
                    "id": "e1",
                    "type": "indicator",
                    "ioc_type": "ip",
                    "value": "203.0.113.7",
                    "quote": "Observed 203.0.113.7.",
                }
            ],
            "v2_relationships": [],
        },
        stage="final",
    )

    assert not [row for row in final.entities if row.canonical_type == "indicator"]


def test_citation_localization_uses_only_final_tim_entities():
    """Including raw entities or relationships would inflate the final citation denominator."""
    final = canonicalize_prediction(
        "AA00-001A",
        {
            "unique_iocs": [],
            "accepted_iocs": [{"type": "ip", "value": "203.0.113.7"}],
            "technique_keywords": [],
            "threat_actors": [],
            "targeted_sectors": [],
            "malware_families": [],
            "targeted_countries": [],
            "exploited_cves": [],
            "victim_technologies": [],
            "campaign_summary": "",
            "v2_entities": [
                {
                    "id": "e1",
                    "type": "malware",
                    "value": "KnownWare",
                    "quote": "KnownWare was deployed.",
                },
                {
                    "id": "e2",
                    "type": "malware",
                    "value": "OtherWare",
                    "quote": "A sentence absent from the source.",
                },
            ],
            "v2_relationships": [
                {"source": "e1", "type": "uses", "target": "e2", "quote": "irrelevant"}
            ],
        },
        stage="final",
    )

    score = citation_localization(final, "The report says: KnownWare was deployed.")

    assert score == {"localized": 1, "total": 2, "rate": 0.5}


def test_raw_to_final_effect_uses_diagnostic_drop_counts():
    """Subtracting canonical sets would misclassify deterministic TIM harvesting as citation keeps."""
    raw = canonicalize_prediction(
        "AA00-001A",
        {
            "raw_v2_entities": [
                {"id": "e1", "type": "malware", "value": "KeptWare", "quote": "q"},
                {"id": "e2", "type": "malware", "value": "DroppedWare", "quote": "q"},
            ],
            "raw_v2_relationships": [
                {"source": "e1", "type": "uses", "target": "e2", "quote": "q"}
            ],
        },
        stage="raw",
    )
    final = canonicalize_prediction(
        "AA00-001A",
            {
                "unique_iocs": [],
                "accepted_iocs": [],
            "technique_keywords": [],
            "threat_actors": [],
            "targeted_sectors": [],
            "malware_families": ["KeptWare"],
            "targeted_countries": [],
            "exploited_cves": [],
            "victim_technologies": [],
            "campaign_summary": "",
            "v2_entities": [
                {"id": "e1", "type": "malware", "value": "KeptWare", "quote": "q"}
            ],
            "v2_relationships": [],
        },
        stage="final",
    )

    effect = raw_to_final_effect(
        raw,
        final,
        {"entities_dropped": 1, "relationships_dropped": 1},
    )

    assert effect["v2_entities"] == {"raw": 2, "kept": 1, "dropped": 1}
    assert effect["v2_relationships"] == {"raw": 1, "kept": 0, "dropped": 1}
    assert effect["final_comparable_entities"] == 1


def test_raw_to_final_effect_counts_malformed_raw_rows_that_validator_dropped():
    """Dropping malformed rows in the adapter must not make citation diagnostics irreconcilable."""
    raw = canonicalize_prediction(
        "AA00-001A",
        {
            "raw_v2_entities": ["not-an-object"],
            "raw_v2_relationships": ["not-an-object"],
        },
        stage="raw",
    )
    final = canonicalize_prediction(
        "AA00-001A",
        {
            "unique_iocs": [],
            "accepted_iocs": [],
            "technique_keywords": [],
            "threat_actors": [],
            "targeted_sectors": [],
            "malware_families": [],
            "targeted_countries": [],
            "exploited_cves": [],
            "victim_technologies": [],
            "campaign_summary": "",
            "v2_entities": [],
            "v2_relationships": [],
        },
        stage="final",
    )

    effect = raw_to_final_effect(
        raw, final, {"entities_dropped": 1, "relationships_dropped": 1}
    )

    assert effect["v2_entities"] == {"raw": 1, "kept": 0, "dropped": 1}
    assert effect["v2_relationships"] == {"raw": 1, "kept": 0, "dropped": 1}


def test_type_sample_is_deterministic_limited_and_covers_documents_first():
    """Pure row sampling could spend all twenty slots on one long advisory."""
    rows = [
        {
            "document": f"AA00-{index % 6:03d}A",
            "canonical_type": "indicator",
            "value": f"indicator-{index:02d}",
        }
        for index in range(30)
    ]

    first = deterministic_type_sample(rows, seed=20260831, limit=20)
    second = deterministic_type_sample(list(reversed(rows)), seed=20260831, limit=20)

    assert first == second
    assert len(first) == 20
    assert {row["document"] for row in first} == {f"AA00-{index:03d}A" for index in range(6)}


def test_relationships_stay_exploratory_below_both_support_thresholds():
    """Five relationships in two documents cannot become a confirmatory verdict."""
    gate = relationship_design_gate(support_documents=2, grounded_relations=5)

    assert gate["mode"] == "exploratory"
    assert gate["confirmatory"] is False
    assert gate["verdict"] is None
    assert gate["requirements"] == {"documents": 8, "grounded_relations": 20}


def test_relationship_candidate_survives_semantic_entity_deduplication():
    """A relation may point to a duplicate local ID even when entity scoring deduplicates its value."""
    from exp02 import cisa_score
    from exp02.cisa_match import validate_equivalences

    reference = [
        entity(
            "indicator",
            "203.0.113.7",
            object_id="indicator--reference",
            indicator_subtype="ip",
        ),
        entity("malware", "KnownWare", object_id="malware--reference"),
    ]
    relation = CanonicalRelation(
        document_id="AA00-001A",
        source_object_id="indicator--reference",
        relationship_type="indicates",
        target_object_id="malware--reference",
        source_entity_id="indicator--reference",
        target_entity_id="malware--reference",
        grounded_in_pdf=True,
        grounding_value="203.0.113.7 indicates KnownWare.",
    )
    final = canonicalize_prediction(
        "AA00-001A",
        {
            "unique_iocs": [],
            "accepted_iocs": [{"type": "ip", "value": "203.0.113.7"}],
            "technique_keywords": [],
            "threat_actors": [],
            "targeted_sectors": [],
            "malware_families": [],
            "targeted_countries": [],
            "exploited_cves": [],
            "victim_technologies": [],
            "campaign_summary": "",
            "v2_entities": [
                {"id": "e1", "type": "indicator", "ioc_type": "ip", "value": "203.0.113.7"},
                {"id": "e2", "type": "malware", "value": "KnownWare"},
                {"id": "e3", "type": "malware", "value": "KnownWare"},
            ],
            "v2_relationships": [{"source": "e1", "type": "indicates", "target": "e3"}],
        },
        stage="final",
    )

    result = cisa_score._relation_run_score(
        [relation], reference, final, validate_equivalences(EQUIVALENCES)
    )

    assert result["candidate_matches"] == 1


def test_relationship_scoring_filters_noncomparable_reference_and_unresolved_tim_endpoints():
    """Exploratory totals must not include relation types or endpoints outside the frozen vocabulary."""
    from exp02 import cisa_score
    from exp02.cisa_match import validate_equivalences

    reference = [
        entity("malware", "KnownWare", object_id="malware--reference"),
        entity("vulnerability", "CVE-2026-12345", object_id="vulnerability--reference"),
    ]
    invalid = CanonicalRelation(
        document_id="AA00-001A",
        source_object_id="malware--reference",
        relationship_type="uses",
        target_object_id="vulnerability--reference",
        source_entity_id="malware--reference",
        target_entity_id="vulnerability--reference",
        grounded_in_pdf=True,
        grounding_value="KnownWare uses CVE-2026-12345.",
    )
    final = canonicalize_prediction(
        "AA00-001A",
        {
            "unique_iocs": [], "accepted_iocs": [], "technique_keywords": [],
            "threat_actors": [], "targeted_sectors": [], "malware_families": ["KnownWare"],
            "targeted_countries": [], "exploited_cves": ["CVE-2026-12345"],
            "victim_technologies": [], "campaign_summary": "",
            "v2_entities": [],
            "v2_relationships": [
                {"source": "final:malware_families:0", "type": "uses", "target": "missing"}
            ],
        },
        stage="final",
    )

    result = cisa_score._relation_run_score(
        [invalid], reference, final, validate_equivalences(EQUIVALENCES)
    )

    assert result["grounded_cisa_relations"] == 0
    assert result["tim_relations"] == 0


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _final_output(value: str = "KnownWare") -> dict:
    return {
        "unique_iocs": [],
        "accepted_iocs": [],
        "technique_keywords": [],
        "threat_actors": [],
        "targeted_sectors": [],
        "malware_families": [value],
        "targeted_countries": [],
        "exploited_cves": [],
        "victim_technologies": [],
        "campaign_summary": "KnownWare was deployed.",
        "v2_entities": [
            {
                "id": "e1",
                "type": "malware",
                "value": value,
                "quote": "KnownWare was deployed.",
            }
        ],
        "v2_relationships": [],
    }


def make_complete_evidence(tmp_path: Path) -> Path:
    from exp02.cisa_runner import (
        EXPECTED_MODEL,
        EXPECTED_PROMPT_SHA256,
        EXPECTED_REGION,
    )

    root = tmp_path / "cisa-evidence"
    config = root.parent / "config" / "cisa-equivalences.v1.json"
    config.parent.mkdir(parents=True)
    config.write_text(json.dumps(EQUIVALENCES), encoding="utf-8")
    from exp02.cisa_match import equivalence_digest
    documents = []
    selection_documents = []
    for index in range(24):
        code = f"AA26-{index:03d}A"
        input_path = root / "documents" / code / "input.txt"
        input_path.parent.mkdir(parents=True, exist_ok=True)
        input_path.write_text("KnownWare was deployed.", encoding="utf-8")
        reference_path = root / "reference" / f"{code}.canonical.json"
        reference_path.parent.mkdir(parents=True, exist_ok=True)
        reference_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "document_id": code,
                    "entities": [
                        {
                            "document_id": code,
                            "canonical_type": "malware",
                            "canonical_value": "KnownWare",
                            "source_value": "KnownWare",
                            "source_object_id": f"malware--{index}",
                            "aliases": [],
                            "reference_origin": "official-cisa-stix",
                            "grounded_in_pdf": True,
                            "grounding_value": "KnownWare",
                            "indicator_subtype": None,
                        }
                    ],
                    "ungrounded_entities": [],
                    "relations": [],
                    "exclusions": [],
                    "excluded_relations": [],
                }
            ),
            encoding="utf-8",
        )
        documents.append(
            {
                "code": code,
                "input_sha256": _sha(input_path),
                "selection_input_sha256": _sha(input_path),
                "reference_sha256": _sha(reference_path),
            }
        )
        selection_documents.append(
            {
                "code": code,
                "input_path": f"documents/{code}/input.txt",
                "text_sha256": _sha(input_path),
            }
        )
    selection = {
        "schema_version": 1,
        "selection_digest": "frozen-selection",
        "documents": selection_documents,
    }
    selection_path = root / "selection-manifest.v1.json"
    selection_path.write_text(json.dumps(selection), encoding="utf-8")
    manifest = {
        "schema_version": 1,
        "kind": "cisa_bedrock_execution",
        "documents": documents,
        "provider": "bedrock",
        "model": EXPECTED_MODEL,
        "aws_region": EXPECTED_REGION,
        "source_type": "advisory",
        "repetitions": [1, 2, 3],
        "expected_records": 72,
        "system_prompt_sha256": EXPECTED_PROMPT_SHA256,
        "selection_manifest_sha256": _sha(selection_path),
        "selection_digest": "frozen-selection",
        "equivalence_file_sha256": _sha(config),
        "equivalence_sha256": equivalence_digest(config),
        "opencti_writes": 0,
    }
    manifest_path = root / "execution-manifest.v1.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    manifest_sha = _sha(manifest_path)
    runs = root / "runs"
    runs.mkdir()
    for document in documents:
        for repetition in (1, 2, 3):
            record = {
                "schema_version": 1,
                "kind": "cisa_document_extraction",
                "created_at_utc": "2026-08-31T00:00:00Z",
                "document": document["code"],
                "repetition": repetition,
                "status": "success",
                "source_type": "advisory",
                "provider": "bedrock",
                "model": EXPECTED_MODEL,
                "aws_region": EXPECTED_REGION,
                "execution_manifest_sha256": manifest_sha,
                "input_sha256": document["input_sha256"],
                "reference_sha256": document["reference_sha256"],
                "opencti_writes": 0,
                "elapsed_seconds": 1.0,
                "raw_model_output": {
                    "raw_response_text": "{}",
                    "raw_v2_entities": _final_output()["v2_entities"],
                    "raw_v2_relationships": [],
                    "citation_stats": {"entities_dropped": 0, "relationships_dropped": 0},
                    "stop_reason": "end_turn",
                    "model_usage": {"input_tokens": 1, "output_tokens": 1},
                },
                "tim_output": _final_output(),
            }
            (runs / f"{document['code']}.run-{repetition}.json").write_text(
                json.dumps(record), encoding="utf-8"
            )
    return root


def test_score_experiment_requires_and_scores_exactly_72_success_records(tmp_path):
    """A complete perfect fixture proves the scorer traverses 24 documents × 3 runs."""
    root = make_complete_evidence(tmp_path)

    result = score_experiment(root, bootstrap_samples=100)

    assert result["integrity"]["documents"] == 24
    assert result["integrity"]["successful_runs"] == 72
    assert result["schema_version"] == 2
    assert result["primary"]["metric"] == "structural_cosine_macro_by_document"
    assert result["primary"]["structural_cosine_macro_by_document"] == 1.0
    assert result["method"]["human_adjudication"] == "none"
    assert result["method"]["tim_only_interpretation"] == "unassessed"
    assert "review_samples" not in result
    assert "review_population_counts" not in result
    assert "thresholds" not in result
    assert set(result["diagnostic_samples"]) == {
        "unresolved_nominal_pairs",
        "tim_only_unassessed",
        "cisa_ungrounded",
    }
    assert result["stability"]["document_median_pairwise_jaccard"]["estimate"] == 1.0
    assert result["relationships"]["gate"]["mode"] == "exploratory"


def test_score_experiment_accepts_only_linked_v3_success_records(tmp_path):
    """V3 scoring must consume freeze-bound attempts instead of falling back to legacy records."""
    from exp02.cisa_execution import _freeze_payload
    from exp02.cisa_runner import EXPECTED_MODEL
    from exp02.jsonio import write_new_json

    root = make_complete_evidence(tmp_path)
    selection = json.loads((root / "selection-manifest.v1.json").read_text(encoding="utf-8"))
    for row in selection["documents"]:
        code = row["code"]
        pdf = root.parent / "cisa-intake" / code / "document.pdf"
        stix = root.parent / "cisa-intake" / code / "reference.stix.json"
        pdf.parent.mkdir(parents=True, exist_ok=True)
        pdf.write_bytes(code.encode("utf-8"))
        stix.write_text(json.dumps({"objects": []}), encoding="utf-8")
        row.update({
            "source_pdf_path": f"cisa-intake/{code}/document.pdf",
            "source_stix_path": f"cisa-intake/{code}/reference.stix.json",
            "pdf_sha256": _sha(pdf), "stix_sha256": _sha(stix),
        })
    (root / "selection-manifest.v1.json").write_text(json.dumps(selection), encoding="utf-8")
    legacy_manifest_path = root / "execution-manifest.v1.json"
    legacy_manifest = json.loads(legacy_manifest_path.read_text(encoding="utf-8"))
    legacy_manifest["selection_manifest_sha256"] = _sha(root / "selection-manifest.v1.json")
    legacy_manifest_path.write_text(json.dumps(legacy_manifest), encoding="utf-8")

    class Runtime:
        LLM_PROVIDER = "bedrock"
        BEDROCK_MODEL = EXPECTED_MODEL
        AWS_REGION = "us-east-1"
        ANTHROPIC_API_KEY = ""
        from extractor import SYSTEM_PROMPT_V21

    freeze = _freeze_payload(root, Runtime())
    digest = write_new_json(root / "freeze.v3.json", freeze)
    (root / "freeze.v3.sha256").write_text(f"{digest}  freeze.v3.json\n", encoding="utf-8")
    manifest = {
        "schema_version": 3, "kind": "cisa_bedrock_execution", "freeze_sha256": digest,
        "provider": "bedrock", "model": EXPECTED_MODEL, "aws_region": "us-east-1",
        "source_type": "advisory", "max_tokens": 32000, "repetitions": [1, 2, 3],
        "expected_records": 72, "max_starts_per_minute": 8, "opencti_writes": 0,
    }
    write_new_json(root / "execution-manifest.v3.json", manifest)
    attempts = root / "attempts"
    attempts.mkdir()
    for path in sorted((root / "runs").glob("*.run-*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        stem = path.name.removesuffix(".json")
        attempt_name = f"{stem}.attempt-1.json"
        attempt = {
            **record, "schema_version": 2, "kind": "cisa_document_attempt", "attempt": 1,
            "freeze_sha256": digest,
        }
        attempt.pop("execution_manifest_sha256")
        attempt_digest = write_new_json(attempts / attempt_name, attempt)
        final = {
            **attempt, "kind": "cisa_document_extraction", "attempt_record": attempt_name,
            "attempt_sha256": attempt_digest,
        }
        path.write_text(json.dumps(final), encoding="utf-8")

    result = score_experiment(root, bootstrap_samples=10)
    assert result["integrity"]["freeze_sha256"] == digest
    assert len(result["integrity"]["final_record_sha256"]) == 72

    tampered = next((root / "runs").glob("*.run-*.json"))
    altered = json.loads(tampered.read_text(encoding="utf-8"))
    altered["tim_output"]["campaign_summary"] = "forged after successful attempt"
    tampered.write_text(json.dumps(altered), encoding="utf-8")
    with pytest.raises(ScoreIntegrityError, match="differs from its bound attempt"):
        score_experiment(root, bootstrap_samples=10)


def test_score_experiment_uses_median_stability_and_per_type_exact_intervals(tmp_path):
    """Reporting only equivalence macro intervals would hide exact per-type uncertainty."""
    root = make_complete_evidence(tmp_path)

    result = score_experiment(root, bootstrap_samples=100)

    assert result["stability"]["document_median_pairwise_jaccard"]["statistic"] == "median"
    assert result["confidence_intervals_by_type"]["malware"]["exact"]["cosine"]["statistic"] == "mean"
    assert result["confidence_intervals_by_type"]["malware"]["equivalence_aware"]["cisa_recall"]["statistic"] == "mean"


def test_score_experiment_bootstraps_aggregate_citation_ratio_by_document(tmp_path):
    """Citation CI must preserve each sampled document's numerator and denominator."""
    root = make_complete_evidence(tmp_path)
    paths = sorted((root / "runs").glob("*.run-*.json"))
    for position, path in enumerate(paths):
        record = json.loads(path.read_text(encoding="utf-8"))
        rows = [
            {"id": f"e{index}", "type": "malware", "value": "KnownWare", "quote": quote}
            for index, quote in enumerate(
                ["KnownWare was deployed."] if position < 3 else ["not in source"] * 100
            )
        ]
        if position >= 6:
            rows = []
        record["raw_model_output"]["raw_v2_entities"] = rows
        record["tim_output"]["v2_entities"] = rows
        path.write_text(json.dumps(record), encoding="utf-8")

    result = score_experiment(root, bootstrap_samples=100)

    assert result["citations"]["confidence_interval_95"]["estimate"] == pytest.approx(1 / 101)
    assert result["citations"]["confidence_interval_95"]["population_documents"] == 24


def test_score_experiment_scores_unresolved_names_without_human_artifacts(tmp_path):
    """Requiring an adjudication file would reintroduce the rejected manual workflow."""
    root = make_complete_evidence(tmp_path)
    for path in (root / "runs").glob("*.run-*.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        record["tim_output"]["malware_families"] = ["OtherWare"]
        record["tim_output"]["v2_entities"] = [
            {"id": "e1", "type": "malware", "value": "OtherWare", "quote": "OtherWare"}
        ]
        path.write_text(json.dumps(record), encoding="utf-8")

    result = score_experiment(root, bootstrap_samples=10)

    assert not (root / "review" / "equivalence-adjudication.v1.json").exists()
    assert result["primary"]["structural_cosine_macro_by_document"] == 0.0
    assert result["diagnostics"]["unresolved_nominal_pairs"] == 72


def test_addition_review_sample_is_drawn_from_the_complete_frozen_population(tmp_path):
    """Pre-truncating a long run would hide rows before the global type sample is selected."""
    root = make_complete_evidence(tmp_path)
    additions = [{"type": "ip", "value": f"198.51.100.{index}"} for index in range(1, 22)]
    for path in (root / "runs").glob("AA26-000A.run-*.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        record["tim_output"]["accepted_iocs"] = additions
        path.write_text(json.dumps(record), encoding="utf-8")

    result = score_experiment(root, bootstrap_samples=10)

    assert result["diagnostic_population_counts"]["tim_only_unassessed"]["indicator"] == 63
    assert len(result["diagnostic_samples"]["tim_only_unassessed"]) == 20


def test_final_relationship_gate_uses_only_comparable_reference_relations(tmp_path):
    """Unsupported reference relations must not manufacture confirmatory support."""
    root = make_complete_evidence(tmp_path)
    manifest_path = root / "execution-manifest.v1.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for document in manifest["documents"][:8]:
        code = document["code"]
        path = root / "reference" / f"{code}.canonical.json"
        reference = json.loads(path.read_text(encoding="utf-8"))
        reference["relations"] = [
            {
                "document_id": code,
                "source_object_id": reference["entities"][0]["source_object_id"],
                "relationship_type": "uses",
                "target_object_id": reference["entities"][0]["source_object_id"],
                "source_entity_id": reference["entities"][0]["source_object_id"],
                "target_entity_id": reference["entities"][0]["source_object_id"],
                "grounded_in_pdf": True,
                "grounding_value": "KnownWare uses KnownWare.",
            }
            for _ in range(3)
        ]
        path.write_text(json.dumps(reference), encoding="utf-8")
        document["reference_sha256"] = _sha(path)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    manifest_sha = _sha(manifest_path)
    by_code = {document["code"]: document for document in manifest["documents"]}
    for path in (root / "runs").glob("*.run-*.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        record["execution_manifest_sha256"] = manifest_sha
        record["reference_sha256"] = by_code[record["document"]]["reference_sha256"]
        path.write_text(json.dumps(record), encoding="utf-8")

    result = score_experiment(root, bootstrap_samples=10)

    assert result["relationships"]["gate"]["support"] == {
        "documents": 0, "grounded_relations": 0
    }
    assert result["relationships"]["gate"]["mode"] == "exploratory"


@pytest.mark.parametrize("damage", ["missing", "error", "malformed"])
def test_score_experiment_rejects_missing_error_or_malformed_run(tmp_path, damage):
    """No failed identity may enter metrics as a successful empty extraction."""
    root = make_complete_evidence(tmp_path)
    path = sorted((root / "runs").glob("*.run-*.json"))[0]
    if damage == "missing":
        path.unlink()
    elif damage == "error":
        record = json.loads(path.read_text(encoding="utf-8"))
        record["status"] = "error"
        record.pop("raw_model_output")
        record.pop("tim_output")
        record["error_type"] = "DiagnosticExtractionError"
        record["error"] = "model failed"
        path.write_text(json.dumps(record), encoding="utf-8")
    else:
        path.write_text("{", encoding="utf-8")

    with pytest.raises(RuntimeError):
        score_experiment(root, bootstrap_samples=10)


def test_score_experiment_rejects_an_extra_canonical_reference(tmp_path):
    """An unsealed twenty-fifth reference must not be silently ignored."""
    root = make_complete_evidence(tmp_path)
    (root / "reference" / "AA00-EXTRA.canonical.json").write_text(
        '{"schema_version":1}', encoding="utf-8"
    )

    with pytest.raises(RuntimeError, match="extra or missing final document"):
        score_experiment(root, bootstrap_samples=10)


def test_score_experiment_reuses_runner_selection_manifest_validation(tmp_path):
    """Scoring must not accept evidence that Task 4 would reject before execution."""
    root = make_complete_evidence(tmp_path)
    selection_path = root / "selection-manifest.v1.json"
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    selection["selection_digest"] = "tampered-selection"
    selection_path.write_text(json.dumps(selection), encoding="utf-8")

    with pytest.raises(RuntimeError, match="selection manifest"):
        score_experiment(root, bootstrap_samples=10)


def test_score_cli_writes_v2_results_without_human_review_artifacts(tmp_path):
    """Creating reviewer queues would preserve an operational dependency the user removed."""
    from exp02.cisa_cli import _parser, main

    root = make_complete_evidence(tmp_path)

    assert main(["score", "--evidence", str(root)]) == 0
    result = json.loads((root / "results.v2.json").read_text(encoding="utf-8"))
    assert result["method"]["bootstrap_samples"] == 10_000
    assert not (root / "review").exists()
    with pytest.raises(SystemExit):
        _parser().parse_args(["prepare-review", "--evidence", str(root)])
    assert main(["score", "--evidence", str(root)]) == 2
