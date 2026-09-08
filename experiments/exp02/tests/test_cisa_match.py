import hashlib
import json
from pathlib import Path

import pytest

from exp02.cisa_match import load_equivalences, match_entities
from exp02.cisa_reference import CanonicalEntity


def entity(
    canonical_type: str,
    canonical_value: str,
    *,
    object_id: str = "object--1",
    aliases: tuple[str, ...] = (),
    indicator_subtype: str | None = None,
) -> CanonicalEntity:
    return CanonicalEntity(
        document_id="AA00-001A",
        canonical_type=canonical_type,
        canonical_value=canonical_value,
        source_value=canonical_value,
        source_object_id=object_id,
        aliases=aliases,
        reference_origin="test",
        grounded_in_pdf=True,
        grounding_value=canonical_value,
        indicator_subtype=indicator_subtype,
    )


def frozen_equivalences(groups: list[list[str]]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "frozen_before_final_runs": True,
        "groups": groups,
    }


def test_controlled_equivalence_is_success_but_not_exact():
    """Changing controlled equivalence into exact matching would be a scoring bug."""
    result = match_entities(
        [entity("country", "China")],
        [entity("country", "People's Republic of China")],
        frozen_equivalences([["China", "People's Republic of China", "PRC"]]),
    )

    assert result.matches[0].layer == "controlled-equivalence"
    assert result.exact_tp == 0
    assert result.equivalent_tp == 1


def test_one_prediction_cannot_match_two_reference_objects():
    """Removing one-to-one admission would double-count a duplicated CISA object."""
    result = match_entities(
        [
            entity("malware", "Foo", object_id="reference--1"),
            entity("malware", "Foo", object_id="reference--2"),
        ],
        [entity("malware", "Foo", object_id="prediction--1")],
        frozen_equivalences([]),
    )

    assert result.equivalent_tp == 1
    assert result.exact_tp == 1


def test_shared_attack_identifier_is_technical_match_before_alias_matching():
    """Dropping ATT&CK-ID detection would leave a real cross-label match pending."""
    result = match_entities(
        [
            entity(
                "attack-pattern",
                "Command and Scripting Interpreter",
                aliases=("T1059",),
            )
        ],
        [entity("attack-pattern", "Command Shell", aliases=("T1059",))],
        frozen_equivalences([]),
    )

    assert [match.layer for match in result.matches] == ["technical-id"]
    assert result.exact_tp == 0
    assert result.equivalent_tp == 1


def test_declared_alias_is_matched_without_name_similarity():
    """Removing declared aliases would discard an explicitly documented identity."""
    result = match_entities(
        [entity("threat-actor", "APT 32", aliases=("OceanLotus",))],
        [entity("threat-actor", "OceanLotus")],
        frozen_equivalences([]),
    )

    assert [match.layer for match in result.matches] == ["declared-alias"]
    assert result.exact_tp == 0
    assert result.equivalent_tp == 1


def test_same_type_names_without_declared_rule_remain_pending():
    """Adding fuzzy name matching would incorrectly turn an unresolved pair into a TP."""
    result = match_entities(
        [entity("malware", "Dark Loader", object_id="reference--1")],
        [entity("malware", "DarkLoader Plus", object_id="prediction--1")],
        frozen_equivalences([]),
    )

    assert result.matches == ()
    assert [match.layer for match in result.pending] == ["pending"]
    assert result.exact_tp == 0
    assert result.equivalent_tp == 0


def test_load_equivalences_validates_the_frozen_schema_and_exposes_canonical_digest(
    tmp_path,
):
    """Accepting an unfrozen or ambiguous dictionary would invalidate final scoring."""
    path = tmp_path / "equivalences.json"
    path.write_text(
        '{"schema_version":1,"frozen_before_final_runs":true,"groups":[["'
        'China","People\'s Republic of China","PRC"]]}',
        encoding="utf-8",
    )

    equivalences = load_equivalences(path)

    assert equivalences.groups == (("China", "People's Republic of China", "PRC"),)
    assert (
        equivalences.canonical_digest
        == hashlib.sha256(
            b'{"frozen_before_final_runs":true,"groups":[["China","People\'s Republic of China","PRC"]],"schema_version":1}\n'
        ).hexdigest()
    )


@pytest.mark.parametrize(
    "groups",
    [
        [["China", ""]],
        [["China", "China"]],
        [["China", "PRC"], ["prc", "People's Republic of China"]],
    ],
)
def test_equivalence_groups_fail_closed_for_ambiguous_surfaces(tmp_path, groups):
    """Allowing duplicate surfaces could make controlled matching non-deterministic."""
    path = tmp_path / "equivalences.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "frozen_before_final_runs": True,
                "groups": groups,
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        load_equivalences(path)


@pytest.mark.parametrize(
    "overrides",
    [
        {"schema_version": 1.0},
        {"frozen_before_final_runs": False},
        {"note": "not part of the frozen schema"},
    ],
)
def test_equivalence_schema_is_exact_and_frozen(tmp_path, overrides):
    """Relaxing version, freeze, or key checks would admit a mutable rule set."""
    payload = {
        "schema_version": 1,
        "frozen_before_final_runs": True,
        "groups": [["China", "PRC"]],
        **overrides,
    }
    path = tmp_path / "equivalences.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError):
        load_equivalences(path)


def test_committed_pilot_dictionary_is_valid_and_frozen():
    """Replacing the committed pilot dictionary with invalid JSON must stop execution."""
    path = Path(__file__).parents[1] / "config" / "cisa-equivalences.v1.json"

    equivalences = load_equivalences(path)

    assert equivalences.groups == (("China", "People's Republic of China", "PRC"),)


def test_committed_pilot_dictionary_records_china_as_controlled_equivalence():
    """Replacing the frozen group with an exact rule would overstate exact recovery."""
    path = Path(__file__).parents[1] / "config" / "cisa-equivalences.v1.json"
    result = match_entities(
        [entity("country", "China")],
        [entity("country", "PRC")],
        load_equivalences(path),
    )

    assert [match.layer for match in result.matches] == ["controlled-equivalence"]
    assert result.exact_tp == 0


def test_exact_indicator_match_refangs_a_defanged_technical_value():
    """Dropping refanging would make a representational IOC difference look unresolved."""
    result = match_entities(
        [entity("indicator", "1.2.3.4", indicator_subtype="ip")],
        [entity("indicator", "1.2.3[.]4", indicator_subtype="ip")],
        frozen_equivalences([]),
    )

    assert [match.layer for match in result.matches] == ["exact"]


def test_url_path_case_difference_is_not_an_exact_or_technical_match():
    """Casefolding a URL path would silently merge different technical IOCs."""
    result = match_entities(
        [
            entity(
                "indicator", "https://host.example/A?Key=One", indicator_subtype="url"
            )
        ],
        [
            entity(
                "indicator", "https://host.example/a?key=one", indicator_subtype="url"
            )
        ],
        frozen_equivalences([]),
    )

    assert result.matches == ()
    assert [match.layer for match in result.pending] == ["pending"]


def test_exact_name_match_ignores_case_whitespace_and_outer_punctuation():
    """Treating surface punctuation as an identity change would create a false FN."""
    result = match_entities(
        [entity("malware", "ExampleWare")],
        [entity("malware", "  exampleware. ")],
        frozen_equivalences([]),
    )

    assert [match.layer for match in result.matches] == ["exact"]


def test_exact_layer_outranks_a_lower_layer_even_when_ids_sort_later():
    """Sorting by IDs before layers would consume the prediction with a weaker match."""
    result = match_entities(
        [
            entity(
                "attack-pattern",
                "Command and Scripting Interpreter",
                object_id="reference--a",
                aliases=("T1059",),
            ),
            entity("attack-pattern", "PowerShell", object_id="reference--z"),
        ],
        [
            entity(
                "attack-pattern",
                "PowerShell",
                object_id="prediction--a",
                aliases=("T1059",),
            )
        ],
        frozen_equivalences([]),
    )

    assert [
        (match.reference.source_object_id, match.layer) for match in result.matches
    ] == [
        ("reference--z", "exact"),
    ]


def test_pending_does_not_cross_indicator_subtypes():
    """Ignoring subtype would compare two technically incompatible indicator atoms."""
    result = match_entities(
        [entity("indicator", "same-value", indicator_subtype="domain")],
        [entity("indicator", "same-value", indicator_subtype="url")],
        frozen_equivalences([]),
    )

    assert result.matches == ()
    assert result.pending == ()


def test_indicators_without_a_subtype_cannot_match_or_enter_pending_queue():
    """Treating two unknown indicator paths as comparable would fabricate a TP or review row."""
    result = match_entities(
        [entity("indicator", "same-value")],
        [entity("indicator", "same-value")],
        frozen_equivalences([]),
    )

    assert result.matches == ()
    assert result.pending == ()


def test_one_to_one_ties_are_ordered_by_object_ids_not_input_order():
    """Depending on incoming list order would make repeated scoring non-reproducible."""
    result = match_entities(
        [
            entity("malware", "Foo", object_id="reference--z"),
            entity("malware", "Foo", object_id="reference--a"),
        ],
        [
            entity("malware", "Foo", object_id="prediction--z"),
            entity("malware", "Foo", object_id="prediction--a"),
        ],
        frozen_equivalences([]),
    )

    assert [
        (match.reference.source_object_id, match.prediction.source_object_id)
        for match in result.matches
    ] == [("reference--a", "prediction--a"), ("reference--z", "prediction--z")]


@pytest.mark.parametrize(
    "equivalences",
    [
        {
            "schema_version": 1,
            "frozen_before_final_runs": False,
            "groups": [["China", "PRC"]],
        },
        {
            "schema_version": 1,
            "frozen_before_final_runs": True,
            "groups": [["China", "PRC"], ["prc", "People's Republic of China"]],
        },
        {"groups": [["China", "PRC"]]},
    ],
)
def test_match_entities_rejects_raw_unfrozen_or_ambiguous_equivalences(equivalences):
    """Bypassing dictionary validation would create mutable controlled TPs."""
    with pytest.raises(ValueError):
        match_entities(
            [entity("country", "China")],
            [entity("country", "PRC")],
            equivalences,
        )
