import json

import pytest

from exp02.cisa_cli import main as cisa_main
from exp02.cisa_reference import canonicalize_bundle


def _object(object_type: str, object_id: str, **values):
    if object_id.endswith("--1"):
        object_id = object_id[:-1] + "00000000-0000-4000-8000-000000000001"
    result = {
        "type": object_type,
        "spec_version": "2.1",
        "id": object_id,
        "created": "2024-01-01T00:00:00Z",
        "modified": "2024-01-01T00:00:00Z",
        **values,
    }
    if object_type == "indicator":
        result.setdefault("pattern_type", "stix")
    if object_type == "malware":
        result.setdefault("is_family", False)
    return result


def bundle_with_pattern(pattern: str):
    return {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": [_object("indicator", "indicator--1", pattern=pattern)],
    }


def fixture_bundle():
    return {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": [
            _object("intrusion-set", "intrusion-set--1", name="APT Example"),
            _object(
                "attack-pattern", "attack-pattern--1", name="Command shell [T1059]",
                external_references=[{"source_name": "mitre-attack", "external_id": "T1059"}],
            ),
        ],
    }


def test_splits_compound_indicator_pattern_into_atomic_values():
    reference = canonicalize_bundle(
        "AA00-001A", bundle_with_pattern(
            "[ipv4-addr:value = '1.2.3.4' OR domain-name:value = 'evil.example']"
        ), "1.2.3[.]4 evil[.]example",
    )

    assert {(entity.canonical_type, entity.canonical_value) for entity in reference.entities} == {
        ("indicator", "1.2.3.4"),
        ("indicator", "evil.example"),
    }
    assert {entity.indicator_subtype for entity in reference.entities} == {"ip", "domain"}


def test_maps_intrusion_set_to_threat_actor_and_grounds_attack_id():
    reference = canonicalize_bundle("AA00-001A", fixture_bundle(), "APT Example used T1059.")

    assert reference.by_source_id["intrusion-set--00000000-0000-4000-8000-000000000001"].canonical_type == "threat-actor"
    assert reference.by_source_id["attack-pattern--00000000-0000-4000-8000-000000000001"].grounded_in_pdf is True
    assert "T1059" in reference.by_source_id["attack-pattern--00000000-0000-4000-8000-000000000001"].aliases


def test_keeps_unsupported_indicator_paths_as_explicit_exclusions():
    reference = canonicalize_bundle(
        "AA00-001A", bundle_with_pattern(
            "[file:name = 'dropper.exe' AND file:hashes.'SHA-512' = '" + "a" * 128 + "']"
        ), "dropper.exe",
    )

    assert reference.entities == ()
    assert {item["reason"] for item in reference.exclusions} == {
        "unsupported-indicator-path"
    }


def test_relation_needs_allowed_type_resolved_endpoints_and_shared_sentence():
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": [
            _object("malware", "malware--1", name="ExampleWare"),
            _object("threat-actor", "threat-actor--1", name="APT Example"),
            _object(
                "relationship", "relationship--1", relationship_type="uses",
                source_ref="threat-actor--00000000-0000-4000-8000-000000000001",
                target_ref="malware--00000000-0000-4000-8000-000000000001",
            ),
        ],
    }

    reference = canonicalize_bundle("AA00-001A", bundle, "APT Example uses ExampleWare.")

    assert len(reference.relations) == 1
    assert reference.relations[0].grounded_in_pdf is True


def test_relation_without_shared_sentence_is_explicitly_excluded():
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": [
            _object("malware", "malware--1", name="ExampleWare"),
            _object("threat-actor", "threat-actor--1", name="APT Example"),
            _object(
                "relationship", "relationship--1", relationship_type="uses",
                source_ref="threat-actor--00000000-0000-4000-8000-000000000001",
                target_ref="malware--00000000-0000-4000-8000-000000000001",
            ),
        ],
    }

    reference = canonicalize_bundle("AA00-001A", bundle, "APT Example appeared. ExampleWare appeared.")

    assert reference.relations == ()
    assert reference.excluded_relations[0]["reason"] == "endpoints-not-co-mentioned"


def test_build_reference_writes_each_manifest_document_once(tmp_path):
    evidence = tmp_path / "cisa-evidence"
    source = tmp_path / "source.stix.json"
    input_path = evidence / "documents" / "AA00-001A" / "input.txt"
    input_path.parent.mkdir(parents=True)
    input_path.write_text("1.2.3[.]4", encoding="utf-8")
    source.write_text(json.dumps(bundle_with_pattern("[ipv4-addr:value = '1.2.3.4']")), encoding="utf-8")
    (evidence / "selection-manifest.v1.json").write_text(json.dumps({
        "documents": [{
            "code": "AA00-001A", "source_stix_path": str(source),
            "input_path": "documents/AA00-001A/input.txt",
        }],
        "quarantined_objects": {},
    }), encoding="utf-8")

    assert cisa_main(["build-reference", "--evidence", str(evidence)]) == 0
    target = evidence / "reference" / "AA00-001A.canonical.json"
    assert json.loads(target.read_text(encoding="utf-8"))["document_id"] == "AA00-001A"
    assert cisa_main(["build-reference", "--evidence", str(evidence)]) == 2


def test_primary_entities_are_grounded_and_retains_ungrounded_entities_separately():
    reference = canonicalize_bundle(
        "AA00-001A", bundle_with_pattern("[ipv4-addr:value = '1.2.3.4']"), "No IOC is printed.",
    )

    assert reference.entities == ()
    assert [(entity.canonical_value, entity.grounded_in_pdf) for entity in reference.ungrounded_entities] == [
        ("1.2.3.4", False),
    ]


def test_excludes_attack_tactics_from_primary_and_records_reason():
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": [_object("attack-pattern", "attack-pattern--1", name="Exfiltration [TA0010]")],
    }

    reference = canonicalize_bundle("AA00-001A", bundle, "Exfiltration [TA0010].")

    assert reference.entities == ()
    assert reference.ungrounded_entities == ()
    assert {item["reason"] for item in reference.exclusions} == {"attack-tactic-not-comparable"}


def test_does_not_ground_parent_attack_id_from_subtechnique_identifier():
    reference = canonicalize_bundle("AA00-001A", fixture_bundle(), "The report only names T1059.001.")

    assert "attack-pattern--00000000-0000-4000-8000-000000000001" not in reference.by_source_id
    assert reference.ungrounded_entities[0].canonical_value == "Command shell [T1059]"


def test_rejects_relation_with_unapproved_tim_signature():
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": [
            _object("malware", "malware--1", name="ExampleWare"),
            _object("threat-actor", "threat-actor--1", name="APT Example"),
            _object(
                "relationship", "relationship--1", relationship_type="uses",
                source_ref="malware--00000000-0000-4000-8000-000000000001",
                target_ref="threat-actor--00000000-0000-4000-8000-000000000001",
            ),
        ],
    }

    reference = canonicalize_bundle("AA00-001A", bundle, "ExampleWare uses APT Example.")

    assert reference.relations == ()
    assert reference.excluded_relations[0]["reason"] == "unsupported-relationship-signature"


def test_campaign_and_tool_are_not_primary_comparable_entities():
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": [
            _object("campaign", "campaign--1", name="Example Campaign"),
            _object("tool", "tool--1", name="Example Tool"),
        ],
    }

    reference = canonicalize_bundle("AA00-001A", bundle, "Example Campaign used Example Tool.")

    assert reference.entities == ()
    assert {item["reason"] for item in reference.exclusions} == {"unsupported-primary-object-type"}


def test_rejects_placeholder_entity_values_from_primary_comparison():
    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-4000-8000-000000000001",
        "objects": [_object("malware", "malware--1", name="Unknown")],
    }

    reference = canonicalize_bundle("AA00-001A", bundle, "Unknown malware was named.")

    assert reference.entities == ()
    assert reference.ungrounded_entities == ()
    assert reference.exclusions[0]["reason"] == "placeholder-entity-value"


@pytest.mark.parametrize(("pattern", "source_text", "expected"), [
    ("[domain-name:value = 'evil.example']", "evil[.]example.", "evil.example"),
    ("[email-message:from_ref.value = 'a@b.com']", "a@b[.]com.", "a@b.com"),
    ("[file:hashes.MD5 = '" + "a" * 32 + "']", "a" * 32 + ".", "a" * 32),
    ("[ipv4-addr:value = '1.2.3.4']", "1.2.3[.]4:443", "1.2.3.4"),
])
def test_grounding_accepts_indicator_trailing_punctuation_and_ip_ports(pattern, source_text, expected):
    reference = canonicalize_bundle("AA00-001A", bundle_with_pattern(pattern), source_text)

    assert [entity.canonical_value for entity in reference.entities] == [expected]
    assert reference.ungrounded_entities == ()


def test_indicator_boundaries_reject_larger_domain_and_ip_prefix_values():
    bundle = bundle_with_pattern(
        "[domain-name:value = 'evil.example' OR ipv4-addr:value = '1.2.3.4']"
    )

    reference = canonicalize_bundle("AA00-001A", bundle, "evil[.]example.com and 1.2.3[.]45")

    assert reference.entities == ()
    assert {entity.canonical_value for entity in reference.ungrounded_entities} == {
        "evil.example", "1.2.3.4",
    }


@pytest.mark.parametrize(("pattern", "source_text", "expected"), [
    ("[ipv4-addr:value = '1.2.3.4']", "1.2.3[.]4:443", "1.2.3.4"),
    ("[ipv6-addr:value = '2001:db8::1']", "[2001:db8::1]:443", "2001:db8::1"),
])
def test_grounding_accepts_only_valid_address_port_forms(pattern, source_text, expected):
    reference = canonicalize_bundle("AA00-001A", bundle_with_pattern(pattern), source_text)

    assert [entity.canonical_value for entity in reference.entities] == [expected]


@pytest.mark.parametrize(("pattern", "source_text"), [
    ("[ipv4-addr:value = '1.2.3.4']", "1.2.3[.]4:evil"),
    ("[ipv4-addr:value = '1.2.3.4']", "1.2.3[.]4:65536"),
    ("[ipv4-addr:value = '1.2.3.4']", "1.2.3[.]4:443:1"),
    ("[ipv6-addr:value = '2001:db8::1']", "2001:db8::1:443"),
])
def test_grounding_rejects_invalid_or_continued_address_values(pattern, source_text):
    reference = canonicalize_bundle("AA00-001A", bundle_with_pattern(pattern), source_text)

    assert reference.entities == ()
    assert len(reference.ungrounded_entities) == 1
