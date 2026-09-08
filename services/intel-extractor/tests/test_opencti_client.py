import inspect

import pytest
import opencti_client

try:
    from opencti_client import lookup_attack_pattern, create_report, create_indicator
    _IMPORT_OK = True
except ImportError:
    _IMPORT_OK = False


_skip = pytest.mark.skipif(not _IMPORT_OK, reason="opencti_client not yet implemented")


def test_lookup_attack_pattern(mock_pycti):
    result = lookup_attack_pattern(mock_pycti, "phishing")
    assert result == "attack-pattern--test-uuid-3456"


def test_create_report(mock_pycti):
    assert "external_reference_ids" in inspect.signature(create_report).parameters
    result = create_report(
        mock_pycti,
        name="Test Report",
        published="2026-06-25T00:00:00Z",
        description="test",
        indicator_ids=["indicator--test-uuid-1234"],
        external_reference_ids=["external-reference--source"],
    )
    assert result["id"] == "report--test-uuid-5678"
    assert mock_pycti.report.create.call_args.kwargs["externalReferences"] == [
        "external-reference--source"
    ]


def test_create_targeting_relationships_preserves_source_provenance(mock_pycti):
    helper = getattr(opencti_client, "create_targeting_relationships", None)
    assert callable(helper), "create_targeting_relationships is missing"

    source_url = "https://source.example/reports/campaign"
    observed_at = "2026-07-13T16:00:00+00:00"
    mock_pycti.external_reference.create.return_value = {"id": "external-reference--source"}
    mock_pycti.intrusion_set.create.return_value = {"id": "intrusion-set--example"}
    mock_pycti.identity.create.return_value = {"id": "identity--water"}
    mock_pycti.stix_core_relationship.create.return_value = {"id": "relationship--targets-water"}

    result = helper(
        client=mock_pycti,
        threat_actor_names=["Example Actor"],
        sector_names=["water"],
        source_url=source_url,
        observed_at=observed_at,
    )

    mock_pycti.external_reference.create.assert_called_once_with(
        source_name="source.example",
        url=source_url,
        update=True,
    )
    mock_pycti.intrusion_set.create.assert_called_once_with(
        name="Example Actor",
        externalReferences=["external-reference--source"],
        update=True,
    )
    mock_pycti.threat_actor_group.create.assert_not_called()
    mock_pycti.identity.create.assert_called_once_with(
        type="Sector",
        name="Water",
        description=f"Sector reported as targeted by {source_url}.",
        externalReferences=["external-reference--source"],
        update=True,
    )
    mock_pycti.stix_core_relationship.create.assert_called_once_with(
        fromId="intrusion-set--example",
        toId="identity--water",
        relationship_type="targets",
        description="Example Actor targets the Water sector.",
        start_time=observed_at,
        externalReferences=["external-reference--source"],
        update=True,
    )
    assert result == {
        "object_ids": [
            "intrusion-set--example",
            "identity--water",
            "relationship--targets-water",
        ],
        "external_reference_ids": ["external-reference--source"],
    }


_SOURCE_URL = "https://source.example/reports/campaign"
_OBSERVED_AT = "2026-07-17T07:00:00+00:00"


def _targeting(mock_pycti, **kwargs):
    mock_pycti.external_reference.create.return_value = {"id": "external-reference--source"}
    return opencti_client.create_targeting_relationships(
        client=mock_pycti,
        threat_actor_names=kwargs.pop("threat_actor_names", []),
        sector_names=kwargs.pop("sector_names", []),
        source_url=_SOURCE_URL,
        observed_at=_OBSERVED_AT,
        **kwargs,
    )


def test_create_targeting_relationships_malware_axis(mock_pycti):
    """Malware→Sector: is_family upsert with NO description, sector relationship."""
    mock_pycti.malware.create.return_value = {"id": "malware--ghostloader"}
    mock_pycti.identity.create.return_value = {"id": "identity--water"}
    mock_pycti.stix_core_relationship.create.return_value = {"id": "relationship--gl-water"}

    result = _targeting(
        mock_pycti, malware_names=["GhostLoader"], sector_names=["water"]
    )

    mock_pycti.malware.create.assert_called_once_with(
        name="GhostLoader",
        is_family=True,
        externalReferences=["external-reference--source"],
        update=True,
    )
    assert "description" not in mock_pycti.malware.create.call_args.kwargs
    mock_pycti.intrusion_set.create.assert_not_called()
    mock_pycti.stix_core_relationship.create.assert_called_once_with(
        fromId="malware--ghostloader",
        toId="identity--water",
        relationship_type="targets",
        description="GhostLoader targets the Water sector.",
        start_time=_OBSERVED_AT,
        externalReferences=["external-reference--source"],
        update=True,
    )
    assert set(result["object_ids"]) == {
        "malware--ghostloader",
        "identity--water",
        "relationship--gl-water",
    }


def test_create_targeting_relationships_country_axis(mock_pycti):
    """Actor→Country: canonical country name (Fase A gazetteer: "US" → "United
    States") so every mention lands on one Location entity."""
    mock_pycti.intrusion_set.create.return_value = {"id": "intrusion-set--example"}
    mock_pycti.location.create.return_value = {"id": "location--us"}
    mock_pycti.stix_core_relationship.create.return_value = {"id": "relationship--ex-us"}

    result = _targeting(
        mock_pycti, threat_actor_names=["Example Actor"], country_names=["US"]
    )

    mock_pycti.location.create.assert_called_once_with(
        type="Country",
        name="United States",
        externalReferences=["external-reference--source"],
        update=True,
    )
    assert "description" not in mock_pycti.location.create.call_args.kwargs
    mock_pycti.stix_core_relationship.create.assert_called_once_with(
        fromId="intrusion-set--example",
        toId="location--us",
        relationship_type="targets",
        description="Example Actor targets United States.",
        start_time=_OBSERVED_AT,
        externalReferences=["external-reference--source"],
        update=True,
    )
    assert set(result["object_ids"]) == {
        "intrusion-set--example",
        "location--us",
        "relationship--ex-us",
    }


def test_create_targeting_relationships_cve_axis_single_actor(mock_pycti):
    """Actor→Vulnerability upserts onto connector-cve entities, honest wording."""
    mock_pycti.intrusion_set.create.return_value = {"id": "intrusion-set--example"}
    mock_pycti.vulnerability.create.return_value = {"id": "vulnerability--cve"}
    mock_pycti.stix_core_relationship.create.return_value = {"id": "relationship--ex-cve"}

    result = _targeting(
        mock_pycti, threat_actor_names=["Example Actor"], cve_ids=["CVE-2023-1234"]
    )

    mock_pycti.vulnerability.create.assert_called_once_with(
        name="CVE-2023-1234",
        externalReferences=["external-reference--source"],
        update=True,
    )
    assert "description" not in mock_pycti.vulnerability.create.call_args.kwargs
    mock_pycti.stix_core_relationship.create.assert_called_once_with(
        fromId="intrusion-set--example",
        toId="vulnerability--cve",
        relationship_type="targets",
        description="Example Actor activity names CVE-2023-1234 (source-reported).",
        start_time=_OBSERVED_AT,
        externalReferences=["external-reference--source"],
        update=True,
    )
    assert set(result["object_ids"]) == {
        "intrusion-set--example",
        "vulnerability--cve",
        "relationship--ex-cve",
    }


def test_create_targeting_relationships_cve_guard_multi_actor(mock_pycti):
    """Two grounded actors → CVE attribution is ambiguous: no vulnerability writes,
    but the sector and country axes still fire."""
    mock_pycti.intrusion_set.create.side_effect = [
        {"id": "intrusion-set--a"},
        {"id": "intrusion-set--b"},
    ]
    mock_pycti.identity.create.return_value = {"id": "identity--water"}
    mock_pycti.location.create.return_value = {"id": "location--us"}
    mock_pycti.stix_core_relationship.create.return_value = {"id": "relationship--any"}

    _targeting(
        mock_pycti,
        threat_actor_names=["Actor A", "Actor B"],
        sector_names=["water"],
        country_names=["US"],
        cve_ids=["CVE-2023-1234"],
    )

    mock_pycti.vulnerability.create.assert_not_called()
    # 2 actors × 1 sector + 2 actors × 1 country = 4 relationships, none to a CVE
    assert mock_pycti.stix_core_relationship.create.call_count == 4
    for call in mock_pycti.stix_core_relationship.create.call_args_list:
        assert call.kwargs["toId"] in {"identity--water", "location--us"}


def test_create_targeting_relationships_cve_cap(mock_pycti):
    """Caps share one code path: 20 CVEs → the 15 lexicographically-first survive."""
    mock_pycti.intrusion_set.create.return_value = {"id": "intrusion-set--example"}
    mock_pycti.vulnerability.create.return_value = {"id": "vulnerability--cve"}
    mock_pycti.stix_core_relationship.create.return_value = {"id": "relationship--any"}

    cve_ids = [f"CVE-2024-{1000 + i}" for i in range(20)]

    _targeting(mock_pycti, threat_actor_names=["Example Actor"], cve_ids=cve_ids)

    assert mock_pycti.vulnerability.create.call_count == 15
    created = [c.kwargs["name"] for c in mock_pycti.vulnerability.create.call_args_list]
    assert created == sorted(cve_ids)[:15]


def test_create_targeting_relationships_entity_thrift(mock_pycti):
    """No target entity is created for an axis that cannot produce a relationship."""
    result = _targeting(mock_pycti, country_names=["US"], cve_ids=["CVE-2023-1234"])

    mock_pycti.location.create.assert_not_called()
    mock_pycti.vulnerability.create.assert_not_called()
    mock_pycti.intrusion_set.create.assert_not_called()
    mock_pycti.stix_core_relationship.create.assert_not_called()
    assert result["object_ids"] == []
