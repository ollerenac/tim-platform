import pytest
from unittest.mock import MagicMock


@pytest.fixture
def mock_pycti():
    client = MagicMock()
    client.indicator.create.return_value = {"id": "indicator--test-uuid-1234"}
    client.report.create.return_value = {"id": "report--test-uuid-5678"}
    client.stix_core_relationship.create.return_value = {"id": "relationship--test-uuid-9012"}
    client.attack_pattern.list.return_value = [
        {"id": "attack-pattern--test-uuid-3456", "name": "Phishing", "x_mitre_id": "T1566"}
    ]
    # Fase A closed-world catalogs: names used across targeting tests must resolve,
    # otherwise create_targeting_relationships quarantines them instead of writing.
    client.intrusion_set.list.return_value = [
        {"id": "intrusion-set--example", "name": "Example Actor", "aliases": ["ExActor"]},
        {"id": "intrusion-set--a", "name": "Actor A", "aliases": []},
        {"id": "intrusion-set--b", "name": "Actor B", "aliases": []},
    ]
    client.malware.list.return_value = [
        {"id": "malware--ghostloader", "name": "GhostLoader", "aliases": []},
    ]
    return client

