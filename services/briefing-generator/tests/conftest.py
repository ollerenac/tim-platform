import pytest
from unittest.mock import MagicMock


@pytest.fixture
def mock_pycti():
    client = MagicMock()
    # Read-only entity list mocks — field names match _build_stats_block() expectations
    client.indicator.list.return_value = [
        {
            "id": "ind-aaa",
            "name": "1.2.3.4",
            "x_opencti_score": 85,
            "x_opencti_main_observable_type": "IPv4-Addr",
            "objectLabel": [{"value": "finance"}],
        }
    ]
    client.threat_actor.list.return_value = [{"id": "ta-aaa", "name": "APT29"}]
    client.malware.list.return_value = [{"id": "mal-aaa", "name": "QakBot"}]
    client.campaign.list.return_value = [{"id": "camp-aaa", "name": "Campaign-X"}]
    client.attack_pattern.list.return_value = [
        {"id": "ap-aaa", "name": "Phishing", "x_mitre_id": "T1566"}
    ]
    return client


@pytest.fixture
def mock_ollama():
    # Attribute path response.message.content matches _call_ollama() in generator.py
    client = MagicMock()
    client.chat.return_value.message.content = (
        "During the past 24 hours, threat activity remained elevated. "
        "APT29 continued targeting financial sector organizations using phishing techniques. "
        "QakBot malware was observed in multiple campaigns. "
        "Security teams should prioritize email filtering and endpoint detection controls."
    )
    return client
