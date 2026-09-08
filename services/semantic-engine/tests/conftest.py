import pytest
from unittest.mock import MagicMock


@pytest.fixture
def mock_pycti():
    client = MagicMock()
    client.indicator.list.return_value = [
        {
            "id": "indicator--test-uuid-1234",
            "name": "1.2.3.4",
            "x_opencti_main_observable_type": "IPv4-Addr",
            "description": "C2 server",
            "objectLabel": [{"value": "botnet-cc"}],
            "updated_at": "2026-06-25T00:00:00.000Z",
        }
    ]
    return client


@pytest.fixture
def mock_ollama():
    # ponytail: response.embeddings[0] shape validates Pitfall 4 — plural, list-of-lists
    client = MagicMock()
    client.embed.return_value = MagicMock(embeddings=[[0.1] * 768])
    return client


@pytest.fixture
def mock_chroma():
    collection = MagicMock()
    collection.get.return_value = {"ids": [], "metadatas": []}
    collection.query.return_value = {
        "distances": [[0.2, 0.8]],
        "metadatas": [[
            {
                "ioc_type": "IPv4-Addr",
                "value": "1.2.3.4",
                "opencti_url": "http://localhost:8080/dashboard/observations/indicators/indicator--test-uuid-1234",
                "embedded_text": "IPv4-Addr: 1.2.3.4 [botnet-cc]",
            },
            {
                "ioc_type": "Domain-Name",
                "value": "evil.com",
                "opencti_url": "http://localhost:8080/dashboard/observations/indicators/indicator--evil-uuid",
                "embedded_text": "Domain-Name: evil.com",
            },
        ]],
        "documents": [["doc1", "doc2"]],
    }
    return collection
