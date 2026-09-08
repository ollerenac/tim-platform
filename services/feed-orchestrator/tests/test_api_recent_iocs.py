"""
Tests for the /feeds/recent ingestion log endpoint.
"""

from api import feeds_recent


class _SearchResponse:
    def raise_for_status(self):
        return None

    def json(self):
        return {
            "hits": {
                "hits": [{
                    "_source": {
                        "ts": "2026-07-09T10:34:24.156820+00:00",
                        "ingested_at": "2026-07-09T10:34:24.156820+00:00",
                        "value": "https://example.test/payload",
                        "pattern": "[url:value = 'https://example.test/payload']",
                        "feed": "urlhaus",
                        "confidence": 49,
                        "stix_id": "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                        "opencti_standard_id": "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                        "stix_id_source": "opencti",
                        "valid_from": "2026-07-09T09:32:08.000Z",
                        "opencti_created_at": "2026-07-09T10:34:13.369Z",
                    },
                }],
            },
        }


def test_feeds_recent_exposes_ingestion_and_opencti_fields(monkeypatch):
    monkeypatch.setattr("api.requests.get", lambda *args, **kwargs: _SearchResponse())

    result = feeds_recent(limit=1)

    assert result["iocs"] == [{
        "ts": "2026-07-09T10:34:24.156820+00:00",
        "ingested_at": "2026-07-09T10:34:24.156820+00:00",
        "value": "https://example.test/payload",
        "type": "URL",
        "feed": "urlhaus",
        "confidence": 49,
        "stix_id": "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "opencti_standard_id": "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "stix_id_source": "opencti",
        "valid_from": "2026-07-09T09:32:08.000Z",
        "opencti_created_at": "2026-07-09T10:34:13.369Z",
    }]
