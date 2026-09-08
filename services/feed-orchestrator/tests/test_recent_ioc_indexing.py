"""
Regression coverage for the ES-backed ingestion log.

The tim-iocs index is an ingestion/event surface, but its stix_id must point at
the real OpenCTI Indicator, not at a locally fabricated UUID.
"""

from feeds.base import BaseFeed


class _OneIndicatorFeed(BaseFeed):
    name = "urlhaus"
    quality_weight = 15
    interval_hours = 1

    def fetch(self):
        return []

    def normalize(self, raw):
        return []


def test_feed_indexes_real_opencti_standard_id(monkeypatch, mock_redis, mock_pycti):
    captured = {}
    opencti_standard_id = "indicator--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

    def fake_create_indicator(**kwargs):
        return {
            "id": "internal-opencti-id",
            "standard_id": opencti_standard_id,
            "created_at": "2026-07-09T10:34:13.369Z",
            "updated_at": "2026-07-09T10:34:13.388Z",
        }

    def fake_post(url, json, timeout):
        captured["url"] = url
        captured["doc"] = json

        class Response:
            status_code = 201

        return Response()

    monkeypatch.setattr("feeds.base.create_indicator", fake_create_indicator)
    monkeypatch.setattr("feeds.base.requests.post", fake_post)

    count = _OneIndicatorFeed()._insert_deduplicated(
        [{
            "name": "http://example.test/payload",
            "pattern": "[url:value = 'http://example.test/payload']",
            "observable_type": "Url",
            "labels": ["malware"],
            "source_name": "URLhaus",
            "valid_from": "2026-07-09T09:32:08+00:00",
        }],
        mock_redis,
        mock_pycti,
    )

    assert count == 1
    assert captured["doc"]["stix_id"] == opencti_standard_id
    assert captured["doc"]["opencti_standard_id"] == opencti_standard_id
    assert captured["doc"]["stix_id_source"] == "opencti"
    assert captured["doc"]["opencti_id"] == "internal-opencti-id"
    assert captured["doc"]["valid_from"] == "2026-07-09T09:32:08+00:00"
    assert captured["doc"]["opencti_created_at"] == "2026-07-09T10:34:13.369Z"
    assert captured["doc"]["opencti_updated_at"] == "2026-07-09T10:34:13.388Z"
    assert captured["doc"]["ingested_at"] == captured["doc"]["ts"]
    assert captured["url"].endswith(f"/tim-iocs/_doc/{opencti_standard_id}")
