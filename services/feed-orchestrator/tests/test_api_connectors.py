"""
test_api_connectors.py - /connectors/status offline tests (quick-260710-874).
"""
import json

import api


class FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


PAYLOAD = {"data": {"connectors": [
    {
        "id": "c1", "name": "MITRE ATT&CK", "active": True, "auto": False,
        "connector_type": "EXTERNAL_IMPORT",
        "connector_state": json.dumps({"last_run_timestamp": 1783666800000}),  # epoch ms
    },
    {
        "id": "c2", "name": "IPinfo", "active": False, "auto": True,
        "connector_type": "INTERNAL_ENRICHMENT",
        "connector_state": None,
    },
    {
        "id": "c3", "name": "MITRE ATT&CK 7x", "active": True, "auto": False,
        "connector_type": "EXTERNAL_IMPORT",
        "connector_state": json.dumps({"last_run": 1783666800}),  # epoch seconds, 7.x key
    },
    {
        "id": "c4", "name": "CISA KEV", "active": True, "auto": False,
        "connector_type": "EXTERNAL_IMPORT",
        "connector_state": json.dumps({"last_update": "2026-07-10T07:00:00+00:00"}),
    },
]}}


def _reset_cache():
    api._connectors_cache = {"ts": 0.0, "data": None}


def test_connectors_status_shape(monkeypatch):
    _reset_cache()
    monkeypatch.setattr(api.requests, "post", lambda *a, **k: FakeResp(PAYLOAD))

    result = api.connectors_status()

    assert set(result) == {"connectors"}
    first, second, third, fourth = result["connectors"]
    assert set(first) == {"name", "active", "connector_type", "last_run"}
    assert first["name"] == "MITRE ATT&CK"
    assert first["active"] is True
    assert first["connector_type"] == "EXTERNAL_IMPORT"
    assert first["last_run"] == "2026-07-10T07:00:00+00:00"
    assert second["last_run"] is None
    assert second["active"] is False
    assert third["last_run"] == "2026-07-10T07:00:00+00:00"   # last_run key, epoch seconds
    assert fourth["last_run"] == "2026-07-10T07:00:00+00:00"  # last_update key, ISO passthrough


def test_connectors_status_cache_hit(monkeypatch):
    _reset_cache()
    calls = {"n": 0}

    def fake_post(*a, **k):
        calls["n"] += 1
        return FakeResp(PAYLOAD)

    monkeypatch.setattr(api.requests, "post", fake_post)

    api.connectors_status()
    api.connectors_status()

    assert calls["n"] == 1
