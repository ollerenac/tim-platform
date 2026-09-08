"""
test_api_status.py - /feeds/status response invariants for Phase 12 review fixes.
"""

from api import feeds_status


def test_feeds_status_includes_error_msg(monkeypatch):
    """The status API exposes Redis error_msg for accepted-error validation."""
    monkeypatch.setattr("api.FEED_NAMES", ["urlhaus"])
    monkeypatch.setattr(
        "api.get_status",
        lambda redis, name: {
            "last_run": "2026-07-07T12:00:00+00:00",
            "ioc_count": "0",
            "status": "error",
            "error_msg": "upstream timeout",
        },
    )

    result = feeds_status()

    assert result["feeds"] == [{
        "name": "urlhaus",
        "last_run": "2026-07-07T12:00:00+00:00",
        "ioc_count": 0,
        "status": "error",
        "error_msg": "upstream timeout",
    }]
