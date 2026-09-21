"""run() records how many rows were fetched and how many survived normalize(),
next to the inserted count, so the ingestion funnel can be read from Redis."""
from unittest.mock import MagicMock

from feeds.base import BaseFeed


class _ThreeRowsTwoIndicators(BaseFeed):
    name = "funnel_test"
    quality_weight = 10
    interval_hours = 1

    def fetch(self):
        return [{"v": "1.1.1.1"}, {"v": "2.2.2.2"}, {"v": "not-an-ip"}]

    def normalize(self, raw):
        return [
            {"name": r["v"], "pattern": f"[ipv4-addr:value = '{r['v']}']", "observable_type": "IPv4-Addr"}
            for r in raw if r["v"][0].isdigit()
        ]


def test_run_records_fetched_and_normalized_counts(mock_redis, mock_pycti, monkeypatch):
    monkeypatch.setattr("feeds.base._index_ioc", lambda *a, **k: None)
    monkeypatch.setattr("feeds.base.create_indicator", lambda **k: {"id": "indicator--x"})

    _ThreeRowsTwoIndicators().run(mock_redis, mock_pycti)

    running, done = (c.kwargs["mapping"] for c in mock_redis.hset.call_args_list)
    assert (running["fetched_count"], running["normalized_count"]) == ("0", "0")
    assert done["status"] == "ok"
    assert (done["fetched_count"], done["normalized_count"], done["ioc_count"]) == ("3", "2", "2")


def test_failed_run_leaves_the_funnel_at_zero(mock_redis, mock_pycti, monkeypatch):
    monkeypatch.setattr("feeds.base.time.sleep", lambda s: None)
    feed = _ThreeRowsTwoIndicators()
    feed.fetch = MagicMock(side_effect=ValueError("empty body"))

    feed.run(mock_redis, mock_pycti)

    running, failed = (c.kwargs["mapping"] for c in mock_redis.hset.call_args_list)
    assert failed["status"] == "error"
    assert (running["fetched_count"], running["normalized_count"]) == ("0", "0")
    assert "fetched_count" not in failed  # the reset above is what a reader sees
