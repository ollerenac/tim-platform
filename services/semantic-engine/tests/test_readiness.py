import asyncio
import json
from unittest.mock import MagicMock

import main


def _set_readiness(status="starting", attempts=0, error=None):
    main.semantic_readiness.clear()
    main.semantic_readiness.update(
        {"status": status, "attempts": attempts, "error": error}
    )


def test_ready_is_503_until_model_warmup_completes(monkeypatch):
    live_checks = []
    monkeypatch.setattr(
        main.searcher,
        "warmup",
        lambda: live_checks.append("warmup") or 768,
    )
    _set_readiness(status="warming", attempts=1)

    response = main.ready()

    assert response.status_code == 503
    assert live_checks == []
    assert json.loads(response.body) == {
        "status": "warming",
        "attempts": 1,
        "error": None,
    }

    _set_readiness(status="ready", attempts=1)
    response = main.ready()

    assert response.status_code == 200
    assert live_checks == ["warmup"]
    assert json.loads(response.body)["status"] == "ready"


def test_ready_recovers_after_a_live_warmup_failure(monkeypatch):
    def fail_warmup():
        raise TimeoutError("model evicted")

    _set_readiness(status="ready", attempts=1)
    monkeypatch.setattr(main.searcher, "warmup", fail_warmup)

    response = main.ready()

    assert response.status_code == 503
    assert main.semantic_readiness == {
        "status": "degraded",
        "attempts": 1,
        "error": "model evicted",
    }

    monkeypatch.setattr(main.searcher, "warmup", lambda: 768)
    response = main.ready()

    assert response.status_code == 200
    assert main.semantic_readiness["status"] == "ready"
    assert main.semantic_readiness["error"] is None


def test_initializer_retries_warmup_before_starting_index_loop():
    events = []
    warmup_attempts = 0

    def warmup():
        nonlocal warmup_attempts
        warmup_attempts += 1
        events.append(f"warmup-{warmup_attempts}")
        if warmup_attempts == 1:
            raise TimeoutError("cold model")
        return 768

    async def index_loop():
        events.append("index-loop")

    async def sleep(seconds):
        events.append(f"sleep-{seconds}")

    async def run_sync(function):
        return function()

    _set_readiness()
    asyncio.run(
        main.initialize_semantic_engine(
            warmup=warmup,
            index_loop=index_loop,
            sleep=sleep,
            run_sync=run_sync,
        )
    )

    assert events == [
        "warmup-1",
        f"sleep-{main.WARMUP_RETRY_SECONDS}",
        "warmup-2",
        "index-loop",
    ]
    assert main.semantic_readiness == {
        "status": "ready",
        "attempts": 2,
        "error": None,
    }


def test_stats_excludes_active_checkpoint_sentinel(monkeypatch):
    collection = MagicMock()
    collection.count.return_value = 1
    monkeypatch.setattr(main.indexer, "get_collection", lambda: collection)
    monkeypatch.setattr(main.indexer, "read_watermark", lambda value: None)
    monkeypatch.setattr(
        main.indexer,
        "read_checkpoint",
        lambda value: {
            "checkpoint_exists": True,
            "last_indexed_at": "",
            "scan_mode": "full",
            "scan_upper_bound": "2026-07-13T10:00:00.000Z",
            "scan_after": "",
            "scan_processed": 0,
        },
        raising=False,
    )

    result = asyncio.run(main.stats())

    assert result["total_indexed"] == 0
    assert result["last_run"] is None
