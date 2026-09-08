"""
Collector gate (incident 2026-08-10): the RSS collector turns feed items into
paid LLM calls with no human in the loop. It must be OFF unless the deployment
opts in with COLLECTOR_ENABLED=true — otherwise the service is manual-API-only.

The gate lives in main.lifespan, so these tests drive the lifespan context
directly (no HTTP client needed).
"""
import asyncio

import pytest

import main


def _run_lifespan(monkeypatch, enabled: bool) -> bool:
    """Run main.lifespan to completion; return whether the collector loop ran."""
    started = asyncio.Event()

    async def fake_loop(*args, **kwargs):
        started.set()
        await asyncio.sleep(3600)  # park until lifespan cancels us

    monkeypatch.setattr(main.stats_store, "init_db", lambda: None)
    monkeypatch.setattr(main.collector, "run_collector_loop", fake_loop)
    monkeypatch.setattr(main.config, "COLLECTOR_ENABLED", enabled)

    async def drive():
        async with main.lifespan(main.app):
            await asyncio.sleep(0)  # let a created task get scheduled
        return started.is_set()

    return asyncio.run(drive())


def test_collector_disabled_by_default_config():
    """The env default itself must be off — a fresh deployment cannot auto-spend."""
    import config
    # config reads the env at import; in the offline suite nothing sets it
    assert config.COLLECTOR_ENABLED is False


def test_lifespan_does_not_start_collector_when_disabled(monkeypatch):
    assert _run_lifespan(monkeypatch, enabled=False) is False


def test_lifespan_starts_collector_when_enabled(monkeypatch):
    assert _run_lifespan(monkeypatch, enabled=True) is True
