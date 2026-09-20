"""TIM patch: decide whether a connector run is due, from the state OpenCTI keeps for it.

pycti's scheduler calls the connector callback on every container start, whatever
CONNECTOR_DURATION_PERIOD says. Upstream reads `last_run_timestamp` only to log it, so every
host restart or redeploy re-imported the full feed: 10,000 IPs, 30,000 queued objects and about
2.6 h of worker time per start (measured 2026-09-20, two runs 20 minutes apart).

Self-check: python3 schedule_guard.py
"""

from datetime import datetime, timedelta, timezone

# ponytail: "recent" is half the period. A restart minutes or hours after a run is skipped, while a
# host that is switched on once a day still imports daily. Skipping a start means the next run comes
# one full period after that start, so the gap between imports can reach 1.5 periods; if that ever
# matters, schedule hourly and keep this guard as the real cadence.
RECENT_FRACTION = 0.5


def run_is_due(state, now, period_seconds):
    """True when the connector never ran, its state is unreadable, or the last run is not recent."""
    try:
        last = datetime.fromisoformat(state["last_run_timestamp"])
    except (TypeError, KeyError, ValueError):
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    elapsed = (now - last).total_seconds()
    # A clock that went backwards leaves the last run "in the future": run, never block the connector.
    return elapsed < 0 or elapsed >= period_seconds * RECENT_FRACTION


if __name__ == "__main__":
    now = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
    day = 86400
    stamp = lambda delta: {"last_run_timestamp": (now - delta).isoformat()}
    assert run_is_due(None, now, day)                                   # first run ever
    assert run_is_due({}, now, day)                                     # state without a timestamp
    assert run_is_due({"last_run_timestamp": "garbage"}, now, day)      # unreadable state
    assert not run_is_due(stamp(timedelta(minutes=20)), now, day)       # redeploy 20 min after a run
    assert not run_is_due(stamp(timedelta(hours=11, minutes=59)), now, day)
    assert run_is_due(stamp(timedelta(hours=12)), now, day)             # boundary: half the period
    assert run_is_due(stamp(timedelta(hours=23, minutes=49)), now, day) # host switched on once a day
    assert run_is_due(stamp(timedelta(hours=-1)), now, day)             # clock went backwards
    assert not run_is_due({"last_run_timestamp": "2026-09-20T11:01:41.860580"}, now, day)  # naive = UTC
    assert not run_is_due({"last_run_timestamp": "2026-09-20T11:01:41.860580+00:00"}, now, day)  # as stored
    print("schedule_guard: ok")
