"""
scheduler.py — APScheduler configuration for feed-orchestrator.

build_scheduler() returns a configured (not yet started) BackgroundScheduler
with one job per feed. main.py calls scheduler.start() AFTER the immediate
startup runs complete (D-06, T-02-07-02).
"""
import logging

from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_MISSED
from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)


def _on_job_event(event) -> None:
    """Log missed or errored feed jobs."""
    if event.exception:
        logger.error("Feed job %s raised an exception: %s", event.job_id, event.exception)
    else:
        logger.warning("Feed job %s was missed (misfire)", event.job_id)


def build_scheduler(feeds, redis_client, pycti_client) -> BackgroundScheduler:
    """
    Create and configure a BackgroundScheduler with one interval job per feed.

    Jobs are added here but the scheduler is NOT started — caller (main.py)
    calls scheduler.start() after all immediate feed runs complete (D-06).

    Args:
        feeds:          List of BaseFeed instances
        redis_client:   Redis client passed as arg to each feed.run()
        pycti_client:   pycti OpenCTIApiClient passed as arg to each feed.run()

    Returns:
        BackgroundScheduler configured with all feed jobs, ready to start.
    """
    scheduler = BackgroundScheduler(
        executors={"default": {"type": "threadpool", "max_workers": 5}},
        job_defaults={
            "coalesce": True,
            "max_instances": 1,  # T-02-07-01: prevent concurrent runs of same feed
            "misfire_grace_time": 60,
        },
    )

    scheduler.add_listener(_on_job_event, EVENT_JOB_ERROR | EVENT_JOB_MISSED)

    for feed in feeds:
        scheduler.add_job(
            feed.run,
            trigger="interval",
            hours=feed.interval_hours,
            args=[redis_client, pycti_client],
            id=f"feed_{feed.name}",
            jitter=60,
            max_instances=1,
            coalesce=True,
        )
        logger.info("Registered scheduler job: feed_%s (every %dh)", feed.name, feed.interval_hours)

    return scheduler
