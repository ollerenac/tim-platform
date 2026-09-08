"""
main.py — Entry point for feed-orchestrator service.

Startup sequence (D-06):
  1. Build Redis and pycti clients
  2. Instantiate all configured feed objects
  3. Run all feeds immediately (synchronously, before scheduler starts)
  4. Build and start the APScheduler background scheduler
  5. Block the main thread via uvicorn.run() (serves HTTP on port 8001)

APScheduler threads are daemon threads and continue running while uvicorn
blocks the main thread.
"""
import logging
import threading
import time

import uvicorn
from redis import from_url as redis_from_url

from api import app
from config import REDIS_URL
from feeds.abuseipdb import AbuseipdbFeed
from feeds.cins import CinsFeed
from feeds.dshield import DshieldFeed
from feeds.et_compromised import EtCompromisedFeed
from feeds.feodo import FeodoFeed
from feeds.malwarebazaar import MalwareBazaarFeed
from feeds.openphish import OpenphishFeed
from feeds.spamhaus_drop import SpamhausDropFeed
from feeds.sslbl_cert import SslblCertFeed
from feeds.sslbl_ja3 import SslblJa3Feed
from feeds.threatfox import ThreatFoxFeed
from feeds.urlhaus import URLhausFeed
from opencti_client import build_pycti_client
from scheduler import build_scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def build_redis_client():
    """Connect to Redis using REDIS_URL from config."""
    return redis_from_url(REDIS_URL, decode_responses=True)


def build_enabled_feeds() -> list:
    """
    Instantiate all configured feed objects.

    All feeds are returned; each feed's run() handles the disabled-if-no-key
    check internally (D-07 pattern). main.py does not pre-filter.
    """
    return [
        URLhausFeed(),
        MalwareBazaarFeed(),
        ThreatFoxFeed(),
        FeodoFeed(),
        SslblCertFeed(),
        SslblJa3Feed(),
        OpenphishFeed(),
        EtCompromisedFeed(),
        SpamhausDropFeed(),
        DshieldFeed(),
        AbuseipdbFeed(),
        # High-volume feeds register last so their first cycle cannot delay later statuses.
        CinsFeed(),
    ]


def _build_pycti_with_retry(max_attempts: int = 10, delay: int = 10):
    """
    Retry build_pycti_client() until OpenCTI is reachable.

    ponytail: simple loop — pycti raises ValueError if OpenCTI unreachable;
    Docker network attachment can lag 5-15s after container start in a restart loop.
    """
    for attempt in range(1, max_attempts + 1):
        try:
            return build_pycti_client()
        except Exception as exc:
            if attempt == max_attempts:
                raise
            logger.warning(
                "OpenCTI not reachable (attempt %d/%d): %s — retrying in %ds",
                attempt, max_attempts, exc, delay,
            )
            time.sleep(delay)


def main() -> None:
    logger.info("feed-orchestrator starting")

    redis_client = build_redis_client()
    pycti_client = _build_pycti_with_retry()
    feeds = build_enabled_feeds()

    scheduler = build_scheduler(feeds, redis_client, pycti_client)
    scheduler.start()
    logger.info("Scheduler started — %d feed jobs registered", len(feeds))

    # D-06: run all feeds immediately, but in a background daemon thread so a slow or
    # failing feed (each retry can sleep up to 90s) can't delay uvicorn — and therefore
    # /health — by minutes at boot. T-02-07-02: the initial pass stays sequential within
    # its own thread, so it still avoids concurrent OpenCTI writes on startup.
    def _initial_run() -> None:
        for feed in feeds:
            logger.info("[%s] initial run starting", feed.name)
            feed.run(redis_client, pycti_client)

    threading.Thread(target=_initial_run, name="initial-feed-run", daemon=True).start()

    # Block main thread via uvicorn; APScheduler threads are daemon threads
    # and continue running while uvicorn serves HTTP on port 8001.
    uvicorn.run(app, host="0.0.0.0", port=8001)


if __name__ == "__main__":
    main()
