"""
feeds/openphish.py - OpenPhish community phishing URL feed parser (SRC-01).

Downloads feed.txt from openphish.com. The URL currently redirects to the
openphish/public_feed GitHub raw file; requests follows that 302 by default.
If the redirect ever breaks, pin OPENPHISH_URL to the raw.githubusercontent.com
target verified in Phase 12 research.

License: non-commercial community feed — accepted for this research deployment;
revisit if the platform is commercialized.

Security: every interpolated value goes through stix_escape() (T-12-11).
"""
import logging
from urllib.parse import urlparse

import requests

from config import FEED_INTERVALS, QUALITY_WEIGHTS
from feeds.base import BaseFeed, stix_escape

logger = logging.getLogger(__name__)

OPENPHISH_URL = "https://openphish.com/feed.txt"


class OpenphishFeed(BaseFeed):
    name = "openphish"
    quality_weight = QUALITY_WEIGHTS["openphish"]   # 20 — curated phishing URLs
    interval_hours = FEED_INTERVALS["openphish"]    # 6 (upstream refreshes ~12h)

    def fetch(self) -> list[dict]:
        resp = requests.get(OPENPHISH_URL, timeout=30)
        resp.raise_for_status()
        rows = []
        for line in resp.text.splitlines():
            url = line.strip()
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue
            rows.append({"url": url})
        if not rows:
            # Pitfall 6: surface silent format drift as status=error, not ioc_count=0 ok
            raise ValueError("empty feed body - possible format drift")
        return rows

    def normalize(self, raw: list[dict]) -> list[dict]:
        result = []
        for row in raw:
            url = row.get("url", "").strip()
            if not url:
                continue
            url_safe = stix_escape(url)  # T-12-11: STIX pattern injection guard
            result.append({
                "name": url_safe,
                "pattern": f"[url:value = '{url_safe}']",
                "observable_type": "Url",
                "labels": ["phishing"],
                "source_name": "OpenPhish",
                # no valid_from in feed — parse_first_seen falls back to now()
            })
        return result
