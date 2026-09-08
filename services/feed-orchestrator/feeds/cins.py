"""
feeds/cins.py - CINS Army badguys feed parser (SRC-01).

Downloads ci-badguys.txt, a high-volume plain text IPv4 list. The first daily
cycle can take tens of minutes because ~15,000 rows are inserted sequentially
through pycti. That is expected; this feed is registered last so it cannot delay
later feeds' first status.

Security: every interpolated value goes through stix_escape() (T-12-11).
"""
import ipaddress
import logging

import requests

from config import FEED_INTERVALS, QUALITY_WEIGHTS
from feeds.base import BaseFeed, stix_escape

logger = logging.getLogger(__name__)

CINS_URL = "https://cinsscore.com/list/ci-badguys.txt"


class CinsFeed(BaseFeed):
    name = "cins"
    quality_weight = QUALITY_WEIGHTS["cins"]   # 15 — volume feed, lower influence
    interval_hours = FEED_INTERVALS["cins"]    # 4 (24h dedup TTL limits full-cost runs)

    def fetch(self) -> list[dict]:
        resp = requests.get(CINS_URL, timeout=30)
        resp.raise_for_status()
        rows = []
        for line in resp.text.splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            try:
                parsed = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if isinstance(parsed, ipaddress.IPv4Address):
                rows.append({"ip": ip})
        if not rows:
            # Pitfall 6: surface silent format drift as status=error, not ioc_count=0 ok
            raise ValueError("empty feed body - possible format drift")
        return rows

    def normalize(self, raw: list[dict]) -> list[dict]:
        result = []
        for row in raw:
            ip = row.get("ip", "").strip()
            if not ip:
                continue
            ip_safe = stix_escape(ip)  # T-12-11: STIX pattern injection guard
            result.append({
                "name": ip_safe,
                "pattern": f"[ipv4-addr:value = '{ip_safe}']",
                "observable_type": "IPv4-Addr",
                "labels": ["attacker-ip"],
                "source_name": "CINS Army",
                # no valid_from in feed — parse_first_seen falls back to now()
            })
        return result
