"""
feeds/urlhaus.py — URLhaus malicious URL feed parser.

Downloads CSV from urlhaus.abuse.ch, skips comment lines, normalizes to STIX url:value patterns.

Security: Single quotes in URL values are escaped before pattern interpolation (T-02-04-01).
"""
import csv
import logging

import requests

from config import FEED_INTERVALS, QUALITY_WEIGHTS
from feeds.base import BaseFeed, stix_escape

logger = logging.getLogger(__name__)

URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
# URLhaus CSV has no non-comment header row; field order is fixed per their docs
_URLHAUS_FIELDS = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]


class URLhausFeed(BaseFeed):
    name = "urlhaus"
    quality_weight = QUALITY_WEIGHTS["urlhaus"]  # 15
    interval_hours = FEED_INTERVALS["urlhaus"]   # 1

    def fetch(self) -> list[dict]:
        resp = requests.get(URLHAUS_URL, timeout=30)
        resp.raise_for_status()
        lines = [l for l in resp.text.splitlines() if not l.startswith("#")]
        return list(csv.DictReader(lines, fieldnames=_URLHAUS_FIELDS))

    def normalize(self, raw: list[dict]) -> list[dict]:
        result = []
        for row in raw:
            url = row.get("url", "").strip()
            if not url:
                continue
            tags = [t.strip() for t in row.get("tags", "").split(",") if t.strip()]
            url_safe = stix_escape(url)  # T-02-04-01: STIX pattern injection guard
            result.append({
                "name": url_safe,
                "pattern": f"[url:value = '{url_safe}']",
                "observable_type": "Url",
                "labels": tags,
                "source_name": "URLhaus",
                "valid_from": row.get("dateadded", ""),
            })
        return result
