"""
feeds/feodo.py — Feodo Tracker C2 IP blocklist feed parser.

Downloads ipblocklist.csv from feodotracker.abuse.ch, skips comment lines,
normalizes to STIX ipv4-addr:value patterns. Every indicator is a confirmed
botnet C2 server — "c2" label is always included.

Security: Single quotes in IP values are escaped before pattern interpolation (T-02-04-01).
"""
import csv
import logging

import requests

from config import FEED_INTERVALS, QUALITY_WEIGHTS
from feeds.base import BaseFeed, stix_escape

logger = logging.getLogger(__name__)

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"


class FeodoFeed(BaseFeed):
    name = "feodo"
    quality_weight = QUALITY_WEIGHTS["feodo"]   # 30 — highest signal, manually curated
    interval_hours = FEED_INTERVALS["feodo"]    # 4

    def fetch(self) -> list[dict]:
        resp = requests.get(FEODO_URL, timeout=30)
        resp.raise_for_status()
        lines = [l for l in resp.text.splitlines() if not l.startswith("#")]
        return list(csv.DictReader(lines))

    def normalize(self, raw: list[dict]) -> list[dict]:
        result = []
        for row in raw:
            dst_ip = row.get("dst_ip", "").strip()
            if not dst_ip:
                continue
            labels = ["c2"]  # always present — all Feodo entries are confirmed C2 servers
            malware = row.get("malware", "").strip()
            if malware:
                labels.append(malware)
            ip_safe = stix_escape(dst_ip)  # T-02-04-01: STIX pattern injection guard
            result.append({
                "name": ip_safe,
                "pattern": f"[ipv4-addr:value = '{ip_safe}']",
                "observable_type": "IPv4-Addr",
                "labels": labels,
                "source_name": "Feodo Tracker",
                "valid_from": row.get("first_seen_utc", ""),
            })
        return result
