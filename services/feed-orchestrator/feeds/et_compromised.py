"""
feeds/et_compromised.py - Emerging Threats compromised-IPs feed parser (SRC-01).

Downloads the ET Open compromised-ips.txt list. The body is plain text with one
IPv4 address per line plus occasional comments. Non-IPv4-shaped lines are
skipped before STIX pattern interpolation (ASVS V5).

Security: every interpolated value goes through stix_escape() (T-12-11).
"""
import ipaddress
import logging

import requests

from config import FEED_INTERVALS, QUALITY_WEIGHTS
from feeds.base import BaseFeed, stix_escape

logger = logging.getLogger(__name__)

ET_COMPROMISED_URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"


class EtCompromisedFeed(BaseFeed):
    name = "et_compromised"
    quality_weight = QUALITY_WEIGHTS["et_compromised"]   # 20 — ET Open compromised hosts
    interval_hours = FEED_INTERVALS["et_compromised"]    # 12 (daily upstream)

    def fetch(self) -> list[dict]:
        resp = requests.get(ET_COMPROMISED_URL, timeout=30)
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
                "labels": ["compromised-host"],
                "source_name": "Emerging Threats",
                # no valid_from in feed — parse_first_seen falls back to now()
            })
        return result
