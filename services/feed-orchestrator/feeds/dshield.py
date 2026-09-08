"""
feeds/dshield.py — DShield recommended block list feed parser (SRC-01).

Downloads block.txt — tab-separated rows (start_ip, end_ip, netmask, attacks,
name, country, email) with '#' comments. The /24 CIDR is derived from the
start-ip + netmask column. CIDR values ride inside normal [ipv4-addr:value]
patterns — the official OpenCTI DShield connector representation; never
expanded into per-IP indicators.

User-Agent: the endpoint 403'd a cloud proxy during research live-probe
(2026-07-07); a stable descriptive UA avoids bot heuristics.

License: CC BY-NC-SA 2.5 — accepted for this research deployment (research
OQ3, adopted; revisit only if the platform is ever commercialized).
Polling policy: <=1 fetch/hour upstream; the 4h interval honors it.

Security: every interpolated value goes through stix_escape() (T-02-04-01).
"""
import ipaddress
import logging

import requests

from config import FEED_INTERVALS, QUALITY_WEIGHTS
from feeds.base import BaseFeed, stix_escape

logger = logging.getLogger(__name__)

DSHIELD_URL = "https://feeds.dshield.org/block.txt"


class DshieldFeed(BaseFeed):
    name = "dshield"
    quality_weight = QUALITY_WEIGHTS["dshield"]   # 20 — attack-volume derived
    interval_hours = FEED_INTERVALS["dshield"]    # 4 (>= 1h upstream ceiling)

    def fetch(self) -> list[dict]:
        resp = requests.get(
            DSHIELD_URL,
            headers={"User-Agent": "tim-feed-orchestrator/1.0"},
            timeout=30,
        )
        resp.raise_for_status()
        rows = []
        for line in resp.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            try:
                network = ipaddress.ip_network(
                    f"{parts[0].strip()}/{parts[2].strip()}", strict=False
                )
            except ValueError:
                continue
            if not isinstance(network, ipaddress.IPv4Network):
                continue
            rows.append({"cidr": str(network)})
        if not rows:
            # Pitfall 6: surface silent format drift as status=error, not ioc_count=0 ok
            raise ValueError("empty feed body - possible format drift")
        return rows

    def normalize(self, raw: list[dict]) -> list[dict]:
        result = []
        for row in raw:
            cidr = stix_escape(row["cidr"])  # T-02-04-01: STIX pattern injection guard
            result.append({
                "name": f"DShield block {cidr}",
                "pattern": f"[ipv4-addr:value = '{cidr}']",
                "observable_type": "IPv4-Addr",
                "labels": ["attacker-netblock"],
                "source_name": "DShield",
                # no valid_from in feed — parse_first_seen falls back to now()
            })
        return result
