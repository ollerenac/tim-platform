"""
feeds/spamhaus_drop.py — Spamhaus DROP v4 hijacked-netblock feed parser (SRC-01).

Downloads drop_v4.json — NDJSON (one JSON object per line, NOT a JSON array;
resp.json() raises — Pitfall 5). Each data line carries {"cidr","sblid","rir"};
the final line is a metadata record without a "cidr" key and is skipped.

CIDR values ride inside normal [ipv4-addr:value] patterns — the representation
the official OpenCTI DShield connector uses and valid STIX 2.1. Never expand
netblocks into per-IP indicators.

Polling policy: Spamhaus allows max 1 fetch/hour and blocks abusive pollers by
IP; the 12h interval honors this with wide margin (list is re-evaluated daily).

Security: every interpolated value goes through stix_escape() (T-02-04-01).
"""
import json
import ipaddress
import logging

import requests

from config import FEED_INTERVALS, QUALITY_WEIGHTS
from feeds.base import BaseFeed, stix_escape

logger = logging.getLogger(__name__)

SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop_v4.json"


class SpamhausDropFeed(BaseFeed):
    name = "spamhaus_drop"
    quality_weight = QUALITY_WEIGHTS["spamhaus_drop"]   # 30 — Spamhaus-curated
    interval_hours = FEED_INTERVALS["spamhaus_drop"]    # 12 (>= 1h upstream ceiling)

    def fetch(self) -> list[dict]:
        resp = requests.get(SPAMHAUS_DROP_URL, timeout=30)
        resp.raise_for_status()
        rows = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if "cidr" not in obj:  # last line is a metadata record without "cidr"
                continue
            try:
                network = ipaddress.ip_network(str(obj["cidr"]).strip(), strict=False)
            except ValueError:
                continue
            if not isinstance(network, ipaddress.IPv4Network):
                continue
            rows.append({**obj, "cidr": str(network)})
        if not rows:
            # Pitfall 6: surface silent format drift as status=error, not ioc_count=0 ok
            raise ValueError("empty feed body - possible format drift")
        return rows

    def normalize(self, raw: list[dict]) -> list[dict]:
        result = []
        for row in raw:
            cidr = stix_escape(row["cidr"])  # T-02-04-01: STIX pattern injection guard
            labels = ["hijacked-netblock"]
            sblid = row.get("sblid")
            if sblid:
                labels.append(sblid)
            result.append({
                "name": f"Spamhaus DROP {cidr}",
                "pattern": f"[ipv4-addr:value = '{cidr}']",
                "observable_type": "IPv4-Addr",
                "labels": labels,
                "source_name": "Spamhaus DROP",
                # no valid_from in feed — parse_first_seen falls back to now();
                # full recency bonus is correct for an actively-maintained list
            })
        return result
