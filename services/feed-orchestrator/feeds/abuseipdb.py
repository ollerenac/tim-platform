"""
feeds/abuseipdb.py — AbuseIPDB blacklist feed parser (quick-260710-4dc).

GETs api.abuseipdb.com/api/v2/blacklist with the Key header. Every free-tier
entry is abuseConfidenceScore=100 confirmed abuse — mixed IPv4 + IPv6.
Endpoint/shape live-probed 2026-07-10: {"meta":{...},"data":[{"ipAddress",
"countryCode","abuseConfidenceScore","lastReportedAt"}]}.

Free-tier usage accepted for this research deployment (same treatment as the
DShield license decision). Rate limit: 5 requests/day (x-ratelimit-limit: 5)
— the 24h cadence is mandatory, daily is the ceiling.

Disabled gracefully when ABUSEIPDB_API_KEY is absent (D-07 pattern).
Security: every interpolated value goes through stix_escape() (T-02-04-01);
the key value is NEVER logged.
"""
import logging

import requests

from config import ABUSEIPDB_API_KEY, FEED_INTERVALS, QUALITY_WEIGHTS
from feeds.base import BaseFeed, stix_escape

logger = logging.getLogger(__name__)

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/blacklist"


class AbuseipdbFeed(BaseFeed):
    name = "abuseipdb"
    quality_weight = QUALITY_WEIGHTS["abuseipdb"]
    interval_hours = FEED_INTERVALS["abuseipdb"]

    def run(self, redis_client, pycti_client) -> None:
        if not ABUSEIPDB_API_KEY:
            logger.warning("[abuseipdb] disabled: ABUSEIPDB_API_KEY not configured")
            redis_client.hset(
                f"tim:feed_status:{self.name}",
                mapping={"status": "disabled", "last_run": "", "ioc_count": 0, "error_msg": ""},
            )
            return
        super().run(redis_client, pycti_client)

    def fetch(self) -> list[dict]:
        resp = requests.get(
            ABUSEIPDB_URL,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"limit": 10000},
            timeout=60,
        )
        resp.raise_for_status()
        body = resp.json()
        data = body.get("data", []) if isinstance(body, dict) else []
        rows = [
            row for row in data
            if isinstance(row, dict) and str(row.get("ipAddress", "")).strip()
        ]
        if not rows:
            # Pitfall 6: surface silent format drift as status=error, not ioc_count=0 ok
            raise ValueError("empty feed body - possible format drift")
        return rows

    def normalize(self, raw: list[dict]) -> list[dict]:
        results = []
        for row in raw:
            ip = str(row.get("ipAddress", "")).strip()
            if not ip:
                continue
            ip_safe = stix_escape(ip)  # T-02-04-01: STIX pattern injection guard
            if ":" in ip:
                pattern = f"[ipv6-addr:value = '{ip_safe}']"
                observable_type = "IPv6-Addr"
            else:
                pattern = f"[ipv4-addr:value = '{ip_safe}']"
                observable_type = "IPv4-Addr"
            country = str(row.get("countryCode") or "").strip()
            description = (
                f"AbuseIPDB confirmed-abuse IP (country: {country})"
                if country
                else "AbuseIPDB confirmed-abuse IP"
            )
            results.append({
                "name": f"AbuseIPDB blacklist {ip}",
                "pattern": pattern,
                "observable_type": observable_type,
                "labels": ["abuseipdb", "abuse-reputation"],
                "source_name": "AbuseIPDB",
                "valid_from": row.get("lastReportedAt", ""),
                "description": description,
            })
        return results
