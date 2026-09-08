"""
feeds/threatfox.py — ThreatFox feed parser (FEED-02b).

POSTs to threatfox-api.abuse.ch with Auth-Key header. Handles five ioc_types:
ip:port, domain, url, md5_hash, sha256_hash. Unknown types silently skipped.

ip:port split uses rsplit(":", 1)[0] to handle IPv6 addresses (Pitfall 2).
SHA-256 pattern uses single-quoted property name (Pitfall 3).
Disabled gracefully when THREATFOX_AUTH_KEY is absent (D-07 pattern).
"""
import logging

import requests

from config import FEED_INTERVALS, QUALITY_WEIGHTS, THREATFOX_AUTH_KEY
from feeds.base import BaseFeed, stix_escape

logger = logging.getLogger(__name__)

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
_LARGE_RESULT_WARN = 50000


class ThreatFoxFeed(BaseFeed):
    name = "threatfox"
    quality_weight = QUALITY_WEIGHTS["threatfox"]
    interval_hours = FEED_INTERVALS["threatfox"]

    def run(self, redis_client, pycti_client) -> None:
        if not THREATFOX_AUTH_KEY:
            logger.warning("[threatfox] disabled: THREATFOX_AUTH_KEY not configured")
            redis_client.hset(
                f"tim:feed_status:{self.name}",
                mapping={"status": "disabled", "last_run": "", "ioc_count": 0, "error_msg": ""},
            )
            return
        super().run(redis_client, pycti_client)

    def fetch(self) -> list[dict]:
        resp = requests.post(
            THREATFOX_URL,
            headers={"Auth-Key": THREATFOX_AUTH_KEY},
            json={"query": "get_iocs", "days": 7},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok":
            raise ValueError(f"ThreatFox API error: {data.get('query_status')}")
        result = data.get("data") or []
        # T-02-05-04: warn on unexpectedly large datasets
        if len(result) > _LARGE_RESULT_WARN:
            logger.warning("[threatfox] large result set: %d rows", len(result))
        return result

    def _parse_ioc(self, ioc_type: str, ioc_value: str):
        """Return (pattern, observable_type) or None for unknown types."""
        # ponytail: escape single quotes in ioc value (T-02-05-02)
        v = stix_escape(ioc_value)
        if ioc_type == "ip:port":
            # rsplit on last ':' so IPv6 addresses like ::1:4444 are handled (Pitfall 2)
            ip = ioc_value.rsplit(":", 1)[0]
            ip_safe = stix_escape(ip)
            return (f"[ipv4-addr:value = '{ip_safe}']", "IPv4-Addr")
        if ioc_type == "domain":
            return (f"[domain-name:value = '{v}']", "Domain-Name")
        if ioc_type == "url":
            return (f"[url:value = '{v}']", "Url")
        if ioc_type == "md5_hash":
            return (f"[file:hashes.MD5 = '{v}']", "StixFile")
        if ioc_type == "sha256_hash":
            return (f"[file:hashes.'SHA-256' = '{v}']", "StixFile")
        # email, mutex, and any future types are out of scope
        return None

    def normalize(self, raw: list[dict]) -> list[dict]:
        results = []
        for ioc_dict in raw:
            ioc_type = ioc_dict.get("ioc_type", "")
            ioc_value = ioc_dict.get("ioc", "")
            parsed = self._parse_ioc(ioc_type, ioc_value)
            if parsed is None:
                continue
            pattern, observable_type = parsed
            labels = [ioc_dict.get("malware_printable", "")] + list(ioc_dict.get("tags") or [])
            labels = [l for l in labels if l]
            results.append({
                "name": f"ThreatFox {ioc_type} {ioc_value[:32]}",
                "pattern": pattern,
                "observable_type": observable_type,
                "confidence": self.quality_weight,
                "labels": labels,
                "source_name": "ThreatFox",
                "valid_from": ioc_dict.get("first_seen", ""),
            })
        return results
