"""
feeds/sslbl_cert.py — abuse.ch SSLBL SSL certificate blacklist feed parser (SRC-01).

Downloads sslblacklist.csv (comment-prefixed CSV: Listingdate,SHA1,Listingreason —
headers live INSIDE comments, so parsing is positional, not DictReader). Normalizes
to STIX x509-certificate SHA-1 hash patterns; every entry is an abuse.ch-curated
C2 TLS certificate, so the "c2" label is always included.

Auth: the static SSLBL CSV downloads unauthenticated today; the Auth-Key header
is sent only when ABUSECH_AUTH_KEY is configured (feed stays enabled without it).

Security: every interpolated value goes through stix_escape() (T-02-04-01);
key value is never logged (config.py bool() convention).
"""
import csv
import logging
import re

import requests

from config import ABUSECH_AUTH_KEY, FEED_INTERVALS, QUALITY_WEIGHTS
from feeds.base import BaseFeed, stix_escape

logger = logging.getLogger(__name__)

SSLBL_CERT_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
_SHA1_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class SslblCertFeed(BaseFeed):
    name = "sslbl_cert"
    quality_weight = QUALITY_WEIGHTS["sslbl_cert"]   # 25 — abuse.ch-curated C2 certs
    interval_hours = FEED_INTERVALS["sslbl_cert"]    # 2

    def fetch(self) -> list[dict]:
        headers = {"Auth-Key": ABUSECH_AUTH_KEY} if ABUSECH_AUTH_KEY else {}
        resp = requests.get(SSLBL_CERT_URL, headers=headers, timeout=30)
        resp.raise_for_status()
        lines = [l for l in resp.text.splitlines()
                 if l.strip() and not l.startswith("#")]
        rows = []
        for cols in csv.reader(lines):
            if len(cols) < 3:
                continue
            listing_date = cols[0].strip()
            sha1 = cols[1].strip()
            reason = cols[2].strip()
            if not _SHA1_RE.fullmatch(sha1):
                continue
            rows.append({
                "listing_date": listing_date,
                "sha1": sha1,
                "reason": reason,
            })
        if not rows:
            # Pitfall 6: surface silent format drift as status=error, not ioc_count=0 ok
            raise ValueError("empty feed body - possible format drift")
        return rows

    def normalize(self, raw: list[dict]) -> list[dict]:
        result = []
        for row in raw:
            sha1 = stix_escape(row["sha1"])  # T-02-04-01: STIX pattern injection guard
            labels = ["c2"]
            reason = row.get("reason", "").strip()
            if reason:
                labels.append(reason)
            result.append({
                "name": f"SSLBL cert {sha1[:16]}",
                "pattern": f"[x509-certificate:hashes.'SHA-1' = '{sha1}']",
                "observable_type": "X509-Certificate",
                "labels": labels,
                "source_name": "abuse.ch SSLBL",
                # Normalization convention: T-separated ISO-8601 with explicit UTC
                # offset for cross-feed consistency (corrected Pitfall 7 — the space
                # form also parses via parse_first_seen's fromisoformat fallback).
                "valid_from": row["listing_date"].replace(" ", "T") + "+00:00",
            })
        return result
