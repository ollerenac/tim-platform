"""
feeds/sslbl_ja3.py — abuse.ch SSLBL JA3 fingerprint blacklist feed parser (SRC-01).

IMPORTANT: this list is FROZEN upstream since 2021-08-03 (~97 rows). It delivers a
one-time import — ioc_count stuck at ~97 (first run) then 0 (dedup) after day one is
EXPECTED, not a bug (research Pitfall 1). abuse.ch itself warns the JA3 list is
untested against known-good traffic and may cause significant false positives —
hence quality_weight 10 and the "fp-prone" label on every indicator.

Representation (adopted decision, research Open Question 1): STIX 2.1 has no JA3
SCO, so JA3 MD5s are emitted as [text:value = '<md5>'] with observable_type "Text".
Smoke-verified against live OpenCTI in plan 12-05; rework is cheap at 97 rows.

CSV shape mirrors sslbl_cert.py: comment-prefixed, positional columns
ja3_md5,Firstseen,Lastseen,Listingreason (headers inside comments — no DictReader).

Security: stix_escape() on every interpolated value (T-02-04-01).
"""
import csv
import logging
import re

import requests

from config import ABUSECH_AUTH_KEY, FEED_INTERVALS, QUALITY_WEIGHTS
from feeds.base import BaseFeed, stix_escape

logger = logging.getLogger(__name__)

SSLBL_JA3_URL = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"
_MD5_RE = re.compile(r"^[0-9a-fA-F]{32}$")


class SslblJa3Feed(BaseFeed):
    name = "sslbl_ja3"
    quality_weight = QUALITY_WEIGHTS["sslbl_ja3"]   # 10 — frozen + FP-prone
    interval_hours = FEED_INTERVALS["sslbl_ja3"]    # 24 — daily no-op on frozen list

    def fetch(self) -> list[dict]:
        headers = {"Auth-Key": ABUSECH_AUTH_KEY} if ABUSECH_AUTH_KEY else {}
        resp = requests.get(SSLBL_JA3_URL, headers=headers, timeout=30)
        resp.raise_for_status()
        lines = [l for l in resp.text.splitlines()
                 if l.strip() and not l.startswith("#")]
        rows = []
        for cols in csv.reader(lines):
            if len(cols) < 4:
                continue
            ja3_md5 = cols[0].strip()
            first_seen = cols[1].strip()
            last_seen = cols[2].strip()
            reason = cols[3].strip()
            if not _MD5_RE.fullmatch(ja3_md5):
                continue
            rows.append({
                "ja3_md5": ja3_md5,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "reason": reason,
            })
        if not rows:
            # Pitfall 6: surface silent format drift as status=error, not ioc_count=0 ok
            raise ValueError("empty feed body - possible format drift")
        return rows

    def normalize(self, raw: list[dict]) -> list[dict]:
        result = []
        for row in raw:
            md5 = stix_escape(row["ja3_md5"])  # T-02-04-01: injection guard
            labels = ["ja3", "c2", "fp-prone"]
            reason = row.get("reason", "").strip()
            if reason:
                labels.append(reason)
            result.append({
                "name": f"JA3 {md5}",
                "pattern": f"[text:value = '{md5}']",
                "observable_type": "Text",
                "labels": labels,
                "source_name": "abuse.ch SSLBL JA3",
                # Normalization convention: T-separated ISO with explicit UTC offset
                # (corrected Pitfall 7 — space form also parses; this is consistency).
                "valid_from": row["first_seen"].replace(" ", "T") + "+00:00",
            })
        return result
