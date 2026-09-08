"""
transport.py — Browser-TLS transport with per-host tier escalation + conditional GET.

ROB-01: default plain `requests`; on a 403 (Akamai/Cloudflare block the Python TLS/JA3
        fingerprint) escalate to `curl_cffi` (impersonate=chrome124) and cache the winning
        tier per host so subsequent fetches skip the doomed plain probe.
ROB-02: conditional GET — send If-None-Match / If-Modified-Since, treat 304 as "no work"
        (returned as FetchResult.status == 304 with body None, WITHOUT raising).

Reuses parser._check_ssrf and parser.MAX_FETCH_BYTES — no duplicated SSRF/size logic. The
status_code is inspected for 304/403 BEFORE raise_for_status(), and allow_redirects=False is
passed to BOTH tiers so a redirect can't bounce past the pre-flight SSRF check.

No collector.py wiring here — that is Plan 10-02.
"""
from typing import NamedTuple, Optional
from urllib.parse import urlparse

import requests
from curl_cffi import requests as cffi

from parser import _check_ssrf, MAX_FETCH_BYTES

_UA = "TIM-collector/1.4 (+security-research)"
_IMPERSONATE = "chrome124"


class FetchResult(NamedTuple):
    status: int
    body: Optional[bytes]
    content_type: Optional[str]
    etag: Optional[str]
    last_modified: Optional[str]
    tier: str


def _fetch_plain(url, *, headers, timeout, allow_redirects):
    return requests.get(
        url, headers=headers, timeout=timeout,
        allow_redirects=allow_redirects, stream=True,
    )


def _fetch_cffi(url, *, headers, timeout, allow_redirects):
    return cffi.get(
        url, headers=headers, timeout=timeout,
        allow_redirects=allow_redirects, stream=True, impersonate=_IMPERSONATE,
    )


def _read_capped(resp) -> bytes:
    """Streamed byte cap mirroring parser.fetch — a lying/absent Content-Length can't exhaust memory."""
    declared = str(resp.headers.get("Content-Length", "") or "")
    if declared.isdigit() and int(declared) > MAX_FETCH_BYTES:
        raise ValueError(f"response too large ({declared} bytes, max {MAX_FETCH_BYTES})")
    chunks: list[bytes] = []
    total = 0
    for chunk in resp.iter_content(chunk_size=65536):
        total += len(chunk)
        if total > MAX_FETCH_BYTES:
            raise ValueError(f"response exceeded {MAX_FETCH_BYTES} bytes — aborted")
        chunks.append(chunk)
    return b"".join(chunks)


def fetch_conditional(
    url: str, *, etag: Optional[str] = None, modified: Optional[str] = None,
    timeout: int = 30, check_ssrf: bool = True, host_tier: Optional[dict] = None,
) -> FetchResult:
    """Tier-escalating, conditional-GET fetch (ROB-01 + ROB-02).

    Guards mirror parser.fetch: http(s) only, no embedded credentials, hostname required,
    SSRF check (unless disabled for operator-configured feed hosts), no redirects, streamed
    size cap. Reads the current tier from host_tier[hostname] (default "plain"); on a plain
    403 escalates to curl_cffi and, if that succeeds, records the winning tier back into
    host_tier. A 304 returns without raising so the caller can treat it as "no work."
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"URL scheme '{parsed.scheme}' not allowed — only http and https are permitted"
        )
    if parsed.username or parsed.password:
        raise ValueError("URL credentials are not permitted")
    hostname = parsed.hostname or ""
    if not hostname:
        raise ValueError("URL has no hostname")
    if check_ssrf:
        _check_ssrf(hostname)

    headers = {"User-Agent": _UA, "Accept-Language": "en"}
    if etag:
        headers["If-None-Match"] = etag
    if modified:
        headers["If-Modified-Since"] = modified

    tier = (host_tier or {}).get(hostname, "plain")
    fetcher = _fetch_plain if tier == "plain" else _fetch_cffi
    resp = fetcher(url, headers=headers, timeout=timeout, allow_redirects=False)
    winning_tier = tier

    if resp.status_code == 403 and tier == "plain":
        resp.close()
        resp = _fetch_cffi(url, headers=headers, timeout=timeout, allow_redirects=False)
        winning_tier = "cffi"
        if resp.status_code != 403 and host_tier is not None:
            host_tier[hostname] = "cffi"  # persist the winner (collector writes to state file)

    try:
        # Inspect status BEFORE raising: 304 is a success ("no work"), not an error.
        if resp.status_code == 304:
            return FetchResult(304, None, None, etag, modified, winning_tier)
        resp.raise_for_status()
        body = _read_capped(resp)
        content_type = (resp.headers.get("Content-Type", "") or "").split(";")[0].strip().lower()
        return FetchResult(
            resp.status_code, body, content_type,
            resp.headers.get("ETag"), resp.headers.get("Last-Modified"), winning_tier,
        )
    finally:
        resp.close()


def fetch(
    url: str, *, timeout: int = 30, check_ssrf: bool = True, host_tier: Optional[dict] = None,
) -> tuple[bytes, str]:
    """Thin (bytes, content_type) shim over fetch_conditional for non-conditional callers.

    Drop-in for the per-entry / PDF-discovery paths wired in later plans; keeps tier
    escalation + SSRF/size guards, drops the ETag/304 plumbing the caller doesn't need.
    """
    result = fetch_conditional(url, timeout=timeout, check_ssrf=check_ssrf, host_tier=host_tier)
    return result.body, result.content_type
