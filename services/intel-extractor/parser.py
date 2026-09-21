"""
parser.py — Document text extraction for intel-extractor.
"""
import io
import ipaddress
import logging
import socket
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from PyPDF2 import PdfReader
import trafilatura

logger = logging.getLogger(__name__)

MAX_FETCH_BYTES = 50_000_000  # 50 MB — matches the upload cap in main.py (_MAX_UPLOAD_BYTES)
MAX_PDF_PAGES = 500           # PDF-bomb guard: stop extracting past this many pages
MAX_TEXT_CHARS = 4_000_000    # cap extracted text so a hostile doc can't drive unbounded LLM work


def fetch(url: str, *, timeout: int = 30, check_ssrf: bool = True) -> tuple[bytes, str]:
    """Fetch a URL, returning (body_bytes, content_type_lowercased).

    Shared by the RSS collector and extract_url_text so no fetch can bypass the
    SSRF/redirect/size protections. Guards: http(s) only, no embedded credentials,
    no private/internal targets (unless check_ssrf=False for operator-configured
    feed hosts), no redirects, and a hard streamed byte cap so a lying or absent
    Content-Length cannot exhaust memory. Raises ValueError on any violation.

    The content_type lets callers route by what actually arrived (application/pdf)
    rather than a URL suffix that lies for query-string or extension-less links.
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

    resp = requests.get(
        url, timeout=timeout, allow_redirects=False, stream=True,
        headers={"User-Agent": "Mozilla/5.0"},
    )
    try:
        resp.raise_for_status()
        declared = resp.headers.get("Content-Length", "")
        if declared.isdigit() and int(declared) > MAX_FETCH_BYTES:
            raise ValueError(f"response too large ({declared} bytes, max {MAX_FETCH_BYTES})")
        content_type = (resp.headers.get("Content-Type", "") or "").split(";")[0].strip().lower()
        chunks: list[bytes] = []
        total = 0
        for chunk in resp.iter_content(chunk_size=65536):
            total += len(chunk)
            if total > MAX_FETCH_BYTES:
                raise ValueError(f"response exceeded {MAX_FETCH_BYTES} bytes — aborted")
            chunks.append(chunk)
        return b"".join(chunks), content_type
    finally:
        resp.close()


def fetch_bytes(url: str, *, timeout: int = 30, check_ssrf: bool = True) -> bytes:
    """Back-compat wrapper: fetch() body only, for callers that don't need the type."""
    return fetch(url, timeout=timeout, check_ssrf=check_ssrf)[0]


def looks_like_pdf(content_type: str, data: bytes, url: str = "") -> bool:
    """Decide if a fetched resource is a PDF by what actually arrived, not the URL suffix.

    Content-Type header is authoritative; the %PDF magic-byte prefix catches
    mislabeled servers; the path suffix (query stripped) is the last-resort hint.
    """
    if content_type == "application/pdf":
        return True
    if data[:5] == b"%PDF-":
        return True
    return urlparse(url).path.lower().endswith(".pdf")


def _check_ssrf(hostname: str) -> None:
    """Raise ValueError if hostname resolves to any non-globally-routable address.

    Checks loopback, link-local, private, reserved, multicast, and !is_global to
    cover RFC1918, CGN (100.64/10), IPv6 link-local (fe80::/10), ULA (fc00::/7),
    and documentation/test ranges that an explicit list would miss.

    ponytail: TOCTOU (DNS rebinding) accepted — DNS is re-resolved at request time by
    trafilatura/requests; pinning the IP would require a custom transport. Risk is low
    for a local analyst tool where the analyst controls all inputs.
    """
    try:
        addrs = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve '{hostname}': {exc}") from exc
    for addr_str in addrs:
        addr = ipaddress.ip_address(addr_str)
        if (
            not addr.is_global
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_private
            or addr.is_reserved
            or addr.is_multicast
        ):
            raise ValueError("URL resolves to a private/internal address — not permitted")


def extract_pdf_text(pdf_bytes: bytes) -> str:
    """Extract plain text from PDF bytes. Raises ValueError for image-based or unreadable PDFs."""
    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        pages_text = []
        for i, page in enumerate(reader.pages):
            if i >= MAX_PDF_PAGES:
                logger.warning("[parser] PDF exceeds %d pages — truncating (PDF-bomb guard)", MAX_PDF_PAGES)
                break
            pages_text.append(page.extract_text())
    except Exception as exc:
        raise ValueError(f"PDF appears to be image-based — no extractable text found") from exc
    full_text = "\n".join(t for t in pages_text if t)
    if not full_text.strip():
        raise ValueError("PDF appears to be image-based — no extractable text found")
    return full_text[:MAX_TEXT_CHARS]


def extract_url_text(url: str) -> str:
    """Fetch and extract plain text from a URL.

    Fetches through transport.fetch — the same tier-escalating fetcher the collector
    uses — so a host that answers 403 to a plain client is retried with a browser TLS
    fingerprint. Before 2026-09-21 this path used the plain fetcher while the collector
    used the escalating one, so POST /extract could not read advisories the collector
    read fine (measured: cisa.gov returned 403 here and 200 there, same container).
    The same guards apply either way: transport mirrors parser.fetch's http(s)-only,
    no-credentials, SSRF, no-redirect and streamed-size checks.

    Routes on what actually arrived, not on the URL suffix: an advisory served as a PDF
    is parsed as a PDF instead of being decoded as HTML into noise.
    """
    # Local import: transport imports from parser, so a module-level import would cycle.
    import transport

    raw, content_type = transport.fetch(url, timeout=15)
    if looks_like_pdf(content_type, raw, url):
        return extract_pdf_text(raw)
    html = raw.decode("utf-8", errors="replace")
    result = trafilatura.extract(html)
    if result:
        return result[:MAX_TEXT_CHARS]
    logger.info("[parser] trafilatura extract failed for %s — falling back to BeautifulSoup", urlparse(url).hostname)
    soup = BeautifulSoup(html, "html.parser")
    return soup.get_text(separator="\n", strip=True)[:MAX_TEXT_CHARS]
