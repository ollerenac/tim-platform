"""
opencti_client.py — pycti wrapper for OpenCTI indicator creation.

Provides:
  build_pycti_client()   — construct and return an OpenCTIApiClient
  create_indicator()     — submit a STIX indicator with D-05 retry (3x, 30/60/120s)

D-05: On pycti insertion failure, retry 3× with delays [30, 60, 120].
After all retries exhausted, log warning and return None (do not raise).
IOCs lost for that run; next scheduled run will re-download and retry.

Assumption A2: pycti.indicator.create() parameter name for labels is
'objectLabel' per RESEARCH.md Pattern 3 and docs.opencti.io.
Verify against pycti/entities/opencti_indicator.py in the installed package
(pycti==6.4.11) during first Docker build. If the parameter is 'labels'
instead of 'objectLabel', update the call below and remove this comment.

Assumption A4: 'confidence' and 'x_opencti_score' are independent fields.
Setting both to the same value is safe per RESEARCH.md Pattern 3.
"""
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from pycti import OpenCTIApiClient

from config import OPENCTI_TOKEN, OPENCTI_URL

logger = logging.getLogger(__name__)

# D-05 retry delays: 30s → 60s → 120s
_RETRY_DELAYS = [30, 60, 120]

# In-process value→id cache. Label values (malware families, tags) repeat heavily across
# a feed run, so resolve each once instead of an API call per indicator.
_label_id_cache: dict = {}


def _resolve_label_ids(client: OpenCTIApiClient, labels: list) -> list:
    """Resolve label value strings to OpenCTI label IDs (get-or-create), cached.

    indicator.create(objectLabel=...) attaches only label IDs — passing raw value
    strings silently dropped every label. label.create() is get-or-create by value.
    """
    ids = []
    for value in labels:
        if not value:
            continue
        lid = _label_id_cache.get(value)
        if lid is None:
            try:
                lid = client.label.create(value=value)["id"]
                _label_id_cache[value] = lid
            except Exception as exc:
                logger.warning("[opencti_client] label resolve failed for %r: %s", value, exc)
                continue
        ids.append(lid)
    return ids


def build_pycti_client() -> OpenCTIApiClient:
    """Build and return an OpenCTIApiClient connected to OPENCTI_URL."""
    return OpenCTIApiClient(
        url=OPENCTI_URL,
        token=OPENCTI_TOKEN,
        log_level="error",  # suppress INFO spam from pycti internals
    )


def create_indicator(
    client: OpenCTIApiClient,
    name: str,
    pattern: str,
    observable_type: str,
    confidence: int,
    labels: list,
    source_name: str,
    valid_from: Optional[str] = None,
    description: Optional[str] = None,
) -> Optional[dict]:
    """
    Submit a STIX indicator to OpenCTI with idempotent upsert (update=True).

    Wraps client.indicator.create() in D-05 retry: 3x with [30, 60, 120]s delays.
    Logs a warning on each failure. Returns None after all retries exhausted.

    Args:
        client:           OpenCTIApiClient instance from build_pycti_client()
        name:             Human-readable indicator name
        pattern:          STIX 2.1 pattern string e.g. "[url:value = 'http://...']"
        observable_type:  x_opencti_main_observable_type value e.g. "IPv4-Addr"
        confidence:       0-100 confidence score (D-09 formula)
        labels:           List of label strings (malware families, tags)
        source_name:      Feed source name for externalReferences
        valid_from:       ISO-8601 UTC string; defaults to now if None
        description:      Optional indicator description (e.g. country context)

    Returns:
        dict with indicator data on success, None on failure after all retries.
    """
    if valid_from is None:
        valid_from = datetime.now(timezone.utc).isoformat()

    # objectLabel attaches by ID, not by value string — resolve once before the retry loop.
    label_ids = _resolve_label_ids(client, labels)

    last_exc: Optional[Exception] = None
    for attempt, delay in enumerate(_RETRY_DELAYS):
        try:
            return client.indicator.create(
                name=name,
                description=description,
                pattern_type="stix",
                pattern=pattern,
                x_opencti_main_observable_type=observable_type,
                valid_from=valid_from,
                confidence=confidence,
                x_opencti_score=confidence,  # A4: same value as confidence
                objectLabel=label_ids,        # label IDs (raw strings do not attach)
                indicator_types=["malicious-activity"],
                x_opencti_create_observables=True,
                update=True,                 # idempotent upsert — safety net beyond Redis dedup
            )
        except Exception as exc:
            last_exc = exc
            if attempt < len(_RETRY_DELAYS) - 1:
                logger.warning(
                    "[opencti_client] indicator create attempt %d failed, retrying in %ds: %s",
                    attempt + 1,
                    delay,
                    exc,
                )
                time.sleep(delay)
            else:
                logger.warning(
                    "[opencti_client] indicator create failed after %d attempts, skipping: %s",
                    len(_RETRY_DELAYS),
                    exc,
                )

    return None
