"""
opencti_client.py — pycti wrapper for OpenCTI read-only queries in briefing-generator.

Provides: build_pycti_client() — construct and return an OpenCTIApiClient for read-only queries.

No write functions (create_indicator, create_report, create_relationship, lookup_attack_pattern)
— briefing-generator is a read-only consumer of OpenCTI data.
"""
import logging

from pycti import OpenCTIApiClient

from config import OPENCTI_TOKEN, OPENCTI_URL

logger = logging.getLogger(__name__)


def build_pycti_client() -> OpenCTIApiClient:
    """Build and return an OpenCTIApiClient connected to OPENCTI_URL."""
    return OpenCTIApiClient(
        url=OPENCTI_URL,
        token=OPENCTI_TOKEN,
        log_level="error",  # suppress INFO spam from pycti internals
    )
