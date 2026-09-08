"""
opencti_client.py — pycti wrapper for reading OpenCTI indicators in semantic-engine.

Provides:
  build_pycti_client()       — construct and return an OpenCTIApiClient
  iter_indicator_pages()     — stream bounded OpenCTI 7 cursor pages
"""
from collections.abc import Iterator
import logging
import time

from pycti import OpenCTIApiClient

from config import OPENCTI_TOKEN, OPENCTI_URL

logger = logging.getLogger(__name__)
PAGE_RETRY_DELAYS = (2, 5, 10)


def build_pycti_client() -> OpenCTIApiClient:
    """Build and return an OpenCTIApiClient connected to OPENCTI_URL."""
    return OpenCTIApiClient(
        url=OPENCTI_URL,
        token=OPENCTI_TOKEN,
        log_level="error",  # suppress INFO spam from pycti internals
    )


def resolve_author_ids(client: OpenCTIApiClient, names: list[str]) -> list[str]:
    """Resolve identity display names to internal ids (exact name match).

    Unresolvable names are logged and skipped — an author with no identity in
    the platform has authored nothing, so nothing is silently lost.
    """
    ids = []
    for name in names:
        # Exact-name filter, NOT search=: the search parser chokes on long names
        # with parentheses (DATABASE_ERROR "Find direct ids fail" on ColCERT).
        f = {
            "mode": "and",
            "filters": [{"key": "name", "values": [name], "operator": "eq", "mode": "or"}],
            "filterGroups": [],
        }
        try:
            matches = client.identity.list(filters=f) or []
        except Exception as exc:
            logger.warning("[opencti_client] author resolve failed for %r: %s", name, exc)
            continue
        exact = [m["id"] for m in matches if m.get("name") == name]
        if exact:
            ids.extend(exact)
        else:
            logger.warning("[opencti_client] curated author not found: %r", name)
    return ids


def _list_indicator_page(client: OpenCTIApiClient, **kwargs) -> dict:
    for attempt in range(len(PAGE_RETRY_DELAYS) + 1):
        try:
            return client.indicator.list(**kwargs)
        except Exception as exc:
            if attempt == len(PAGE_RETRY_DELAYS):
                raise
            delay = PAGE_RETRY_DELAYS[attempt]
            logger.warning(
                "[opencti_client] page fetch failed attempt %d/%d; "
                "retrying in %ds: %s",
                attempt + 1,
                len(PAGE_RETRY_DELAYS) + 1,
                delay,
                exc,
            )
            time.sleep(delay)


def iter_indicator_pages(
    client: OpenCTIApiClient,
    *,
    since: str | None,
    upper_bound: str,
    after: str | None = None,
    page_size: int = 100,
    curated_ids: list[str] | None = None,
) -> Iterator[dict]:
    """Yield stable, bounded pages without pycti's in-memory ``getAll`` path."""
    if not 1 <= page_size <= 100:
        raise ValueError("page_size must be between 1 and 100 for OpenCTI 7")
    if not upper_bound:
        raise ValueError("upper_bound is required")

    filters = []
    if curated_ids:
        filters.append(
            {
                "key": "createdBy",
                "values": curated_ids,
                "operator": "eq",
                "mode": "or",
            }
        )
    if since:
        filters.append(
            {
                "key": "updated_at",
                "values": [since],
                "operator": "gt",
                "mode": "or",
            }
        )
    filters.append(
        {
            "key": "updated_at",
            "values": [upper_bound],
            "operator": "lte",
            "mode": "or",
        }
    )
    filter_group = {"mode": "and", "filters": filters, "filterGroups": []}

    cursor = after
    while True:
        page = _list_indicator_page(
            client,
            first=page_size,
            withPagination=True,
            orderBy="updated_at",
            orderMode="asc",
            filters=filter_group,
            after=cursor,
        )
        if not isinstance(page, dict):
            raise RuntimeError("OpenCTI indicator page is not an object")
        entities = page.get("entities")
        pagination = page.get("pagination")
        if not isinstance(entities, list) or not isinstance(pagination, dict):
            raise RuntimeError("OpenCTI indicator page has invalid pagination data")

        has_next = pagination.get("hasNextPage")
        end_cursor = pagination.get("endCursor")
        if not isinstance(has_next, bool):
            raise RuntimeError("OpenCTI indicator page has invalid hasNextPage")
        if has_next and not end_cursor:
            raise RuntimeError("OpenCTI hasNextPage response is missing endCursor")
        if has_next and end_cursor == cursor:
            raise RuntimeError("OpenCTI pagination returned a repeated endCursor")

        yield page
        if not has_next:
            return
        cursor = end_cursor
