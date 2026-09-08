"""
indexer.py — Core indexing engine for semantic-engine.

Fetches OpenCTI indicators, embeds them via Ollama nomic-embed-text,
and upserts them into ChromaDB with a watermark sentinel for incremental
restarts (D-04).

Exports at module level for main.py:
  index_state       — progress dict spread into /health response (D-05)
  get_collection()  — returns the ChromaDB collection (called by searcher)
  run_index_loop()  — async coroutine launched by lifespan (D-05)
"""
import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import chromadb
import ollama

from config import (
    CHROMADB_URL,
    CURATED_AUTHORS,
    EMBED_BATCH_SIZE,
    OLLAMA_EMBED_MODEL,
    OLLAMA_KEEP_ALIVE,
    OLLAMA_URL,
    OPENCTI_PAGE_SIZE,
    OPENCTI_BASE_URL,
    POLL_INTERVAL_SECONDS,
)
from opencti_client import (
    build_pycti_client,
    iter_indicator_pages,
    resolve_author_ids,
)

logger = logging.getLogger(__name__)

# ── Module-level state dict exported for main.py /health (D-05) ─────────────
index_state: dict = {"status": "starting", "indexed": 0, "total": 0}

# ── ChromaDB — lazy singleton (defer connect to avoid import-time network call) ──
# ponytail: lazy init so test_indexer.py import guard works without a live ChromaDB
# v2: provenance-curated collection (CURATED_AUTHORS allowlist). New name forces
# a clean rebuild — the old "ioc_embeddings" (467k vectors, ~70% commodity noise)
# stays behind until manually dropped once v2 is verified.
COLLECTION_NAME = "ioc_embeddings_curated"
_chroma: Optional[chromadb.HttpClient] = None  # type: ignore[type-arg]


def _get_chroma() -> chromadb.HttpClient:  # type: ignore[type-arg]
    global _chroma
    if _chroma is None:
        parsed = urlparse(CHROMADB_URL)
        _chroma = chromadb.HttpClient(host=parsed.hostname, port=parsed.port or 8000)
    return _chroma


# ── Ollama singleton ─────────────────────────────────────────────────────────
_ollama = ollama.Client(host=OLLAMA_URL)

# ── Retry delays: same pattern as intel-extractor ───────────────────────────
_RETRY_DELAYS = [30, 60, 120]

# ── Watermark sentinel (D-04) ────────────────────────────────────────────────
WATERMARK_ID = "_watermark_"


def get_collection():
    """
    Get or create the ChromaDB IOC collection with cosine distance.

    MUST use configuration= key (not metadata=) and cosine space — default
    is L2 which produces poor text similarity results (RESEARCH Pitfall 2).
    Safe to call on every startup (get_or_create is idempotent).
    """
    return _get_chroma().get_or_create_collection(
        name=COLLECTION_NAME,
        configuration={"hnsw": {"space": "cosine"}},
    )


def read_checkpoint(collection) -> dict:
    """Read the durable scan cursor stored in the existing watermark sentinel."""
    result = collection.get(ids=[WATERMARK_ID], include=["metadatas"])
    exists = bool(result.get("ids"))
    metadata = result["metadatas"][0] if exists else {}
    scan_mode = metadata.get("scan_mode") or ""
    if scan_mode not in {"", "full", "incremental"}:
        raise RuntimeError(f"Invalid semantic scan_mode: {scan_mode!r}")
    try:
        scan_processed = int(metadata.get("scan_processed") or 0)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Invalid semantic scan_processed checkpoint") from exc
    return {
        "checkpoint_exists": exists,
        "last_indexed_at": metadata.get("last_indexed_at") or "",
        "scan_mode": scan_mode,
        "scan_upper_bound": metadata.get("scan_upper_bound") or "",
        "scan_after": metadata.get("scan_after") or "",
        "scan_processed": scan_processed,
    }


def write_checkpoint(collection, state: dict) -> None:
    """Atomically advance the durable cursor after a successful page upsert."""
    metadata = {
        "last_indexed_at": state.get("last_indexed_at") or "",
        "scan_mode": state.get("scan_mode") or "",
        "scan_upper_bound": state.get("scan_upper_bound") or "",
        "scan_after": state.get("scan_after") or "",
        "scan_processed": int(state.get("scan_processed") or 0),
    }
    collection.upsert(
        ids=[WATERMARK_ID],
        embeddings=[[0.0] * 768],
        documents=["watermark"],
        metadatas=[metadata],
    )


def read_watermark(collection) -> Optional[str]:
    """Compatibility accessor for the last completed scan timestamp."""
    return read_checkpoint(collection)["last_indexed_at"] or None


def write_watermark(collection, timestamp: str) -> None:
    """Compatibility writer for a completed scan timestamp."""
    write_checkpoint(
        collection,
        {
            "last_indexed_at": timestamp,
            "scan_mode": "",
            "scan_upper_bound": "",
            "scan_after": "",
            "scan_processed": 0,
        },
    )


def build_embed_text(indicator: dict) -> str:
    """
    Build the text that will be embedded for a given indicator.

    D-01: With description → "{type}: {value} — {description} {labels}"
    D-03: Without description → "{type}: {value} [{labels}]"

    The em dash (—) is U+2014. Never skip no-description IOCs.
    """
    ioc_type = indicator.get("x_opencti_main_observable_type", "Unknown")
    value = indicator.get("name", "")
    description = indicator.get("description") or ""
    labels = [lbl["value"] for lbl in (indicator.get("objectLabel") or [])]
    label_str = " ".join(labels)

    if description:
        return f"{ioc_type}: {value} — {description} {label_str}".strip()
    else:
        return f"{ioc_type}: {value} [{label_str}]".strip()  # ponytail: D-03 bracket format


def _embed_with_retry(texts: list[str]) -> list[list]:
    """Embed one bounded chunk; raise rather than checkpointing missing vectors."""
    for attempt in range(len(_RETRY_DELAYS) + 1):
        try:
            response = _ollama.embed(
                model=OLLAMA_EMBED_MODEL,
                input=texts,
                keep_alive=OLLAMA_KEEP_ALIVE,
            )
            vectors = list(response.embeddings)
            if len(vectors) != len(texts) or any(not vector for vector in vectors):
                raise RuntimeError("Ollama returned incomplete embedding batch")
            return vectors
        except Exception as exc:
            if attempt < len(_RETRY_DELAYS):
                delay = _RETRY_DELAYS[attempt]
                logger.warning(
                    "[indexer] embed failed attempt %d, retrying in %ds: %s",
                    attempt + 1, delay, exc,
                )
                time.sleep(delay)
            else:
                raise RuntimeError(
                    f"Embedding batch failed after {attempt + 1} attempts"
                ) from exc


def _index_batch(collection, indicators: list[dict]) -> int:
    """
    Embed and upsert a batch of indicators into ChromaDB.

    A failed chunk raises, so the caller never advances the page checkpoint.
    Already-upserted chunks are safe to replay because Chroma IDs are stable.
    """
    candidates = [item for item in indicators if item.get("id") != WATERMARK_ID]
    count = 0
    for start in range(0, len(candidates), EMBED_BATCH_SIZE):
        chunk = candidates[start : start + EMBED_BATCH_SIZE]
        documents = [build_embed_text(indicator) for indicator in chunk]
        vectors = _embed_with_retry(documents)
        collection.upsert(
            ids=[indicator["id"] for indicator in chunk],
            embeddings=vectors,
            documents=documents,
            metadatas=[
                {
                    "ioc_type": indicator.get(
                        "x_opencti_main_observable_type", "Unknown"
                    ),
                    "value": indicator.get("name", ""),
                    "author": (indicator.get("createdBy") or {}).get("name", ""),
                    "opencti_url": (
                        f"{OPENCTI_BASE_URL}/dashboard/observations/indicators/"
                        f"{indicator['id']}"
                    ),
                    "embedded_text": document,
                }
                for indicator, document in zip(chunk, documents)
            ],
        )
        count += len(chunk)
    return count


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _run_index_cycle(watermark: Optional[str]) -> tuple:
    """Sync helper — one full index cycle. Runs in a thread via asyncio.to_thread.

    All blocking I/O (pycti, ollama, chromadb) is safe to do here because the
    caller awaits this in a threadpool — the event loop stays free to serve /health
    and /search while indexing is in progress (fixes event-loop starvation on startup).
    """
    client = build_pycti_client()
    collection = get_collection()

    checkpoint = read_checkpoint(collection)
    if checkpoint.get("scan_upper_bound"):
        scan_mode = checkpoint["scan_mode"]
        upper_bound = checkpoint["scan_upper_bound"]
        after = checkpoint["scan_after"] or None
        processed = checkpoint["scan_processed"]
        logger.info(
            "[indexer] Resuming %s scan at cursor=%s (%d processed)",
            scan_mode,
            bool(after),
            processed,
        )
    else:
        completed_watermark = checkpoint.get("last_indexed_at") or watermark or ""
        scan_mode = "incremental" if completed_watermark else "full"
        upper_bound = _utc_now()
        after = None
        processed = 0
        checkpoint = {
            "last_indexed_at": completed_watermark,
            "scan_mode": scan_mode,
            "scan_upper_bound": upper_bound,
            "scan_after": "",
            "scan_processed": 0,
        }
        write_checkpoint(collection, checkpoint)
        logger.info(
            "[indexer] Starting %s scan through %s", scan_mode, upper_bound
        )

    since = checkpoint.get("last_indexed_at") or None
    if scan_mode == "full":
        since = None
    elif scan_mode != "incremental" or since is None:
        raise RuntimeError("Incremental semantic checkpoint has no watermark")

    # Provenance allowlist: resolved fresh each cycle so identities created
    # after service start (e.g. a new curated source) are picked up.
    curated_ids = (
        resolve_author_ids(client, CURATED_AUTHORS) if CURATED_AUTHORS else None
    )

    index_state.update(status="fetching", indexed=processed, total=0)
    indexed_this_cycle = 0
    pages = iter_indicator_pages(
        client,
        since=since,
        upper_bound=upper_bound,
        after=after,
        page_size=OPENCTI_PAGE_SIZE,
        curated_ids=curated_ids,
    )
    for page in pages:
        entities = page["entities"]
        pagination = page["pagination"]
        global_count = pagination.get("globalCount")
        if isinstance(global_count, int):
            index_state["total"] = global_count

        index_state["status"] = "indexing"
        indexed_this_cycle += _index_batch(collection, entities)
        processed += len(entities)
        index_state["indexed"] = processed

        if pagination["hasNextPage"]:
            checkpoint = {
                "last_indexed_at": since or "",
                "scan_mode": scan_mode,
                "scan_upper_bound": upper_bound,
                "scan_after": pagination["endCursor"],
                "scan_processed": processed,
            }
            write_checkpoint(collection, checkpoint)
            index_state["status"] = "fetching"
            continue

        completed = {
            "last_indexed_at": upper_bound,
            "scan_mode": "",
            "scan_upper_bound": "",
            "scan_after": "",
            "scan_processed": 0,
        }
        write_checkpoint(collection, completed)
        index_state["status"] = "ready"
        logger.info(
            "[indexer] Cycle complete: %d embedded, %d scanned",
            indexed_this_cycle,
            processed,
        )
        return indexed_this_cycle, upper_bound

    raise RuntimeError("OpenCTI pagination ended without a final page")


async def run_index_loop() -> None:
    """Async coroutine — offloads each blocking index cycle to a thread (D-05).

    asyncio.to_thread releases the event loop during sync I/O so /health responds
    immediately even while indexing is in progress.
    """
    watermark: Optional[str] = None

    while True:
        try:
            _, watermark = await asyncio.to_thread(_run_index_cycle, watermark)
        except Exception as exc:
            logger.error("[indexer] Cycle failed: %s", exc)
            index_state["status"] = "error"

        await asyncio.sleep(POLL_INTERVAL_SECONDS)
