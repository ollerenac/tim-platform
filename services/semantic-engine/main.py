"""
main.py — FastAPI service entry point for semantic-engine.

Endpoints:
  GET /health  — immediate response with index progress (D-05, never blocks)
  GET /ready   — 200 only after a real Ollama embedding warmup
  GET /search  — natural-language IOC search with similarity scoring (AISEM-02/03/04)

Lifespan: warms the embedding model, then starts indexer.run_index_loop() in the
background without blocking liveness responses.
"""
import asyncio
import logging
import threading
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import indexer
import searcher
from config import SEMANTIC_WARMUP_RETRY_SECONDS, SIMILARITY_THRESHOLD

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
WARMUP_RETRY_SECONDS = SEMANTIC_WARMUP_RETRY_SECONDS
MAX_READINESS_ERROR_CHARS = 512
semantic_readiness = {"status": "starting", "attempts": 0, "error": None}
_readiness_probe_lock = threading.Lock()


def _readiness_error(exc: Exception) -> str:
    error = " ".join(str(exc).split())[:MAX_READINESS_ERROR_CHARS]
    return error or type(exc).__name__


async def initialize_semantic_engine(
    *,
    warmup=None,
    index_loop=None,
    sleep=asyncio.sleep,
    run_sync=asyncio.to_thread,
):
    """Warm Ollama before indexing so first-load work has a single owner."""
    warmup = warmup or searcher.warmup
    index_loop = index_loop or indexer.run_index_loop

    while True:
        semantic_readiness["status"] = "warming"
        semantic_readiness["attempts"] += 1
        semantic_readiness["error"] = None
        attempt = semantic_readiness["attempts"]
        try:
            dimensions = await run_sync(warmup)
        except Exception as exc:
            semantic_readiness["error"] = _readiness_error(exc)
            logger.warning(
                "[semantic-readiness] warmup attempt %d failed; retrying in %ds: %s",
                attempt,
                WARMUP_RETRY_SECONDS,
                semantic_readiness["error"],
            )
            await sleep(WARMUP_RETRY_SECONDS)
            continue

        semantic_readiness.update(status="ready", error=None)
        logger.info(
            "[semantic-readiness] READY after %d attempt(s); dimensions=%d; starting indexer",
            attempt,
            dimensions,
        )
        await index_loop()
        return


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialization stays in the background so /health remains a liveness probe.
    semantic_readiness.update(status="starting", attempts=0, error=None)
    initialization = asyncio.create_task(initialize_semantic_engine())
    try:
        yield
    finally:
        initialization.cancel()
        with suppress(asyncio.CancelledError):
            await initialization


app = FastAPI(title="semantic-engine", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://localhost"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/stats")
async def stats():
    """
    Return ChromaDB index statistics (STATS-01).
    Wrapped in asyncio.to_thread — ChromaDB I/O is blocking (D-04).
    """
    def _get_stats():
        col = indexer.get_collection()
        count = col.count()
        checkpoint = indexer.read_checkpoint(col)
        return count, checkpoint
    count, checkpoint = await asyncio.to_thread(_get_stats)
    last_run = checkpoint["last_indexed_at"] or None
    total_indexed = (
        max(0, count - 1) if checkpoint["checkpoint_exists"] else count
    )
    stats_status = indexer.index_state["status"]
    if stats_status == "starting" and not checkpoint["scan_upper_bound"]:
        stats_status = "ok" if last_run else "never_run"
    return {
        "total_indexed": total_indexed,
        "collection": indexer.COLLECTION_NAME,
        "last_run": last_run,
        "status": stats_status,
    }


@app.get("/health")
def health():
    """Return index progress immediately. Never awaits indexer state (D-05)."""
    return {"status": "ok", **indexer.index_state}


@app.get("/ready")
def ready():
    """Prove point-in-time readiness without changing the Docker liveness probe."""
    if semantic_readiness["status"] in {"starting", "warming"}:
        return JSONResponse(status_code=503, content=dict(semantic_readiness))

    with _readiness_probe_lock:
        try:
            dimensions = searcher.warmup()
        except Exception as exc:
            semantic_readiness.update(
                status="degraded",
                error=_readiness_error(exc),
            )
            logger.warning(
                "[semantic-readiness] live probe failed: %s",
                semantic_readiness["error"],
            )
            return JSONResponse(status_code=503, content=dict(semantic_readiness))

        semantic_readiness.update(status="ready", error=None)
        logger.info(
            "[semantic-readiness] live probe passed; dimensions=%d",
            dimensions,
        )
        return JSONResponse(status_code=200, content=dict(semantic_readiness))


@app.get("/search")
def search_iocs(q: str = "", n_results: int = 10):
    """
    Natural-language IOC search (AISEM-02/03/04).

    V5 input validation (T-04-04-01, T-04-04-03):
    - q empty → 400
    - q > 500 chars → 400 (DoS prevention before embed call)
    """
    if not q:
        raise HTTPException(status_code=400, detail="q parameter required")
    if len(q) > 500:
        raise HTTPException(status_code=400, detail="q too long (max 500 chars)")
    n_results = max(1, min(n_results, 100))

    results = searcher.search(
        indexer.get_collection(),
        q,
        n_results=n_results,
        threshold=SIMILARITY_THRESHOLD,
    )
    return {"query": q, "results": results, "count": len(results)}
