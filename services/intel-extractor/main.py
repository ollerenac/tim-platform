"""
main.py — FastAPI entry point for intel-extractor.

Endpoints:
  POST /extract  — submit PDF or URL for background extraction
  GET  /jobs/{id} — poll job status
  GET  /health   — liveness probe

D-06: job state stored in extractor.jobs (module-level dict, lost on restart).
T-03-05-01: file upload limited to 50 MB; returns 413 if exceeded.
"""
import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

import collector
import cnsd_ingest
import config
import queue_store
import queue_worker
import stats_store
from extractor import jobs, recent_docs, register_job, run_extraction

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    stats_store.init_db()
    # Incident 2026-08-10: a fresh volume + auto-started collector queued ~120
    # RSS docs into paid LLM extractions. The collector loop is opt-in now —
    # without COLLECTOR_ENABLED=true this service is a manual-extraction API only.
    task = None
    if config.COLLECTOR_ENABLED:
        task = asyncio.create_task(
            collector.run_collector_loop(
                dispatchers={"cnsd_strict": cnsd_ingest.ingest_discovered_document}
            )
        )
        logger.warning("[main] collector loop ENABLED — feed items will auto-extract via %s", config.LLM_PROVIDER)
    else:
        logger.info("[main] collector loop disabled (COLLECTOR_ENABLED=false) — manual /extract only")
    yield
    if task is not None:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


app = FastAPI(title="intel-extractor", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://localhost"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

_MAX_UPLOAD_BYTES = 50_000_000  # T-03-05-01: 50 MB cap


@app.post("/extract")
async def submit_extract(
    background_tasks: BackgroundTasks,
    file: Optional[UploadFile] = File(None),
    url: Optional[str] = Form(None),
):
    if not file and not url:
        raise HTTPException(status_code=400, detail="provide file or url")

    job_id = str(uuid.uuid4())
    # ponytail: init BEFORE add_task — task may read jobs[job_id] before this line runs otherwise
    register_job(job_id)

    if file:
        content = await file.read()
        # T-03-05-01: reject oversized uploads
        if len(content) > _MAX_UPLOAD_BYTES:
            del jobs[job_id]
            logger.warning("[main] upload rejected: %d bytes (limit %d)", len(content), _MAX_UPLOAD_BYTES)
            raise HTTPException(status_code=413, detail="file too large (max 50 MB)")
        background_tasks.add_task(run_extraction, job_id, "pdf", content, None)
    else:
        background_tasks.add_task(run_extraction, job_id, "url", None, url)

    return {"job_id": job_id, "status": "queued"}


@app.get("/jobs/{job_id}")
async def get_job(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail="job not found")
    return {"job_id": job_id, **jobs[job_id]}


@app.get("/recent")
async def recent():
    return {"docs": stats_store.get_recent_documents(50)}


@app.get("/stats")
async def stats():
    row = stats_store.get_stats()
    last_run = row.get("last_run")
    return {
        "total_docs": row.get("total_docs", 0),
        "total_iocs": row.get("total_iocs", 0),
        "last_run": last_run,
        "status": "ok" if last_run else "never_run",
    }


@app.get("/collector/status")
async def collector_status():
    # get_status() does blocking disk reads (_load_state/_load_sources) — keep them off the loop
    return await asyncio.to_thread(collector.get_status)


@app.get("/collector/validate")
async def collector_validate():
    # ROB-05: full network sweep across all configured sources — runs off-loop
    # (T-10-08); /collector/status above stays network-free and fast.
    return await asyncio.to_thread(collector.validate_sources)


# ── Fase B: entity quarantine queue (design 260724-fa) ──────────────────────

_QUEUE_STATUSES = {"pending", "approved", "rejected", "auto_matched"}


@app.get("/queue")
async def queue_list(status: str = "pending", limit: int = 200):
    if status not in _QUEUE_STATUSES:
        raise HTTPException(status_code=422, detail=f"status must be one of {sorted(_QUEUE_STATUSES)}")
    entries = await asyncio.to_thread(queue_store.list_entries, status, limit)
    return {"status": status, "count": len(entries), "entries": entries}


@app.post("/queue/{entry_id}/approve")
async def queue_approve(entry_id: int):
    """Analyst confirms the candidate is real: entity created + deferred claim
    replayed through the closed-world seam with original-document provenance."""
    try:
        return await asyncio.to_thread(queue_worker.approve_entry, entry_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.post("/queue/{entry_id}/reject")
async def queue_reject(entry_id: int):
    try:
        await asyncio.to_thread(queue_worker.reject_entry, entry_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {"id": entry_id, "status": "rejected"}


@app.get("/health")
async def health():
    return {"status": "ok"}
