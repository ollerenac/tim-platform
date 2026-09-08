"""
main.py — FastAPI entry point for briefing-generator.

Endpoints:
  POST /generate              — trigger async briefing generation
  GET  /briefings/{id}        — poll briefing status / fetch result
  GET  /briefings/{id}/pdf    — download briefing as PDF (status must be "done")
  GET  /briefings             — list all briefing summaries
  GET  /health                — liveness probe

Briefing state persisted to SQLite via store.py (DB_PATH=/data/briefings.db, mounted volume).
T-05-04-01: period_hours validated by Pydantic Field(ge=1, le=720) before any I/O.
"""
import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field

import store
from generator import run_generate

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init_db()
    yield


app = FastAPI(title="briefing-generator", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "https://localhost"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


class GenerateRequest(BaseModel):
    period_hours: int = Field(default=24, ge=1, le=720)


@app.post("/generate")
async def generate(body: GenerateRequest, background_tasks: BackgroundTasks):
    briefing_id = str(uuid.uuid4())
    # ponytail: upsert BEFORE add_task — background thread reads the row immediately
    store.upsert(briefing_id, {
        "status": "generating",
        "text": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "period_hours": body.period_hours,
        "error": None,
    })
    background_tasks.add_task(run_generate, briefing_id, body.period_hours)
    return {"briefing_id": briefing_id, "status": "generating"}


@app.get("/briefings/{briefing_id}")
async def get_briefing(briefing_id: str):
    entry = store.get(briefing_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="briefing not found")
    return {"briefing_id": briefing_id, **entry}


@app.get("/briefings/{briefing_id}/pdf")
async def get_briefing_pdf(briefing_id: str):
    entry = store.get(briefing_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="briefing not found")
    if entry["status"] != "done":
        # Pitfall 5: never call render_pdf() when text is None
        raise HTTPException(status_code=404, detail="briefing not ready")
    from pdf_renderer import render_pdf  # lazy import — only needed on this path
    try:
        pdf_bytes = render_pdf(entry)
    except Exception as exc:
        # e.g. fpdf2 FPDFException on a glyph missing from DejaVuSans (emoji in LLM text)
        logger.error("[main] PDF render failed for %s: %s", briefing_id, exc)
        raise HTTPException(status_code=500, detail="PDF render failed")
    return Response(content=pdf_bytes, media_type="application/pdf")


@app.get("/briefings")
async def list_briefings():
    return [
        {
            "briefing_id": r["id"],
            "created_at": r["created_at"],
            "period_hours": r["period_hours"],
            "status": r["status"],
        }
        for r in store.list_all()
    ]


# P0.2: techniques ranked by REAL `uses` relationship count via one distribution
# query (the fake count=1 made the "Top" card an arbitrary list). 5-min cache —
# the ranking moves slowly and the dashboard polls every 30s.
_TOP_TECH_TTL = 300.0
_top_tech_cache = {"ts": 0.0, "data": None}

_USES_DISTRIBUTION_QUERY = """
query TopUsedTechniques($limit: Int, $filters: FilterGroup) {
  stixCoreRelationshipsDistribution(
    relationship_type: "uses"
    isTo: true
    toTypes: ["Attack-Pattern"]
    field: "internal_id"
    operation: count
    limit: $limit
    filters: $filters
  ) {
    label
    value
    entity { ... on AttackPattern { name x_mitre_id } }
  }
}
"""


def _top_techniques(client, fallback_patterns: list, curated_ids: list | None = None) -> list:
    """Top 5 ATT&CK techniques by `uses` relationship count.

    On any failure (schema drift, timeout) fall back to the unranked pattern
    list with count=None — never fabricate a count again.
    Provenance: with curated_ids, only `uses` authored by the allowlist count.
    """
    import time
    now = time.monotonic()
    if _top_tech_cache["data"] is not None and now - _top_tech_cache["ts"] < _TOP_TECH_TTL:
        return _top_tech_cache["data"]
    try:
        filters = None
        if curated_ids:
            filters = {
                "mode": "and",
                "filters": [{"key": ["createdBy"], "values": curated_ids,
                             "operator": "eq", "mode": "or"}],
                "filterGroups": [],
            }
        result = client.query(_USES_DISTRIBUTION_QUERY, {"limit": 5, "filters": filters})
        rows = result["data"]["stixCoreRelationshipsDistribution"] or []
        techniques = [
            {
                "id": (r.get("entity") or {}).get("x_mitre_id") or "",
                "name": (r.get("entity") or {}).get("name") or "",
                "count": r.get("value"),
            }
            for r in rows if r
        ]
        if not techniques:
            raise ValueError("empty distribution result")
    except Exception as exc:
        logger.warning("[stats] uses-distribution failed (%s) — unranked fallback, no counts", exc)
        techniques = [
            {"id": p.get("x_mitre_id") or "", "name": p.get("name", ""), "count": None}
            for p in fallback_patterns[:5]
        ]
    _top_tech_cache["ts"] = now
    _top_tech_cache["data"] = techniques
    return techniques


@app.get("/stats")
async def stats():
    """
    Return IOC count (last 24h) and top 5 ATT&CK techniques (DASH-02, D-05, D-06).

    Uses asyncio.to_thread to keep pycti I/O off the event loop (T-06-01-03).
    Techniques ranked by real `uses` counts (P0.2) — see _top_techniques.
    """
    def _get_stats():
        from opencti_client import build_pycti_client
        from generator import _collect_threat_data, _make_updated_at_filter, _resolve_curated_ids
        client = build_pycti_client()
        data = _collect_threat_data(client, 24)
        curated_ids = _resolve_curated_ids(client)
        # Real 24h count via globalCount (WR-01 pattern) — data["indicators"] is the
        # briefing input list, capped at 25 by D-04, so len() flatlines at 25.
        # Provenance (e111119 follow-up): same curated-author filter as the briefing.
        try:
            result = client.indicator.list(
                first=1, getAll=False, withPagination=True,
                filters=_make_updated_at_filter(24, curated_ids),
                orderBy="updated_at", orderMode="desc",
            ) or {}
            count = (result.get("pagination") or {}).get("globalCount")
        except Exception:
            count = None
        if count is None:
            count = len(data.get("indicators", []))
        techniques = _top_techniques(client, data.get("attack_patterns", []), curated_ids)
        return count, techniques

    ioc_count, techniques = await asyncio.to_thread(_get_stats)
    return {
        "ioc_count_24h": ioc_count,
        "top_techniques": techniques,
    }


@app.get("/cve/stats")
async def cve_stats():
    """
    Return total CVE count from OpenCTI and last-seen timestamp (STATS-03).
    Wrapped in asyncio.to_thread — pycti I/O is blocking (D-04).
    last_run derived from max updated_at across vulnerability objects.
    """
    def _get_cve_stats():
        from opencti_client import build_pycti_client
        client = build_pycti_client()
        # first=1 + withPagination gives globalCount without fetching all objects (WR-01)
        result = client.vulnerability.list(
            first=1, getAll=False, withPagination=True,
            orderBy="updated_at", orderMode="desc",
        ) or {}
        total = (result.get("pagination") or {}).get("globalCount", 0)
        entities = result.get("entities") or []
        last_run = entities[0].get("updated_at") if entities else None
        return total, last_run
    total_cves, last_run = await asyncio.to_thread(_get_cve_stats)
    return {
        "total_cves": total_cves,
        "last_run": last_run,
        "status": "ok" if last_run else "never_run",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
