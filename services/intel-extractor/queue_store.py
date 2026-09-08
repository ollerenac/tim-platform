"""
queue_store.py — quarantine queue for unresolved entity candidates (Fase A/B).

Every candidate the resolver could not match is recorded here instead of being
silently dropped (the audit's recurring bug class) or written to the graph (the
junk-entity bug class). Each row keeps the full deferred claim so a later
approval or automatic re-match can create the relationships retroactively with
provenance to the original document.

Quick A ships INSERT + read; approve/reject endpoints and the re-match job are
Quick B.
"""
import json
import logging
from datetime import datetime, timezone

from stats_store import _conn

logger = logging.getLogger(__name__)


def _ensure() -> None:
    with _conn() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS entity_queue (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                category       TEXT NOT NULL
                    CHECK(category IN ('actor', 'malware', 'sector', 'country')),
                candidate_name TEXT NOT NULL,
                claim_payload  TEXT NOT NULL,
                source_url     TEXT NOT NULL,
                report_id      TEXT,
                status         TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'approved', 'rejected', 'auto_matched')),
                created_at     TEXT NOT NULL,
                resolved_at    TEXT,
                resolved_entity_id TEXT,
                UNIQUE(category, candidate_name, source_url)
            )
        """)
        con.execute("""
            CREATE INDEX IF NOT EXISTS idx_entity_queue_status
            ON entity_queue(status, created_at DESC)
        """)


def enqueue(category: str, candidate_name: str, claim_payload: dict,
            source_url: str, report_id: str | None = None) -> None:
    """Record one unresolved candidate. Idempotent per (category, name, source)."""
    _ensure()
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as con:
        con.execute(
            """
            INSERT INTO entity_queue
                (category, candidate_name, claim_payload, source_url, report_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(category, candidate_name, source_url) DO NOTHING
            """,
            (category, candidate_name, json.dumps(claim_payload, ensure_ascii=False),
             source_url, report_id, now),
        )
    logger.info("[queue] %s candidate quarantined: %r (source %s)",
                category, candidate_name, source_url)


def get_entry(entry_id: int) -> dict | None:
    _ensure()
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM entity_queue WHERE id = ?", (int(entry_id),)
        ).fetchone()
    if row is None:
        return None
    entry = dict(row)
    try:
        entry["claim_payload"] = json.loads(entry["claim_payload"])
    except (TypeError, ValueError):
        pass
    return entry


def mark(entry_id: int, status: str, resolved_entity_id: str | None = None) -> None:
    """Transition one entry out of pending; stamps resolved_at."""
    _ensure()
    with _conn() as con:
        con.execute(
            """
            UPDATE entity_queue
            SET status = ?, resolved_at = ?, resolved_entity_id = ?
            WHERE id = ?
            """,
            (status, datetime.now(timezone.utc).isoformat(),
             resolved_entity_id, int(entry_id)),
        )


def list_entries(status: str = "pending", limit: int = 200) -> list[dict]:
    _ensure()
    bounded = max(1, min(int(limit), 1000))
    with _conn() as con:
        rows = con.execute(
            """
            SELECT id, category, candidate_name, claim_payload, source_url,
                   report_id, status, created_at, resolved_at, resolved_entity_id
            FROM entity_queue WHERE status = ?
            ORDER BY created_at DESC LIMIT ?
            """,
            (status, bounded),
        ).fetchall()
    entries = []
    for row in rows:
        entry = dict(row)
        try:
            entry["claim_payload"] = json.loads(entry["claim_payload"])
        except (TypeError, ValueError):
            pass
        entries.append(entry)
    return entries
