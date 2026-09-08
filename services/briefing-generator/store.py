"""
store.py — SQLite persistence for briefing-generator.

All connections are per-call (open → commit/rollback → close) so background
threads and the async event loop share the same DB file safely.
"""
import json
import sqlite3
from contextlib import contextmanager

from config import DB_PATH


@contextmanager
def _conn():
    # timeout=30: /generate upsert, the background thread's update_status, and pollers'
    # get() all hit the same file — the default 5s could raise "database is locked".
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def init_db() -> None:
    with _conn() as con:
        # WAL lets readers (pollers) proceed concurrently with a writer — fewer lock waits.
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("""
            CREATE TABLE IF NOT EXISTS briefings (
                id           TEXT PRIMARY KEY,
                status       TEXT NOT NULL,
                text         TEXT,
                created_at   TEXT NOT NULL,
                period_hours INTEGER NOT NULL,
                error        TEXT,
                anchor       TEXT
            )
        """)
        # Migración idempotente para DBs creadas antes del sintetizador (2026-08-19):
        # `anchor` = JSON del control de identificadores (total_facts legado, unanchored, ...).
        try:
            con.execute("ALTER TABLE briefings ADD COLUMN anchor TEXT")
        except sqlite3.OperationalError:
            pass  # columna ya existe


def upsert(briefing_id: str, data: dict) -> None:
    with _conn() as con:
        con.execute(
            "INSERT OR REPLACE INTO briefings "
            "(id, status, text, created_at, period_hours, error) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (briefing_id, data["status"], data.get("text"),
             data["created_at"], data["period_hours"], data.get("error")),
        )


def update_status(briefing_id: str, status: str,
                  text: str | None = None, error: str | None = None,
                  anchor: str | None = None) -> None:
    with _conn() as con:
        con.execute(
            "UPDATE briefings SET status = ?, text = ?, error = ?, anchor = ? WHERE id = ?",
            (status, text, error, anchor, briefing_id),
        )


def get(briefing_id: str) -> dict | None:
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM briefings WHERE id = ?", (briefing_id,)
        ).fetchone()
    if row is None:
        return None
    entry = dict(row)
    if entry.get("anchor"):
        try:
            entry["anchor"] = json.loads(entry["anchor"])
        except ValueError:
            pass  # JSON corrupto: se devuelve el string crudo antes que ocultar datos
    return entry


def list_all() -> list[dict]:
    with _conn() as con:
        rows = con.execute(
            "SELECT id, status, created_at, period_hours "
            "FROM briefings ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]
