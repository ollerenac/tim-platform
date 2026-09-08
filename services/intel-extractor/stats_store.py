"""SQLite-backed telemetry and durable document pipeline state."""
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.environ.get("DB_PATH", "/data/stats.db")


@contextmanager
def _conn():
    con = sqlite3.connect(DB_PATH)
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
        con.execute("""
            CREATE TABLE IF NOT EXISTS stats (
                id         INTEGER PRIMARY KEY,
                total_docs INTEGER NOT NULL DEFAULT 0,
                total_iocs INTEGER NOT NULL DEFAULT 0,
                last_run   TEXT
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS document_pipeline (
                document_key       TEXT PRIMARY KEY,
                landing_url        TEXT,
                document_url       TEXT,
                title              TEXT NOT NULL,
                source             TEXT NOT NULL,
                status             TEXT NOT NULL
                    CHECK(status IN ('previewed', 'ingested', 'failed')),
                vulnerability_count INTEGER NOT NULL DEFAULT 0,
                indicator_count    INTEGER NOT NULL DEFAULT 0,
                previewed_at       TEXT NOT NULL,
                first_ingested_at  TEXT,
                last_attempt_at    TEXT NOT NULL,
                failed_at          TEXT,
                updated_at         TEXT NOT NULL,
                report_id          TEXT,
                report_standard_id TEXT,
                error              TEXT
            )
        """)
        con.execute("""
            CREATE INDEX IF NOT EXISTS idx_document_pipeline_updated
            ON document_pipeline(updated_at DESC)
        """)


def increment(docs: int, iocs: int) -> None:
    """Atomically add docs and iocs to the running totals and stamp last_run."""
    with _conn() as con:
        con.execute(
            """
            INSERT INTO stats (id, total_docs, total_iocs, last_run)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                total_docs = total_docs + excluded.total_docs,
                total_iocs = total_iocs + excluded.total_iocs,
                last_run   = excluded.last_run
            """,
            (docs, iocs, datetime.now(timezone.utc).isoformat()),
        )


def get_stats() -> dict:
    with _conn() as con:
        row = con.execute("SELECT * FROM stats WHERE id = 1").fetchone()
    return dict(row) if row else {"total_docs": 0, "total_iocs": 0, "last_run": None}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitize_error(error) -> str | None:
    if error is None:
        return None
    value = " ".join(str(error).split())
    value = re.sub(
        r"(?i)\b(token|password|authorization)\s*[=:]\s*\S+",
        r"\1=<redacted>",
        value,
    )
    return value[:500]


def _pipeline_values(fields: dict) -> tuple:
    return (
        fields["document_key"],
        fields.get("landing_url"),
        fields.get("document_url"),
        fields.get("title") or fields.get("landing_url") or fields["document_key"],
        fields.get("source") or "intel-extractor",
        max(0, int(fields.get("vulnerability_count") or 0)),
        max(0, int(fields.get("indicator_count") or 0)),
        fields.get("report_id"),
        fields.get("report_standard_id"),
    )


def record_previewed(**fields) -> None:
    """Create or refresh one attempt without demoting an ingested row."""
    now = _now()
    values = _pipeline_values(fields)
    with _conn() as con:
        con.execute(
            """
            INSERT INTO document_pipeline (
                document_key, landing_url, document_url, title, source, status,
                vulnerability_count, indicator_count, previewed_at,
                last_attempt_at, updated_at, report_id, report_standard_id, error
            ) VALUES (?, ?, ?, ?, ?, 'previewed', ?, ?, ?, ?, ?, ?, ?, NULL)
            ON CONFLICT(document_key) DO UPDATE SET
                landing_url = excluded.landing_url,
                document_url = excluded.document_url,
                title = excluded.title,
                source = excluded.source,
                status = CASE
                    WHEN document_pipeline.status = 'ingested' THEN 'ingested'
                    ELSE 'previewed'
                END,
                vulnerability_count = excluded.vulnerability_count,
                indicator_count = excluded.indicator_count,
                last_attempt_at = excluded.last_attempt_at,
                updated_at = excluded.updated_at,
                report_standard_id = COALESCE(
                    excluded.report_standard_id,
                    document_pipeline.report_standard_id
                ),
                error = CASE
                    WHEN document_pipeline.status = 'ingested' THEN NULL
                    ELSE document_pipeline.error
                END
            """,
            (*values[:7], now, now, now, *values[7:]),
        )


def record_failed(**fields) -> None:
    """Upsert one failed attempt while retaining immutable history fields."""
    now = _now()
    values = _pipeline_values(fields)
    error = _sanitize_error(fields.get("error")) or "operation failed"
    with _conn() as con:
        con.execute(
            """
            INSERT INTO document_pipeline (
                document_key, landing_url, document_url, title, source, status,
                vulnerability_count, indicator_count, previewed_at,
                last_attempt_at, failed_at, updated_at, report_id,
                report_standard_id, error
            ) VALUES (?, ?, ?, ?, ?, 'failed', ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(document_key) DO UPDATE SET
                landing_url = excluded.landing_url,
                document_url = excluded.document_url,
                title = excluded.title,
                source = excluded.source,
                status = 'failed',
                vulnerability_count = excluded.vulnerability_count,
                indicator_count = excluded.indicator_count,
                last_attempt_at = excluded.last_attempt_at,
                failed_at = excluded.failed_at,
                updated_at = excluded.updated_at,
                report_id = COALESCE(excluded.report_id, document_pipeline.report_id),
                report_standard_id = COALESCE(
                    excluded.report_standard_id,
                    document_pipeline.report_standard_id
                ),
                error = excluded.error
            """,
            (*values[:7], now, now, now, now, *values[7:], error),
        )


def record_ingested(*, update_totals: bool = False, **fields) -> None:
    """Commit one verified graph and optional first-ingestion totals atomically."""
    now = _now()
    values = _pipeline_values(fields)
    with _conn() as con:
        prior = con.execute(
            "SELECT first_ingested_at FROM document_pipeline WHERE document_key = ?",
            (fields["document_key"],),
        ).fetchone()
        first_transition = prior is None or prior["first_ingested_at"] is None
        con.execute(
            """
            INSERT INTO document_pipeline (
                document_key, landing_url, document_url, title, source, status,
                vulnerability_count, indicator_count, previewed_at,
                first_ingested_at, last_attempt_at, updated_at, report_id,
                report_standard_id, error
            ) VALUES (?, ?, ?, ?, ?, 'ingested', ?, ?, ?, ?, ?, ?, ?, ?, NULL)
            ON CONFLICT(document_key) DO UPDATE SET
                landing_url = excluded.landing_url,
                document_url = excluded.document_url,
                title = excluded.title,
                source = excluded.source,
                status = 'ingested',
                vulnerability_count = excluded.vulnerability_count,
                indicator_count = excluded.indicator_count,
                first_ingested_at = COALESCE(
                    document_pipeline.first_ingested_at,
                    excluded.first_ingested_at
                ),
                last_attempt_at = excluded.last_attempt_at,
                failed_at = NULL,
                updated_at = excluded.updated_at,
                report_id = excluded.report_id,
                report_standard_id = excluded.report_standard_id,
                error = NULL
            """,
            (*values[:7], now, now, now, now, *values[7:]),
        )
        if update_totals and first_transition:
            con.execute(
                """
                INSERT INTO stats (id, total_docs, total_iocs, last_run)
                VALUES (1, 1, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    total_docs = total_docs + 1,
                    total_iocs = total_iocs + excluded.total_iocs,
                    last_run = excluded.last_run
                """,
                (values[6], now),
            )


def get_recent_documents(limit: int = 50) -> list[dict]:
    """Return durable dashboard-compatible rows, newest attempt first."""
    bounded_limit = max(1, min(int(limit), 500))
    with _conn() as con:
        rows = con.execute(
            """
            SELECT
                document_key, landing_url, document_url, title, source, status,
                vulnerability_count, indicator_count, previewed_at,
                first_ingested_at, last_attempt_at, failed_at, updated_at,
                report_id, report_standard_id, error,
                title AS filename,
                COALESCE(first_ingested_at, updated_at) AS ingested_at,
                indicator_count AS ioc_count
            FROM document_pipeline
            ORDER BY updated_at DESC, document_key ASC
            LIMIT ?
            """,
            (bounded_limit,),
        ).fetchall()
    return [dict(row) for row in rows]
