"""Log ingestion audit and import job history service for WinSentinel UI."""

from __future__ import annotations

import json
from typing import Any

from app.database.connection import DatabaseManager
from app.ui.state import get_db_manager


class ImportUIService:
    """Audits imported log files, parser execution statistics, and malformed error records."""

    def __init__(self, db_manager: DatabaseManager | None = None) -> None:
        self.db = db_manager or get_db_manager()

    def get_import_history(self, limit: int = 50, offset: int = 0) -> tuple[list[dict[str, Any]], int]:
        """Query import job audit records ordered by most recent first.

        Returns:
            Tuple of (list_of_job_dicts, total_count).
        """
        with self.db.get_connection() as conn:
            cur = conn.cursor()

            cur.execute("SELECT COUNT(*) FROM import_jobs;")
            total_count = cur.fetchone()[0]

            sql = """
                SELECT j.id, COALESCE(f.file_name, j.file_path) AS file_name,
                       j.file_path, j.status, j.start_time, j.end_time,
                       j.total_events, j.parsed_events, j.malformed_events,
                       j.quarantined_events, j.duplicate_events
                FROM import_jobs j
                LEFT JOIN imported_files f ON j.file_id = f.id
                ORDER BY j.id DESC
                LIMIT ? OFFSET ?;
            """
            cur.execute(sql, (limit, offset))
            rows = cur.fetchall()

        jobs: list[dict[str, Any]] = []
        for r in rows:
            jobs.append({
                "id": r[0],
                "file_name": r[1],
                "file_path": r[2],
                "status": r[3],
                "start_time": r[4],
                "end_time": r[5],
                "total_events": r[6],
                "parsed_events": r[7],
                "malformed_events": r[8],
                "quarantined_events": r[9],
                "duplicate_events": r[10],
            })

        return jobs, total_count

    def get_import_errors(self, job_id: int) -> list[dict[str, Any]]:
        """Retrieve detailed error log records and malformed event details for a job.

        Args:
            job_id: The ID of the import job.

        Returns:
            List of error dictionaries.
        """
        with self.db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT error_log_json FROM import_jobs WHERE id = ?;", (job_id,))
            row = cur.fetchone()

        if not row or not row[0]:
            return []

        try:
            parsed = json.loads(row[0])
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
            return [{"message": str(parsed)}]
        except Exception:
            return [{"message": str(row[0])}]

    def get_job_summary(self, job_id: int) -> dict[str, Any] | None:
        """Retrieve full status, timeline, and counts for a specific job."""
        with self.db.get_connection() as conn:
            cur = conn.cursor()
            sql = """
                SELECT j.id, COALESCE(f.file_name, j.file_path) AS file_name,
                       j.file_path, j.status, j.start_time, j.end_time,
                       j.total_events, j.parsed_events, j.malformed_events,
                       j.quarantined_events, j.duplicate_events, j.error_log_json
                FROM import_jobs j
                LEFT JOIN imported_files f ON j.file_id = f.id
                WHERE j.id = ?;
            """
            cur.execute(sql, (job_id,))
            row = cur.fetchone()

        if not row:
            return None

        return {
            "id": row[0],
            "file_name": row[1],
            "file_path": row[2],
            "status": row[3],
            "start_time": row[4],
            "end_time": row[5],
            "total_events": row[6],
            "parsed_events": row[7],
            "malformed_events": row[8],
            "quarantined_events": row[9],
            "duplicate_events": row[10],
            "has_errors": bool(row[11]),
        }

