"""Event Explorer analytical service with multi-field filtering and pagination."""

from __future__ import annotations

import json
from typing import Any

from app.database.connection import DatabaseManager
from app.ui.state import get_db_manager


class EventExplorerService:
    """Powers multi-field event search, filtering, and forensic record inspection."""

    def __init__(self, db_manager: DatabaseManager | None = None) -> None:
        self.db = db_manager or get_db_manager()

    def filter_events(
        self,
        event_id: int | None = None,
        computer: str | None = None,
        image: str | None = None,
        user: str | None = None,
        category: str | None = None,
        search: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """Query events matching multi-field filter conditions with pagination.

        Returns:
            Tuple of (list_of_event_dicts, total_matching_count).
        """
        conditions: list[str] = []
        params: list[Any] = []

        if event_id is not None:
            conditions.append("event_id = ?")
            params.append(event_id)

        if computer:
            conditions.append("computer LIKE ?")
            params.append(f"%{computer}%")

        if image:
            conditions.append("image LIKE ?")
            params.append(f"%{image}%")

        if user:
            conditions.append("user LIKE ?")
            params.append(f"%{user}%")

        if category:
            conditions.append("event_category = ?")
            params.append(category.upper())

        if search:
            conditions.append("(command_line LIKE ? OR image LIKE ? OR raw_payload LIKE ?)")
            term = f"%{search}%"
            params.extend([term, term, term])

        if start_time:
            conditions.append("timestamp_utc >= ?")
            params.append(start_time)

        if end_time:
            conditions.append("timestamp_utc <= ?")
            params.append(end_time)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            # Count total matching rows
            count_sql = f"SELECT COUNT(*) FROM events {where_clause};"
            cursor.execute(count_sql, params)
            total_count = cursor.fetchone()[0]

            # Fetch paginated records
            query_sql = f"""
                SELECT id, event_id, computer, timestamp_utc, event_category, image, command_line, user, process_guid
                FROM events
                {where_clause}
                ORDER BY timestamp_utc DESC
                LIMIT ? OFFSET ?;
            """
            cursor.execute(query_sql, params + [limit, offset])
            rows = cursor.fetchall()

            records = [
                {
                    "id": r[0],
                    "event_id": r[1],
                    "computer": r[2],
                    "timestamp": r[3],
                    "category": r[4],
                    "image": r[5],
                    "command_line": r[6],
                    "user": r[7],
                    "process_guid": r[8],
                }
                for r in rows
            ]

            return records, total_count

    def get_event_detail(self, db_id: int) -> dict[str, Any] | None:
        """Fetch the full forensic payload of a single event by database primary key."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM events WHERE id = ?;", (db_id,))
            row = cursor.fetchone()
            if not row:
                return None

            col_names = [desc[0] for desc in cursor.description]
            event_dict = dict(zip(col_names, row))

            # Decode hashes and extra_fields if stored as JSON
            for json_col in ("hashes", "extra_fields", "quarantine_reasons"):
                if json_col in event_dict and isinstance(event_dict[json_col], str):
                    try:
                        event_dict[json_col] = json.loads(event_dict[json_col])
                    except Exception:
                        pass

            return event_dict
