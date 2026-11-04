"""Chronological investigation timeline service for multi-source event sequencing."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.database.connection import DatabaseManager
from app.ui.components.visualizers import render_svg_timeline
from app.ui.state import get_db_manager


class TimelineService:
    """Extracts, filters, and sequences multi-source events along an investigation timeline."""

    def __init__(self, db_manager: DatabaseManager | None = None) -> None:
        self.db = db_manager or get_db_manager()

    def get_timeline(
        self,
        computer: str | None = None,
        process_guid: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query chronological events formatted with forensic context for timeline charting."""
        conditions: list[str] = []
        params: list[Any] = []

        if computer:
            conditions.append("e.computer LIKE ?")
            params.append(f"%{computer}%")

        if process_guid:
            conditions.append("e.process_guid = ?")
            params.append(process_guid)

        if start_time:
            conditions.append("e.timestamp_utc >= ?")
            params.append(start_time)

        if end_time:
            conditions.append("e.timestamp_utc <= ?")
            params.append(end_time)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            # Query events joined with alert evidence to identify alerted events
            query = f"""
                SELECT e.id, e.event_id, e.computer, e.timestamp_utc, e.event_category,
                       e.event_type, e.image, e.command_line, e.user, e.process_guid,
                       CASE WHEN ae.id IS NOT NULL THEN 1 ELSE 0 END as is_alert
                FROM events e
                LEFT JOIN alert_evidence ae ON e.id = ae.event_id
                {where_clause}
                GROUP BY e.id
                ORDER BY e.timestamp_utc ASC
                LIMIT ?;
            """
            cursor.execute(query, params + [limit])
            rows = cursor.fetchall()

        timeline_items: list[dict[str, Any]] = []
        for r in rows:
            db_id, eid, host, ts, cat, ev_type, img, cmd, user, p_guid, is_alert = r

            # Synthesize descriptive title
            title = f"{cat}: {Path(img or 'system').name}" if img else f"{cat} ({ev_type})"
            if cmd:
                desc = (cmd[:70] + "...") if len(cmd) > 70 else cmd
            else:
                desc = f"EID {eid} from {host}"

            timeline_items.append({
                "id": db_id,
                "event_id": eid,
                "computer": host,
                "timestamp": ts,
                "category": cat,
                "event_type": ev_type,
                "image": img,
                "command_line": cmd,
                "user": user,
                "process_guid": p_guid,
                "title": title,
                "description": desc,
                "is_alert": bool(is_alert),
            })

        return timeline_items

    def render_timeline_svg(self, timeline_items: list[dict[str, Any]]) -> str:
        """Render the chronological event list as an interactive SVG timeline."""
        return render_svg_timeline(timeline_items)
