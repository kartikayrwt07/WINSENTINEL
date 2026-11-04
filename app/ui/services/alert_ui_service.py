"""Alert management and triage analytical service for WinSentinel UI."""

from __future__ import annotations

import json
from typing import Any

from app.correlation.alert_manager import AlertManager, InvalidStatusTransitionError
from app.database.connection import DatabaseManager
from app.ui.state import get_db_manager


class AlertUIService:
    """Powers alert triage, search, FSM lifecycle transitions, and evidence drill-down."""

    def __init__(self, db_manager: DatabaseManager | None = None) -> None:
        self.db = db_manager or get_db_manager()
        self.manager = AlertManager(db_manager=self.db)

    def get_alerts(
        self,
        status: str | None = None,
        severity: str | None = None,
        computer: str | None = None,
        rule_id: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """Query alert records matching multi-field filter conditions with pagination.

        Returns:
            Tuple of (list_of_alert_dicts, total_matching_count).
        """
        conditions: list[str] = []
        params: list[Any] = []

        if status and status != "ALL":
            conditions.append("LOWER(status) = LOWER(?)")
            params.append(status)

        if severity and severity != "ALL":
            conditions.append("LOWER(severity) = LOWER(?)")
            params.append(severity)

        if computer:
            conditions.append("computer LIKE ?")
            params.append(f"%{computer}%")

        if rule_id:
            conditions.append("rule_id LIKE ?")
            params.append(f"%{rule_id}%")

        if search:
            conditions.append("(title LIKE ? OR description LIKE ? OR user LIKE ?)")
            term = f"%{search}%"
            params.extend([term, term, term])

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            count_sql = f"SELECT COUNT(*) FROM alerts {where_clause};"
            cursor.execute(count_sql, params)
            total_count = cursor.fetchone()[0]

            query_sql = f"""
                SELECT id, rule_id, title, severity, status, description, computer,
                       user, process_guid, first_seen, last_seen, event_count,
                       mitre_tactics_json, mitre_techniques_json
                FROM alerts
                {where_clause}
                ORDER BY last_seen DESC
                LIMIT ? OFFSET ?;
            """
            cursor.execute(query_sql, params + [limit, offset])
            rows = cursor.fetchall()

        alerts: list[dict[str, Any]] = []
        for r in rows:
            tactics = []
            techniques = []
            if r[12]:
                try:
                    tactics = json.loads(r[12])
                except Exception:
                    pass
            if r[13]:
                try:
                    techniques = json.loads(r[13])
                except Exception:
                    pass

            alerts.append({
                "id": r[0],
                "rule_id": r[1],
                "title": r[2],
                "severity": r[3],
                "status": r[4],
                "description": r[5],
                "computer": r[6],
                "user": r[7],
                "process_guid": r[8],
                "first_seen": r[9],
                "last_seen": r[10],
                "event_count": r[11],
                "mitre_tactics": tactics,
                "mitre_techniques": techniques,
            })

        return alerts, total_count

    def get_alert_detail(self, alert_id: int) -> dict[str, Any]:
        """Retrieve complete forensic drill-down backing an alert."""
        return self.manager.get_alert_forensic_drilldown(alert_id)

    def update_status(
        self,
        alert_id: int,
        new_status: str,
        analyst: str = "Analyst",
        notes: str = "",
    ) -> dict[str, Any]:
        """Transition alert status in compliance with FSM rules and record analyst notes."""
        status_map = {
            "new": "New",
            "investigating": "Investigating",
            "escalated": "Escalated",
            "resolved": "Resolved",
            "false positive": "False Positive",
            "falsepositive": "False Positive",
        }
        normalized_status = status_map.get(new_status.strip().lower(), new_status)
        success = self.manager.update_alert_status(
            alert_id=alert_id,
            new_status=normalized_status,
            analyst=analyst,
            comment=notes,
        )
        return {
            "alert_id": alert_id,
            "status": normalized_status,
            "success": success,
        }

    def add_note(
        self,
        alert_id: int,
        note_text: str,
        analyst: str = "Analyst",
        disposition: str | None = None,
    ) -> int:
        """Add an analyst note and disposition to an alert."""
        return self.manager.add_analyst_note(
            alert_id=alert_id,
            note_text=note_text,
            analyst=analyst,
            disposition=disposition,
        )
