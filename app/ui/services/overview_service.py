"""Overview analytical service aggregating dashboard KPIs and threat posture."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from app.database.connection import DatabaseManager
from app.ui.state import get_db_manager


class OverviewService:
    """Aggregates high-level telemetry and alert KPIs for the Overview Dashboard."""

    def __init__(self, db_manager: DatabaseManager | None = None) -> None:
        self.db = db_manager or get_db_manager()

    def get_kpis(self) -> dict[str, Any]:
        """Aggregate primary SOC summary metrics."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            # Total events
            cursor.execute("SELECT COUNT(*) FROM events;")
            total_events = cursor.fetchone()[0]

            # Total alerts and severity breakdown
            cursor.execute("SELECT COUNT(*) FROM alerts;")
            total_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE LOWER(severity) = 'critical';")
            critical_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE LOWER(severity) = 'high';")
            high_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE LOWER(severity) = 'medium';")
            medium_alerts = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM alerts WHERE LOWER(severity) = 'low';")
            low_alerts = cursor.fetchone()[0]

            # Active incidents
            cursor.execute("SELECT COUNT(*) FROM investigations;")
            total_incidents = cursor.fetchone()[0]

            # Total imported files
            cursor.execute("SELECT COUNT(*) FROM import_jobs;")
            imported_files = cursor.fetchone()[0]

            return {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "critical_alerts": critical_alerts,
                "high_alerts": high_alerts,
                "medium_alerts": medium_alerts,
                "low_alerts": low_alerts,
                "total_incidents": total_incidents,
                "imported_files": imported_files,
            }

    def get_severity_breakdown(self) -> dict[str, int]:
        """Return counts of alerts grouped by severity."""
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT LOWER(severity), COUNT(*) FROM alerts GROUP BY LOWER(severity);")
            for sev, count in cursor.fetchall():
                if sev in severities:
                    severities[sev] = count
                else:
                    severities[sev] = count
        return severities

    def get_mitre_breakdown(self, limit: int = 10) -> list[dict[str, Any]]:
        """Calculate frequency distribution of MITRE ATT&CK techniques across alerts."""
        technique_counts: Counter[str] = Counter()
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT mitre_techniques_json FROM alerts WHERE mitre_techniques_json IS NOT NULL;")
            for row in cursor.fetchall():
                val = row[0]
                if not val:
                    continue
                try:
                    techniques = json.loads(val)
                    if isinstance(techniques, list):
                        for t in techniques:
                            technique_counts[str(t)] += 1
                except Exception:
                    # Comma-separated fallback
                    for t in str(val).split(","):
                        if t.strip():
                            technique_counts[t.strip()] += 1

        return [
            {"technique": tech, "count": count}
            for tech, count in technique_counts.most_common(limit)
        ]

    def get_top_targeted_hosts(self, limit: int = 5) -> list[dict[str, Any]]:
        """Return top host computers by alert volume."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT computer, COUNT(*) as alert_count
                FROM alerts
                WHERE computer IS NOT NULL AND computer != ''
                GROUP BY computer
                ORDER BY alert_count DESC
                LIMIT ?;
                """,
                (limit,),
            )
            return [{"computer": r[0], "alert_count": r[1]} for r in cursor.fetchall()]

    def get_recent_alerts(self, limit: int = 5) -> list[dict[str, Any]]:
        """Return recent alerts for the overview feed."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, rule_id, title, severity, status, computer, last_seen, event_count
                FROM alerts
                ORDER BY last_seen DESC
                LIMIT ?;
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            return [
                {
                    "id": r[0],
                    "rule_id": r[1],
                    "title": r[2],
                    "severity": r[3],
                    "status": r[4],
                    "computer": r[5],
                    "last_seen": r[6],
                    "event_count": r[7],
                }
                for r in rows
            ]
