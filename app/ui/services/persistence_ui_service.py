"""Persistence mechanism analysis and aggregation service for the UI."""

from __future__ import annotations

from typing import Any

from app.database.connection import DatabaseManager
from app.ui.state import get_db_manager


class PersistenceUIService:
    """Aggregates and categorizes persistence indicators from stored events."""

    def __init__(self, db_manager: DatabaseManager | None = None) -> None:
        self.db = db_manager or get_db_manager()

    def get_persistence_summary(self, computer: str | None = None) -> dict[str, list[dict[str, Any]]]:
        """Collect persistence evidence across all 5 Windows persistence mechanisms.

        Categories:
        - registry_run: CurrentVersion\\Run and RunOnce keys
        - ifeo_debugger: Image File Execution Options Debugger values
        - services: Service creation and suspicious driver loads
        - scheduled_tasks: Task creation (Security 4698 / Task Scheduler Operational)
        - wmi: WMI EventFilter, EventConsumer, and FilterToConsumerBinding
        - startup_drops: Binary creation in Startup folders
        """
        host_filter = "AND computer LIKE ?" if computer else ""
        host_params = [f"%{computer}%"] if computer else []

        summary: dict[str, list[dict[str, Any]]] = {
            "registry_run": [],
            "ifeo_debugger": [],
            "services": [],
            "scheduled_tasks": [],
            "wmi": [],
            "startup_drops": [],
        }

        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            # 1. Registry Run / RunOnce
            cursor.execute(
                f"""
                SELECT id, event_id, computer, timestamp_utc, image, registry_target_object, registry_details, user
                FROM events
                WHERE event_category = 'REGISTRY'
                  AND (registry_target_object LIKE '%\\CurrentVersion\\Run%' OR registry_target_object LIKE '%\\CurrentVersion\\RunOnce%')
                  {host_filter}
                ORDER BY timestamp_utc DESC LIMIT 50;
                """,
                host_params,
            )
            for r in cursor.fetchall():
                summary["registry_run"].append({
                    "id": r[0],
                    "event_id": r[1],
                    "computer": r[2],
                    "timestamp": r[3],
                    "image": r[4],
                    "target": r[5],
                    "details": r[6],
                    "user": r[7],
                })

            # 2. IFEO Debugger
            cursor.execute(
                f"""
                SELECT id, event_id, computer, timestamp_utc, image, registry_target_object, registry_details, user
                FROM events
                WHERE event_category = 'REGISTRY'
                  AND registry_target_object LIKE '%\\Image File Execution Options\\%'
                  AND registry_target_object LIKE '%\\Debugger%'
                  {host_filter}
                ORDER BY timestamp_utc DESC LIMIT 50;
                """,
                host_params,
            )
            for r in cursor.fetchall():
                summary["ifeo_debugger"].append({
                    "id": r[0],
                    "event_id": r[1],
                    "computer": r[2],
                    "timestamp": r[3],
                    "image": r[4],
                    "target": r[5],
                    "details": r[6],
                    "user": r[7],
                })

            # 3. Services & Drivers
            cursor.execute(
                f"""
                SELECT id, event_id, computer, timestamp_utc, service_name, service_file_name, image_loaded, user
                FROM events
                WHERE (event_id = 4697 OR service_name IS NOT NULL OR (event_category = 'DRIVER' AND signed = 'false'))
                  {host_filter}
                ORDER BY timestamp_utc DESC LIMIT 50;
                """,
                host_params,
            )
            for r in cursor.fetchall():
                summary["services"].append({
                    "id": r[0],
                    "event_id": r[1],
                    "computer": r[2],
                    "timestamp": r[3],
                    "service_name": r[4],
                    "service_file": r[5],
                    "driver_loaded": r[6],
                    "user": r[7],
                })

            # 4. Scheduled Tasks
            cursor.execute(
                f"""
                SELECT id, event_id, computer, timestamp_utc, task_name, task_content, user
                FROM events
                WHERE (event_id = 4698 OR task_name IS NOT NULL)
                  {host_filter}
                ORDER BY timestamp_utc DESC LIMIT 50;
                """,
                host_params,
            )
            for r in cursor.fetchall():
                summary["scheduled_tasks"].append({
                    "id": r[0],
                    "event_id": r[1],
                    "computer": r[2],
                    "timestamp": r[3],
                    "task_name": r[4],
                    "task_content": r[5],
                    "user": r[6],
                })

            # 5. WMI Subscriptions
            cursor.execute(
                f"""
                SELECT id, event_id, computer, timestamp_utc, wmi_operation, wmi_consumer, wmi_filter, wmi_query, user
                FROM events
                WHERE event_category = 'WMI' OR event_id IN (19, 20, 21)
                  {host_filter}
                ORDER BY timestamp_utc DESC LIMIT 50;
                """,
                host_params,
            )
            for r in cursor.fetchall():
                summary["wmi"].append({
                    "id": r[0],
                    "event_id": r[1],
                    "computer": r[2],
                    "timestamp": r[3],
                    "operation": r[4],
                    "consumer": r[5],
                    "filter": r[6],
                    "query": r[7],
                    "user": r[8],
                })

            # 6. Startup Folder Drops
            cursor.execute(
                f"""
                SELECT id, event_id, computer, timestamp_utc, image, target_filename, user
                FROM events
                WHERE event_category = 'FILE'
                  AND target_filename LIKE '%\\Start Menu\\Programs\\Startup%'
                  {host_filter}
                ORDER BY timestamp_utc DESC LIMIT 50;
                """,
                host_params,
            )
            for r in cursor.fetchall():
                summary["startup_drops"].append({
                    "id": r[0],
                    "event_id": r[1],
                    "computer": r[2],
                    "timestamp": r[3],
                    "image": r[4],
                    "target_filename": r[5],
                    "user": r[6],
                })

        return summary

