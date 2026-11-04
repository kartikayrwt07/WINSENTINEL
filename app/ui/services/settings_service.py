"""Settings and system health service for WinSentinel."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from app.database.connection import DatabaseManager
from app.ui.state import get_db_manager, get_stream_state


class SettingsService:
    """Provides platform diagnostics, database health statistics, and configuration."""

    def __init__(self, db_manager: DatabaseManager | None = None) -> None:
        self.db = db_manager or get_db_manager()

    def get_system_health(self) -> dict[str, Any]:
        """Collect platform health stats, database size, and table row counts."""
        db_path = Path(self.db.db_path)
        file_size = 0
        if db_path.is_file():
            try:
                file_size = os.path.getsize(db_path)
            except OSError:
                file_size = 0

        table_counts: dict[str, int] = {}
        tables = [
            "events",
            "alerts",
            "alert_evidence",
            "investigations",
            "analyst_notes",
            "import_jobs",
            "schema_migrations",
        ]

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sqlite_version();")
            sqlite_version = cursor.fetchone()[0]

            for table in tables:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table};")
                    table_counts[table] = cursor.fetchone()[0]
                except Exception:
                    table_counts[table] = 0

        return {
            "db_path": str(db_path),
            "is_memory": self.db.is_memory,
            "file_size_bytes": file_size,
            "sqlite_version": sqlite_version,
            "table_counts": table_counts,
        }

    def get_active_config(self) -> dict[str, Any]:
        """Retrieve current configuration parameters from session state or defaults."""
        state = get_stream_state()
        return {
            "correlation_window_minutes": state.get("correlation_window_minutes", 30),
            "rules_dir": state.get("rules_dir", "rules/sysmon"),
            "db_path": state.get("db_path", str(self.db.db_path)),
            "auto_refresh": state.get("auto_refresh", False),
        }

    def update_config(self, key: str, value: Any) -> None:
        """Update a platform configuration parameter."""
        state = get_stream_state()
        state[key] = value

