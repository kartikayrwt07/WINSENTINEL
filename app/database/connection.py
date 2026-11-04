"""SQLite connection management and pragmas for WinSentinel."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from app.config import DatabaseSettings, get_database_settings


class DatabaseManager:
    """Thread-safe SQLite connection manager with WAL concurrency and strict pragmas."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        settings: DatabaseSettings | None = None,
    ) -> None:
        """Initialize DatabaseManager with configured database path and settings."""
        self.settings: DatabaseSettings = settings or get_database_settings()
        
        if db_path is not None:
            self.db_path: Path = Path(db_path)
        else:
            self.db_path = Path(self.settings.db_path)

        self.is_memory: bool = (
            str(self.db_path) == ":memory:" or ":memory:" in str(self.db_path)
        )

        if not self.is_memory:
            # Ensure parent directory exists for file-backed databases
            if self.db_path.parent and str(self.db_path.parent) != ".":
                self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def execute_pragmas(self, conn: sqlite3.Connection) -> None:
        """Apply performance and integrity pragmas to the SQLite connection."""
        cur = conn.cursor()
        try:
            if self.settings.foreign_keys:
                cur.execute("PRAGMA foreign_keys = ON;")
            
            cur.execute(f"PRAGMA busy_timeout = {int(self.settings.busy_timeout_ms)};")
            cur.execute(f"PRAGMA synchronous = {self.settings.synchronous};")

            if self.settings.wal_mode and not self.is_memory:
                cur.execute("PRAGMA journal_mode = WAL;")
        finally:
            cur.close()

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager yielding an active, configured SQLite connection.

        Automatically commits on successful block exit, rolls back on exceptions,
        and guarantees connection handle closure.
        """
        is_uri = str(self.db_path).startswith("file:")
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=float(self.settings.busy_timeout_ms) / 1000.0,
            check_same_thread=True,
            uri=is_uri,
        )
        conn.row_factory = sqlite3.Row
        self.execute_pragmas(conn)

        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
