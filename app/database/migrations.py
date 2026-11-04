"""Sequential transactional migration runner with checksum validation for WinSentinel."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from pydantic import BaseModel, Field

from app.database.connection import DatabaseManager


class MigrationRecord(BaseModel):
    """Record of an applied database migration."""

    version: int = Field(description="Sequential numeric version of the migration.")
    name: str = Field(description="Descriptive name of the migration.")
    applied_at: str = Field(description="ISO-8601 UTC timestamp when applied.")
    checksum: str = Field(description="SHA-256 hex digest of the migration SQL content.")


class MigrationRunner:
    """Discovers, validates, and atomically executes sequential SQL migrations."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        migrations_dir: str | Path | None = None,
    ) -> None:
        """Initialize MigrationRunner with DatabaseManager and migrations directory."""
        self.db_manager = db_manager
        if migrations_dir is not None:
            self.migrations_dir = Path(migrations_dir)
        else:
            self.migrations_dir = Path(__file__).parent / "migrations"

    def ensure_migration_table(self, conn: sqlite3.Connection) -> None:
        """Ensure the schema_migrations tracking table exists."""
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL,
                checksum TEXT NOT NULL
            );
            """
        )

    def get_applied_migrations(self, conn: sqlite3.Connection) -> dict[int, MigrationRecord]:
        """Retrieve all applied migrations indexed by version."""
        self.ensure_migration_table(conn)
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT version, name, applied_at, checksum FROM schema_migrations ORDER BY version ASC;"
            )
            return {
                row["version"]: MigrationRecord(
                    version=row["version"],
                    name=row["name"],
                    applied_at=row["applied_at"],
                    checksum=row["checksum"],
                )
                for row in cursor.fetchall()
            }
        finally:
            cursor.close()

    def discover_migrations(self) -> list[tuple[int, str, Path]]:
        """Scan migrations directory for valid sequential SQL migration files.

        Returns list of (version, name, file_path) sorted ascending by version.
        """
        if not self.migrations_dir.exists():
            return []

        pattern = re.compile(r"^(\d{3,})_(.+)\.sql$")
        migrations: list[tuple[int, str, Path]] = []

        for file_path in self.migrations_dir.iterdir():
            if not file_path.is_file():
                continue
            match = pattern.match(file_path.name)
            if match:
                version = int(match.group(1))
                name = match.group(2)
                migrations.append((version, name, file_path))

        migrations.sort(key=lambda m: m[0])
        return migrations

    def compute_checksum(self, file_path: Path) -> str:
        """Compute SHA-256 hex digest of migration file contents."""
        return hashlib.sha256(file_path.read_bytes()).hexdigest()

    def apply_migrations(self) -> list[int]:
        """Apply all pending migrations sequentially inside atomic transactions.

        Validates checksums of previously applied migrations to detect tampering.
        Returns a list of newly applied migration versions.
        """
        applied_versions: list[int] = []

        with self.db_manager.get_connection() as conn:
            self.ensure_migration_table(conn)
            applied = self.get_applied_migrations(conn)
            discovered = self.discover_migrations()

            # 1. Validate checksum integrity for all previously applied migrations
            for version, name, path in discovered:
                current_checksum = self.compute_checksum(path)
                if version in applied:
                    if applied[version].checksum != current_checksum:
                        raise RuntimeError(
                            f"Migration checksum mismatch for version {version} ({name}): "
                            f"stored checksum '{applied[version].checksum}' does not match "
                            f"current checksum '{current_checksum}'. File may have been tampered with."
                        )

            # 2. Execute unapplied migrations
            for version, name, path in discovered:
                if version in applied:
                    continue

                checksum = self.compute_checksum(path)
                sql_content = path.read_text(encoding="utf-8")

                try:
                    conn.executescript(f"BEGIN TRANSACTION;\n{sql_content}")
                    applied_at = datetime.now(timezone.utc).isoformat()
                    conn.execute(
                        "INSERT INTO schema_migrations (version, name, applied_at, checksum) VALUES (?, ?, ?, ?);",
                        (version, name, applied_at, checksum),
                    )
                    conn.commit()
                except Exception:
                    conn.rollback()
                    raise

                applied_versions.append(version)

        return applied_versions
