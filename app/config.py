"""Configuration models and application settings for WinSentinel."""

from __future__ import annotations

from pathlib import Path
from pydantic import BaseModel, Field


class DatabaseSettings(BaseModel):
    """Configuration settings for SQLite database persistence."""

    db_path: Path = Field(
        default=Path("data/winsentinel.db"),
        description="Path to the SQLite database file.",
    )
    busy_timeout_ms: int = Field(
        default=5000,
        description="Busy timeout in milliseconds for SQLite lock contention.",
    )
    wal_mode: bool = Field(
        default=True,
        description="Enable Write-Ahead Logging (WAL) journal mode for concurrency.",
    )
    foreign_keys: bool = Field(
        default=True,
        description="Enforce foreign key constraints on every connection.",
    )
    synchronous: str = Field(
        default="NORMAL",
        description="Disk synchronization mode (NORMAL, FULL, OFF).",
    )


class AppSettings(BaseModel):
    """Top-level application settings container."""

    database: DatabaseSettings = Field(
        default_factory=DatabaseSettings,
        description="Database configuration settings.",
    )


_app_settings: AppSettings | None = None


def get_app_settings() -> AppSettings:
    """Return the global AppSettings singleton."""
    global _app_settings
    if _app_settings is None:
        _app_settings = AppSettings()
    return _app_settings


def get_database_settings() -> DatabaseSettings:
    """Convenience helper to retrieve current DatabaseSettings."""
    return get_app_settings().database
