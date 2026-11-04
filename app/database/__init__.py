"""Database persistence, connection management, repositories, and migrations for WinSentinel."""

from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRecord, MigrationRunner
from app.database.query import (
    AlertFilter,
    EventFilter,
    PaginatedResult,
    build_alert_query,
    build_alert_where_clause,
    build_event_query,
    build_event_where_clause,
)
from app.database.repository import (
    AlertRepository,
    EventRepository,
    ImportedFileRepository,
    ImportJobRepository,
    ProcessRepository,
)

__all__ = [
    "AlertFilter",
    "AlertRepository",
    "DatabaseManager",
    "EventFilter",
    "EventRepository",
    "ImportedFileRepository",
    "ImportJobRepository",
    "MigrationRecord",
    "MigrationRunner",
    "PaginatedResult",
    "ProcessRepository",
    "build_alert_query",
    "build_alert_where_clause",
    "build_event_query",
    "build_event_where_clause",
]
