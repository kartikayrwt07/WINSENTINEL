"""Parameterized dynamic query builders, filter specifications, and pagination models."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Generic, TypeVar

from app.models.events import EventCategory

T = TypeVar("T")


@dataclass
class PaginatedResult(Generic[T]):
    """Generic container for paginated query results."""

    items: list[T]
    total_count: int
    page: int
    page_size: int
    total_pages: int

    @classmethod
    def create(
        cls,
        items: list[T],
        total_count: int,
        page: int,
        page_size: int,
    ) -> PaginatedResult[T]:
        """Construct PaginatedResult with automatically calculated total_pages."""
        safe_page_size = max(1, page_size)
        total_pages = math.ceil(total_count / safe_page_size) if total_count > 0 else 0
        return cls(
            items=items,
            total_count=total_count,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )


@dataclass
class EventFilter:
    """Filter parameters for querying normalized forensic events."""

    event_ids: list[int] | None = None
    categories: list[EventCategory | str] | None = None
    computer: str | None = None
    user: str | None = None
    image_contains: str | None = None
    command_line_contains: str | None = None
    process_guid: str | None = None
    parent_process_guid: str | None = None
    start_time: datetime | str | None = None
    end_time: datetime | str | None = None
    is_quarantined: bool | None = None
    import_job_id: int | None = None


@dataclass
class AlertFilter:
    """Filter parameters for querying threat detection alerts."""

    statuses: list[str] | None = None
    severities: list[str] | None = None
    computer: str | None = None
    rule_id: str | None = None
    start_time: datetime | str | None = None
    end_time: datetime | str | None = None


def build_event_where_clause(filter_params: EventFilter | None = None) -> tuple[str, list[Any]]:
    """Build a safe parameterized SQL WHERE clause and parameter list for events.

    Immune to SQL injection: all dynamic values are converted to positional '?' bindings.
    """
    conditions: list[str] = ["1=1"]
    params: list[Any] = []

    if filter_params is None:
        return "1=1", []

    if filter_params.computer:
        conditions.append("computer = ?")
        params.append(filter_params.computer)

    if filter_params.user:
        conditions.append("user LIKE ?")
        params.append(f"%{filter_params.user}%")

    if filter_params.event_ids:
        placeholders = ",".join("?" for _ in filter_params.event_ids)
        conditions.append(f"event_id IN ({placeholders})")
        params.extend(filter_params.event_ids)

    if filter_params.categories:
        cat_values = [
            c.value if isinstance(c, EventCategory) else str(c)
            for c in filter_params.categories
        ]
        placeholders = ",".join("?" for _ in cat_values)
        conditions.append(f"event_category IN ({placeholders})")
        params.extend(cat_values)

    if filter_params.start_time is not None:
        ts = (
            filter_params.start_time.isoformat()
            if isinstance(filter_params.start_time, datetime)
            else str(filter_params.start_time)
        )
        conditions.append("timestamp_utc >= ?")
        params.append(ts)

    if filter_params.end_time is not None:
        ts = (
            filter_params.end_time.isoformat()
            if isinstance(filter_params.end_time, datetime)
            else str(filter_params.end_time)
        )
        conditions.append("timestamp_utc <= ?")
        params.append(ts)

    if filter_params.process_guid:
        conditions.append("process_guid = ?")
        params.append(filter_params.process_guid)

    if filter_params.parent_process_guid:
        conditions.append("parent_process_guid = ?")
        params.append(filter_params.parent_process_guid)

    if filter_params.command_line_contains:
        conditions.append("command_line LIKE ?")
        params.append(f"%{filter_params.command_line_contains}%")

    if filter_params.image_contains:
        conditions.append("image LIKE ?")
        params.append(f"%{filter_params.image_contains}%")

    if filter_params.is_quarantined is not None:
        conditions.append("is_quarantined = ?")
        params.append(1 if filter_params.is_quarantined else 0)

    if filter_params.import_job_id is not None:
        conditions.append("import_job_id = ?")
        params.append(filter_params.import_job_id)

    return " AND ".join(conditions), params


def build_alert_where_clause(filter_params: AlertFilter | None = None) -> tuple[str, list[Any]]:
    """Build a safe parameterized SQL WHERE clause and parameter list for alerts.

    Immune to SQL injection: all dynamic values are converted to positional '?' bindings.
    """
    conditions: list[str] = ["1=1"]
    params: list[Any] = []

    if filter_params is None:
        return "1=1", []

    if filter_params.statuses:
        placeholders = ",".join("?" for _ in filter_params.statuses)
        conditions.append(f"status IN ({placeholders})")
        params.extend(filter_params.statuses)

    if filter_params.severities:
        placeholders = ",".join("?" for _ in filter_params.severities)
        conditions.append(f"severity IN ({placeholders})")
        params.extend(filter_params.severities)

    if filter_params.computer:
        conditions.append("computer = ?")
        params.append(filter_params.computer)

    if filter_params.rule_id:
        conditions.append("rule_id = ?")
        params.append(filter_params.rule_id)

    if filter_params.start_time is not None:
        ts = (
            filter_params.start_time.isoformat()
            if isinstance(filter_params.start_time, datetime)
            else str(filter_params.start_time)
        )
        conditions.append("created_at >= ?")
        params.append(ts)

    if filter_params.end_time is not None:
        ts = (
            filter_params.end_time.isoformat()
            if isinstance(filter_params.end_time, datetime)
            else str(filter_params.end_time)
        )
        conditions.append("created_at <= ?")
        params.append(ts)

    return " AND ".join(conditions), params


def build_event_query(
    filter_obj: EventFilter | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[str, str, list[Any]]:
    """Generate count SQL, paginated select SQL, and query parameter list for events.

    Returns:
        (count_sql, query_sql, query_params)
        where query_params binds to query_sql, and query_params[:-2] binds to count_sql.
    """
    where_clause, base_params = build_event_where_clause(filter_obj)
    count_sql = f"SELECT COUNT(*) FROM events WHERE {where_clause}"
    query_sql = (
        f"SELECT * FROM events WHERE {where_clause} "
        "ORDER BY timestamp_utc DESC LIMIT ? OFFSET ?"
    )
    offset = max(0, (page - 1) * page_size)
    query_params = list(base_params) + [page_size, offset]
    return count_sql, query_sql, query_params


def build_alert_query(
    filter_obj: AlertFilter | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[str, str, list[Any]]:
    """Generate count SQL, paginated select SQL, and query parameter list for alerts.

    Returns:
        (count_sql, query_sql, query_params)
        where query_params binds to query_sql, and query_params[:-2] binds to count_sql.
    """
    where_clause, base_params = build_alert_where_clause(filter_obj)
    count_sql = f"SELECT COUNT(*) FROM alerts WHERE {where_clause}"
    query_sql = (
        f"SELECT * FROM alerts WHERE {where_clause} "
        "ORDER BY created_at DESC LIMIT ? OFFSET ?"
    )
    offset = max(0, (page - 1) * page_size)
    query_params = list(base_params) + [page_size, offset]
    return count_sql, query_sql, query_params
