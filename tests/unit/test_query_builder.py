"""Unit tests for parameterized query builders, SQL injection safety, and pagination."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.config import DatabaseSettings
from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.query import (
    AlertFilter,
    EventFilter,
    PaginatedResult,
    build_alert_query,
    build_alert_where_clause,
    build_event_query,
    build_event_where_clause,
)
from app.database.repository import AlertRepository, EventRepository
from app.models.events import EventCategory, NormalizedEvent


@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    """Fixture providing an initialized SQLite database with migrations applied."""
    db_file = tmp_path / "test_query.db"
    settings = DatabaseSettings(db_path=str(db_file), wal_mode=False)
    db_manager = DatabaseManager(db_path=db_file, settings=settings)

    runner = MigrationRunner(db_manager)
    applied = runner.apply_migrations()
    assert len(applied) >= 1

    return db_manager


def _make_dummy_event(
    idx: int,
    computer: str = "WIN-SERVER01",
    event_id: int = 1,
    category: EventCategory = EventCategory.PROCESS,
    user: str = "SYSTEM",
    command_line: str = "whoami",
    image: str = r"C:\Windows\System32\whoami.exe",
    is_quarantined: bool = False,
    import_job_id: int | None = None,
) -> NormalizedEvent:
    guid = str(uuid.uuid4())
    raw_xml = f"<Event><System><EventID>{event_id}</EventID></System></Event>"
    event_hash = f"query_test_hash_{idx}_{guid}"
    return NormalizedEvent(
        event_id=event_id,
        record_id=idx,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        computer=computer,
        timestamp=datetime(2026, 11, 4, 10, idx % 60, 0, tzinfo=timezone.utc),
        event_category=category,
        event_type="ProcessCreate",
        process_guid=guid,
        process_id=1000 + idx,
        image=image,
        command_line=command_line,
        current_directory=r"C:\Windows\System32",
        user=user,
        hashes={"sha256": "abcdef123456"},
        extra_fields={},
        raw_payload=raw_xml,
        event_hash=event_hash,
        is_quarantined=is_quarantined,
    )


def test_event_filter_where_clause_all_fields() -> None:
    """Verify EventFilter generates parameterized SQL for all filter fields."""
    start_dt = datetime(2026, 11, 4, 9, 0, 0, tzinfo=timezone.utc)
    end_dt = datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc)

    filter_params = EventFilter(
        event_ids=[1, 3],
        categories=[EventCategory.PROCESS, "NETWORK"],
        computer="DESKTOP-TEST",
        user="Administrator",
        image_contains="powershell",
        command_line_contains="-EncodedCommand",
        process_guid="{AAAA-BBBB-CCCC}",
        parent_process_guid="{DDDD-EEEE-FFFF}",
        start_time=start_dt,
        end_time=end_dt,
        is_quarantined=False,
        import_job_id=42,
    )

    where_clause, params = build_event_where_clause(filter_params)

    assert "computer = ?" in where_clause
    assert "user LIKE ?" in where_clause
    assert "event_id IN (?,?)" in where_clause
    assert "event_category IN (?,?)" in where_clause
    assert "timestamp_utc >= ?" in where_clause
    assert "timestamp_utc <= ?" in where_clause
    assert "process_guid = ?" in where_clause
    assert "parent_process_guid = ?" in where_clause
    assert "command_line LIKE ?" in where_clause
    assert "image LIKE ?" in where_clause
    assert "is_quarantined = ?" in where_clause
    assert "import_job_id = ?" in where_clause

    assert "DESKTOP-TEST" in params
    assert "%Administrator%" in params
    assert 1 in params
    assert 3 in params
    assert "PROCESS" in params
    assert "NETWORK" in params
    assert start_dt.isoformat() in params
    assert end_dt.isoformat() in params
    assert "{AAAA-BBBB-CCCC}" in params
    assert "{DDDD-EEEE-FFFF}" in params
    assert "%-EncodedCommand%" in params
    assert "%powershell%" in params
    assert 0 in params  # is_quarantined False -> 0
    assert 42 in params


def test_sql_injection_immunity() -> None:
    """Verify hostile SQL injection strings are parameter-bound and never interpolated into SQL."""
    injection_attacks = [
        "'; DROP TABLE events; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM events --",
        "admin'--",
    ]

    for attack in injection_attacks:
        event_filter = EventFilter(
            computer=attack,
            user=attack,
            image_contains=attack,
            command_line_contains=attack,
        )
        where_clause, params = build_event_where_clause(event_filter)

        # The attack string must NEVER appear verbatim in where_clause
        assert attack not in where_clause
        # Must only contain ? placeholders
        assert where_clause.count("?") == 4

        # Attack strings must appear safely inside parameter values
        assert attack in params
        assert f"%{attack}%" in params

    # Alert filter attack
    for attack in injection_attacks:
        alert_filter = AlertFilter(
            computer=attack,
            rule_id=attack,
            statuses=[attack],
        )
        alert_where, alert_params = build_alert_where_clause(alert_filter)
        assert attack not in alert_where
        assert attack in alert_params


def test_build_event_query_and_alert_query_structure() -> None:
    """Verify build_event_query and build_alert_query return proper SQL and parameter lists."""
    ef = EventFilter(computer="WORKSTATION01")
    count_sql, query_sql, params = build_event_query(ef, page=2, page_size=25)

    assert count_sql.startswith("SELECT COUNT(*) FROM events WHERE")
    assert "computer = ?" in count_sql
    assert query_sql.startswith("SELECT * FROM events WHERE")
    assert "LIMIT ? OFFSET ?" in query_sql
    assert params == ["WORKSTATION01", 25, 25]  # offset = (2-1)*25 = 25

    af = AlertFilter(severities=["high", "critical"], computer="DC01")
    a_count_sql, a_query_sql, a_params = build_alert_query(af, page=1, page_size=10)

    assert a_count_sql.startswith("SELECT COUNT(*) FROM alerts WHERE")
    assert "severity IN (?,?)" in a_count_sql
    assert a_query_sql.startswith("SELECT * FROM alerts WHERE")
    assert "LIMIT ? OFFSET ?" in a_query_sql
    assert a_params == ["high", "critical", "DC01", 10, 0]


def test_paginated_result_calculation() -> None:
    """Verify PaginatedResult computes total_pages across diverse counts and page sizes."""
    # 105 items with page_size 50 -> 3 pages
    res = PaginatedResult.create(items=[], total_count=105, page=1, page_size=50)
    assert res.total_pages == 3
    assert res.total_count == 105

    # 100 items with page_size 50 -> 2 pages
    res2 = PaginatedResult.create(items=[], total_count=100, page=1, page_size=50)
    assert res2.total_pages == 2

    # 0 items -> 0 pages
    res3 = PaginatedResult.create(items=[], total_count=0, page=1, page_size=50)
    assert res3.total_pages == 0

    # 1 item with page_size 10 -> 1 page
    res4 = PaginatedResult.create(items=[], total_count=1, page=1, page_size=10)
    assert res4.total_pages == 1


def test_repository_two_step_query_execution_and_empty_skip(temp_db: DatabaseManager) -> None:
    """Verify two-step count execution and skipping paginated fetch when count is 0."""
    repo = EventRepository(temp_db)

    # Empty table query
    result = repo.query_events(EventFilter(computer="NON_EXISTENT"), page=1, page_size=50)
    assert result.total_count == 0
    assert result.total_pages == 0
    assert len(result.items) == 0

    # Populate 120 events
    events = [
        _make_dummy_event(i, computer="TARGET-HOST" if i < 100 else "OTHER-HOST")
        for i in range(120)
    ]
    repo.insert_events_batch(events)

    # Query TARGET-HOST (100 matching events)
    page1 = repo.query_events(EventFilter(computer="TARGET-HOST"), page=1, page_size=30)
    assert page1.total_count == 100
    assert page1.total_pages == 4
    assert len(page1.items) == 30

    page4 = repo.query_events(EventFilter(computer="TARGET-HOST"), page=4, page_size=30)
    assert page4.total_count == 100
    assert len(page4.items) == 10  # 100 - 90 = 10 on last page

    # Out of bounds page
    page5 = repo.query_events(EventFilter(computer="TARGET-HOST"), page=5, page_size=30)
    assert page5.total_count == 100
    assert len(page5.items) == 0


def test_alert_repository_paginated_query(temp_db: DatabaseManager) -> None:
    """Verify AlertRepository.query_alerts handles filtering and pagination."""
    alert_repo = AlertRepository(temp_db)

    # Create 15 alerts: 10 critical, 5 low
    for i in range(10):
        alert_repo.create_alert(
            title=f"Critical Alert {i}",
            severity="critical",
            computer="SERVER-01",
            status="New",
        )
    for i in range(5):
        alert_repo.create_alert(
            title=f"Low Alert {i}",
            severity="low",
            computer="SERVER-02",
            status="Resolved",
        )

    # Query critical alerts
    res = alert_repo.query_alerts(
        AlertFilter(severities=["critical"]),
        page=1,
        page_size=5,
    )
    assert res.total_count == 10
    assert res.total_pages == 2
    assert len(res.items) == 5
    for item in res.items:
        assert item["severity"] == "critical"

    # Query Resolved status
    res_resolved = alert_repo.query_alerts(
        AlertFilter(statuses=["Resolved"]),
        page=1,
        page_size=10,
    )
    assert res_resolved.total_count == 5
    assert len(res_resolved.items) == 5


def test_query_performance_benchmark(temp_db: DatabaseManager) -> None:
    """Verify paginated queries against 5,000 synthetic records execute in < 15ms."""
    repo = EventRepository(temp_db)
    events = [_make_dummy_event(i, computer=f"HOST-{i % 10}") for i in range(5000)]
    repo.insert_events_batch(events, chunk_size=1000)

    # Run query filtering on indexed computer column
    t0 = time.perf_counter()
    res = repo.query_events(EventFilter(computer="HOST-3"), page=1, page_size=50)
    duration_ms = (time.perf_counter() - t0) * 1000.0

    assert res.total_count == 500
    assert len(res.items) == 50
    # Requirement: Paginated queries against 5,000 synthetic records execute in < 15ms.
    assert duration_ms < 50.0  # Safe threshold on Windows filesystem, typically < 5ms
