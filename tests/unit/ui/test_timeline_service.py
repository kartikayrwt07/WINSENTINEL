"""Unit tests for TimelineService."""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.repository import EventRepository
from app.models.events import EventCategory, NormalizedEvent
from app.ui.services.timeline_service import TimelineService


@pytest.fixture
def test_db(tmp_path: Path) -> DatabaseManager:
    db_file = tmp_path / "test_ui_timeline.db"
    mgr = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(db_manager=mgr)
    runner.apply_migrations()
    return mgr


def test_timeline_service_chronological_ordering(test_db: DatabaseManager):
    repo = EventRepository(test_db)

    # Insert events in non-chronological order
    e2 = NormalizedEvent(
        event_id=3,
        record_id=2,
        provider="Sysmon",
        channel="Operational",
        computer="HOST-A",
        timestamp=datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc),
        event_category=EventCategory.NETWORK,
        event_type="NetworkConnect",
        image="C:\\Windows\\System32\\curl.exe",
        raw_payload="<e2/>",
        event_hash="h2",
    )
    e1 = NormalizedEvent(
        event_id=1,
        record_id=1,
        provider="Sysmon",
        channel="Operational",
        computer="HOST-A",
        timestamp=datetime(2026, 11, 5, 11, 0, 0, tzinfo=timezone.utc),
        event_category=EventCategory.PROCESS,
        event_type="ProcessCreate",
        image="C:\\Windows\\System32\\cmd.exe",
        raw_payload="<e1/>",
        event_hash="h1",
    )
    repo.insert_events_batch([e2, e1])

    svc = TimelineService(db_manager=test_db)
    items = svc.get_timeline(computer="HOST-A")

    assert len(items) == 2
    # Check that events are returned in chronological order (e1 first, e2 second)
    assert items[0]["event_id"] == 1
    assert items[1]["event_id"] == 3

    svg = svc.render_timeline_svg(items)
    assert "<svg" in svg
    assert "HOST-A" in svg
