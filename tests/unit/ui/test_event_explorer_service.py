"""Unit tests for EventExplorerService."""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.repository import EventRepository
from app.models.events import EventCategory, NormalizedEvent
from app.ui.services.event_explorer_service import EventExplorerService


@pytest.fixture
def test_db(tmp_path: Path) -> DatabaseManager:
    db_file = tmp_path / "test_ui_events.db"
    mgr = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(db_manager=mgr)
    runner.apply_migrations()
    return mgr


def test_event_explorer_filtering_and_detail(test_db: DatabaseManager):
    event_repo = EventRepository(test_db)

    # Insert 3 events
    e1 = NormalizedEvent(
        event_id=1,
        record_id=101,
        provider="Sysmon",
        channel="Operational",
        computer="HOST-A",
        timestamp=datetime(2026, 11, 5, 10, 0, 0, tzinfo=timezone.utc),
        event_category=EventCategory.PROCESS,
        event_type="ProcessCreate",
        image="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe /c dir",
        user="CORP\\alice",
        raw_payload="<Event>1</Event>",
        event_hash="hash1",
    )
    e2 = NormalizedEvent(
        event_id=1,
        record_id=102,
        provider="Sysmon",
        channel="Operational",
        computer="HOST-B",
        timestamp=datetime(2026, 11, 5, 11, 0, 0, tzinfo=timezone.utc),
        event_category=EventCategory.PROCESS,
        event_type="ProcessCreate",
        image="C:\\Windows\\System32\\powershell.exe",
        command_line="powershell.exe -enc ...",
        user="CORP\\bob",
        raw_payload="<Event>2</Event>",
        event_hash="hash2",
    )
    e3 = NormalizedEvent(
        event_id=3,
        record_id=103,
        provider="Sysmon",
        channel="Operational",
        computer="HOST-A",
        timestamp=datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc),
        event_category=EventCategory.NETWORK,
        event_type="NetworkConnect",
        image="C:\\Windows\\System32\\curl.exe",
        user="CORP\\alice",
        raw_payload="<Event>3</Event>",
        event_hash="hash3",
    )
    event_repo.insert_events_batch([e1, e2, e3])
    id1 = event_repo.get_db_id_by_hash(e1.event_hash)

    svc = EventExplorerService(db_manager=test_db)

    # Filter by computer
    records, count = svc.filter_events(computer="HOST-A")
    assert count == 2
    assert len(records) == 2

    # Filter by user and category
    records, count = svc.filter_events(user="bob", category="PROCESS")
    assert count == 1
    assert records[0]["user"] == "CORP\\bob"

    # Search filter
    records, count = svc.filter_events(search="curl")
    assert count == 1
    assert records[0]["event_id"] == 3

    # Detail view
    assert id1 is not None
    detail = svc.get_event_detail(id1)
    assert detail is not None
    assert detail["raw_payload"] == "<Event>1</Event>"
    assert detail["image"] == "C:\\Windows\\System32\\cmd.exe"
