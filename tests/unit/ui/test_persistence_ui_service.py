"""Unit tests for PersistenceUIService."""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.repository import EventRepository
from app.models.events import EventCategory, NormalizedEvent
from app.ui.services.persistence_ui_service import PersistenceUIService


@pytest.fixture
def test_db(tmp_path: Path) -> DatabaseManager:
    db_file = tmp_path / "test_ui_persist.db"
    mgr = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(db_manager=mgr)
    runner.apply_migrations()
    return mgr


def test_persistence_service_categories(test_db: DatabaseManager):
    repo = EventRepository(test_db)

    # 1. Registry Run key
    e_reg = NormalizedEvent(
        event_id=12,
        record_id=1,
        provider="Sysmon",
        channel="Operational",
        computer="HOST-A",
        timestamp=datetime.now(timezone.utc),
        event_category=EventCategory.REGISTRY,
        event_type="SetValue",
        registry_target_object="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor",
        registry_details="C:\\evil.exe",
        image="C:\\Windows\\cmd.exe",
        raw_payload="<e/>",
        event_hash="h_reg",
    )

    # 2. IFEO Debugger
    e_ifeo = NormalizedEvent(
        event_id=12,
        record_id=2,
        provider="Sysmon",
        channel="Operational",
        computer="HOST-A",
        timestamp=datetime.now(timezone.utc),
        event_category=EventCategory.REGISTRY,
        event_type="SetValue",
        registry_target_object="HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe\\Debugger",
        registry_details="C:\\evil.exe",
        image="C:\\Windows\\reg.exe",
        raw_payload="<e/>",
        event_hash="h_ifeo",
    )

    # 3. Scheduled Task
    e_task = NormalizedEvent(
        event_id=4698,
        record_id=3,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        computer="HOST-A",
        timestamp=datetime.now(timezone.utc),
        event_category=EventCategory.SECURITY,
        event_type="TaskCreated",
        task_name="\\MaliciousJob",
        task_content="<Task>content</Task>",
        raw_payload="<e/>",
        event_hash="h_task",
    )

    repo.insert_events_batch([e_reg, e_ifeo, e_task])

    svc = PersistenceUIService(db_manager=test_db)
    summary = svc.get_persistence_summary(computer="HOST-A")

    assert len(summary["registry_run"]) == 1
    assert "Run\\Backdoor" in summary["registry_run"][0]["target"]

    assert len(summary["ifeo_debugger"]) == 1
    assert "sethc.exe\\Debugger" in summary["ifeo_debugger"][0]["target"]

    assert len(summary["scheduled_tasks"]) == 1
    assert summary["scheduled_tasks"][0]["task_name"] == "\\MaliciousJob"

