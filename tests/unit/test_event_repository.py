"""Unit tests for EventRepository, AlertRepository, and ImportJobRepository."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.config import DatabaseSettings
from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.repository import AlertRepository, EventRepository, ImportJobRepository
from app.models.events import EventCategory, NormalizedEvent


@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    """Fixture providing an initialized SQLite database with migrations applied."""
    db_file = tmp_path / "test_repo.db"
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
) -> NormalizedEvent:
    """Helper to generate unique synthetic NormalizedEvents."""
    guid = str(uuid.uuid4())
    raw_xml = f"<Event><System><EventID>{event_id}</EventID></System><EventData><Data>{idx}</Data></EventData></Event>"
    event_hash = f"test_hash_{idx}_{guid}"
    return NormalizedEvent(
        event_id=event_id,
        record_id=idx,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        computer=computer,
        timestamp=datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc),
        event_category=category,
        event_type="ProcessCreate",
        process_guid=guid,
        process_id=1000 + idx,
        image=r"C:\Windows\System32\cmd.exe",
        command_line=f"cmd.exe /c echo {idx}",
        current_directory=r"C:\Windows\System32",
        user=r"NT AUTHORITY\SYSTEM",
        hashes={"sha256": "abcdef123456", "md5": "123456abcdef"},
        extra_fields={"custom_idx": idx},
        raw_payload=raw_xml,
        event_hash=event_hash,
    )


def test_insert_events_batch_chunking_and_rowcount(temp_db: DatabaseManager) -> None:
    """Verify insert_events_batch handles 2,500 events in chunks of 1,000 and counts rows."""
    repo = EventRepository(temp_db)
    events = [_make_dummy_event(i) for i in range(2500)]

    inserted, duplicates = repo.insert_events_batch(events, chunk_size=1000)
    assert inserted == 2500
    assert duplicates == 0

    # Query count directly
    with temp_db.get_connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events;").fetchone()[0]
        assert count == 2500


def test_duplicate_suppression(temp_db: DatabaseManager) -> None:
    """Verify duplicate event_hashes are ignored atomically without UniqueConstraint error."""
    repo = EventRepository(temp_db)
    batch = [_make_dummy_event(i) for i in range(50)]

    # First insert
    ins1, dup1 = repo.insert_events_batch(batch)
    assert ins1 == 50
    assert dup1 == 0

    # Second insert with same events
    ins2, dup2 = repo.insert_events_batch(batch)
    assert ins2 == 0
    assert dup2 == 50

    # Mixed batch: 25 old + 25 new
    new_batch = batch[:25] + [_make_dummy_event(i + 100) for i in range(25)]
    ins3, dup3 = repo.insert_events_batch(new_batch)
    assert ins3 == 25
    assert dup3 == 25


def test_get_event_by_hash_and_id_reconstruction(temp_db: DatabaseManager) -> None:
    """Verify get_event_by_hash and get_event_by_id faithfully reconstruct typed models."""
    repo = EventRepository(temp_db)
    orig_event = _make_dummy_event(99)

    inserted, duplicates = repo.insert_events_batch([orig_event])
    assert inserted == 1

    # Fetch by hash
    retrieved_by_hash = repo.get_event_by_hash(orig_event.event_hash)
    assert retrieved_by_hash is not None
    assert retrieved_by_hash.event_hash == orig_event.event_hash
    assert retrieved_by_hash.timestamp == orig_event.timestamp
    assert retrieved_by_hash.hashes == {"sha256": "abcdef123456", "md5": "123456abcdef"}
    assert retrieved_by_hash.extra_fields == {"custom_idx": 99}
    assert retrieved_by_hash.raw_payload == orig_event.raw_payload
    assert retrieved_by_hash.event_category == EventCategory.PROCESS

    # Fetch by ID
    event_id = repo.get_db_id_by_hash(orig_event.event_hash)
    assert event_id is not None
    retrieved_by_id = repo.get_event_by_id(event_id)
    assert retrieved_by_id is not None
    assert retrieved_by_id == retrieved_by_hash


def test_import_job_repository_lifecycle(temp_db: DatabaseManager) -> None:
    """Verify ImportJobRepository tracks files, deduplicates by hash, and updates jobs."""
    job_repo = ImportJobRepository(temp_db)

    # Register file
    file_id_1 = job_repo.create_or_get_imported_file(
        file_path="/var/log/sysmon.xml",
        file_name="sysmon.xml",
        file_size_bytes=1048576,
        file_hash_sha256="sha256_mock_file_hash_1",
    )
    assert file_id_1 > 0

    # Register same file again -> returns same id
    file_id_2 = job_repo.create_or_get_imported_file(
        file_path="/var/log/sysmon_renamed.xml",
        file_name="sysmon_renamed.xml",
        file_size_bytes=1048576,
        file_hash_sha256="sha256_mock_file_hash_1",
    )
    assert file_id_1 == file_id_2

    # Create job
    job_id = job_repo.create_import_job(
        file_id=file_id_1,
        file_path="/var/log/sysmon.xml",
        status="RUNNING",
    )
    assert job_id > 0

    # Check job initially RUNNING
    job_data = job_repo.get_import_job(job_id)
    assert job_data is not None
    assert job_data["status"] == "RUNNING"
    assert job_data["total_events"] == 0

    # Update job to COMPLETED
    job_repo.update_import_job(
        job_id=job_id,
        status="COMPLETED",
        total_events=1000,
        parsed_events=980,
        malformed_events=10,
        quarantined_events=10,
        duplicate_events=0,
        error_log=["Recoverable warning on record 45"],
    )

    updated_job = job_repo.get_import_job(job_id)
    assert updated_job is not None
    assert updated_job["status"] == "COMPLETED"
    assert updated_job["total_events"] == 1000
    assert updated_job["parsed_events"] == 980
    assert updated_job["malformed_events"] == 10
    assert updated_job["quarantined_events"] == 10
    assert updated_job["error_log"] == ["Recoverable warning on record 45"]
    assert updated_job["end_time"] is not None


def test_alert_repository_lifecycle_evidence_and_notes(temp_db: DatabaseManager) -> None:
    """Verify AlertRepository creates alerts, links evidence, attaches notes, and updates status."""
    event_repo = EventRepository(temp_db)
    alert_repo = AlertRepository(temp_db)

    # Insert an event first
    event = _make_dummy_event(1)
    event_repo.insert_events_batch([event])
    db_event_id = event_repo.get_db_id_by_hash(event.event_hash)
    assert db_event_id is not None

    # Create alert
    alert_id = alert_repo.create_alert(
        title="Suspicious Process Execution",
        severity="high",
        computer="WIN-SERVER01",
        description="Execution of cmd.exe with suspicious parameters",
        user=r"NT AUTHORITY\SYSTEM",
        mitre_tactics=["Execution"],
        mitre_techniques=["T1059.003"],
    )
    assert alert_id > 0

    # Link evidence
    ev_id = alert_repo.link_alert_evidence(
        alert_id=alert_id,
        event_id=db_event_id,
        matched_field="image",
        matched_value=r"C:\Windows\System32\cmd.exe",
        explanation="Matched command interpreter rule pattern",
    )
    assert ev_id > 0

    # Add analyst note
    note_id = alert_repo.add_analyst_note(
        author="SOC-Analyst-Alice",
        note_text="Investigating parent process ancestry.",
        alert_id=alert_id,
    )
    assert note_id > 0

    # Verify status update
    alert_repo.update_alert_status(alert_id, "Investigating")

    # Fetch full alert
    alert_details = alert_repo.get_alert(alert_id)
    assert alert_details is not None
    assert alert_details["title"] == "Suspicious Process Execution"
    assert alert_details["severity"] == "high"
    assert alert_details["status"] == "Investigating"
    assert alert_details["mitre_tactics"] == ["Execution"]
    assert alert_details["mitre_techniques"] == ["T1059.003"]

    assert len(alert_details["evidence"]) == 1
    assert alert_details["evidence"][0]["event_id"] == db_event_id
    assert alert_details["evidence"][0]["matched_field"] == "image"

    assert len(alert_details["notes"]) == 1
    assert alert_details["notes"][0]["author"] == "SOC-Analyst-Alice"
    assert alert_details["notes"][0]["note_text"] == "Investigating parent process ancestry."


def test_alert_deletion_cascades_foreign_keys(temp_db: DatabaseManager) -> None:
    """Verify deleting an alert cascades to alert_evidence and analyst_notes."""
    event_repo = EventRepository(temp_db)
    alert_repo = AlertRepository(temp_db)

    # Insert event
    event = _make_dummy_event(2)
    event_repo.insert_events_batch([event])
    db_event_id = event_repo.get_db_id_by_hash(event.event_hash)
    assert db_event_id is not None

    # Create alert, evidence, note
    alert_id = alert_repo.create_alert(
        title="Test Alert",
        severity="medium",
        computer="WIN-TEST",
    )
    alert_repo.link_alert_evidence(alert_id=alert_id, event_id=db_event_id)
    alert_repo.add_analyst_note(
        author="Bob",
        note_text="Cascade test note",
        alert_id=alert_id,
    )

    # Ensure evidence and notes exist
    with temp_db.get_connection() as conn:
        ev_count = conn.execute("SELECT COUNT(*) FROM alert_evidence WHERE alert_id = ?;", (alert_id,)).fetchone()[0]
        notes_count = conn.execute("SELECT COUNT(*) FROM analyst_notes WHERE alert_id = ?;", (alert_id,)).fetchone()[0]
        assert ev_count == 1
        assert notes_count == 1

    # Delete alert
    deleted = alert_repo.delete_alert(alert_id)
    assert deleted is True

    # Assert cascaded deletion
    with temp_db.get_connection() as conn:
        ev_count = conn.execute("SELECT COUNT(*) FROM alert_evidence WHERE alert_id = ?;", (alert_id,)).fetchone()[0]
        notes_count = conn.execute("SELECT COUNT(*) FROM analyst_notes WHERE alert_id = ?;", (alert_id,)).fetchone()[0]
        assert ev_count == 0
        assert notes_count == 0

        # Event itself must still exist!
        event_count = conn.execute("SELECT COUNT(*) FROM events WHERE id = ?;", (db_event_id,)).fetchone()[0]
        assert event_count == 1
