"""Unit tests for ImportUIService."""

from datetime import datetime, timezone
import json
from pathlib import Path
import pytest

from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.repository import ImportJobRepository
from app.ui.services.import_ui_service import ImportUIService


@pytest.fixture
def test_db(tmp_path: Path):
    db_file = tmp_path / "test_import_ui.db"
    manager = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(db_manager=manager)
    runner.apply_migrations()
    yield manager


def test_import_ui_service(test_db):
    repo = ImportJobRepository(test_db)
    file_id = repo.create_or_get_imported_file(
        file_path="C:\\logs\\sysmon_sample.evtx",
        file_name="sysmon_sample.evtx",
        file_size_bytes=1048576,
        file_hash_sha256="abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    )
    job_id = repo.create_import_job(
        file_id=file_id,
        file_path="C:\\logs\\sysmon_sample.evtx",
        status="COMPLETED",
    )

    # Update job with counts and error log
    errs = [
        {"record_id": 42, "error": "Invalid XML structure in EventData"},
        {"record_id": 99, "error": "Missing System.TimeCreated element"},
    ]
    now = datetime.now(timezone.utc).isoformat()
    with test_db.get_connection() as conn:
        conn.execute(
            """
            UPDATE import_jobs
            SET end_time = ?, total_events = 100, parsed_events = 98,
                malformed_events = 2, error_log_json = ?
            WHERE id = ?;
            """,
            (now, json.dumps(errs), job_id),
        )

    service = ImportUIService(db_manager=test_db)

    # 1. get_import_history
    history, total = service.get_import_history()
    assert total == 1
    assert len(history) == 1
    job = history[0]
    assert job["id"] == job_id
    assert job["file_name"] == "sysmon_sample.evtx"
    assert job["status"] == "COMPLETED"
    assert job["total_events"] == 100
    assert job["parsed_events"] == 98
    assert job["malformed_events"] == 2

    # 2. get_job_summary
    summary = service.get_job_summary(job_id)
    assert summary is not None
    assert summary["id"] == job_id
    assert summary["has_errors"] is True

    # 3. get_import_errors
    errors = service.get_import_errors(job_id)
    assert len(errors) == 2
    assert errors[0]["record_id"] == 42

