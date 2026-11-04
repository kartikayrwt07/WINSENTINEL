"""Integration tests verifying end-to-end telemetry ingestion into SQLite via IngestionPipeline."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.config import DatabaseSettings
from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.query import EventFilter
from app.database.repository import EventRepository, ImportJobRepository
from app.ingestion.pipeline import IngestionPipeline
from app.models.events import EventCategory


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).parent.parent.parent


@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    """Fixture providing an initialized SQLite database with migrations applied."""
    db_file = tmp_path / "test_pipeline.db"
    settings = DatabaseSettings(db_path=str(db_file), wal_mode=False)
    db_manager = DatabaseManager(db_path=db_file, settings=settings)

    runner = MigrationRunner(db_manager)
    applied = runner.apply_migrations()
    assert len(applied) >= 1

    return db_manager


def test_pipeline_initialization_with_db_manager(temp_db: DatabaseManager, repo_root: Path) -> None:
    """Verify IngestionPipeline can be initialized with an optional DatabaseManager."""
    pipeline = IngestionPipeline(base_dir=repo_root, db_manager=temp_db)
    assert pipeline.db_manager is temp_db
    assert isinstance(pipeline.event_repo, EventRepository)
    assert isinstance(pipeline.job_repo, ImportJobRepository)


def test_ingest_and_persist_xml_telemetry(temp_db: DatabaseManager, repo_root: Path) -> None:
    """Verify ingest_and_persist parses XML, hashes file, creates audit records, and commits to DB."""
    pipeline = IngestionPipeline(base_dir=repo_root, db_manager=temp_db)
    sample_file = repo_root / "sample_data" / "sysmon" / "sysmon_eid1.xml"

    events, stats, job_id = pipeline.ingest_and_persist(sample_file)

    assert len(events) == 1
    assert stats.parsed_events == 1
    assert stats.duplicate_events == 0
    assert stats.malformed_events == 0
    assert job_id > 0

    # Verify imported_files record
    with temp_db.get_connection() as conn:
        file_row = conn.execute(
            "SELECT * FROM imported_files WHERE file_name = ?;",
            ("sysmon_eid1.xml",),
        ).fetchone()
        assert file_row is not None
        assert file_row["file_size_bytes"] == sample_file.stat().st_size
        assert len(file_row["file_hash_sha256"]) == 64

        # Verify import_jobs record
        job_row = conn.execute("SELECT * FROM import_jobs WHERE id = ?;", (job_id,)).fetchone()
        assert job_row is not None
        assert job_row["status"] == "COMPLETED"
        assert job_row["total_events"] == 1
        assert job_row["parsed_events"] == 1
        assert job_row["duplicate_events"] == 0
        assert job_row["end_time"] is not None

        # Verify events table
        event_row = conn.execute("SELECT * FROM events WHERE import_job_id = ?;", (job_id,)).fetchone()
        assert event_row is not None
        assert event_row["event_id"] == 1
        assert event_row["event_category"] == "PROCESS"
        assert "powershell.exe" in event_row["image"]

    # Verify query through EventRepository
    event_repo = EventRepository(temp_db)
    query_result = event_repo.query_events(EventFilter(event_ids=[1]))
    assert query_result.total_count == 1
    assert query_result.items[0].event_id == 1
    assert query_result.items[0].event_category == EventCategory.PROCESS


def test_duplicate_reingestion_updates_metrics(temp_db: DatabaseManager, repo_root: Path) -> None:
    """Verify ingesting the same file twice records duplicates and updates file metadata."""
    sample_file = repo_root / "sample_data" / "sysmon" / "sysmon_eid1.xml"

    # First ingestion
    pipeline1 = IngestionPipeline(base_dir=repo_root, db_manager=temp_db)
    events1, stats1, job_id_1 = pipeline1.ingest_and_persist(sample_file)
    assert stats1.parsed_events == 1
    assert stats1.duplicate_events == 0

    with temp_db.get_connection() as conn:
        file_row1 = conn.execute("SELECT * FROM imported_files WHERE file_name = ?;", ("sysmon_eid1.xml",)).fetchone()
        first_imported_at = file_row1["first_imported_at"]
        last_imported_at_1 = file_row1["last_imported_at"]

    # Second ingestion with clean pipeline state
    pipeline2 = IngestionPipeline(base_dir=repo_root, db_manager=temp_db)
    events2, stats2, job_id_2 = pipeline2.ingest_and_persist(sample_file)
    assert job_id_2 != job_id_1
    assert stats2.duplicate_events == 1
    assert stats2.parsed_events == 0

    with temp_db.get_connection() as conn:
        # Check imported_files was updated, not duplicated
        file_count = conn.execute("SELECT COUNT(*) FROM imported_files;").fetchone()[0]
        assert file_count == 1

        file_row2 = conn.execute("SELECT * FROM imported_files WHERE file_name = ?;", ("sysmon_eid1.xml",)).fetchone()
        assert file_row2["first_imported_at"] == first_imported_at

        # Check second job has accurate duplicate metrics
        job_row2 = conn.execute("SELECT * FROM import_jobs WHERE id = ?;", (job_id_2,)).fetchone()
        assert job_row2["status"] == "COMPLETED"
        assert job_row2["total_events"] == 1
        assert job_row2["parsed_events"] == 0
        assert job_row2["duplicate_events"] == 1

        # Check events table still only contains 1 row
        events_count = conn.execute("SELECT COUNT(*) FROM events;").fetchone()[0]
        assert events_count == 1


def test_multi_source_forensic_filtering(temp_db: DatabaseManager, repo_root: Path) -> None:
    """Verify filtering across multiple telemetry formats persisted in the database."""
    pipeline = IngestionPipeline(base_dir=repo_root, db_manager=temp_db)

    sysmon_file = repo_root / "sample_data" / "sysmon" / "sysmon_eid1.xml"
    network_file = repo_root / "sample_data" / "sysmon" / "sysmon_eid3.xml"
    security_file = repo_root / "sample_data" / "security" / "security_eid4688.xml"

    pipeline.ingest_and_persist(sysmon_file)
    pipeline.ingest_and_persist(network_file)
    pipeline.ingest_and_persist(security_file)

    event_repo = EventRepository(temp_db)

    # Filter by category
    network_results = event_repo.query_events(EventFilter(categories=[EventCategory.NETWORK]))
    assert network_results.total_count == 1
    assert network_results.items[0].destination_port == 443

    # Filter by EID list
    process_results = event_repo.query_events(EventFilter(event_ids=[1, 4688]))
    assert process_results.total_count == 2

    # Filter by image wildcard
    whoami_results = event_repo.query_events(EventFilter(image_contains="whoami"))
    assert whoami_results.total_count == 1
    assert whoami_results.items[0].event_id == 4688


def test_high_throughput_persistence_benchmark(temp_db: DatabaseManager, tmp_path: Path) -> None:
    """Verify benchmark: 5,000 events persist end-to-end through pipeline into SQLite in < 2.0s."""
    # Create 5,000 synthetic JSONL records
    jsonl_file = tmp_path / "benchmark_5000.jsonl"
    lines = []
    base_time = "2026-11-04T12:00:00Z"
    for i in range(5000):
        record = {
            "Provider": "Microsoft-Windows-Sysmon",
            "EventID": 1,
            "EventRecordID": i + 1,
            "Computer": f"BENCH-PC-{i % 5}",
            "TimeCreated": base_time,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "ProcessGuid": f"{{11111111-2222-3333-4444-{i:012d}}}",
            "ProcessId": str(2000 + i),
            "Image": r"C:\Windows\System32\svchost.exe",
            "CommandLine": f"svchost.exe -k netsvcs -p -s Service_{i}",
            "User": r"NT AUTHORITY\SYSTEM",
            "Hashes": "SHA256=A1B2C3D4E5F67890",
        }
        lines.append(json.dumps(record))

    jsonl_file.write_text("\n".join(lines), encoding="utf-8")

    pipeline = IngestionPipeline(base_dir=tmp_path, db_manager=temp_db)

    t0 = time.perf_counter()
    res = pipeline.ingest_and_persist(jsonl_file, chunk_size=1000, sync_processes=False)
    elapsed = time.perf_counter() - t0

    assert res.stats.parsed_events == 5000
    assert res.stats.duplicate_events == 0
    assert res.stats.malformed_events == 0
    assert res.inserted_count == 5000

    # Ensure all 5,000 events are queryable
    event_repo = EventRepository(temp_db)
    query_res = event_repo.query_events(page=1, page_size=10)
    assert query_res.total_count == 5000

    # SLA requirement: < 2.0 seconds for 5,000 events
    assert elapsed < 2.0, f"Ingestion took {elapsed:.3f}s, exceeding 2.0s SLA requirement"
