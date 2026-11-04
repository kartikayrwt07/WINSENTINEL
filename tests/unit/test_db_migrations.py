"""Unit tests for the sequential transactional migration runner and initial schema DDL."""

from __future__ import annotations

from pathlib import Path
import pytest

from app.database import DatabaseManager, MigrationRunner


def test_initial_migration_applies_all_12_tables_and_indexes(tmp_path: Path) -> None:
    """Verify that 001_initial_schema.sql establishes all 12 core tables and composite indexes."""
    db_file = tmp_path / "test_initial.db"
    db_manager = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(db_manager=db_manager)

    applied = runner.apply_migrations()
    assert 1 in applied

    expected_tables = {
        "schema_migrations",
        "imported_files",
        "import_jobs",
        "events",
        "processes",
        "detection_rules",
        "alerts",
        "alert_evidence",
        "investigations",
        "analyst_notes",
        "evaluation_runs",
        "evaluation_results",
    }

    expected_indexes = {
        "idx_events_timestamp",
        "idx_events_proc_guid",
        "idx_events_process_guid",
        "idx_events_parent_proc_guid",
        "idx_events_parent_process_guid",
        "idx_events_comp_ts",
        "idx_events_computer_ts",
        "idx_events_eid_ts",
        "idx_events_category",
        "idx_events_category_ts",
        "idx_events_user",
        "idx_events_job_id",
        "idx_events_hash",
        "idx_processes_parent_guid",
        "idx_processes_parent",
        "idx_processes_start_time",
        "idx_processes_image",
        "idx_alerts_status",
        "idx_alerts_severity",
        "idx_alerts_comp",
        "idx_alerts_computer",
        "idx_alerts_rule",
        "idx_alerts_created",
        "idx_evidence_alert",
        "idx_evidence_event",
        "idx_notes_alert",
        "idx_notes_investigation",
        "idx_eval_results_run",
        "idx_eval_results_rule",
    }

    with db_manager.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type = 'table';")
        tables = {row["name"] for row in cursor.fetchall()}
        # sqlite_sequence is an internal table created for AUTOINCREMENT
        tables.discard("sqlite_sequence")
        assert expected_tables.issubset(tables), f"Missing tables: {expected_tables - tables}"

        cursor.execute("SELECT name FROM sqlite_master WHERE type = 'index';")
        indexes = {row["name"] for row in cursor.fetchall()}
        assert expected_indexes.issubset(indexes), f"Missing indexes: {expected_indexes - indexes}"


def test_migration_runner_discovery_and_ordering(tmp_path: Path) -> None:
    """Verify that MigrationRunner discovers migrations matching regex pattern in ascending order."""
    migrations_dir = tmp_path / "custom_migrations"
    migrations_dir.mkdir()

    # Create dummy migrations out of order
    (migrations_dir / "003_third_step.sql").write_text("-- third", encoding="utf-8")
    (migrations_dir / "001_first_step.sql").write_text("-- first", encoding="utf-8")
    (migrations_dir / "002_second_step.sql").write_text("-- second", encoding="utf-8")
    (migrations_dir / "invalid_name.sql").write_text("-- ignore", encoding="utf-8")
    (migrations_dir / "readme.txt").write_text("ignore", encoding="utf-8")

    db_manager = DatabaseManager(db_path=tmp_path / "ordering.db")
    runner = MigrationRunner(db_manager=db_manager, migrations_dir=migrations_dir)

    discovered = runner.discover_migrations()
    assert len(discovered) == 3
    assert discovered[0][0] == 1
    assert discovered[0][1] == "first_step"
    assert discovered[1][0] == 2
    assert discovered[1][1] == "second_step"
    assert discovered[2][0] == 3
    assert discovered[2][1] == "third_step"


def test_migration_runner_checksum_and_record_tracking(tmp_path: Path) -> None:
    """Verify that applied migrations record valid SHA-256 checksums and metadata in schema_migrations."""
    migrations_dir = tmp_path / "checksum_migrations"
    migrations_dir.mkdir()
    sql_path = migrations_dir / "001_create_dummy.sql"
    sql_content = "CREATE TABLE dummy_items (id INTEGER PRIMARY KEY, title TEXT);"
    sql_path.write_text(sql_content, encoding="utf-8")

    db_manager = DatabaseManager(db_path=tmp_path / "checksum.db")
    runner = MigrationRunner(db_manager=db_manager, migrations_dir=migrations_dir)

    expected_checksum = runner.compute_checksum(sql_path)
    applied = runner.apply_migrations()
    assert 1 in applied

    with db_manager.get_connection() as conn:
        applied_records = runner.get_applied_migrations(conn)
        assert 1 in applied_records
        record = applied_records[1]
        assert record.version == 1
        assert record.name == "create_dummy"
        assert record.checksum == expected_checksum
        assert record.applied_at != ""


def test_migration_runner_idempotency(tmp_path: Path) -> None:
    """Verify that running apply_migrations repeatedly is a no-op once applied."""
    db_file = tmp_path / "idempotent.db"
    db_manager = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(db_manager=db_manager)

    # First run applies migrations
    applied_first = runner.apply_migrations()
    assert 1 in applied_first and 2 in applied_first

    # Second run is a no-op
    applied_second = runner.apply_migrations()
    assert applied_second == []


def test_migration_runner_detects_checksum_tampering(tmp_path: Path) -> None:
    """Verify that tampering with an already-applied migration SQL file raises a RuntimeError."""
    migrations_dir = tmp_path / "tamper_migrations"
    migrations_dir.mkdir()
    sql_path = migrations_dir / "001_initial.sql"
    sql_path.write_text("CREATE TABLE test_tbl (id INTEGER PRIMARY KEY);", encoding="utf-8")

    db_manager = DatabaseManager(db_path=tmp_path / "tamper.db")
    runner = MigrationRunner(db_manager=db_manager, migrations_dir=migrations_dir)

    # Apply migration initially
    runner.apply_migrations()

    # Tamper with the applied migration file
    sql_path.write_text("CREATE TABLE test_tbl (id INTEGER PRIMARY KEY, tampered TEXT);", encoding="utf-8")

    # Re-running migrations must fail with RuntimeError due to checksum mismatch
    with pytest.raises(RuntimeError, match="Migration checksum mismatch for version 1"):
        runner.apply_migrations()


def test_migration_runner_transaction_rollback_on_error(tmp_path: Path) -> None:
    """Verify that a failing migration rolls back completely without leaving partial tables or corrupting records."""
    migrations_dir = tmp_path / "rollback_migrations"
    migrations_dir.mkdir()

    # First valid migration
    (migrations_dir / "001_valid.sql").write_text(
        "CREATE TABLE table_one (id INTEGER PRIMARY KEY);", encoding="utf-8"
    )

    # Second faulty migration containing a syntax error after creating a table
    (migrations_dir / "002_faulty.sql").write_text(
        "CREATE TABLE table_two (id INTEGER PRIMARY KEY);\nINVALID SQL SYNTAX HERE;",
        encoding="utf-8",
    )

    db_manager = DatabaseManager(db_path=tmp_path / "rollback.db")
    runner = MigrationRunner(db_manager=db_manager, migrations_dir=migrations_dir)

    # Running migrations should fail on migration 002
    with pytest.raises(Exception):
        runner.apply_migrations()

    with db_manager.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type = 'table';")
        tables = {row["name"] for row in cursor.fetchall()}

        # table_one was applied in migration 1
        assert "table_one" in tables
        # table_two MUST NOT exist because migration 2 rolled back completely
        assert "table_two" not in tables

        applied = runner.get_applied_migrations(conn)
        assert 1 in applied
        assert 2 not in applied
