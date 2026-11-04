"""Unit tests for DatabaseSettings and DatabaseManager."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
import pytest

from app.config import DatabaseSettings, get_app_settings, get_database_settings
from app.database.connection import DatabaseManager


def test_database_settings_defaults() -> None:
    """Verify DatabaseSettings default values match architectural requirements."""
    settings = DatabaseSettings()
    assert settings.db_path == Path("data/winsentinel.db")
    assert settings.busy_timeout_ms == 5000
    assert settings.wal_mode is True
    assert settings.foreign_keys is True
    assert settings.synchronous == "NORMAL"

    app_settings = get_app_settings()
    assert isinstance(app_settings.database, DatabaseSettings)
    assert get_database_settings() == app_settings.database


def test_database_manager_creates_parent_directory(tmp_path: Path) -> None:
    """Verify DatabaseManager creates non-existent parent directories for db_path."""
    nested_dir = tmp_path / "deep" / "nested" / "path"
    db_file = nested_dir / "test.db"
    assert not nested_dir.exists()

    manager = DatabaseManager(db_path=db_file)
    assert nested_dir.exists()
    assert nested_dir.is_dir()
    assert manager.db_path == db_file


def test_database_manager_pragmas_applied(tmp_path: Path) -> None:
    """Verify get_connection applies WAL, foreign keys, busy timeout, and synchronous pragmas."""
    db_file = tmp_path / "test.db"
    manager = DatabaseManager(db_path=db_file)

    with manager.get_connection() as conn:
        # Check foreign_keys
        cur = conn.cursor()
        cur.execute("PRAGMA foreign_keys;")
        assert cur.fetchone()[0] == 1

        # Check busy_timeout
        cur.execute("PRAGMA busy_timeout;")
        assert cur.fetchone()[0] == 5000

        # Check synchronous: 1 is NORMAL in SQLite
        cur.execute("PRAGMA synchronous;")
        assert cur.fetchone()[0] == 1

        # Check journal_mode: should be 'wal'
        cur.execute("PRAGMA journal_mode;")
        assert cur.fetchone()[0].lower() == "wal"


def test_database_manager_row_factory(tmp_path: Path) -> None:
    """Verify sqlite3.Row row factory allows column access by name."""
    db_file = tmp_path / "test.db"
    manager = DatabaseManager(db_path=db_file)

    with manager.get_connection() as conn:
        conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT);")
        conn.execute("INSERT INTO items (name) VALUES (?);", ("Sentinel",))

    with manager.get_connection() as conn:
        cur = conn.execute("SELECT id, name FROM items WHERE id = 1;")
        row = cur.fetchone()
        assert isinstance(row, sqlite3.Row)
        assert row["name"] == "Sentinel"
        assert row["id"] == 1


def test_database_manager_transaction_commit_and_rollback(tmp_path: Path) -> None:
    """Verify automatic commit on normal exit and rollback on unhandled exceptions."""
    db_file = tmp_path / "test.db"
    manager = DatabaseManager(db_path=db_file)

    with manager.get_connection() as conn:
        conn.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, msg TEXT);")

    # Successful transaction commits automatically
    with manager.get_connection() as conn:
        conn.execute("INSERT INTO logs (msg) VALUES (?);", ("first",))

    with manager.get_connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM logs;").fetchone()[0]
        assert count == 1

    # Exception during transaction rolls back automatically
    with pytest.raises(ValueError, match="Deliberate error"):
        with manager.get_connection() as conn:
            conn.execute("INSERT INTO logs (msg) VALUES (?);", ("second",))
            raise ValueError("Deliberate error")

    with manager.get_connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM logs;").fetchone()[0]
        assert count == 1
        row = conn.execute("SELECT msg FROM logs WHERE id = 1;").fetchone()
        assert row["msg"] == "first"


def test_database_manager_foreign_key_enforcement(tmp_path: Path) -> None:
    """Verify that foreign key constraints are enforced, raising IntegrityError on violation."""
    db_file = tmp_path / "test.db"
    manager = DatabaseManager(db_path=db_file)

    with manager.get_connection() as conn:
        conn.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY);")
        conn.execute(
            "CREATE TABLE child (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id));"
        )
        conn.execute("INSERT INTO parent (id) VALUES (1);")
        conn.execute("INSERT INTO child (id, parent_id) VALUES (10, 1);")

    with pytest.raises(sqlite3.IntegrityError):
        with manager.get_connection() as conn:
            conn.execute("INSERT INTO child (id, parent_id) VALUES (11, 999);")


def test_database_manager_in_memory() -> None:
    """Verify in-memory database creation and basic operations without directory creation."""
    manager = DatabaseManager(db_path=":memory:")
    assert manager.is_memory is True

    with manager.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("PRAGMA foreign_keys;")
        assert cur.fetchone()[0] == 1
        conn.execute("CREATE TABLE mem_tbl (val TEXT);")
        conn.execute("INSERT INTO mem_tbl VALUES ('test');")
        val = conn.execute("SELECT val FROM mem_tbl;").fetchone()[0]
        assert val == "test"


def test_database_manager_concurrent_reads_and_writes(tmp_path: Path) -> None:
    """Verify that concurrent reader threads do not block writer threads in WAL mode."""
    db_file = tmp_path / "test.db"
    manager = DatabaseManager(db_path=db_file)

    with manager.get_connection() as conn:
        conn.execute("CREATE TABLE counter (val INTEGER);")
        conn.execute("INSERT INTO counter VALUES (0);")

    errors: list[Exception] = []
    reads_performed: list[int] = []
    stop_event = threading.Event()

    def reader() -> None:
        try:
            while not stop_event.is_set():
                with manager.get_connection() as conn:
                    val = conn.execute("SELECT val FROM counter;").fetchone()[0]
                    reads_performed.append(val)
                time.sleep(0.005)
        except Exception as exc:
            errors.append(exc)

    def writer() -> None:
        try:
            for i in range(1, 20):
                with manager.get_connection() as conn:
                    conn.execute("UPDATE counter SET val = ?;", (i,))
                time.sleep(0.01)
        except Exception as exc:
            errors.append(exc)

    reader_thread = threading.Thread(target=reader)
    writer_thread = threading.Thread(target=writer)

    reader_thread.start()
    writer_thread.start()

    writer_thread.join()
    stop_event.set()
    reader_thread.join()

    assert not errors, f"Concurrent execution produced errors: {errors}"
    assert len(reads_performed) > 0
    with manager.get_connection() as conn:
        final_val = conn.execute("SELECT val FROM counter;").fetchone()[0]
        assert final_val == 19
