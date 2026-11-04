"""Unit tests for ProcessRepository and Migration 002 SQLite persistence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.analyzers.process_analyzer import ProcessNode, ProcessTreeGraph
from app.database import DatabaseManager, MigrationRunner, ProcessRepository


@pytest.fixture
def test_db(tmp_path: Path) -> tuple[DatabaseManager, ProcessRepository]:
    """Fixture providing initialized SQLite database with migrations 001 and 002 applied."""
    db_file = tmp_path / "test_processes.db"
    db_manager = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(db_manager=db_manager)
    applied = runner.apply_migrations()
    assert 1 in applied and 2 in applied
    repo = ProcessRepository(db_manager=db_manager)
    return db_manager, repo


def test_migration_002_columns_and_indexes(test_db: tuple[DatabaseManager, ProcessRepository]) -> None:
    """Verify migration 002 added computer and is_synthesized columns and composite indexes."""
    db_manager, _ = test_db
    with db_manager.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(processes);")
        columns = {row["name"]: row["type"] for row in cursor.fetchall()}

        assert "computer" in columns
        assert "is_synthesized" in columns

        cursor.execute("SELECT name FROM sqlite_master WHERE type = 'index';")
        indexes = {row["name"] for row in cursor.fetchall()}
        assert "idx_processes_comp_guid" in indexes
        assert "idx_processes_comp_pid" in indexes
        assert "idx_processes_anomalous" in indexes


def test_upsert_process_single_insert(test_db: tuple[DatabaseManager, ProcessRepository]) -> None:
    """Verify upsert_process inserts a ProcessNode with correct type conversions."""
    db_manager, repo = test_db
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)

    node = ProcessNode(
        process_guid="{guid-100}",
        process_id=1234,
        computer="WORKSTATION01",
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c dir",
        current_directory=r"C:\Users\victim",
        user=r"CORP\victim",
        integrity_level="Medium",
        parent_process_guid="{parent-guid-99}",
        parent_process_id=1000,
        parent_image=r"C:\Windows\explorer.exe",
        parent_command_line=r"C:\Windows\explorer.exe",
        parent_user=r"CORP\victim",
        start_time=t0,
        is_synthesized=False,
        is_orphaned=False,
        is_anomalous=True,
        anomaly_reasons=["LIN-OFFICE-SHELL"],
    )

    with db_manager.get_connection() as conn:
        repo.upsert_process(conn, node)

    retrieved = repo.get_process_by_guid("{guid-100}")
    assert retrieved is not None
    assert retrieved.process_guid == "{guid-100}"
    assert retrieved.process_id == 1234
    assert retrieved.computer == "WORKSTATION01"
    assert retrieved.image == r"C:\Windows\System32\cmd.exe"
    assert retrieved.command_line == "cmd.exe /c dir"
    assert retrieved.current_directory == r"C:\Users\victim"
    assert retrieved.user == r"CORP\victim"
    assert retrieved.integrity_level == "Medium"
    assert retrieved.parent_process_guid == "{parent-guid-99}"
    assert retrieved.parent_process_id == 1000
    assert retrieved.parent_image == r"C:\Windows\explorer.exe"
    assert retrieved.start_time == t0
    assert retrieved.end_time is None
    assert not retrieved.is_synthesized
    assert not retrieved.is_orphaned
    assert retrieved.is_anomalous
    assert retrieved.anomaly_reasons == ["LIN-OFFICE-SHELL"]


def test_upsert_process_conflict_handling_synthesized_upgrade(test_db: tuple[DatabaseManager, ProcessRepository]) -> None:
    """Verify upsert_process upgrades a synthesized placeholder to genuine process on arrival."""
    db_manager, repo = test_db
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 4, 10, 30, 0, tzinfo=timezone.utc)

    # 1. Insert synthesized placeholder parent
    synth_parent = ProcessNode(
        process_guid="{synth-guid-1}",
        process_id=2000,
        computer="HOST01",
        image=r"C:\temp\unknown.exe",
        command_line=None,
        start_time=t0,
        is_synthesized=True,
        is_orphaned=True,
    )
    with db_manager.get_connection() as conn:
        repo.upsert_process(conn, synth_parent)

    first_fetch = repo.get_process_by_guid("{synth-guid-1}")
    assert first_fetch is not None
    assert first_fetch.is_synthesized
    assert first_fetch.is_orphaned

    # 2. Genuine process creation event arrives for the same GUID with termination info
    genuine_node = ProcessNode(
        process_guid="{synth-guid-1}",
        process_id=2000,
        computer="HOST01",
        image=r"C:\Program Files\Office\winword.exe",
        command_line="winword.exe doc.docx",
        user=r"CORP\analyst",
        start_time=t0,
        end_time=t1,
        exit_code=0,
        is_synthesized=False,
        is_orphaned=False,
    )
    with db_manager.get_connection() as conn:
        repo.upsert_process(conn, genuine_node)

    upgraded = repo.get_process_by_guid("{synth-guid-1}")
    assert upgraded is not None
    assert not upgraded.is_synthesized
    assert upgraded.image == r"C:\Program Files\Office\winword.exe"
    assert upgraded.command_line == "winword.exe doc.docx"
    assert upgraded.user == r"CORP\analyst"
    assert upgraded.end_time == t1
    assert upgraded.exit_code == 0


def test_upsert_processes_batch(test_db: tuple[DatabaseManager, ProcessRepository]) -> None:
    """Verify upsert_processes_batch inserts multiple nodes across transactions."""
    _, repo = test_db
    t0 = datetime(2026, 11, 4, 9, 0, 0, tzinfo=timezone.utc)

    nodes = [
        ProcessNode(
            process_guid=f"{{batch-guid-{i}}}",
            process_id=1000 + i,
            computer="BATCH-HOST",
            image=f"C:\\app_{i}.exe",
            start_time=t0 + timedelta(minutes=i),
        )
        for i in range(25)
    ]

    count = repo.upsert_processes_batch(nodes, chunk_size=10)
    assert count == 25

    fetched = repo.get_processes_by_computer("BATCH-HOST")
    assert len(fetched) == 25
    assert [n.process_guid for n in fetched] == [f"{{batch-guid-{i}}}" for i in range(25)]


def test_update_process_termination(test_db: tuple[DatabaseManager, ProcessRepository]) -> None:
    """Verify update_process_termination by GUID and by computer+pid."""
    db_manager, repo = test_db
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 4, 10, 15, 0, tzinfo=timezone.utc)

    n1 = ProcessNode(process_guid="{term-by-guid}", process_id=3001, computer="H1", image="t1.exe", start_time=t0)
    n2 = ProcessNode(process_guid="{term-by-pid}", process_id=3002, computer="H1", image="t2.exe", start_time=t0)

    with db_manager.get_connection() as conn:
        repo.upsert_process(conn, n1)
        repo.upsert_process(conn, n2)

    # Terminate by GUID
    ok1 = repo.update_process_termination("H1", 3001, t1, exit_code=42, process_guid="{term-by-guid}")
    assert ok1
    p1 = repo.get_process_by_guid("{term-by-guid}")
    assert p1 is not None
    assert p1.end_time == t1
    assert p1.exit_code == 42

    # Terminate by PID
    ok2 = repo.update_process_termination("H1", 3002, t1, exit_code=1)
    assert ok2
    p2 = repo.get_process_by_guid("{term-by-pid}")
    assert p2 is not None
    assert p2.end_time == t1
    assert p2.exit_code == 1

    # Terminate non-existent returns False
    assert not repo.update_process_termination("H1", 9999, t1)


def test_get_all_processes_and_limit(test_db: tuple[DatabaseManager, ProcessRepository]) -> None:
    """Verify get_all_processes obeys limit and ordering."""
    _, repo = test_db
    t0 = datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc)

    nodes = [
        ProcessNode(
            process_guid=f"{{all-guid-{i}}}",
            process_id=5000 + i,
            computer="HOST_ALL",
            image=f"proc_{i}.exe",
            start_time=t0 + timedelta(seconds=i),
        )
        for i in range(10)
    ]
    repo.upsert_processes_batch(nodes)

    all_procs = repo.get_all_processes(limit=5)
    assert len(all_procs) == 5
    assert all_procs[0].process_guid == "{all-guid-0}"
    assert all_procs[4].process_guid == "{all-guid-4}"


def test_hydrate_tree_graph_full_roundtrip(test_db: tuple[DatabaseManager, ProcessRepository]) -> None:
    """Verify hydrate_tree_graph loads nodes from SQLite and reconstructs the directed graph."""
    _, repo = test_db
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)

    # Create root -> parent -> child hierarchy in DB
    root = ProcessNode(
        process_guid="{root-h}",
        process_id=100,
        computer="CORP-DC",
        image=r"C:\Windows\System32\services.exe",
        start_time=t0,
    )
    parent = ProcessNode(
        process_guid="{parent-h}",
        process_id=200,
        computer="CORP-DC",
        image=r"C:\Windows\System32\spoolsv.exe",
        parent_process_guid="{root-h}",
        start_time=t0 + timedelta(seconds=1),
    )
    child = ProcessNode(
        process_guid="{child-h}",
        process_id=300,
        computer="CORP-DC",
        image=r"C:\Windows\System32\cmd.exe",
        parent_process_guid="{parent-h}",
        start_time=t0 + timedelta(seconds=2),
    )
    other_host_node = ProcessNode(
        process_guid="{other-h}",
        process_id=400,
        computer="OTHER-HOST",
        image=r"C:\other.exe",
        start_time=t0,
    )

    repo.upsert_processes_batch([root, parent, child, other_host_node])

    # Hydrate scoped to CORP-DC
    tree = repo.hydrate_tree_graph(computer="CORP-DC")
    assert isinstance(tree, ProcessTreeGraph)
    assert tree.node_count == 3
    assert tree.edge_count == 2
    assert tree.get_parent("{child-h}") == parent
    assert tree.get_parent("{parent-h}") == root

    # Ancestry walk from child
    lineage = tree.get_ancestors_lineage("{child-h}")
    assert [n.process_guid for n in lineage] == ["{root-h}", "{parent-h}", "{child-h}"]

    # Hydrate with time window filter
    filtered_tree = repo.hydrate_process_tree(
        computer="CORP-DC",
        start_time=t0 + timedelta(seconds=1),
    )
    # Root was at t0, so only parent and child matched start_time >= t0+1s
    assert filtered_tree.node_count == 2
    assert filtered_tree.get_node("{root-h}") is None
    assert filtered_tree.get_node("{parent-h}") is not None
    assert filtered_tree.get_node("{child-h}") is not None
