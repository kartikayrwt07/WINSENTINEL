"""Unit tests for ProcessGraphService and SVG process tree generation."""

from pathlib import Path
import pytest

from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.ui.components.visualizers import render_svg_process_tree
from app.ui.services.process_graph_service import ProcessGraphService


@pytest.fixture
def test_db(tmp_path: Path) -> DatabaseManager:
    db_file = tmp_path / "test_ui_proc.db"
    mgr = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(db_manager=mgr)
    runner.apply_migrations()
    return mgr


def test_svg_process_tree_rendering():
    nodes = [
        {"id": "guid-root", "label": "explorer.exe", "pid": 1000, "threat_level": "normal", "command_line": "explorer.exe"},
        {"id": "guid-child", "label": "cmd.exe", "pid": 2000, "threat_level": "suspicious", "command_line": "cmd.exe /c whoami"},
        {"id": "guid-alert", "label": "certutil.exe", "pid": 3000, "threat_level": "alert", "command_line": "certutil.exe -urlcache ..."},
    ]
    edges = [
        ("guid-root", "guid-child"),
        ("guid-child", "guid-alert"),
    ]

    svg = render_svg_process_tree(nodes, edges)
    assert "<svg" in svg
    assert "explorer.exe" in svg
    assert "cmd.exe" in svg
    assert "certutil.exe" in svg
    assert "ALERT" in svg
    assert "SUSPICIOUS" in svg


def test_process_graph_service_empty(test_db: DatabaseManager):
    svc = ProcessGraphService(db_manager=test_db)
    candidates = svc.get_candidate_processes()
    assert candidates == []

    tree = svc.build_process_tree("non-existent-guid")
    assert tree["nodes"] == []
    assert tree["target_process"] is None


def test_process_graph_service_lineage(test_db: DatabaseManager):
    with test_db.get_connection() as conn:
        conn.execute(
            """
            INSERT INTO processes (process_guid, process_id, image, command_line, user, computer, start_time)
            VALUES ('{P1}', 100, 'C:\\Windows\\explorer.exe', 'explorer.exe', 'CORP\\user', 'HOST-A', '2026-11-05T10:00:00Z');
            """
        )
        conn.execute(
            """
            INSERT INTO processes (process_guid, parent_process_guid, process_id, image, command_line, user, computer, start_time)
            VALUES ('{P2}', '{P1}', 200, 'C:\\Windows\\System32\\cmd.exe', 'cmd.exe', 'CORP\\user', 'HOST-A', '2026-11-05T10:01:00Z');
            """
        )
        conn.execute(
            """
            INSERT INTO processes (process_guid, parent_process_guid, process_id, image, command_line, user, computer, start_time)
            VALUES ('{P3}', '{P2}', 300, 'C:\\Windows\\System32\\certutil.exe', 'certutil.exe -urlcache', 'CORP\\user', 'HOST-A', '2026-11-05T10:02:00Z');
            """
        )

    svc = ProcessGraphService(db_manager=test_db)
    candidates = svc.get_candidate_processes(computer="HOST-A")
    assert len(candidates) == 3

    # Inspect tree centered on P2
    tree = svc.build_process_tree("{P2}")
    node_ids = {n["id"] for n in tree["nodes"]}
    assert node_ids == {"{P1}", "{P2}", "{P3}"}
    assert len(tree["edges"]) == 2
    assert "{P2}" in tree["target_process"]["process_guid"]
