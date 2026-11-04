"""Unit tests for SettingsService."""

from pathlib import Path
import pytest

from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.ui.services.settings_service import SettingsService


@pytest.fixture
def test_db(tmp_path: Path) -> DatabaseManager:
    db_file = tmp_path / "test_ui_settings.db"
    mgr = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(db_manager=mgr)
    runner.apply_migrations()
    return mgr


def test_settings_service_health_and_config(test_db: DatabaseManager):
    svc = SettingsService(db_manager=test_db)
    health = svc.get_system_health()

    assert "sqlite_version" in health
    assert "table_counts" in health
    assert "events" in health["table_counts"]
    assert "alerts" in health["table_counts"]
    assert health["file_size_bytes"] >= 0

    cfg = svc.get_active_config()
    assert "correlation_window_minutes" in cfg
    assert cfg["correlation_window_minutes"] == 30

    svc.update_config("correlation_window_minutes", 60)
    assert svc.get_active_config()["correlation_window_minutes"] == 60
