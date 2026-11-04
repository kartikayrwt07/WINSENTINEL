"""End-to-end integration smoke test for all 10 WinSentinel SOC UI pages and services."""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.repository import AlertRepository, EventRepository, ImportJobRepository
from app.detection.loader import RuleLoader
from app.models.events import EventCategory, NormalizedEvent
from app.ui.pages import (
    page_01_overview,
    page_02_events,
    page_03_alerts,
    page_04_process_tree,
    page_05_timeline,
    page_06_persistence,
    page_07_rules,
    page_08_evaluation,
    page_09_import_history,
    page_10_settings,
)
from app.ui.services import (
    AlertUIService,
    EvaluationUIService,
    EventExplorerService,
    ImportUIService,
    OverviewService,
    PersistenceUIService,
    ProcessGraphService,
    RuleUIService,
    SettingsService,
    TimelineService,
)


@pytest.fixture
def test_db(tmp_path: Path) -> DatabaseManager:
    """Fixture providing an initialized SQLite test database with seed events, alerts, and jobs."""
    db_file = tmp_path / "smoke_test.db"
    manager = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(db_manager=manager)
    runner.apply_migrations()

    # Pre-sync rules
    loader = RuleLoader()
    rules = loader.load_rules_from_directory("rules/sysmon")
    loader.sync_rules_to_db(manager, rules)

    now = datetime.now(timezone.utc).isoformat()

    # Seed an imported file and import job
    job_repo = ImportJobRepository(manager)
    file_id = job_repo.create_or_get_imported_file(
        file_path="C:\\sample.evtx",
        file_name="sample.evtx",
        file_size_bytes=4096,
        file_hash_sha256="deadbeef" * 8,
    )
    job_repo.create_import_job(file_id=file_id, file_path="C:\\sample.evtx", status="COMPLETED")

    # Seed an event
    ev_repo = EventRepository(manager)
    event = NormalizedEvent(
        event_id=1,
        record_id=1,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="WORKSTATION-01",
        timestamp=datetime.now(timezone.utc),
        event_category=EventCategory.PROCESS,
        event_type="ProcessCreate",
        process_guid="{PROC-1111}",
        process_id=1234,
        image="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe /c whoami",
        user="CORP\\analyst",
        raw_payload="<event></event>",
        event_hash="hash123456",
    )
    ev_repo.insert_events_batch([event])

    # Seed an alert
    alert_repo = AlertRepository(manager)
    alert_repo.create_alert(
        rule_id="WS-SYS-001",
        title="Suspicious Certutil Download",
        severity="high",
        computer="WORKSTATION-01",
        user="CORP\\analyst",
        process_guid="{PROC-1111}",
        first_seen=now,
        last_seen=now,
        event_count=1,
    )

    yield manager


def test_ui_services_instantiation_and_smoke(test_db: DatabaseManager):
    """Verify that all 10 decoupled presentation services instantiate and query successfully."""
    s1 = OverviewService(db_manager=test_db)
    assert "total_events" in s1.get_kpis()

    s2 = EventExplorerService(db_manager=test_db)
    events, total = s2.filter_events(limit=10)
    assert total >= 1

    s3 = ProcessGraphService(db_manager=test_db)
    procs = s3.get_candidate_processes(limit=10)
    assert isinstance(procs, list)

    s4 = TimelineService(db_manager=test_db)
    tl = s4.get_timeline(limit=10)
    assert isinstance(tl, list)

    s5 = PersistenceUIService(db_manager=test_db)
    ps = s5.get_persistence_summary()
    assert "registry_run" in ps

    s6 = AlertUIService(db_manager=test_db)
    alerts, a_total = s6.get_alerts()
    assert a_total >= 1

    s7 = RuleUIService(rules_dir="rules/sysmon", db_manager=test_db)
    rules = s7.list_rules()
    assert len(rules) >= 16

    s8 = EvaluationUIService(rules_dir="rules/sysmon", datasets_dir="tests/data/benchmarks")
    ds = s8.get_available_datasets()
    assert len(ds) >= 1

    s9 = ImportUIService(db_manager=test_db)
    jobs, j_total = s9.get_import_history()
    assert j_total >= 1

    s10 = SettingsService(db_manager=test_db)
    cfg = s10.get_active_config()
    assert "db_path" in cfg


def test_all_10_pages_render_headless(test_db: DatabaseManager):
    """Verify that render_page() on all 10 SOC pages executes without unhandled exceptions."""
    r1 = page_01_overview.render_page(db_manager=test_db)
    assert isinstance(r1, dict)
    assert "kpis" in r1

    r2 = page_02_events.render_page(db_manager=test_db)
    assert isinstance(r2, dict)
    assert "events" in r2

    r3 = page_03_alerts.render_page(db_manager=test_db)
    assert isinstance(r3, dict)
    assert "alerts" in r3

    r4 = page_04_process_tree.render_page(db_manager=test_db)
    assert isinstance(r4, dict)
    assert "nodes" in r4

    r5 = page_05_timeline.render_page(db_manager=test_db)
    assert isinstance(r5, list)

    r6 = page_06_persistence.render_page(db_manager=test_db)
    assert isinstance(r6, dict)
    assert "registry_run" in r6

    r7 = page_07_rules.render_page(db_manager=test_db)
    assert isinstance(r7, dict)
    assert "rules" in r7

    r8 = page_08_evaluation.render_page(db_manager=test_db)
    assert isinstance(r8, dict)

    r9 = page_09_import_history.render_page(db_manager=test_db)
    assert isinstance(r9, dict)
    assert "jobs" in r9

    r10 = page_10_settings.render_page(db_manager=test_db)
    assert isinstance(r10, dict)
    assert "health" in r10


def test_main_app_import_smoke():
    """Verify app.ui.main entrypoint imports and exposes routing."""
    import app.ui.main as ui_main
    assert hasattr(ui_main, "main")
    assert hasattr(ui_main, "route_page")
    assert hasattr(ui_main, "render_sidebar")
    assert len(ui_main.PAGE_NAMES) == 10
