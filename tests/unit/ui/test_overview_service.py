"""Unit tests for OverviewService."""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.repository import AlertRepository, EventRepository
from app.detection.loader import RuleLoader
from app.models.events import EventCategory, NormalizedEvent
from app.ui.services.overview_service import OverviewService


@pytest.fixture
def test_db(tmp_path: Path) -> DatabaseManager:
    db_file = tmp_path / "test_ui.db"
    mgr = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(db_manager=mgr)
    runner.apply_migrations()

    # Pre-sync rules for foreign key integrity
    loader = RuleLoader()
    rules = loader.load_rules_from_directory("rules/sysmon")
    loader.sync_rules_to_db(mgr, rules)
    return mgr


def test_overview_service_empty(test_db: DatabaseManager):
    svc = OverviewService(db_manager=test_db)
    kpis = svc.get_kpis()
    assert kpis["total_events"] == 0
    assert kpis["total_alerts"] == 0
    assert kpis["critical_alerts"] == 0

    breakdown = svc.get_severity_breakdown()
    assert breakdown["critical"] == 0

    assert svc.get_top_targeted_hosts() == []
    assert svc.get_recent_alerts() == []


def test_overview_service_populated(test_db: DatabaseManager):
    event_repo = EventRepository(test_db)
    alert_repo = AlertRepository(test_db)

    # Insert an event
    ev = NormalizedEvent(
        event_id=1,
        record_id=10,
        provider="Sysmon",
        channel="Operational",
        computer="ENDPOINT-01",
        timestamp=datetime.now(timezone.utc),
        event_category=EventCategory.PROCESS,
        event_type="ProcessCreate",
        raw_payload="<raw/>",
        event_hash="h1",
    )
    event_repo.insert_events_batch([ev])

    # Insert alerts
    alert_repo.create_alert(
        title="Certutil Download",
        severity="critical",
        computer="ENDPOINT-01",
        rule_id="WS-SYS-001",
        mitre_tactics=["Command and Control"],
        mitre_techniques=["T1105"],
    )

    alert_repo.create_alert(
        title="Whoami Recon",
        severity="medium",
        computer="ENDPOINT-01",
        rule_id="WS-SYS-006",
        mitre_tactics=["Discovery"],
        mitre_techniques=["T1033"],
    )

    svc = OverviewService(db_manager=test_db)
    kpis = svc.get_kpis()
    assert kpis["total_events"] == 1
    assert kpis["total_alerts"] == 2
    assert kpis["critical_alerts"] == 1
    assert kpis["medium_alerts"] == 1

    hosts = svc.get_top_targeted_hosts()
    assert len(hosts) == 1
    assert hosts[0]["computer"] == "ENDPOINT-01"
    assert hosts[0]["alert_count"] == 2

    mitre = svc.get_mitre_breakdown()
    techniques = [m["technique"] for m in mitre]
    assert "T1105" in techniques
    assert "T1033" in techniques
