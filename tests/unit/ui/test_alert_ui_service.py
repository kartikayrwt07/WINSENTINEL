"""Unit tests for AlertUIService."""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from app.correlation.alert_manager import AlertManager, InvalidStatusTransitionError
from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.repository import AlertRepository
from app.detection.loader import RuleLoader
from app.ui.services.alert_ui_service import AlertUIService


@pytest.fixture
def test_db(tmp_path: Path):
    db_file = tmp_path / "test_alerts_ui.db"
    manager = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(db_manager=manager)
    runner.apply_migrations()

    # Pre-sync rules so rule_id foreign keys resolve cleanly
    loader = RuleLoader()
    rules = loader.load_rules_from_directory("rules/sysmon")
    loader.sync_rules_to_db(manager, rules)

    yield manager


def test_alert_ui_service_get_alerts_and_filter(test_db):
    repo = AlertRepository(test_db)
    now = datetime.now(timezone.utc).isoformat()

    alert_id = repo.create_alert(
        rule_id="WS-SYS-001",
        title="Whoami Reconnaissance Activity",
        severity="medium",
        description="whoami.exe executed in terminal",
        computer="WIN-SEC-01",
        user="CONTOSO\\Administrator",
        process_guid="{AAAA-1111-2222}",
        first_seen=now,
        last_seen=now,
        event_count=1,
        mitre_tactics=["TA0007"],
        mitre_techniques=["T1033"],
    )

    service = AlertUIService(db_manager=test_db)

    # 1. Fetch all alerts
    alerts, total = service.get_alerts()
    assert total == 1
    assert len(alerts) == 1
    assert alerts[0]["id"] == alert_id
    assert alerts[0]["title"] == "Whoami Reconnaissance Activity"
    assert alerts[0]["status"].lower() == "new"
    assert alerts[0]["mitre_tactics"] == ["TA0007"]
    assert alerts[0]["mitre_techniques"] == ["T1033"]

    # 2. Filter by status
    alerts_new, total_new = service.get_alerts(status="new")
    assert total_new == 1
    alerts_inv, total_inv = service.get_alerts(status="investigating")
    assert total_inv == 0

    # 3. Filter by severity
    alerts_med, total_med = service.get_alerts(severity="medium")
    assert total_med == 1
    alerts_high, total_high = service.get_alerts(severity="high")
    assert total_high == 0

    # 4. Search filter
    alerts_srch, total_srch = service.get_alerts(search="Administrator")
    assert total_srch == 1
    alerts_none, total_none = service.get_alerts(search="nonexistent")
    assert total_none == 0


def test_alert_ui_service_lifecycle_and_notes(test_db):
    repo = AlertRepository(test_db)
    now = datetime.now(timezone.utc).isoformat()

    alert_id = repo.create_alert(
        rule_id="WS-SYS-002",
        title="Certutil File Download",
        severity="high",
        description="certutil.exe downloaded payload",
        computer="WORKSTATION-02",
        user="CORP\\jdoe",
        process_guid="{BBBB-2222-3333}",
        first_seen=now,
        last_seen=now,
        event_count=2,
    )

    service = AlertUIService(db_manager=test_db)

    # Transition: new -> investigating
    res = service.update_status(
        alert_id=alert_id,
        new_status="investigating",
        analyst="SecAnalyst1",
        notes="Reviewing parent process command line",
    )
    assert res["status"].lower() == "investigating"

    # Add an analyst note
    note_id = service.add_note(
        alert_id=alert_id,
        note_text="Confirmed suspicious curl command invocation",
        analyst="SecAnalyst1",
        disposition="true_positive",
    )
    assert note_id > 0

    # Drill down
    detail = service.get_alert_detail(alert_id)
    assert detail["alert"]["id"] == alert_id
    assert detail["alert"]["status"].lower() == "investigating"
    assert len(detail["notes"]) >= 2  # status transition note + manual note
