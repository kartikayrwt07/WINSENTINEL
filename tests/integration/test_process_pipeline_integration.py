"""Integration tests validating process tree reconstruction, anomaly tagging, and SQLite persistence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.analyzers.process_analyzer import ProcessTreeGraph
from app.config import DatabaseSettings
from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.repository import ProcessRepository
from app.ingestion.pipeline import IngestionPipeline, IngestionResult


@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    """Fixture providing an initialized SQLite database with all migrations applied."""
    db_file = tmp_path / "test_process_pipeline.db"
    settings = DatabaseSettings(db_path=str(db_file), wal_mode=False)
    db_manager = DatabaseManager(db_path=db_file, settings=settings)

    runner = MigrationRunner(db_manager)
    applied = runner.apply_migrations()
    assert len(applied) >= 2  # migrations 001 and 002

    return db_manager


def test_pipeline_exposes_process_repo(temp_db: DatabaseManager, tmp_path: Path) -> None:
    """Verify IngestionPipeline exposes process_repo property backed by DatabaseManager."""
    pipeline = IngestionPipeline(base_dir=tmp_path, db_manager=temp_db)
    assert pipeline.process_repo is not None
    assert isinstance(pipeline.process_repo, ProcessRepository)
    assert pipeline.process_repo.db_manager is temp_db


def test_ingest_and_persist_reconstructs_tree_and_anomalies(
    temp_db: DatabaseManager,
    tmp_path: Path,
) -> None:
    """Verify ingest_and_persist reconstructs ProcessTreeGraph and executes LineageAnomalyDetector."""
    jsonl_file = tmp_path / "attack_telemetry.jsonl"
    t0 = "2026-11-04T12:00:00.000000Z"
    t1 = "2026-11-04T12:01:00.000000Z"

    events_data = [
        # 1. winword.exe created
        {
            "Provider": "Microsoft-Windows-Sysmon",
            "EventID": 1,
            "EventRecordID": 101,
            "Computer": "VICTIM-PC",
            "TimeCreated": t0,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "ProcessGuid": "{11111111-0000-0000-0000-000000000001}",
            "ProcessId": "1000",
            "Image": r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
            "CommandLine": r'"WINWORD.EXE" invoice.docm',
            "User": r"CORP\victim",
        },
        # 2. winword spawns powershell.exe (LIN-OFFICE-SHELL)
        {
            "Provider": "Microsoft-Windows-Sysmon",
            "EventID": 1,
            "EventRecordID": 102,
            "Computer": "VICTIM-PC",
            "TimeCreated": t1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "ProcessGuid": "{22222222-0000-0000-0000-000000000002}",
            "ProcessId": "2000",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -w hidden -enc SQBFAFgA...",
            "User": r"CORP\victim",
            "ParentProcessGuid": "{11111111-0000-0000-0000-000000000001}",
            "ParentProcessId": "1000",
            "ParentImage": r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
        },
    ]

    jsonl_file.write_text("\n".join(json.dumps(e) for e in events_data), encoding="utf-8")

    pipeline = IngestionPipeline(base_dir=tmp_path, db_manager=temp_db)
    result = pipeline.ingest_and_persist(jsonl_file, chunk_size=100)

    assert isinstance(result, IngestionResult)
    assert len(result.events) == 2
    assert result.process_tree is not None
    assert result.process_tree.node_count == 2
    assert len(result.anomalies) == 1

    anomaly = result.anomalies[0]
    assert anomaly.rule_id == "LIN-OFFICE-SHELL"
    assert anomaly.severity == "CRITICAL"
    assert anomaly.child_guid == "{22222222-0000-0000-0000-000000000002}"

    # Verify SQLite persistence
    repo = pipeline.process_repo
    ps_node = repo.get_process_by_guid("{22222222-0000-0000-0000-000000000002}")
    assert ps_node is not None
    assert ps_node.is_anomalous is True
    assert any("LIN-OFFICE-SHELL" in reason for reason in ps_node.anomaly_reasons)


def test_ingest_and_persist_process_termination_updates_sqlite(
    temp_db: DatabaseManager,
    tmp_path: Path,
) -> None:
    """Verify process termination events (EID 5) update process end_time and exit_code in SQLite."""
    t0 = "2026-11-04T14:00:00.000000Z"
    t1 = "2026-11-04T14:05:00.000000Z"

    # Step 1: Ingest creation event
    create_file = tmp_path / "proc_create.jsonl"
    create_file.write_text(
        json.dumps({
            "Provider": "Microsoft-Windows-Sysmon",
            "EventID": 1,
            "EventRecordID": 501,
            "Computer": "HOST01",
            "TimeCreated": t0,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "ProcessGuid": "{proc-terminate-test}",
            "ProcessId": "7777",
            "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": "cmd.exe /c exit 42",
        }),
        encoding="utf-8",
    )

    pipeline = IngestionPipeline(base_dir=tmp_path, db_manager=temp_db)
    pipeline.ingest_and_persist(create_file)

    repo = pipeline.process_repo
    proc_before = repo.get_process_by_guid("{proc-terminate-test}")
    assert proc_before is not None
    assert proc_before.end_time is None
    assert proc_before.exit_code is None

    # Step 2: Ingest termination event
    term_file = tmp_path / "proc_term.jsonl"
    term_file.write_text(
        json.dumps({
            "Provider": "Microsoft-Windows-Sysmon",
            "EventID": 5,
            "EventRecordID": 502,
            "Computer": "HOST01",
            "TimeCreated": t1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "ProcessGuid": "{proc-terminate-test}",
            "ProcessId": "7777",
            "Image": r"C:\Windows\System32\cmd.exe",
            "ExitCode": "42",
        }),
        encoding="utf-8",
    )

    pipeline.ingest_and_persist(term_file)

    proc_after = repo.get_process_by_guid("{proc-terminate-test}")
    assert proc_after is not None
    assert proc_after.end_time is not None
    assert proc_after.end_time == datetime(2026, 11, 4, 14, 5, 0, tzinfo=timezone.utc)
    assert proc_after.exit_code == 42


def test_end_to_end_pipeline_tree_hydration_and_serialization(
    temp_db: DatabaseManager,
    tmp_path: Path,
) -> None:
    """Verify complete end-to-end flow: ingest, persist, hydrate tree from DB, and serialize to D3/Cytoscape."""
    xml_content = """<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <EventRecordID>1001</EventRecordID>
    <TimeCreated SystemTime="2026-11-04T15:00:00.000000Z" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>SERVER01</Computer>
  </System>
  <EventData>
    <Data Name="ProcessGuid">{spool-root-guid}</Data>
    <Data Name="ProcessId">1234</Data>
    <Data Name="Image">C:\\Windows\\System32\\spoolsv.exe</Data>
    <Data Name="CommandLine">C:\\Windows\\System32\\spoolsv.exe</Data>
    <Data Name="User">NT AUTHORITY\\SYSTEM</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <EventRecordID>1002</EventRecordID>
    <TimeCreated SystemTime="2026-11-04T15:00:05.000000Z" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>SERVER01</Computer>
  </System>
  <EventData>
    <Data Name="ProcessGuid">{cmd-child-guid}</Data>
    <Data Name="ProcessId">5678</Data>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="ParentProcessGuid">{spool-root-guid}</Data>
    <Data Name="ParentProcessId">1234</Data>
    <Data Name="ParentImage">C:\\Windows\\System32\\spoolsv.exe</Data>
    <Data Name="User">NT AUTHORITY\\SYSTEM</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" />
    <EventID>1</EventID>
    <EventRecordID>1003</EventRecordID>
    <TimeCreated SystemTime="2026-11-04T15:00:06.000000Z" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>SERVER01</Computer>
  </System>
  <EventData>
    <Data Name="ProcessGuid">{whoami-grandchild-guid}</Data>
    <Data Name="ProcessId">9012</Data>
    <Data Name="Image">C:\\Windows\\System32\\whoami.exe</Data>
    <Data Name="CommandLine">whoami /priv</Data>
    <Data Name="ParentProcessGuid">{cmd-child-guid}</Data>
    <Data Name="ParentProcessId">5678</Data>
    <Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="User">NT AUTHORITY\\SYSTEM</Data>
  </EventData>
</Event>
</Events>"""

    xml_file = tmp_path / "printnightmare.xml"
    xml_file.write_text(xml_content, encoding="utf-8")

    pipeline = IngestionPipeline(base_dir=tmp_path, db_manager=temp_db)
    result = pipeline.ingest_and_persist(xml_file)

    assert len(result.events) == 3
    assert result.inserted_count == 3
    assert len(result.anomalies) >= 1

    # Check LIN-SPOOLSV-EXEC triggered on spoolsv -> cmd
    spool_anomaly = next(a for a in result.anomalies if a.rule_id == "LIN-SPOOLSV-EXEC")
    assert spool_anomaly.severity == "CRITICAL"
    assert spool_anomaly.child_guid == "{cmd-child-guid}"

    # Verify ProcessRepository can rehydrate the full tree graph from SQLite
    repo = pipeline.process_repo
    hydrated_tree = repo.hydrate_tree_graph(computer="SERVER01")
    assert hydrated_tree.node_count == 3
    assert hydrated_tree.edge_count == 2

    # Check ancestry walks on hydrated tree
    lineage = hydrated_tree.get_ancestors_lineage("{whoami-grandchild-guid}")
    assert [n.process_guid for n in lineage] == [
        "{spool-root-guid}",
        "{cmd-child-guid}",
        "{whoami-grandchild-guid}",
    ]

    # Verify D3 serialization from hydrated tree
    d3_data = hydrated_tree.to_d3_tree("{spool-root-guid}")
    assert d3_data["name"] == "spoolsv.exe"
    assert d3_data["children"][0]["name"] == "cmd.exe"
    assert d3_data["children"][0]["is_anomalous"] is True

    # Verify Cytoscape serialization
    cy_data = hydrated_tree.to_cytoscape()
    assert len([e for e in cy_data if "source" not in e["data"]]) == 3
    assert len([e for e in cy_data if "source" in e["data"]]) == 2
