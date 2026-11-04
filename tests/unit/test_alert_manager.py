"""Unit tests for AlertManager and InvestigationRepository in WinSentinel."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from app.analyzers.process_analyzer import ProcessNode
from app.correlation.alert_manager import (
    AlertManager,
    InvalidStatusTransitionError,
)
from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.database.repository import (
    AlertRepository,
    EventRepository,
    InvestigationRepository,
    ProcessRepository,
)
from app.models.detection import DetectionMatch, EvidenceItem
from app.models.events import EventCategory, NormalizedEvent


@pytest.fixture
def db_manager(tmp_path: Path) -> DatabaseManager:
    """Provide a fresh SQLite database migrated with initial schema."""
    db_file = tmp_path / "test_alert_manager.db"
    mgr = DatabaseManager(db_path=db_file)
    runner = MigrationRunner(mgr)
    runner.apply_migrations()
    return mgr


@pytest.fixture
def alert_manager(db_manager: DatabaseManager) -> AlertManager:
    """Provide an AlertManager instance configured with a 60-minute deduplication window."""
    return AlertManager(db_manager=db_manager, dedup_window_minutes=60)


def _make_dummy_event(
    event_id: int = 1,
    computer: str = "WORKSTATION01",
    user: str = "CORP\\jdoe",
    process_guid: str = "{11111111-0000-0000-0000-000000000001}",
    image: str = "C:\\Windows\\System32\\cmd.exe",
    command_line: str = "cmd.exe /c whoami",
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    ts = timestamp or datetime.now(timezone.utc)
    return NormalizedEvent(
        event_id=event_id,
        record_id=100,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        computer=computer,
        timestamp=ts,
        event_category=EventCategory.PROCESS,
        event_type="PROCESS_CREATE",
        process_guid=process_guid,
        process_id=1234,
        image=image,
        command_line=command_line,
        user=user,
        raw_payload="<Event></Event>",
        event_hash=uuid.uuid4().hex,
    )


def test_windowed_deduplication_aggregates_matches(
    alert_manager: AlertManager,
    db_manager: DatabaseManager,
) -> None:
    """Verify that multiple matches within 60 minutes update event_count and link evidence."""
    event_repo = EventRepository(db_manager)
    t_start = datetime.now(timezone.utc)
    proc_guid = "{AAAA-BBBB-CCCC-DDDD}"

    # Insert 5 events into events table to link evidence
    event_ids: list[int] = []
    events: list[NormalizedEvent] = []
    for i in range(5):
        ev = _make_dummy_event(
            process_guid=proc_guid,
            timestamp=t_start + timedelta(minutes=i * 2),
        )
        events.append(ev)

    event_repo.insert_events_batch(events)
    for ev in events:
        db_id = event_repo.get_db_id_by_hash(ev.event_hash)
        assert db_id is not None
        event_ids.append(db_id)

    # Process 5 identical matches spaced 2 minutes apart (total 8 minutes << 60 min window)
    alert_ids: list[int] = []
    duplicates: list[bool] = []

    for i in range(5):
        match = DetectionMatch(
            rule_id="RULE-BEACON-001",
            rule_title="Suspicious Beacon Activity",
            severity="High",
            event_id=events[i].event_id,
            timestamp_utc=t_start + timedelta(minutes=i * 2),
            computer="WORKSTATION01",
            user="CORP\\jdoe",
            process_guid=proc_guid,
            explanation="Repeated network egress beacon detected.",
            mitre_tactics=["Command and Control"],
            mitre_techniques=["T1071.001"],
            matched_evidence=[
                EvidenceItem(
                    field="destination_ip",
                    actual_value="198.51.100.25",
                    matched_pattern="198.51.100.25",
                )
            ],
            event_db_id=event_ids[i],
        )
        aid, is_dup = alert_manager.process_match(match, events[i], event_db_id=event_ids[i])
        alert_ids.append(aid)
        duplicates.append(is_dup)

    # First should be new, remaining 4 should be duplicates
    assert duplicates == [False, True, True, True, True]
    assert len(set(alert_ids)) == 1, "All matches should map to the exact same alert row"

    # Query alert in SQLite
    alert_row = alert_manager.alert_repo.get_alert(alert_ids[0])
    assert alert_row is not None
    assert alert_row["event_count"] == 5
    assert len(alert_row["evidence"]) == 5
    assert alert_row["status"] == "New"


def test_window_expiration_creates_separate_alert(
    alert_manager: AlertManager,
    db_manager: DatabaseManager,
) -> None:
    """Verify that an identical match outside 60-min window generates a new alert."""
    event_repo = EventRepository(db_manager)
    t_start = datetime.now(timezone.utc) - timedelta(hours=2)
    proc_guid = "{EXPIRE-WINDOW-TEST}"

    ev1 = _make_dummy_event(process_guid=proc_guid, timestamp=t_start)
    ev2 = _make_dummy_event(process_guid=proc_guid, timestamp=t_start + timedelta(minutes=65))
    event_repo.insert_events_batch([ev1, ev2])

    eid1 = event_repo.get_db_id_by_hash(ev1.event_hash)
    eid2 = event_repo.get_db_id_by_hash(ev2.event_hash)

    match1 = DetectionMatch(
        rule_id="RULE-EXPIRE-001",
        rule_title="Expired Window Test",
        severity="Medium",
        event_id=ev1.event_id,
        timestamp_utc=t_start,
        computer="WORKSTATION01",
        process_guid=proc_guid,
        explanation="Initial match before window expiry",
        matched_evidence=[],
        event_db_id=eid1,
    )
    aid1, is_dup1 = alert_manager.process_match(match1, ev1, event_db_id=eid1)
    assert is_dup1 is False

    match2 = DetectionMatch(
        rule_id="RULE-EXPIRE-001",
        rule_title="Expired Window Test",
        severity="Medium",
        event_id=ev2.event_id,
        timestamp_utc=t_start + timedelta(minutes=65),
        computer="WORKSTATION01",
        process_guid=proc_guid,
        explanation="Match after 65 minutes expiry",
        matched_evidence=[],
        event_db_id=eid2,
    )
    aid2, is_dup2 = alert_manager.process_match(match2, ev2, event_db_id=eid2)
    assert is_dup2 is False
    assert aid1 != aid2, "Expired window must generate a separate alert ID"


def test_valid_lifecycle_status_transitions(alert_manager: AlertManager) -> None:
    """Verify standard lifecycle transitions: New -> Investigating -> Escalated -> Resolved."""
    aid, _ = alert_manager.process_alert(
        rule_id="RULE-LIFECYCLE-001",
        title="Lifecycle Test",
        severity="Low",
        computer="HOST01",
    )

    # 1. New -> Investigating
    res = alert_manager.update_status(aid, "Investigating", author="Analyst1", note="Triage initiated")
    assert res["status"] == "Investigating"
    assert len(res["notes"]) == 1
    assert "Triage initiated" in res["notes"][0]["note_text"]

    # 2. Investigating -> Escalated
    res = alert_manager.update_status(aid, "Escalated", author="Tier2", note="Escalating to IR")
    assert res["status"] == "Escalated"
    assert len(res["notes"]) == 2

    # 3. Escalated -> Resolved
    res = alert_manager.update_status(aid, "Resolved", author="IRLead", note="Malware removed")
    assert res["status"] == "Resolved"

    # 4. Resolved -> Investigating (reopening)
    res = alert_manager.update_status(aid, "Investigating", author="Tier1", note="Reopened on new telemetry")
    assert res["status"] == "Investigating"

    # 5. Investigating -> False Positive
    res = alert_manager.update_status(aid, "False Positive", author="Admin", note="Authorized scanner")
    assert res["status"] == "False Positive"


def test_invalid_lifecycle_status_transitions(alert_manager: AlertManager) -> None:
    """Verify that disallowed transitions strictly raise InvalidStatusTransitionError."""
    aid, _ = alert_manager.process_alert(
        rule_id="RULE-INVALID-001",
        title="Invalid FSM Transition Test",
        severity="High",
        computer="HOST01",
    )

    # Illegal: New -> Resolved (must go through Investigating first)
    with pytest.raises(InvalidStatusTransitionError) as exc_info:
        alert_manager.update_alert_status(aid, "Resolved")
    assert "Cannot transition alert from 'New' to 'Resolved'" in str(exc_info.value)

    # Illegal: New -> False Positive
    with pytest.raises(InvalidStatusTransitionError):
        alert_manager.update_alert_status(aid, "False Positive")

    # Transition to Investigating
    alert_manager.update_alert_status(aid, "Investigating")

    # Transition to Resolved
    alert_manager.update_alert_status(aid, "Resolved")

    # Illegal: Resolved -> Escalated directly (must go to Investigating first)
    with pytest.raises(InvalidStatusTransitionError):
        alert_manager.update_alert_status(aid, "Escalated")

    # Illegal: Unknown status string
    with pytest.raises(InvalidStatusTransitionError):
        alert_manager.update_alert_status(aid, "NonExistentStatus")


def test_analyst_notes_and_disposition(alert_manager: AlertManager) -> None:
    """Verify add_analyst_note records author, text, disposition, and timestamp."""
    aid, _ = alert_manager.process_alert(
        rule_id="RULE-NOTE-001",
        title="Analyst Note Test",
        severity="Low",
        computer="HOST02",
    )

    nid = alert_manager.add_analyst_note(
        author="Alice Analyst",
        note_text="Identified lateral movement attempt via SMB",
        alert_id=aid,
        disposition="True Positive",
    )
    assert nid > 0

    alert = alert_manager.alert_repo.get_alert(aid)
    assert alert is not None
    assert len(alert["notes"]) == 1
    note = alert["notes"][0]
    assert note["author"] == "Alice Analyst"
    assert "[True Positive]" in note["note_text"]
    assert "Identified lateral movement attempt" in note["note_text"]


def test_alert_forensic_drilldown(
    alert_manager: AlertManager,
    db_manager: DatabaseManager,
) -> None:
    """Verify get_alert_forensic_drilldown retrieves alert metadata, evidence, event payloads, and process tree."""
    event_repo = EventRepository(db_manager)
    proc_repo = ProcessRepository(db_manager)

    parent_guid = "{PARENT-GUID-0001}"
    child_guid = "{CHILD-GUID-0002}"
    subchild_guid = "{SUBCHILD-GUID-0003}"
    t0 = datetime.now(timezone.utc)

    # Create processes in processes table
    with db_manager.get_connection() as conn:
        parent_node = ProcessNode(
            process_guid=parent_guid,
            process_id=1000,
            computer="WORKSTATION01",
            image="C:\\Windows\\explorer.exe",
            command_line="explorer.exe",
            current_directory="C:\\Windows",
            user="CORP\\jdoe",
            integrity_level="Medium",
            hashes={},
            parent_process_guid=None,
            parent_process_id=None,
            parent_image=None,
            parent_command_line=None,
            parent_user=None,
            start_time=t0,
            is_orphaned=False,
            is_anomalous=False,
            anomaly_reasons=[],
        )
        child_node = ProcessNode(
            process_guid=child_guid,
            process_id=2000,
            computer="WORKSTATION01",
            image="C:\\Windows\\System32\\cmd.exe",
            command_line="cmd.exe /c powershell.exe",
            current_directory="C:\\Windows",
            user="CORP\\jdoe",
            integrity_level="Medium",
            hashes={},
            parent_process_guid=parent_guid,
            parent_process_id=1000,
            parent_image="C:\\Windows\\explorer.exe",
            parent_command_line="explorer.exe",
            parent_user="CORP\\jdoe",
            start_time=t0 + timedelta(seconds=1),
            is_orphaned=False,
            is_anomalous=False,
            anomaly_reasons=[],
        )
        subchild_node = ProcessNode(
            process_guid=subchild_guid,
            process_id=3000,
            computer="WORKSTATION01",
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -enc AAAA==",
            current_directory="C:\\Windows",
            user="CORP\\jdoe",
            integrity_level="Medium",
            hashes={},
            parent_process_guid=child_guid,
            parent_process_id=2000,
            parent_image="C:\\Windows\\System32\\cmd.exe",
            parent_command_line="cmd.exe /c powershell.exe",
            parent_user="CORP\\jdoe",
            start_time=t0 + timedelta(seconds=2),
            is_orphaned=False,
            is_anomalous=False,
            anomaly_reasons=[],
        )
        proc_repo.upsert_process(conn, parent_node)
        proc_repo.upsert_process(conn, child_node)
        proc_repo.upsert_process(conn, subchild_node)

    # Insert raw event
    ev = _make_dummy_event(
        process_guid=child_guid,
        image="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe /c powershell.exe",
        timestamp=t0 + timedelta(seconds=1),
    )
    event_repo.insert_events_batch([ev])
    ev_db_id = event_repo.get_db_id_by_hash(ev.event_hash)
    assert ev_db_id is not None

    # Create alert linked to child_guid
    aid, _ = alert_manager.process_alert(
        rule_id="RULE-CMD-PWSH",
        title="Cmd Spawned PowerShell",
        severity="High",
        computer="WORKSTATION01",
        user="CORP\\jdoe",
        process_guid=child_guid,
        description="Command prompt spawned PowerShell with encoded argument",
        evidence_items=[
            {
                "event_id": ev_db_id,
                "matched_field": "command_line",
                "matched_value": "cmd.exe /c powershell.exe",
                "explanation": "Parent cmd.exe invocation",
            }
        ],
    )
    alert_manager.add_analyst_note("Forensic Analyst", "Investigating process ancestry", alert_id=aid)

    # Fetch drill-down
    drilldown = alert_manager.get_alert_forensic_drilldown(aid)
    assert drilldown["alert_id"] == aid
    assert drilldown["title"] == "Cmd Spawned PowerShell"
    assert drilldown["severity"] == "High"
    assert len(drilldown["evidence"]) == 1
    assert len(drilldown["events"]) == 1
    assert drilldown["events"][0]["command_line"] == "cmd.exe /c powershell.exe"

    # Verify process tree context
    pctx = drilldown["process_context"]
    assert pctx["process"]["image"] == "C:\\Windows\\System32\\cmd.exe"
    assert pctx["parent"]["image"] == "C:\\Windows\\explorer.exe"
    assert len(pctx["children"]) == 1
    assert "powershell.exe" in pctx["children"][0]["image"]

    # Verify notes
    assert len(drilldown["notes"]) == 1
    assert "Investigating process ancestry" in drilldown["notes"][0]["note_text"]


def test_investigation_repository_crud(db_manager: DatabaseManager) -> None:
    """Verify InvestigationRepository creation, retrieval, filtering, and status updates."""
    inv_repo = InvestigationRepository(db_manager)

    inv_id = inv_repo.create_investigation(
        title="Investigation: Suspicious Lateral Movement",
        priority="Critical",
        lead_analyst="Jane Doe",
        summary="Multiple SMB logons from untrusted subnet",
    )
    assert inv_id > 0

    inv = inv_repo.get_investigation(inv_id)
    assert inv is not None
    assert inv["title"] == "Investigation: Suspicious Lateral Movement"
    assert inv["priority"] == "Critical"
    assert inv["lead_analyst"] == "Jane Doe"
    assert inv["status"] == "Open"
    assert inv["closed_at"] is None

    # Add note to investigation
    alert_repo = AlertRepository(db_manager)
    alert_repo.add_analyst_note(
        author="Jane Doe",
        note_text="Host isolated from network",
        investigation_id=inv_id,
    )

    inv_with_notes = inv_repo.get_investigation(inv_id)
    assert inv_with_notes is not None
    assert len(inv_with_notes["notes"]) == 1
    assert inv_with_notes["notes"][0]["note_text"] == "Host isolated from network"

    # List investigations
    invs = inv_repo.list_investigations(priority="Critical")
    assert len(invs) >= 1
    assert invs[0]["id"] == inv_id

    # Update status to Closed
    success = inv_repo.update_investigation_status(inv_id, "Closed")
    assert success is True
    inv_closed = inv_repo.get_investigation(inv_id)
    assert inv_closed is not None
    assert inv_closed["status"] == "Closed"
    assert inv_closed["closed_at"] is not None
