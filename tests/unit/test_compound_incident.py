"""Unit tests for CompoundIncident, IncidentStage, and chronological narrative generator."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.models.incident import (
    CompoundIncident,
    IncidentStage,
    generate_incident_narrative,
)


@pytest.fixture
def sample_stages() -> list[IncidentStage]:
    t0 = datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=5)
    t2 = t0 + timedelta(minutes=10)

    s1 = IncidentStage(
        stage_number=1,
        stage_name="Initial Document Execution",
        tactic="Initial Access",
        technique="T1204.002",
        timestamp=t0,
        process_guid="{11111111-2222-3333-4444-555555555555}",
        image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        command_line=r'"WINWORD.EXE" "C:\Users\victim\invoice.docm"',
        event_ids=[101],
        alert_ids=[1],
        narrative="User opened weaponized document via Microsoft Word.",
    )
    s2 = IncidentStage(
        stage_number=2,
        stage_name="PowerShell Execution Cradle",
        tactic="Execution",
        technique="T1059.001",
        timestamp=t1,
        process_guid="{22222222-3333-4444-5555-666666666666}",
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line=r'powershell.exe -enc SQBFAFgA...',
        event_ids=[102, 103],
        alert_ids=[2],
        narrative="Word spawned encoded PowerShell cradle downloading payload.",
    )
    s3 = IncidentStage(
        stage_number=3,
        stage_name="Outbound C2 Egress",
        tactic="Command and Control",
        technique="T1105",
        timestamp=t2,
        process_guid="{22222222-3333-4444-5555-666666666666}",
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line=None,
        event_ids=[104],
        alert_ids=[],
        narrative="PowerShell established outbound TCP connection to remote C2 IP 198.51.100.23:443.",
    )
    return [s1, s2, s3]


def test_incident_stage_validation_and_immutability(sample_stages: list[IncidentStage]) -> None:
    """Verify IncidentStage validates attributes and enforces immutability."""
    s1 = sample_stages[0]
    assert s1.stage_number == 1
    assert s1.stage_name == "Initial Document Execution"
    assert s1.tactic == "Initial Access"
    assert s1.technique == "T1204.002"
    assert s1.timestamp.tzinfo == timezone.utc
    assert s1.image == r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
    assert s1.event_ids == [101]
    assert s1.alert_ids == [1]

    # Verify frozen model immutability
    with pytest.raises(ValidationError):
        s1.stage_number = 2  # type: ignore[misc]

    with pytest.raises(ValidationError):
        s1.narrative = "Mutated"  # type: ignore[misc]


def test_incident_stage_naive_timestamp_normalized() -> None:
    """Verify naive timestamp is converted to UTC."""
    naive_dt = datetime(2026, 11, 4, 14, 30, 0)
    stage = IncidentStage(
        stage_number=1,
        stage_name="Test Stage",
        tactic="Execution",
        technique="T1059",
        timestamp=naive_dt,
        narrative="Test narrative",
    )
    assert stage.timestamp.tzinfo == timezone.utc


def test_compound_incident_validation_and_defaults(sample_stages: list[IncidentStage]) -> None:
    """Verify CompoundIncident default attributes, duration computation, and aggregations."""
    t0 = sample_stages[0].timestamp
    t2 = sample_stages[2].timestamp

    incident = CompoundIncident(
        incident_id="INC-CHAIN-PHISH-001-0001",
        chain_id="CHAIN-PHISH-001",
        chain_name="Malicious Document / Phishing Execution",
        computer="VICTIM-PC.corp.local",
        user=r"CORP\victim",
        root_process_guid="{11111111-2222-3333-4444-555555555555}",
        first_seen=t0,
        last_seen=t2,
        stages=sample_stages,
    )

    assert incident.severity == "Critical"
    assert incident.status == "New"
    assert incident.duration_seconds == 600.0  # 10 minutes = 600 seconds
    assert incident.participating_event_ids == [101, 102, 103, 104]
    assert incident.participating_alert_ids == [1, 2]
    assert "Initial Access" in incident.mitre_tactics
    assert "Execution" in incident.mitre_tactics
    assert "Command and Control" in incident.mitre_tactics
    assert "T1204.002" in incident.mitre_techniques
    assert "T1059.001" in incident.mitre_techniques
    assert "T1105" in incident.mitre_techniques

    # Narrative auto-generation sync
    assert incident.summary_narrative != ""
    assert incident.narrative_story == incident.summary_narrative
    assert "Correlated Multi-Stage Intrusion" in incident.summary_narrative
    assert "VICTIM-PC.corp.local" in incident.summary_narrative


def test_compound_incident_immutability(sample_stages: list[IncidentStage]) -> None:
    """Verify CompoundIncident is an immutable Pydantic model."""
    t0 = sample_stages[0].timestamp
    t2 = sample_stages[2].timestamp

    incident = CompoundIncident(
        incident_id="INC-001",
        chain_id="CHAIN-PHISH-001",
        chain_name="Phishing",
        computer="PC-1",
        first_seen=t0,
        last_seen=t2,
        stages=sample_stages,
    )
    with pytest.raises(ValidationError):
        incident.severity = "Medium"  # type: ignore[misc]

    with pytest.raises(ValidationError):
        incident.status = "Resolved"  # type: ignore[misc]


def test_compound_incident_requires_at_least_two_stages(sample_stages: list[IncidentStage]) -> None:
    """Verify validation fails if stages list is empty or has only 1 stage."""
    t0 = datetime.now(timezone.utc)
    with pytest.raises(ValidationError) as exc_info:
        CompoundIncident(
            incident_id="INC-001",
            chain_id="CHAIN-PHISH-001",
            chain_name="Phishing",
            computer="PC-1",
            first_seen=t0,
            last_seen=t0,
            stages=[],
        )
    assert "at least 2 correlated attack stages" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info2:
        CompoundIncident(
            incident_id="INC-001",
            chain_id="CHAIN-PHISH-001",
            chain_name="Phishing",
            computer="PC-1",
            first_seen=t0,
            last_seen=t0,
            stages=[sample_stages[0]],
        )
    assert "at least 2 correlated attack stages" in str(exc_info2.value)


def test_generate_incident_narrative_formatting(sample_stages: list[IncidentStage]) -> None:
    """Verify generate_incident_narrative outputs structured, readable timeline."""
    narrative = generate_incident_narrative(
        chain_name="Malicious Document / Phishing Execution",
        computer="VICTIM-PC",
        user=r"CORP\victim",
        stages=sample_stages,
    )

    assert "Correlated Multi-Stage Intrusion: Malicious Document / Phishing Execution" in narrative
    assert "Host: VICTIM-PC" in narrative
    assert r"User Context: CORP\victim" in narrative
    assert "Stage 1: Initial Document Execution" in narrative
    assert "Stage 2: PowerShell Execution Cradle" in narrative
    assert "Stage 3: Outbound C2 Egress" in narrative
    assert "WINWORD.EXE" in narrative
    assert "powershell.exe" in narrative
    assert "Contributing Event IDs: [101, 102, 103, 104]" in narrative
    assert "Contributing Alert IDs: [1, 2]" in narrative

    # Also test alternative argument order (stages, computer, user)
    alt_narrative = generate_incident_narrative(
        sample_stages,
        computer="SERVER-01",
        user="SYSTEM",
    )
    assert "Host: SERVER-01" in alt_narrative
    assert "User Context: SYSTEM" in alt_narrative
    assert "Stage 1: Initial Document Execution" in alt_narrative


def test_to_investigation_dict(sample_stages: list[IncidentStage]) -> None:
    """Verify to_investigation_dict produces valid columns for the investigations table."""
    t0 = sample_stages[0].timestamp
    t2 = sample_stages[2].timestamp

    incident = CompoundIncident(
        incident_id="INC-001",
        chain_id="CHAIN-PHISH-001",
        chain_name="Phishing Attack",
        computer="DESKTOP-TEST",
        user="Alice",
        first_seen=t0,
        last_seen=t2,
        stages=sample_stages,
    )
    inv_dict = incident.to_investigation_dict()

    assert inv_dict["title"] == "Compound Incident: Phishing Attack on DESKTOP-TEST"
    assert inv_dict["status"] == "Open"
    assert inv_dict["priority"] == "Critical"
    assert inv_dict["lead_analyst"] is None
    assert "Correlated Multi-Stage Intrusion" in inv_dict["summary"]
    assert inv_dict["created_at"] == t0.isoformat()
    assert inv_dict["updated_at"] == t2.isoformat()
    assert inv_dict["closed_at"] is None


def test_to_alert_dict(sample_stages: list[IncidentStage]) -> None:
    """Verify to_alert_dict produces valid parameters for AlertRepository.create_alert()."""
    t0 = sample_stages[0].timestamp
    t2 = sample_stages[2].timestamp

    incident = CompoundIncident(
        incident_id="INC-001",
        chain_id="CHAIN-PHISH-001",
        chain_name="Phishing Attack",
        computer="DESKTOP-TEST",
        user="Alice",
        root_process_guid="{11111111-2222-3333-4444-555555555555}",
        first_seen=t0,
        last_seen=t2,
        stages=sample_stages,
    )
    alert_dict = incident.to_alert_dict()

    assert alert_dict["rule_id"] == "CHAIN-PHISH-001"
    assert alert_dict["title"] == "Compound Incident: Phishing Attack"
    assert alert_dict["severity"] == "Critical"
    assert alert_dict["status"] == "New"
    assert alert_dict["computer"] == "DESKTOP-TEST"
    assert alert_dict["user"] == "Alice"
    assert alert_dict["process_guid"] == "{11111111-2222-3333-4444-555555555555}"
    assert alert_dict["first_seen"] == t0
    assert alert_dict["last_seen"] == t2
    assert alert_dict["event_count"] == 4
    assert "Initial Access" in alert_dict["mitre_tactics"]
    assert "T1204.002" in alert_dict["mitre_techniques"]


def test_to_evidence_dicts(sample_stages: list[IncidentStage]) -> None:
    """Verify to_evidence_dicts produces valid records for AlertRepository.link_alert_evidence()."""
    t0 = sample_stages[0].timestamp
    t2 = sample_stages[2].timestamp

    incident = CompoundIncident(
        incident_id="INC-001",
        chain_id="CHAIN-PHISH-001",
        chain_name="Phishing Attack",
        computer="DESKTOP-TEST",
        first_seen=t0,
        last_seen=t2,
        stages=sample_stages,
    )
    evidence_list = incident.to_evidence_dicts(alert_id=42)

    assert len(evidence_list) == 4
    event_ids = [e["event_id"] for e in evidence_list]
    assert event_ids == [101, 102, 103, 104]

    for ev in evidence_list:
        assert ev["alert_id"] == 42
        assert ev["matched_field"] == "event_id"
        assert "Participating event in correlated attack chain" in ev["explanation"]
