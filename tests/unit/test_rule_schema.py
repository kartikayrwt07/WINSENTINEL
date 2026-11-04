"""Unit tests for DetectionRule, LogSource, DetectionBlock, RuleSeverity, and RuleStatus Pydantic v2 schemas."""

import pytest
from pydantic import ValidationError

from app.models.rule import (
    DetectionBlock,
    DetectionRule,
    LogSource,
    RuleSeverity,
    RuleStatus,
)


def test_rule_severity_enum_values():
    """Verify RuleSeverity enum supports informational, low, medium, high, critical with lowercase values."""
    assert RuleSeverity.INFORMATIONAL.value == "informational"
    assert RuleSeverity.LOW.value == "low"
    assert RuleSeverity.MEDIUM.value == "medium"
    assert RuleSeverity.HIGH.value == "high"
    assert RuleSeverity.CRITICAL.value == "critical"


def test_rule_status_enum_values():
    """Verify RuleStatus enum supports active, testing, deprecated."""
    assert RuleStatus.ACTIVE.value == "active"
    assert RuleStatus.TESTING.value == "testing"
    assert RuleStatus.DEPRECATED.value == "deprecated"


def test_logsource_defaults_and_event_id_coercion():
    """Verify LogSource model defaults product to 'windows' and coerces event_ids."""
    ls_default = LogSource()
    assert ls_default.product == "windows"
    assert ls_default.category is None
    assert ls_default.service is None
    assert ls_default.event_id is None

    # Single integer
    ls_single = LogSource(category="process_creation", event_id=1)
    assert ls_single.event_id == 1

    # String integer coercion
    ls_str = LogSource(event_id="10")
    assert ls_str.event_id == 10

    # List of integers
    ls_list = LogSource(event_id=[12, 13, 14])
    assert ls_list.event_id == [12, 13, 14]

    # Comma-delimited string of ints
    ls_csv = LogSource(event_id="12, 13, 14")
    assert ls_list.event_id == [12, 13, 14]


def test_detection_block_extra_selections():
    """Verify DetectionBlock parses condition and captures arbitrary selection/filter dictionaries."""
    db = DetectionBlock(
        condition="selection and not filter_admin",
        selection={"Image|endswith": "\\certutil.exe"},
        filter_admin={"User": "NT AUTHORITY\\SYSTEM"},
    )
    assert db.condition == "selection and not filter_admin"
    assert "selection" in db.selections
    assert db.selections["selection"] == {"Image|endswith": "\\certutil.exe"}
    assert "filter_admin" in db.selections
    assert db.selections["filter_admin"] == {"User": "NT AUTHORITY\\SYSTEM"}

    # Key access and get() support
    assert db["selection"] == {"Image|endswith": "\\certutil.exe"}
    assert db.get("filter_admin") == {"User": "NT AUTHORITY\\SYSTEM"}
    assert db.get("nonexistent", None) is None


def test_detection_rule_valid_instantiation():
    """Verify DetectionRule validates required fields and sets sensible defaults."""
    rule = DetectionRule(
        id="WS-SYS-001",
        title="Suspicious Certutil Ingress Tool Download",
        description="Detects execution of certutil.exe with flags indicative of remote file downloads.",
        detection=DetectionBlock(
            condition="selection",
            selection={"Image|endswith": "\\certutil.exe"},
        ),
    )
    assert rule.id == "WS-SYS-001"
    assert rule.title == "Suspicious Certutil Ingress Tool Download"
    assert rule.severity == RuleSeverity.MEDIUM
    assert rule.status == RuleStatus.ACTIVE
    assert rule.author == "WinSentinel Team"
    assert rule.logsource.product == "windows"
    assert rule.mitre_attack == []
    assert rule.references == []
    assert rule.falsepositives == []
    assert rule.investigation_steps == []


def test_detection_rule_rejects_empty_id():
    """Verify DetectionRule rejects empty or whitespace-only rule IDs."""
    with pytest.raises(ValidationError) as exc_info:
        DetectionRule(
            id="   ",
            title="Invalid Rule ID Test",
            description="Testing ID validation",
            detection=DetectionBlock(condition="selection"),
        )
    assert "id" in str(exc_info.value)


def test_detection_rule_severity_and_status_case_insensitivity():
    """Verify DetectionRule accepts case-insensitive string values for severity and status."""
    rule = DetectionRule(
        id="WS-SYS-002",
        title="UAC Bypass via Fodhelper",
        description="Detects elevated shell spawn from fodhelper.exe.",
        severity="HIGH",
        status="TESTING",
        detection=DetectionBlock(condition="selection"),
    )
    assert rule.severity == RuleSeverity.HIGH
    assert rule.status == RuleStatus.TESTING


def test_detection_rule_enrichment_fields():
    """Verify DetectionRule parses enrichment fields: mitre_attack, references, etc."""
    rule = DetectionRule(
        id="WS-SYS-003",
        title="Remote Thread Injection into LSASS",
        description="Detects injection targeting LSASS process memory.",
        severity="critical",
        mitre_attack=["T1055.001", "T1003.001"],
        references=["https://attack.mitre.org/techniques/T1055/"],
        falsepositives=["Antivirus products scanning LSASS"],
        investigation_steps=["Check parent process", "Inspect call stack"],
        detection=DetectionBlock(condition="selection"),
    )
    assert rule.mitre_attack == ["T1055.001", "T1003.001"]
    assert len(rule.references) == 1
    assert len(rule.falsepositives) == 1
    assert len(rule.investigation_steps) == 2


def test_detection_rule_missing_condition_rejection():
    """Verify DetectionRule rejects detection block missing the condition field."""
    with pytest.raises(ValidationError):
        DetectionRule.model_validate({
            "id": "WS-SYS-004",
            "title": "Missing Condition Rule",
            "description": "Rule without condition",
            "detection": {
                "selection": {"Image": "calc.exe"}
            }
        })


def test_detection_rule_from_yaml_parsing():
    """Verify DetectionRule.from_yaml parses YAML string and preserves raw_yaml."""
    yaml_text = """
id: WS-SYS-005
title: Suspicious PowerShell Encoded Command
description: Detects powershell.exe with -enc or -encodedcommand parameter.
severity: high
status: active
logsource:
  category: process_creation
  product: windows
  event_id: 1
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-enc '
      - '-encodedcommand '
  condition: selection
tags:
  - attack.t1059.001
  - attack.execution
references:
  - https://attack.mitre.org/techniques/T1059/001/
falsepositives:
  - Legitimate administrative scripts
investigation_steps:
  - Decode Base64 payload in CommandLine
  - Review script execution context
"""
    rule = DetectionRule.from_yaml(yaml_text)
    assert rule.id == "WS-SYS-005"
    assert rule.title == "Suspicious PowerShell Encoded Command"
    assert rule.severity == RuleSeverity.HIGH
    assert rule.logsource.event_id == 1
    assert rule.detection.condition == "selection"
    assert "selection" in rule.detection.selections
    assert "T1059.001" in rule.mitre_attack
    assert rule.raw_yaml == yaml_text
    assert len(rule.investigation_steps) == 2
