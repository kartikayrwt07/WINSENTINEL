"""Unit tests for RuleUIService."""

import pytest
from pathlib import Path

from app.ui.services.rule_ui_service import RuleUIService


def test_rule_ui_service_list_rules():
    service = RuleUIService(rules_dir="rules/sysmon")
    rules = service.list_rules()

    assert len(rules) >= 16
    rule_ids = [r["id"] for r in rules]
    assert "WS-SYS-001" in rule_ids
    assert "WS-SYS-002" in rule_ids

    # Test filtering by category
    proc_rules = service.list_rules(category="process_creation")
    assert len(proc_rules) > 0
    for r in proc_rules:
        assert r["category"].lower() == "process_creation"

    # Test filtering by severity
    high_rules = service.list_rules(severity="high")
    assert len(high_rules) > 0
    for r in high_rules:
        assert r["severity"].lower() == "high"

    # Test search
    certutil_rules = service.list_rules(search="certutil")
    assert len(certutil_rules) >= 1
    assert any("certutil" in r["id"].lower() or "certutil" in r["title"].lower() for r in certutil_rules)


def test_rule_ui_service_detail_and_yaml():
    service = RuleUIService(rules_dir="rules/sysmon")

    detail = service.get_rule_detail("WS-SYS-001")
    assert detail is not None
    assert detail["id"] == "WS-SYS-001"
    assert "certutil" in detail["title"].lower()
    assert "condition" in detail
    assert "selection" in detail["condition"].lower()

    raw_yaml = service.get_rule_yaml("WS-SYS-001")
    assert "WS-SYS-001" in raw_yaml
    assert "title:" in raw_yaml

    # Nonexistent rule
    assert service.get_rule_detail("NONEXISTENT-RULE") is None
    assert service.get_rule_yaml("NONEXISTENT-RULE") == ""
