"""Unit tests for the Core Sysmon Detection Rule Library.

Validates that all 16 Sysmon detection rules in rules/sysmon/ load cleanly,
satisfy Pydantic schema validation, contain unique WS-SYS-0* IDs, valid MITRE ATT&CK
mappings, actionable investigation steps, and parse into valid AST conditions.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.detection.ast_parser import ASTNode, ConditionParser
from app.detection.loader import RuleLoader
from app.models.rule import DetectionRule, RuleSeverity, RuleStatus


RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules" / "sysmon"

EXPECTED_RULE_IDS = [f"WS-SYS-{i:03d}" for i in range(1, 17)]


def test_sysmon_rules_directory_exists() -> None:
    """Verify rules/sysmon directory exists and contains categorized subdirectories."""
    assert RULES_DIR.is_dir(), f"Expected rules directory at {RULES_DIR}"
    categories = [p.name for p in RULES_DIR.iterdir() if p.is_dir()]
    expected_categories = {
        "process_creation",
        "remote_thread",
        "process_access",
        "driver_load",
        "image_load",
        "registry",
        "dns_query",
    }
    assert expected_categories.issubset(set(categories))


def test_all_16_rules_load_successfully() -> None:
    """Verify RuleLoader loads exactly 16 rules without schema or validation errors."""
    loader = RuleLoader()
    rules = loader.load_rules_from_directory(RULES_DIR, recursive=True, strict=True)
    assert len(rules) == 16, f"Expected exactly 16 rules, found {len(rules)}"


def test_rule_ids_are_unique_and_sequential() -> None:
    """Verify every rule has a unique ID from WS-SYS-001 through WS-SYS-016."""
    loader = RuleLoader()
    rules = loader.load_rules_from_directory(RULES_DIR, recursive=True, strict=True)
    loaded_ids = sorted(r.id for r in rules)
    assert loaded_ids == EXPECTED_RULE_IDS


def test_rule_metadata_integrity() -> None:
    """Verify all rules have valid status, author, description, and severity."""
    loader = RuleLoader()
    rules = loader.load_rules_from_directory(RULES_DIR, recursive=True, strict=True)

    for rule in rules:
        assert rule.status == RuleStatus.ACTIVE
        assert rule.author and len(rule.author.strip()) > 0
        assert rule.title and len(rule.title.strip()) >= 5
        assert rule.description and len(rule.description.strip()) >= 10
        assert isinstance(rule.severity, RuleSeverity)


def test_rule_mitre_attack_mappings() -> None:
    """Verify every rule specifies non-empty MITRE ATT&CK technique tags."""
    loader = RuleLoader()
    rules = loader.load_rules_from_directory(RULES_DIR, recursive=True, strict=True)

    mitre_pattern = re.compile(r"^T\d{4}(\.\d{3})?$")

    for rule in rules:
        assert len(rule.mitre_attack) > 0, f"Rule {rule.id} has no MITRE ATT&CK tags"
        for tech in rule.mitre_attack:
            assert mitre_pattern.match(tech), f"Rule {rule.id} has invalid MITRE ID: {tech}"


def test_rule_investigation_steps_and_false_positives() -> None:
    """Verify every rule includes non-empty investigation steps and false positives."""
    loader = RuleLoader()
    rules = loader.load_rules_from_directory(RULES_DIR, recursive=True, strict=True)

    for rule in rules:
        assert len(rule.investigation_steps) >= 2, (
            f"Rule {rule.id} must have at least 2 investigation steps, got {len(rule.investigation_steps)}"
        )
        assert len(rule.falsepositives) >= 1, (
            f"Rule {rule.id} must have at least 1 documented false positive scenario"
        )


def test_rule_condition_ast_compilation() -> None:
    """Verify every rule condition compiles into a valid AST with ConditionParser."""
    loader = RuleLoader()
    parser = ConditionParser()
    rules = loader.load_rules_from_directory(RULES_DIR, recursive=True, strict=True)

    for rule in rules:
        ast_root = parser.parse(rule.detection.condition)
        assert isinstance(ast_root, ASTNode), (
            f"Rule {rule.id} condition failed to compile into ASTNode"
        )
