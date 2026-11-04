"""Unit tests for RuleLoader, duplicate ID rejection, and SQLite database sync."""

import sqlite3
from pathlib import Path

import pytest

from app.config import DatabaseSettings
from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner
from app.detection.loader import (
    DuplicateRuleIdError,
    RuleLoader,
    RuleValidationError,
)
from app.models.rule import DetectionRule, RuleSeverity, RuleStatus


@pytest.fixture
def sample_valid_rule_yaml() -> str:
    return """
id: WS-TEST-001
title: Test Rule One
description: First test rule for loader verification
severity: high
status: active
author: Test Author
logsource:
  category: process_creation
  product: windows
  event_id: 1
detection:
  selection:
    Image|endswith: '\\cmd.exe'
  condition: selection
mitre_attack:
  - T1059.003
"""


@pytest.fixture
def sample_rule_yaml_2() -> str:
    return """
id: WS-TEST-002
title: Test Rule Two
description: Second test rule for loader verification
severity: medium
status: testing
author: Test Author
logsource:
  category: image_load
  product: windows
  event_id: 7
detection:
  selection:
    ImageLoaded|contains: '\\Temp\\'
  condition: selection
mitre_attack:
  - T1574.002
"""


@pytest.fixture
def temp_db(tmp_path: Path) -> DatabaseManager:
    """Fixture providing an initialized SQLite database with migrations applied."""
    db_file = tmp_path / "test_rules.db"
    settings = DatabaseSettings(db_path=str(db_file), wal_mode=False)
    db_manager = DatabaseManager(db_path=db_file, settings=settings)
    runner = MigrationRunner(db_manager)
    runner.apply_migrations()
    return db_manager


def test_load_rule_from_yaml(sample_valid_rule_yaml):
    """Verify load_rule_from_yaml parses valid YAML content and retains raw_yaml."""
    loader = RuleLoader()
    rule = loader.load_rule_from_yaml(sample_valid_rule_yaml)
    assert isinstance(rule, DetectionRule)
    assert rule.id == "WS-TEST-001"
    assert rule.title == "Test Rule One"
    assert rule.severity == RuleSeverity.HIGH
    assert rule.status == RuleStatus.ACTIVE
    assert rule.raw_yaml == sample_valid_rule_yaml
    assert rule.logsource.event_id == 1


def test_load_rule_from_yaml_invalid_syntax():
    """Verify load_rule_from_yaml raises RuleValidationError on malformed YAML or condition."""
    loader = RuleLoader()
    malformed_yaml = "id: WS-TEST-001\ntitle: [unclosed list"
    with pytest.raises(RuleValidationError):
        loader.load_rule_from_yaml(malformed_yaml)

    # Invalid boolean condition
    bad_condition_yaml = """
id: WS-TEST-003
title: Bad Condition Rule
description: Testing condition syntax check
detection:
  selection:
    Image: cmd.exe
  condition: selection AND AND invalid
"""
    with pytest.raises(RuleValidationError):
        loader.load_rule_from_yaml(bad_condition_yaml)


def test_load_rules_from_directory(tmp_path, sample_valid_rule_yaml, sample_rule_yaml_2):
    """Verify load_rules_from_directory recursively finds YAML files and ignores non-YAML."""
    sub_dir = tmp_path / "subdir"
    sub_dir.mkdir()

    # Valid rules in root and sub_dir
    (tmp_path / "rule1.yml").write_text(sample_valid_rule_yaml, encoding="utf-8")
    (sub_dir / "rule2.yaml").write_text(sample_rule_yaml_2, encoding="utf-8")

    # Non-YAML files that should be ignored
    (tmp_path / "notes.txt").write_text("Just notes", encoding="utf-8")
    (sub_dir / "README.md").write_text("# Readme", encoding="utf-8")

    loader = RuleLoader()
    rules = loader.load_rules_from_directory(tmp_path)
    assert len(rules) == 2
    rule_ids = {r.id for r in rules}
    assert rule_ids == {"WS-TEST-001", "WS-TEST-002"}


def test_duplicate_rule_id_rejection(tmp_path, sample_valid_rule_yaml):
    """Verify load_rules_from_directory raises DuplicateRuleIdError when two files share an ID."""
    (tmp_path / "rule_a.yml").write_text(sample_valid_rule_yaml, encoding="utf-8")
    (tmp_path / "rule_b.yml").write_text(sample_valid_rule_yaml, encoding="utf-8")

    loader = RuleLoader()
    with pytest.raises(DuplicateRuleIdError) as exc_info:
        loader.load_rules_from_directory(tmp_path)

    err_msg = str(exc_info.value)
    assert "WS-TEST-001" in err_msg
    assert "Duplicate rule ID" in err_msg


def test_load_rules_strict_vs_lenient(tmp_path, sample_valid_rule_yaml):
    """Verify strict mode raises error on invalid file, while lenient skips and logs."""
    (tmp_path / "valid.yml").write_text(sample_valid_rule_yaml, encoding="utf-8")
    (tmp_path / "broken.yml").write_text("invalid: yaml: [", encoding="utf-8")

    loader = RuleLoader()

    # Lenient mode (default): skips broken file
    rules = loader.load_rules_from_directory(tmp_path, strict=False)
    assert len(rules) == 1
    assert rules[0].id == "WS-TEST-001"

    # Strict mode: raises RuleValidationError
    with pytest.raises(RuleValidationError):
        loader.load_rules_from_directory(tmp_path, strict=True)


def test_sync_rules_to_database(temp_db, sample_valid_rule_yaml, sample_rule_yaml_2):
    """Verify sync_rules_to_database populates SQLite detection_rules table idempotently."""
    loader = RuleLoader()
    rule1 = loader.load_rule_from_yaml(sample_valid_rule_yaml)
    rule2 = loader.load_rule_from_yaml(sample_rule_yaml_2)

    # Initial sync
    count = loader.sync_rules_to_database([rule1, rule2], temp_db)
    assert count == 2

    with temp_db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, title, severity, status, author, rule_yaml FROM detection_rules ORDER BY id;")
        rows = cursor.fetchall()

    assert len(rows) == 2
    assert rows[0][0] == "WS-TEST-001"
    assert rows[0][1] == "Test Rule One"
    assert rows[0][2] == "high"
    assert rows[0][3] == "active"
    assert rows[0][4] == "Test Author"
    assert rows[0][5] == sample_valid_rule_yaml

    assert rows[1][0] == "WS-TEST-002"
    assert rows[1][1] == "Test Rule Two"

    # Update rule1 and re-sync (upsert check)
    updated_rule1_yaml = sample_valid_rule_yaml.replace("Test Rule One", "Updated Rule One")
    rule1_updated = loader.load_rule_from_yaml(updated_rule1_yaml)

    count_resync = loader.sync_rules_to_database([rule1_updated], temp_db)
    assert count_resync == 1

    with temp_db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT title FROM detection_rules WHERE id = 'WS-TEST-001';")
        row = cursor.fetchone()
        assert row[0] == "Updated Rule One"
        # Total count should still be 2
        cursor.execute("SELECT count(*) FROM detection_rules;")
        assert cursor.fetchone()[0] == 2


def test_sync_rules_to_db_alias(temp_db, sample_valid_rule_yaml):
    """Verify sync_rules_to_db works with (db_manager, rules) signature."""
    loader = RuleLoader()
    rule = loader.load_rule_from_yaml(sample_valid_rule_yaml)
    count = loader.sync_rules_to_db(temp_db, [rule])
    assert count == 1


def test_load_rule_from_file_not_found():
    """Verify load_rule_from_file raises FileNotFoundError for non-existent path."""
    loader = RuleLoader()
    with pytest.raises(FileNotFoundError):
        loader.load_rule_from_file(Path("non_existent_file.yml"))
