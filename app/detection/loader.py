"""YAML detection rule directory loader, validator, and SQLite synchronizer."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from app.database.connection import DatabaseManager
from app.detection.ast_parser import ConditionParser, RuleSyntaxError
from app.models.rule import DetectionRule

logger = logging.getLogger(__name__)


class DuplicateRuleIdError(ValueError):
    """Raised when two detection rules share the same ID during loading."""


class RuleValidationError(ValueError):
    """Raised when a rule fails schema validation, YAML parsing, or condition syntax."""


class RuleLoader:
    """Loads, validates, and synchronizes YAML detection rules."""

    def __init__(self, parser: ConditionParser | None = None) -> None:
        self._parser = parser or ConditionParser()

    def load_rule_from_yaml(
        self,
        yaml_content: str,
        source_path: Path | str | None = None,
    ) -> DetectionRule:
        """Parse, validate, and verify a DetectionRule from YAML text.

        Raises:
            RuleValidationError: If YAML parsing fails, required fields are missing,
                                 or the boolean condition expression has syntax errors.
        """
        try:
            parsed = yaml.safe_load(yaml_content)
        except yaml.YAMLError as exc:
            src_str = f" in {source_path}" if source_path else ""
            raise RuleValidationError(f"Invalid YAML syntax{src_str}: {exc}") from exc

        if not isinstance(parsed, dict):
            src_str = f" in {source_path}" if source_path else ""
            raise RuleValidationError(f"Rule YAML content must evaluate to a dictionary{src_str}")

        parsed["raw_yaml"] = yaml_content

        try:
            rule = DetectionRule.model_validate(parsed)
        except ValidationError as exc:
            src_str = f" in {source_path}" if source_path else ""
            raise RuleValidationError(f"Rule schema validation failed{src_str}: {exc}") from exc

        # Pre-validate the boolean condition expression
        try:
            self._parser.parse(rule.detection.condition)
        except RuleSyntaxError as exc:
            src_str = f" in {source_path}" if source_path else ""
            raise RuleValidationError(
                f"Invalid boolean condition in rule '{rule.id}'{src_str}: {exc}"
            ) from exc

        return rule

    def load_rule_from_file(self, file_path: Path | str) -> DetectionRule:
        """Load and validate a DetectionRule from a file path."""
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Rule file not found: {path}")

        content = path.read_text(encoding="utf-8")
        return self.load_rule_from_yaml(content, source_path=path)

    def load_rules_from_directory(
        self,
        directory: Path | str,
        recursive: bool = True,
        strict: bool = False,
    ) -> list[DetectionRule]:
        """Scan directory for YAML rule files, validate, and check for unique IDs.

        Args:
            directory: Root directory containing rule YAML files.
            recursive: Whether to traverse subdirectories recursively.
            strict: If True, any malformed rule file aborts loading; if False,
                    logs warning and continues.

        Returns:
            List of validated DetectionRule instances.

        Raises:
            FileNotFoundError: If the directory does not exist.
            DuplicateRuleIdError: If two or more rules share the same ID.
            RuleValidationError: If strict=True and a rule file is malformed.
        """
        root_path = Path(directory)
        if not root_path.exists() or not root_path.is_dir():
            raise FileNotFoundError(f"Rules directory not found: {root_path}")

        rule_files: list[Path] = []
        patterns = ("*.yml", "*.yaml")
        for pat in patterns:
            if recursive:
                rule_files.extend(root_path.rglob(pat))
            else:
                rule_files.extend(root_path.glob(pat))

        # Sort for deterministic processing order
        rule_files.sort(key=lambda p: str(p))

        seen_ids: dict[str, Path] = {}
        rules: list[DetectionRule] = []

        for file_path in rule_files:
            if not file_path.is_file():
                continue

            try:
                rule = self.load_rule_from_file(file_path)
            except Exception as exc:
                if strict:
                    raise RuleValidationError(
                        f"Failed to load rule from {file_path}: {exc}"
                    ) from exc
                logger.warning("Skipping invalid rule file %s: %s", file_path, exc)
                continue

            if rule.id in seen_ids:
                raise DuplicateRuleIdError(
                    f"Duplicate rule ID '{rule.id}' found in {file_path} and {seen_ids[rule.id]}"
                )

            seen_ids[rule.id] = file_path
            rules.append(rule)

        return rules

    def sync_rules_to_database(
        self,
        rules: list[DetectionRule],
        db_manager: DatabaseManager,
    ) -> int:
        """Upsert detection rules into the SQLite detection_rules table.

        Args:
            rules: List of DetectionRule models to synchronize.
            db_manager: DatabaseManager managing the target SQLite database.

        Returns:
            Total count of rules synchronized.
        """
        if not rules:
            return 0

        now_utc = datetime.now(timezone.utc).isoformat()
        sql = """
        INSERT INTO detection_rules (
            id, title, description, severity, status, author, rule_yaml, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            title=excluded.title,
            description=excluded.description,
            severity=excluded.severity,
            status=excluded.status,
            author=excluded.author,
            rule_yaml=excluded.rule_yaml,
            updated_at=excluded.updated_at;
        """

        records = [
            (
                rule.id,
                rule.title,
                rule.description,
                rule.severity.value,
                rule.status.value,
                rule.author,
                rule.raw_yaml,
                now_utc,
                now_utc,
            )
            for rule in rules
        ]

        with db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(sql, records)

        return len(records)

    def sync_rules_to_db(
        self,
        db_manager: DatabaseManager,
        rules: list[DetectionRule],
    ) -> int:
        """Convenience alias accepting (db_manager, rules) signature."""
        return self.sync_rules_to_database(rules, db_manager)
