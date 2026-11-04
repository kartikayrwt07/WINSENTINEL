"""Detection Rule catalog and YAML inspection service for WinSentinel UI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.database.connection import DatabaseManager
from app.detection.loader import RuleLoader
from app.models.rule import DetectionRule
from app.ui.state import get_db_manager

EVENT_ID_CATEGORY_MAP: dict[int, str] = {
    1: "process_creation",
    3: "network_connection",
    6: "driver_load",
    7: "image_load",
    8: "remote_thread",
    10: "process_access",
    11: "file_create",
    12: "registry",
    13: "registry",
    14: "registry",
    22: "dns_query",
}


class RuleUIService:
    """Introspects active Sigma detection rules, conditions AST structure, and YAML definitions."""

    def __init__(
        self,
        rules_dir: Path | str | None = None,
        db_manager: DatabaseManager | None = None,
    ) -> None:
        self.rules_dir = Path(rules_dir) if rules_dir else Path("rules")
        self.db = db_manager or get_db_manager()
        self.loader = RuleLoader()
        self._rules_cache: dict[str, DetectionRule] = {}
        self._load_rules()

    def _resolve_category(self, rule: DetectionRule) -> str:
        if rule.logsource.category:
            return rule.logsource.category
        if isinstance(rule.logsource.event_id, int):
            return EVENT_ID_CATEGORY_MAP.get(rule.logsource.event_id, "windows")
        if isinstance(rule.logsource.event_id, list) and rule.logsource.event_id:
            return EVENT_ID_CATEGORY_MAP.get(rule.logsource.event_id[0], "windows")
        return "windows"

    def _load_rules(self) -> None:
        """Load detection rules from disk or database."""
        if self.rules_dir.exists() and self.rules_dir.is_dir():
            rules = self.loader.load_rules_from_directory(self.rules_dir, recursive=True, strict=False)
            for r in rules:
                self._rules_cache[r.id] = r

        # If cache is empty or db has rules, supplement/fallback to database
        if not self._rules_cache and self.db is not None:
            try:
                with self.db.get_connection() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT id, raw_yaml FROM detection_rules WHERE is_active = 1;")
                    rows = cur.fetchall()
                    for r_id, raw_yaml in rows:
                        if raw_yaml:
                            try:
                                parsed_rule = self.loader.load_rule_from_yaml(raw_yaml)
                                self._rules_cache[parsed_rule.id] = parsed_rule
                            except Exception:
                                pass
            except Exception:
                pass

    def list_rules(
        self,
        category: str | None = None,
        severity: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, Any]]:
        """List summary info for all available rules matching filter criteria.

        Args:
            category: Optional category filter (e.g., process_creation, dns_query).
            severity: Optional severity filter (low, medium, high, critical).
            search: Optional text search in title, id, or description.

        Returns:
            List of rule summary dictionaries.
        """
        results: list[dict[str, Any]] = []

        for rule in self._rules_cache.values():
            cat = self._resolve_category(rule)
            sev = rule.severity.value if hasattr(rule.severity, "value") else str(rule.severity)

            if category and category.lower() != "all" and cat.lower() != category.lower():
                continue
            if severity and severity.lower() != "all" and sev.lower() != severity.lower():
                continue
            if search:
                term = search.lower()
                in_id = term in rule.id.lower()
                in_title = term in rule.title.lower()
                in_desc = term in rule.description.lower()
                if not (in_id or in_title or in_desc):
                    continue

            results.append({
                "id": rule.id,
                "title": rule.title,
                "severity": sev,
                "status": rule.status.value if hasattr(rule.status, "value") else str(rule.status),
                "category": cat,
                "event_id": rule.logsource.event_id,
                "mitre_attack": rule.mitre_attack,
                "author": rule.author,
                "description": rule.description,
            })

        results.sort(key=lambda r: (r["severity"], r["id"]))
        return results

    def get_rule_detail(self, rule_id: str) -> dict[str, Any] | None:
        """Retrieve structured details, condition expressions, and investigation steps.

        Args:
            rule_id: The unique identifier of the rule.

        Returns:
            Dictionary with rule detail fields, or None if not found.
        """
        rule = self._rules_cache.get(rule_id)
        if not rule:
            return None

        sev = rule.severity.value if hasattr(rule.severity, "value") else str(rule.severity)
        stat = rule.status.value if hasattr(rule.status, "value") else str(rule.status)
        cat = self._resolve_category(rule)

        return {
            "id": rule.id,
            "title": rule.title,
            "description": rule.description,
            "author": rule.author,
            "severity": sev,
            "status": stat,
            "category": cat,
            "product": rule.logsource.product,
            "service": rule.logsource.service,
            "event_id": rule.logsource.event_id,
            "condition": rule.detection.condition,
            "selections": rule.detection.selections,
            "mitre_attack": rule.mitre_attack,
            "references": rule.references,
            "falsepositives": rule.falsepositives,
            "investigation_steps": rule.investigation_steps,
        }

    def get_rule_yaml(self, rule_id: str) -> str:
        """Retrieve raw or serialized YAML representation of a rule.

        Args:
            rule_id: The unique identifier of the rule.

        Returns:
            YAML string, or empty string if not found.
        """
        rule = self._rules_cache.get(rule_id)
        if not rule:
            return ""

        if rule.raw_yaml:
            return rule.raw_yaml

        import yaml
        dump_data = rule.model_dump(exclude={"raw_yaml"})
        return yaml.dump(dump_data, sort_keys=False, default_flow_style=False)
