"""In-memory indexed detection engine and alert persistence bridge for WinSentinel.

Provides fast candidate rule dispatch using (provider, event_id) hashing,
condition AST evaluation with exclusion filtering, batch event evaluation,
and persistence to SQLite alerts and alert_evidence tables.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from app.database.connection import DatabaseManager
from app.database.repository import AlertRepository
from app.detection.ast_parser import ASTNode, ConditionParser
from app.detection.matcher import FieldMatcher
from app.models.detection import DetectionMatch, EvidenceItem, generate_explanation
from app.models.events import NormalizedEvent
from app.models.rule import DetectionRule


@dataclass
class CompiledRule:
    """In-memory compiled detection rule with pre-parsed AST and selections."""

    rule: DetectionRule
    ast_root: ASTNode
    selections: dict[str, dict[str, Any]]
    matcher: FieldMatcher

    def match(
        self,
        event: NormalizedEvent,
        event_db_id: int | None = None,
    ) -> DetectionMatch | None:
        """Evaluate a NormalizedEvent against this compiled rule.

        Returns DetectionMatch with forensic evidence on success, or None on failure.
        """
        context: dict[str, bool] = {}
        selection_evidence: dict[str, list[EvidenceItem]] = {}

        for sel_name, sel_dict in self.selections.items():
            if isinstance(sel_dict, dict):
                is_match, evidence = self.matcher.match_selection(event, sel_dict)
                context[sel_name] = is_match
                if is_match:
                    selection_evidence[sel_name] = evidence
            else:
                context[sel_name] = False

        if not self.ast_root.evaluate(context):
            return None

        # Condition evaluated to True! Gather contributing evidence and exclusions
        contributing_evidence: list[EvidenceItem] = []
        exclusions_evaluated: list[str] = []

        for sel_name in self.selections.keys():
            if sel_name.lower().startswith("filter"):
                exclusions_evaluated.append(sel_name)
            elif context.get(sel_name, False):
                contributing_evidence.extend(selection_evidence.get(sel_name, []))

        # Fallback if no specific positive selections were tracked
        if not contributing_evidence:
            for ev_list in selection_evidence.values():
                contributing_evidence.extend(ev_list)

        explanation = generate_explanation(
            rule_id=self.rule.id,
            rule_title=self.rule.title,
            computer=event.computer,
            evidence=contributing_evidence,
            exclusions_evaluated=exclusions_evaluated if exclusions_evaluated else None,
            event_id=event.event_id,
            mitre_attack=self.rule.mitre_attack,
        )

        return DetectionMatch(
            rule_id=self.rule.id,
            rule_title=self.rule.title,
            severity=self.rule.severity.value,
            event_id=event.event_id,
            event_record_id=event.record_id,
            event_db_id=event_db_id,
            computer=event.computer,
            timestamp_utc=event.timestamp,
            process_guid=event.process_guid,
            user=event.user,
            image=event.image,
            command_line=event.command_line,
            matched_evidence=contributing_evidence,
            explanation=explanation,
            mitre_tactics=[],
            mitre_techniques=self.rule.mitre_attack,
            investigation_steps=self.rule.investigation_steps,
        )


class DetectionEngine:
    """Evaluates telemetry events against registered rules with O(1) indexed dispatch."""

    def __init__(
        self,
        matcher: FieldMatcher | None = None,
        parser: ConditionParser | None = None,
    ) -> None:
        self._matcher = matcher or FieldMatcher()
        self._parser = parser or ConditionParser()
        self._index: dict[tuple[str, int], list[CompiledRule]] = defaultdict(list)
        self._universal_rules: list[CompiledRule] = []
        self._rules: dict[str, CompiledRule] = {}

    @property
    def rules(self) -> dict[str, CompiledRule]:
        """Dictionary of all registered rules keyed by rule ID."""
        return self._rules

    def register_rule(self, rule: DetectionRule) -> CompiledRule:
        """Compile and index a DetectionRule into the engine.

        Indexes rule by (provider, event_id) for O(1) candidate lookup, or adds
        to universal_rules if no event_id filter is specified.
        """
        ast_root = self._parser.parse(rule.detection.condition)
        selections = {
            k: v for k, v in rule.detection.selections.items() if isinstance(v, dict)
        }
        compiled = CompiledRule(
            rule=rule,
            ast_root=ast_root,
            selections=selections,
            matcher=self._matcher,
        )
        self._rules[rule.id] = compiled

        # Determine target event IDs
        target_eids: list[int] = []
        if isinstance(rule.logsource.event_id, int):
            target_eids = [rule.logsource.event_id]
        elif isinstance(rule.logsource.event_id, (list, tuple, set)):
            target_eids = [int(eid) for eid in rule.logsource.event_id]

        provider = (rule.logsource.service or rule.logsource.product or "").strip().lower()

        if not target_eids:
            self._universal_rules.append(compiled)
        else:
            for eid in target_eids:
                self._index[(provider, eid)].append(compiled)
                if provider == "sysmon":
                    self._index[("microsoft-windows-sysmon", eid)].append(compiled)
                elif "sysmon" in provider:
                    self._index[("sysmon", eid)].append(compiled)

                # Fallback index without provider
                self._index[("", eid)].append(compiled)

        return compiled

    def load_rules(self, rules: list[DetectionRule]) -> int:
        """Register a list of DetectionRules. Returns the number of registered rules."""
        for rule in rules:
            self.register_rule(rule)
        return len(rules)

    register_rules = load_rules

    def evaluate_event(
        self,
        event: NormalizedEvent,
        event_db_id: int | None = None,
    ) -> list[DetectionMatch]:
        """Evaluate a NormalizedEvent against matching candidate rules."""
        provider = event.provider.strip().lower()
        eid = event.event_id

        candidates: list[CompiledRule] = []
        seen_rule_ids: set[str] = set()

        keys_to_check = [
            (provider, eid),
            ("", eid),
        ]
        if "sysmon" in provider:
            keys_to_check.append(("sysmon", eid))
        if "security" in provider:
            keys_to_check.append(("security", eid))
        if "powershell" in provider:
            keys_to_check.append(("powershell", eid))

        for key in keys_to_check:
            for rule in self._index.get(key, []):
                if rule.rule.id not in seen_rule_ids:
                    seen_rule_ids.add(rule.rule.id)
                    candidates.append(rule)

        for rule in self._universal_rules:
            if rule.rule.id not in seen_rule_ids:
                seen_rule_ids.add(rule.rule.id)
                candidates.append(rule)

        matches: list[DetectionMatch] = []
        for candidate in candidates:
            match = candidate.match(event, event_db_id=event_db_id)
            if match is not None:
                matches.append(match)

        return matches

    def evaluate_batch(
        self,
        events: list[NormalizedEvent],
    ) -> list[DetectionMatch]:
        """Evaluate an ordered collection of NormalizedEvents, aggregating all matches."""
        all_matches: list[DetectionMatch] = []
        for event in events:
            all_matches.extend(self.evaluate_event(event))
        return all_matches

    evaluate_events = evaluate_batch

    def persist_matches(
        self,
        first: DatabaseManager | AlertRepository | list[DetectionMatch],
        second: DatabaseManager | AlertRepository | list[DetectionMatch] | None = None,
    ) -> list[int]:
        """Persist detection matches into SQLite alerts and alert_evidence tables.

        Accepts either:
        - persist_matches(db_manager, matches)
        - persist_matches(matches, alert_repo)
        - persist_matches(alert_repo, matches)

        Returns:
            List of generated alert primary key IDs.
        """
        if isinstance(first, list):
            matches = first
            target = second
        else:
            target = first
            matches = second if isinstance(second, list) else []

        if target is None:
            raise ValueError("A DatabaseManager or AlertRepository instance must be provided")

        if isinstance(target, AlertRepository):
            alert_repo = target
        elif hasattr(target, "get_connection"):
            alert_repo = AlertRepository(target)  # type: ignore[arg-type]
        else:
            raise TypeError(f"Expected DatabaseManager or AlertRepository, got {type(target)}")

        alert_ids: list[int] = []
        now_iso = None

        for match in matches:
            # Ensure referenced rule exists in detection_rules to satisfy foreign key constraint
            if match.rule_id:
                with alert_repo.db_manager.get_connection() as conn:
                    cur = conn.cursor()
                    cur.execute("SELECT 1 FROM detection_rules WHERE id = ?;", (match.rule_id,))
                    if cur.fetchone() is None:
                        from datetime import datetime, timezone
                        now_iso = datetime.now(timezone.utc).isoformat()
                        compiled = self._rules.get(match.rule_id)
                        desc = compiled.rule.description if compiled else ""
                        status_val = compiled.rule.status.value if compiled else "active"
                        author_val = compiled.rule.author if compiled else "WinSentinel"
                        yaml_val = compiled.rule.raw_yaml if compiled else ""
                        cur.execute(
                            """
                            INSERT OR IGNORE INTO detection_rules (
                                id, title, description, severity, status, author, rule_yaml, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                            """,
                            (
                                match.rule_id,
                                match.rule_title,
                                desc,
                                match.severity,
                                status_val,
                                author_val,
                                yaml_val,
                                now_iso,
                                now_iso,
                            ),
                        )

            alert_id = alert_repo.create_alert(**match.to_alert_dict())
            alert_ids.append(alert_id)

            if match.event_db_id is not None and match.event_db_id > 0:
                for ev_dict in match.to_evidence_dicts(alert_id=alert_id):
                    alert_repo.link_alert_evidence(
                        alert_id=ev_dict["alert_id"],
                        event_id=ev_dict["event_id"],
                        matched_field=ev_dict["matched_field"],
                        matched_value=ev_dict["matched_value"],
                        explanation=ev_dict["explanation"],
                    )

        return alert_ids
