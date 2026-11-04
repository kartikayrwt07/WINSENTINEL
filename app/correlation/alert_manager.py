"""Alert Manager for WinSentinel.

Provides windowed deduplication, lifecycle status state machine, analyst notes,
and forensic evidence drill-down retrieval.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from app.database.connection import DatabaseManager
from app.database.repository import (
    AlertRepository,
    EventRepository,
    ProcessRepository,
)
from app.models.detection import DetectionMatch
from app.models.events import NormalizedEvent

logger = logging.getLogger(__name__)


class InvalidStatusTransitionError(ValueError):
    """Raised when an illegal alert status lifecycle transition is attempted."""


def _ensure_utc(dt: datetime | str | None) -> datetime:
    """Ensure timestamp is a UTC datetime instance."""
    if dt is None:
        return datetime.now(timezone.utc)
    if isinstance(dt, datetime):
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(dt))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _ensure_detection_rule(
    alert_repo: AlertRepository,
    rule_id: str,
    title: str,
    severity: str,
    description: str = "",
) -> None:
    """Ensure detection_rule exists to satisfy foreign key constraints."""
    if not rule_id or alert_repo.db_manager is None:
        return
    try:
        with alert_repo.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM detection_rules WHERE id = ?;", (rule_id,))
            if cur.fetchone() is None:
                now_iso = datetime.now(timezone.utc).isoformat()
                cur.execute(
                    """
                    INSERT OR IGNORE INTO detection_rules (
                        id, title, description, severity, status, author, rule_yaml, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        rule_id,
                        title,
                        description,
                        severity,
                        "active",
                        "WinSentinel System",
                        f"id: {rule_id}\ntitle: {title}\nseverity: {severity}",
                        now_iso,
                        now_iso,
                    ),
                )
    except Exception as err:
        logger.debug("Failed to ensure detection rule %s: %s", rule_id, err)


class AlertManager:
    """Manages alert deduplication, lifecycle transitions, notes, and forensic drill-down."""

    VALID_TRANSITIONS: dict[str, set[str]] = {
        "New": {"Investigating"},
        "Investigating": {"Escalated", "Resolved", "False Positive"},
        "Escalated": {"Investigating", "Resolved", "False Positive"},
        "Resolved": {"Investigating"},
        "False Positive": {"Investigating"},
    }

    def __init__(
        self,
        db_manager: DatabaseManager,
        dedup_window_minutes: int = 60,
    ) -> None:
        """Initialize AlertManager with database connection and deduplication window."""
        self.db_manager = db_manager
        self.alert_repo = AlertRepository(db_manager)
        self.event_repo = EventRepository(db_manager)
        self.process_repo = ProcessRepository(db_manager)
        self.dedup_window_minutes = dedup_window_minutes
        # Sliding window cache: (rule_id, computer, process_guid) -> {alert_id, last_seen, event_count}
        self._window_cache: dict[tuple[str, str, str], dict[str, Any]] = {}

    def _make_cache_key(
        self,
        rule_id: str,
        computer: str,
        process_guid: str | None,
    ) -> tuple[str, str, str]:
        """Generate composite key for windowed deduplication."""
        rule_key = str(rule_id).strip()
        comp_key = (computer or "UNKNOWN").strip().upper()
        pguid_key = (process_guid or "GLOBAL").strip()
        return (rule_key, comp_key, pguid_key)

    def process_alert(
        self,
        rule_id: str,
        title: str,
        severity: str,
        computer: str,
        user: str | None = None,
        process_guid: str | None = None,
        description: str | None = None,
        first_seen: datetime | str | None = None,
        last_seen: datetime | str | None = None,
        mitre_tactics: list[str] | None = None,
        mitre_techniques: list[str] | None = None,
        evidence_items: list[dict[str, Any]] | None = None,
    ) -> tuple[int, bool]:
        """Process an alert through sliding-window deduplication.

        Returns:
            Tuple of (alert_id, is_duplicate).
        """
        first_dt = _ensure_utc(first_seen)
        last_dt = _ensure_utc(last_seen or first_seen)

        cache_key = self._make_cache_key(rule_id, computer, process_guid)
        window_seconds = self.dedup_window_minutes * 60

        # Check in-memory sliding cache
        if cache_key in self._window_cache:
            entry = self._window_cache[cache_key]
            delta = abs((last_dt - entry["last_seen"]).total_seconds())
            if delta <= window_seconds:
                alert_id = entry["alert_id"]
                new_last_seen = max(entry["last_seen"], last_dt)
                self.alert_repo.touch_alert(
                    alert_id=alert_id,
                    last_seen=new_last_seen,
                    count_increment=1,
                )
                if evidence_items:
                    for ev in evidence_items:
                        self.alert_repo.link_alert_evidence(
                            alert_id=alert_id,
                            event_id=ev["event_id"],
                            matched_field=ev.get("matched_field"),
                            matched_value=ev.get("matched_value"),
                            explanation=ev.get("explanation"),
                        )
                entry["last_seen"] = new_last_seen
                entry["event_count"] += 1
                return (alert_id, True)

        # Check SQLite database for an active alert within window
        rule_key, comp_key, pguid_key = cache_key
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            if pguid_key == "GLOBAL":
                cur.execute(
                    """
                    SELECT id, last_seen, event_count FROM alerts
                    WHERE rule_id = ? AND UPPER(computer) = ? AND (process_guid IS NULL OR process_guid = '' OR process_guid = 'GLOBAL')
                    ORDER BY last_seen DESC LIMIT 1;
                    """,
                    (rule_key, comp_key),
                )
            else:
                cur.execute(
                    """
                    SELECT id, last_seen, event_count FROM alerts
                    WHERE rule_id = ? AND UPPER(computer) = ? AND process_guid = ?
                    ORDER BY last_seen DESC LIMIT 1;
                    """,
                    (rule_key, comp_key, pguid_key),
                )
            row = cur.fetchone()
            if row is not None:
                db_last_seen = _ensure_utc(row["last_seen"])
                delta = abs((last_dt - db_last_seen).total_seconds())
                if delta <= window_seconds:
                    alert_id = int(row["id"])
                    new_last_seen = max(db_last_seen, last_dt)
                    self.alert_repo.touch_alert(
                        alert_id=alert_id,
                        last_seen=new_last_seen,
                        count_increment=1,
                    )
                    if evidence_items:
                        for ev in evidence_items:
                            self.alert_repo.link_alert_evidence(
                                alert_id=alert_id,
                                event_id=ev["event_id"],
                                matched_field=ev.get("matched_field"),
                                matched_value=ev.get("matched_value"),
                                explanation=ev.get("explanation"),
                            )
                    self._window_cache[cache_key] = {
                        "alert_id": alert_id,
                        "last_seen": new_last_seen,
                        "event_count": int(row["event_count"]) + 1,
                    }
                    return (alert_id, True)

        # Outside window or new tuple -> create new alert
        _ensure_detection_rule(
            alert_repo=self.alert_repo,
            rule_id=rule_id,
            title=title,
            severity=severity,
            description=description or "",
        )
        alert_id = self.alert_repo.create_alert(
            rule_id=rule_id,
            title=title,
            severity=severity,
            status="New",
            description=description,
            computer=computer,
            user=user,
            process_guid=process_guid,
            first_seen=first_dt,
            last_seen=last_dt,
            event_count=1,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
        )

        if evidence_items:
            for ev in evidence_items:
                self.alert_repo.link_alert_evidence(
                    alert_id=alert_id,
                    event_id=ev["event_id"],
                    matched_field=ev.get("matched_field"),
                    matched_value=ev.get("matched_value"),
                    explanation=ev.get("explanation"),
                )

        self._window_cache[cache_key] = {
            "alert_id": alert_id,
            "last_seen": last_dt,
            "event_count": 1,
        }
        return (alert_id, False)

    def process_match(
        self,
        match: DetectionMatch,
        event: NormalizedEvent,
        event_db_id: int | None = None,
    ) -> tuple[int, bool]:
        """Convert a DetectionMatch into an alert with evidence linking and deduplication."""
        db_id = event_db_id or match.event_db_id
        evidence_items: list[dict[str, Any]] = []
        if db_id is not None and db_id > 0:
            raw_evidence = match.to_evidence_dicts(alert_id=0, event_db_id=db_id)
            for ev in raw_evidence:
                ev["event_id"] = db_id
                evidence_items.append(ev)

        title = getattr(match, "title", None) or getattr(match, "rule_title", "Detection Match")
        description = getattr(match, "description", None) or getattr(match, "explanation", "")
        matched_at = (
            getattr(match, "matched_at", None)
            or getattr(match, "timestamp_utc", None)
            or event.timestamp
        )

        return self.process_alert(
            rule_id=match.rule_id,
            title=title,
            severity=match.severity,
            computer=match.computer or event.computer,
            user=match.user or event.user,
            process_guid=match.process_guid or event.process_guid,
            description=description,
            first_seen=matched_at,
            last_seen=matched_at,
            mitre_tactics=match.mitre_tactics,
            mitre_techniques=match.mitre_techniques,
            evidence_items=evidence_items,
        )

    def update_alert_status(
        self,
        alert_id: int,
        new_status: str,
        analyst: str | None = None,
        comment: str | None = None,
    ) -> bool:
        """Validate and transition an alert status according to the lifecycle state machine."""
        alert = self.alert_repo.get_alert(alert_id)
        if alert is None:
            raise ValueError(f"Alert with ID {alert_id} not found")

        current_status = alert.get("status", "New")
        allowed = self.VALID_TRANSITIONS.get(current_status, set())
        if new_status not in allowed:
            raise InvalidStatusTransitionError(
                f"Cannot transition alert from '{current_status}' to '{new_status}'. "
                f"Allowed transitions: {sorted(list(allowed))}"
            )

        self.alert_repo.update_alert_status(alert_id, new_status)

        author = analyst or "Analyst"
        if comment:
            self.alert_repo.add_analyst_note(
                author=author,
                note_text=comment,
                alert_id=alert_id,
            )
        return True

    def update_status(
        self,
        alert_id: int,
        new_status: str,
        author: str = "Analyst",
        note: str | None = None,
    ) -> dict[str, Any]:
        """Update status and return updated alert dictionary."""
        self.update_alert_status(
            alert_id=alert_id,
            new_status=new_status,
            analyst=author,
            comment=note,
        )
        updated = self.alert_repo.get_alert(alert_id)
        return updated or {}

    def add_analyst_note(
        self,
        *args: Any,
        author: str | None = None,
        note_text: str | None = None,
        alert_id: int | None = None,
        investigation_id: int | None = None,
        disposition: str | None = None,
        **kwargs: Any,
    ) -> int:
        """Attach an analyst note with author attribution and optional disposition."""
        if args:
            if isinstance(args[0], int):
                alert_id = args[0]
                if len(args) > 1:
                    note_text = args[1]
                if len(args) > 2:
                    author = args[2]
                if len(args) > 3:
                    investigation_id = args[3]
            else:
                author = str(args[0])
                if len(args) > 1:
                    note_text = str(args[1])
                if len(args) > 2:
                    if isinstance(args[2], int):
                        alert_id = args[2]
                    else:
                        author = str(args[2])

        if "analyst" in kwargs and author is None:
            author = kwargs["analyst"]
        if "comment" in kwargs and note_text is None:
            note_text = kwargs["comment"]

        actual_author = str(author or "Analyst")
        actual_text = str(note_text or "")
        if disposition:
            actual_text = f"[{disposition}] {actual_text}"

        return self.alert_repo.add_analyst_note(
            author=actual_author,
            note_text=actual_text,
            alert_id=alert_id,
            investigation_id=investigation_id,
        )

    def get_alert_forensic_drilldown(self, alert_id: int) -> dict[str, Any]:
        """Retrieve complete forensic context for an alert.

        Includes alert metadata, all linked alert_evidence items, full NormalizedEvent
        records from the events table, process tree context (parent and children),
        and analyst notes.
        """
        alert_dict = self.alert_repo.get_alert(alert_id)
        if alert_dict is None:
            return {}

        evidence_rows = alert_dict.get("evidence", [])
        event_ids = [r["event_id"] for r in evidence_rows if "event_id" in r]

        events: list[dict[str, Any]] = []
        for eid in event_ids:
            ev = self.event_repo.get_event_by_id(eid)
            if ev is not None:
                events.append(ev.model_dump())

        process_context: dict[str, Any] = {}
        pguid = alert_dict.get("process_guid")
        if pguid:
            proc_node = self.process_repo.get_process_by_guid(pguid)
            if proc_node:
                process_context["process"] = proc_node.model_dump()
                if proc_node.parent_process_guid:
                    parent_node = self.process_repo.get_process_by_guid(
                        proc_node.parent_process_guid
                    )
                    process_context["parent"] = (
                        parent_node.model_dump() if parent_node else None
                    )
                with self.db_manager.get_connection() as conn:
                    cur = conn.cursor()
                    cur.execute(
                        "SELECT * FROM processes WHERE parent_process_guid = ?;",
                        (pguid,),
                    )
                    children = [
                        self.process_repo._row_to_node(r).model_dump()
                        for r in cur.fetchall()
                    ]
                    process_context["children"] = children

        return {
            "alert": alert_dict,
            "alert_id": alert_id,
            "title": alert_dict.get("title"),
            "severity": alert_dict.get("severity"),
            "status": alert_dict.get("status"),
            "event_count": alert_dict.get("event_count"),
            "evidence": evidence_rows,
            "events": events,
            "process_context": process_context,
            "notes": alert_dict.get("notes", []),
        }
