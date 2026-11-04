"""Detection match and forensic evidence data models for WinSentinel.

Encapsulates match provenance, key-value evidence items, human-readable forensic
explanations, MITRE ATT&CK mappings, and database persistence bridge methods.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EvidenceItem(BaseModel):
    """Immutable record of an individual field comparison that satisfied a rule criterion."""

    model_config = ConfigDict(frozen=True)

    field: str
    actual_value: Any
    matched_pattern: Any
    modifier: str = "exact"


def generate_explanation(
    rule_id: str,
    rule_title: str,
    computer: str,
    evidence: list[EvidenceItem],
    exclusions_evaluated: list[str] | None = None,
    event_id: int | None = None,
    mitre_attack: list[str] | None = None,
) -> str:
    """Build a structured, human-readable forensic narrative for detection matches."""
    event_clause = f" for event {event_id}" if event_id is not None else ""
    ev_parts = [
        f"{e.field} (modifier: {e.modifier}) matched '{e.matched_pattern}' with actual value '{e.actual_value}'"
        for e in evidence
    ]
    ev_str = "; ".join(ev_parts) if ev_parts else "No specific evidence items recorded"
    narrative = f"Rule [{rule_id}] '{rule_title}' triggered{event_clause} on {computer}. Evidence: {ev_str}."

    if mitre_attack:
        narrative += f" MITRE ATT&CK: {', '.join(mitre_attack)}."

    if exclusions_evaluated:
        narrative += f" Exclusions evaluated: {', '.join(exclusions_evaluated)} (all benign baselines negative)."

    return narrative


class DetectionMatch(BaseModel):
    """Forensic detection match result containing complete provenance and evidence."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    rule_title: str
    severity: str
    event_id: int
    event_record_id: int | None = None
    event_db_id: int | None = None
    computer: str
    timestamp_utc: datetime
    process_guid: str | None = None
    user: str | None = None
    image: str | None = None
    command_line: str | None = None
    matched_evidence: list[EvidenceItem]
    explanation: str
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    investigation_steps: list[str] = Field(default_factory=list)

    def to_alert_dict(self) -> dict[str, Any]:
        """Convert match attributes into kwargs formatted for AlertRepository.create_alert()."""
        return {
            "rule_id": self.rule_id,
            "title": self.rule_title,
            "severity": self.severity,
            "computer": self.computer,
            "user": self.user,
            "process_guid": self.process_guid,
            "first_seen": self.timestamp_utc,
            "last_seen": self.timestamp_utc,
            "description": self.explanation,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
        }

    def to_evidence_dicts(
        self,
        alert_id: int,
        event_db_id: int | None = None,
    ) -> list[dict[str, Any]]:
        """Convert match evidence into kwargs formatted for AlertRepository.link_alert_evidence()."""
        target_event_id = event_db_id if event_db_id is not None else (self.event_db_id or 0)
        return [
            {
                "alert_id": alert_id,
                "event_id": target_event_id,
                "matched_field": json.dumps([e.field for e in self.matched_evidence]),
                "matched_value": json.dumps([str(e.actual_value) for e in self.matched_evidence]),
                "explanation": self.explanation,
            }
        ]
