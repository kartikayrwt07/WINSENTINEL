"""Persistence analysis data models for WinSentinel.

Provides typed forensic persistence artifacts bridging threat analysis results directly
into AlertRepository and SQLite persistence without schema alterations.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PersistenceType(str, Enum):
    """Enumeration of persistence mechanism categories."""

    REGISTRY = "REGISTRY"
    SERVICE = "SERVICE"
    DRIVER = "DRIVER"
    SCHEDULED_TASK = "SCHEDULED_TASK"
    WMI_SUBSCRIPTION = "WMI_SUBSCRIPTION"
    STARTUP_FOLDER = "STARTUP_FOLDER"


class PersistenceArtifact(BaseModel):
    """Immutable forensic artifact capturing a detected persistence mechanism."""

    model_config = ConfigDict(frozen=True)

    persistence_type: PersistenceType
    event_id: int
    record_id: int | None = None
    event_db_id: int | None = None
    computer: str
    timestamp_utc: datetime
    process_guid: str | None = None
    user: str | None = None
    target_name: str  # Reg key, service name, task name, consumer name, or file path
    payload: str | None = None  # Command line, binary path, script block, WMI query
    severity: str  # "Low", "Medium", "High", "Critical"
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence_fields: dict[str, Any] = Field(default_factory=dict)
    explanation: str
    investigation_steps: list[str] = Field(default_factory=list)

    def to_alert_dict(self) -> dict[str, Any]:
        """Convert into kwargs compatible with AlertRepository.create_alert()."""
        return {
            "title": f"Persistence Mechanism Detected: {self.persistence_type.value} ({self.target_name})",
            "severity": self.severity,
            "computer": self.computer,
            "status": "New",
            "rule_id": f"PERS-{self.persistence_type.value}-001",
            "description": self.explanation,
            "user": self.user,
            "process_guid": self.process_guid,
            "first_seen": self.timestamp_utc,
            "last_seen": self.timestamp_utc,
            "event_count": 1,
            "mitre_tactics": list(self.mitre_tactics),
            "mitre_techniques": list(self.mitre_techniques),
        }

    def to_evidence_dicts(self, alert_id: int) -> list[dict[str, Any]]:
        """Convert into kwargs compatible with AlertRepository.link_alert_evidence()."""
        db_eid = self.event_db_id if self.event_db_id is not None else (self.record_id or self.event_id)
        evidence: list[dict[str, Any]] = []

        # 1. Target persistence object
        evidence.append({
            "alert_id": alert_id,
            "event_id": db_eid,
            "matched_field": "target_name",
            "matched_value": str(self.target_name)[:1000],
            "explanation": f"Persistence target ({self.persistence_type.value})",
        })

        # 2. Persistence payload if present
        if self.payload:
            evidence.append({
                "alert_id": alert_id,
                "event_id": db_eid,
                "matched_field": "payload",
                "matched_value": str(self.payload)[:1000],
                "explanation": "Persistence execution payload or binary",
            })

        # 3. Specific evidence fields
        for field_name, field_val in self.evidence_fields.items():
            evidence.append({
                "alert_id": alert_id,
                "event_id": db_eid,
                "matched_field": field_name,
                "matched_value": str(field_val)[:1000],
                "explanation": f"Forensic detail: {field_name}",
            })

        return evidence
