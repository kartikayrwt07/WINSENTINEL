"""PowerShell analysis data models for WinSentinel.

Provides typed forensic artifacts bridging threat analysis results directly
into AlertRepository and SQLite persistence without schema alterations.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PowerShellAnalysisResult(BaseModel):
    """Immutable forensic analysis result for a PowerShell command or script block."""

    model_config = ConfigDict(frozen=True)

    event_id: int
    record_id: int | None = None
    event_db_id: int | None = None
    computer: str
    timestamp_utc: datetime
    process_guid: str | None = None
    user: str | None = None
    raw_command: str
    decoded_command: str | None = None
    deobfuscated_command: str | None = None
    risk_score: int  # 0 to 100 clamped
    severity: str  # "Informational", "Medium", "High", "Critical"
    indicators: list[str] = Field(default_factory=list)
    matched_patterns: dict[str, list[str]] = Field(default_factory=dict)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    investigation_steps: list[str] = Field(default_factory=list)

    def to_alert_dict(self) -> dict[str, Any]:
        """Convert into kwargs compatible with AlertRepository.create_alert()."""
        indicators_str = ", ".join(self.indicators) if self.indicators else "None"
        description = (
            f"PowerShell composite risk score {self.risk_score}/100 detected with indicators: "
            f"[{indicators_str}]. Raw command: {self.raw_command[:300]}"
        )
        return {
            "title": f"Suspicious PowerShell Activity ({self.severity}) - Score {self.risk_score}",
            "severity": self.severity,
            "computer": self.computer,
            "status": "New",
            "rule_id": "PWSH-COMPOSITE-001",
            "description": description,
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

        # 1. Raw command
        evidence.append({
            "alert_id": alert_id,
            "event_id": db_eid,
            "matched_field": "command_line",
            "matched_value": self.raw_command[:1000],
            "explanation": "Original raw command line or script block input",
        })

        # 2. Decoded command (if Base64 was present)
        if self.decoded_command:
            evidence.append({
                "alert_id": alert_id,
                "event_id": db_eid,
                "matched_field": "decoded_command",
                "matched_value": self.decoded_command[:1000],
                "explanation": "Base64 de-obfuscated script payload",
            })

        # 3. Deobfuscated command (if normalized differently)
        if self.deobfuscated_command and self.deobfuscated_command not in (self.raw_command, self.decoded_command):
            evidence.append({
                "alert_id": alert_id,
                "event_id": db_eid,
                "matched_field": "deobfuscated_command",
                "matched_value": self.deobfuscated_command[:1000],
                "explanation": "Normalized command text after syntax de-obfuscation",
            })

        # 4. Matched patterns per indicator
        for indicator, patterns in self.matched_patterns.items():
            evidence.append({
                "alert_id": alert_id,
                "event_id": db_eid,
                "matched_field": f"indicator:{indicator}",
                "matched_value": ", ".join(patterns)[:1000],
                "explanation": f"Matched forensic pattern for indicator {indicator}",
            })

        # 5. Composite risk score
        evidence.append({
            "alert_id": alert_id,
            "event_id": db_eid,
            "matched_field": "risk_score",
            "matched_value": str(self.risk_score),
            "explanation": f"Composite risk score ({self.severity})",
        })

        return evidence
