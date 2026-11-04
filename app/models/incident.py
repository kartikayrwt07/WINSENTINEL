"""Compound incident data models and chronological narrative generation for WinSentinel.

Encapsulates multi-stage correlated threat incidents, individual attack stages,
MITRE ATT&CK tactic/technique mappings, and database persistence bridge methods.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def _sanitize_string(text: str | None) -> str:
    """Sanitize strings for narrative formatting, removing control chars."""
    if not text:
        return ""
    # Strip non-printable control characters except newline and tab
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", "", str(text)).strip()


class IncidentStage(BaseModel):
    """Immutable representation of a single stage within a correlated attack chain."""

    model_config = ConfigDict(frozen=True)

    stage_number: int = Field(ge=1, description="Sequential stage order (1-indexed).")
    stage_name: str = Field(description="Descriptive stage name (e.g. Initial Execution, Script Cradle).")
    tactic: str = Field(description="MITRE ATT&CK tactic name (e.g. Initial Access, Execution).")
    technique: str = Field(description="MITRE ATT&CK technique ID (e.g. T1204.002, T1059.001).")
    timestamp: datetime = Field(description="Timestamp when this stage event occurred (UTC).")
    process_guid: str | None = Field(default=None, description="Invariant GUID of the participating process.")
    image: str | None = Field(default=None, description="Binary image path associated with this stage.")
    command_line: str | None = Field(default=None, description="Command line invocation of this stage.")
    event_ids: list[int] = Field(default_factory=list, description="Raw event database/record IDs backing this stage.")
    alert_ids: list[int] = Field(default_factory=list, description="Atomic alert IDs contributing to this stage.")
    narrative: str = Field(description="Forensic explanation of what occurred during this stage.")

    @field_validator("timestamp", mode="after")
    @classmethod
    def _ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


def generate_incident_narrative(
    chain_name_or_stages: str | list[IncidentStage] | None = None,
    computer: str | None = None,
    user: str | None = None,
    stages: list[IncidentStage] | None = None,
    chain_name: str | None = None,
) -> str:
    """Synthesize an explainable, chronological narrative story linking all attack stages.

    Accepts (chain_name, computer, user, stages) or (stages, computer, user) or keyword arguments.
    Traces the intrusion from initial access to final objective with forensic traceability.
    """
    if chain_name_or_stages is not None:
        if isinstance(chain_name_or_stages, list):
            actual_stages = chain_name_or_stages
            actual_chain = chain_name or "Multi-Stage Attack"
        else:
            actual_chain = str(chain_name_or_stages)
            actual_stages = stages or []
    else:
        actual_chain = chain_name or "Multi-Stage Attack"
        actual_stages = stages or []

    actual_comp = computer or "UNKNOWN_HOST"
    actual_user = user

    clean_comp = _sanitize_string(actual_comp) or "UNKNOWN_HOST"
    clean_user = _sanitize_string(actual_user) if actual_user else "SYSTEM/Unknown"
    clean_chain = _sanitize_string(actual_chain) or "Correlated Attack Chain"

    sorted_stages = sorted(actual_stages, key=lambda s: (s.stage_number, s.timestamp))

    lines: list[str] = [
        f"=== Correlated Multi-Stage Intrusion: {clean_chain} ===",
        f"Host: {clean_comp} | User Context: {clean_user} | Severity: CRITICAL",
    ]

    if sorted_stages:
        t_start = sorted_stages[0].timestamp
        t_end = sorted_stages[-1].timestamp
        dur_s = max(0.0, (t_end - t_start).total_seconds())
        lines.append(
            f"Execution Window: {t_start.strftime('%Y-%m-%d %H:%M:%S UTC')} to "
            f"{t_end.strftime('%Y-%m-%d %H:%M:%S UTC')} ({dur_s:.1f}s)"
        )
        lines.append("")
        lines.append("Chronological Attack Progression:")

        all_event_ids: list[int] = []
        all_alert_ids: list[int] = []

        for stage in sorted_stages:
            ts_str = stage.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            lines.append(
                f"[Stage {stage.stage_number}: {stage.stage_name}] ({stage.tactic} / {stage.technique}) at {ts_str}"
            )
            lines.append(f"  Summary: {_sanitize_string(stage.narrative)}")
            if stage.image:
                lines.append(f"  Process: {_sanitize_string(stage.image)}")
            if stage.command_line:
                lines.append(f"  Command Line: {_sanitize_string(stage.command_line)}")
            if stage.process_guid:
                lines.append(f"  Process GUID: {_sanitize_string(stage.process_guid)}")

            for eid in stage.event_ids:
                if eid not in all_event_ids:
                    all_event_ids.append(eid)
            for aid in stage.alert_ids:
                if aid not in all_alert_ids:
                    all_alert_ids.append(aid)

        lines.append("")
        lines.append("Forensic Evidence & Traceability:")
        lines.append(
            f"  Contributing Event IDs: {all_event_ids if all_event_ids else 'None recorded'}"
        )
        lines.append(
            f"  Contributing Alert IDs: {all_alert_ids if all_alert_ids else 'None recorded'}"
        )
    else:
        lines.append("No stages recorded for this incident.")

    return "\n".join(lines)


class CompoundIncident(BaseModel):
    """Correlated multi-stage attack incident elevated to Critical severity."""

    model_config = ConfigDict(frozen=True)

    incident_id: str = Field(description="Unique incident identifier (e.g. INC-CHAIN-PHISH-001-A1B2C3D4).")
    chain_id: str = Field(description="Associated attack chain rule identifier (e.g. CHAIN-PHISH-001).")
    chain_name: str = Field(description="Human-readable attack chain name.")
    severity: str = Field(default="Critical", description="Incident severity level (always Critical).")
    status: str = Field(default="New", description="Lifecycle triage status (New, Investigating, Escalated, Resolved).")
    computer: str = Field(description="Host where the incident occurred.")
    user: str | None = Field(default=None, description="Primary user context involved in the incident.")
    root_process_guid: str | None = Field(default=None, description="Invariant GUID of the root process starting the chain.")
    first_seen: datetime = Field(description="Timestamp of the earliest stage event (UTC).")
    last_seen: datetime = Field(description="Timestamp of the latest stage event (UTC).")
    duration_seconds: float = Field(default=0.0, ge=0.0, description="Total incident span in seconds.")
    stages: list[IncidentStage] = Field(description="Ordered list of participating attack stages.")
    mitre_tactics: list[str] = Field(default_factory=list, description="Unique MITRE ATT&CK tactics involved.")
    mitre_techniques: list[str] = Field(default_factory=list, description="Unique MITRE ATT&CK techniques involved.")
    participating_alert_ids: list[int] = Field(default_factory=list, description="Underlying atomic alert IDs.")
    participating_event_ids: list[int] = Field(default_factory=list, description="Underlying raw/normalized event IDs.")
    summary_narrative: str = Field(default="", description="Explainable chronological narrative story.")
    narrative_story: str = Field(default="", description="Alias for summary_narrative.")
    investigation_steps: list[str] = Field(default_factory=list, description="Recommended SOC triage investigation steps.")

    @field_validator("first_seen", "last_seen", mode="after")
    @classmethod
    def _ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_validator("stages")
    @classmethod
    def _validate_stages(cls, v: list[IncidentStage]) -> list[IncidentStage]:
        if not v or len(v) < 2:
            raise ValueError("A CompoundIncident requires at least 2 correlated attack stages.")
        return v

    @model_validator(mode="after")
    def _post_init_sync(self) -> CompoundIncident:
        # Calculate duration if not populated
        computed_duration = self.duration_seconds
        if computed_duration == 0.0 and self.first_seen and self.last_seen:
            computed_duration = max(0.0, (self.last_seen - self.first_seen).total_seconds())
            object.__setattr__(self, "duration_seconds", computed_duration)

        # Aggregate participating event IDs from stages if empty
        if not self.participating_event_ids and self.stages:
            ev_ids: list[int] = []
            for s in self.stages:
                for eid in s.event_ids:
                    if eid not in ev_ids:
                        ev_ids.append(eid)
            object.__setattr__(self, "participating_event_ids", ev_ids)

        # Aggregate participating alert IDs from stages if empty
        if not self.participating_alert_ids and self.stages:
            al_ids: list[int] = []
            for s in self.stages:
                for aid in s.alert_ids:
                    if aid not in al_ids:
                        al_ids.append(aid)
            object.__setattr__(self, "participating_alert_ids", al_ids)

        # Aggregate MITRE tactics from stages if empty
        if not self.mitre_tactics and self.stages:
            tactics: list[str] = []
            for s in self.stages:
                if s.tactic and s.tactic not in tactics:
                    tactics.append(s.tactic)
            object.__setattr__(self, "mitre_tactics", tactics)

        # Aggregate MITRE techniques from stages if empty
        if not self.mitre_techniques and self.stages:
            techniques: list[str] = []
            for s in self.stages:
                if s.technique and s.technique not in techniques:
                    techniques.append(s.technique)
            object.__setattr__(self, "mitre_techniques", techniques)

        # Synchronize narrative story / summary narrative
        story = self.summary_narrative or self.narrative_story
        if not story and self.stages:
            story = generate_incident_narrative(
                chain_name=self.chain_name,
                computer=self.computer,
                user=self.user,
                stages=self.stages,
            )
        if not self.summary_narrative:
            object.__setattr__(self, "summary_narrative", story)
        if not self.narrative_story:
            object.__setattr__(self, "narrative_story", story)

        return self

    def to_investigation_dict(self) -> dict[str, Any]:
        """Format incident attributes for the SQLite investigations table."""
        return {
            "title": f"Compound Incident: {self.chain_name} on {self.computer}",
            "status": "Open",
            "priority": self.severity,
            "lead_analyst": None,
            "summary": self.summary_narrative,
            "created_at": self.first_seen.isoformat(),
            "updated_at": self.last_seen.isoformat(),
            "closed_at": None,
        }

    def to_alert_dict(self) -> dict[str, Any]:
        """Format incident attributes for AlertRepository.create_alert() under rule CHAIN-<name>."""
        return {
            "rule_id": self.chain_id,
            "title": f"Compound Incident: {self.chain_name}",
            "severity": self.severity,
            "status": self.status,
            "description": self.summary_narrative,
            "computer": self.computer,
            "user": self.user,
            "process_guid": self.root_process_guid,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": len(self.participating_event_ids) if self.participating_event_ids else len(self.stages),
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
        }

    def to_evidence_dicts(self, alert_id: int = 0) -> list[dict[str, Any]]:
        """Format evidence tuples for AlertRepository.link_alert_evidence()."""
        stage_by_event: dict[int, str] = {}
        for stage in self.stages:
            for eid in stage.event_ids:
                stage_by_event[eid] = f"Stage {stage.stage_number} ({stage.stage_name}): {stage.narrative}"

        evidence_items: list[dict[str, Any]] = []
        for eid in self.participating_event_ids:
            stage_desc = stage_by_event.get(eid, f"Correlated event in {self.chain_id}")
            evidence_items.append(
                {
                    "alert_id": alert_id,
                    "event_id": eid,
                    "matched_field": "event_id",
                    "matched_value": str(eid),
                    "explanation": (
                        f"Participating event in correlated attack chain {self.chain_id} "
                        f"({self.chain_name}). {stage_desc}"
                    ),
                }
            )
        return evidence_items
