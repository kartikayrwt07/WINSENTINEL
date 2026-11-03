"""Import audit statistics and quarantine tracking models for WinSentinel."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, model_validator


class QuarantineRecord(BaseModel):
    """Encapsulates a failed or partially normalized event record for triage."""

    event_id: int | None = None
    record_id: int | None = None
    raw_payload: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    error_reasons: list[str] = Field(default_factory=list)
    file_path: str = ""


class ImportStatistics(BaseModel):
    """Tracks metrics, duplicate counts, and errors across an ingestion job."""

    file_path: str = ""
    total_events: int = 0
    parsed_events: int = 0
    malformed_events: int = 0
    quarantined_events: int = 0
    duplicate_events: int = 0
    start_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: datetime | None = None
    error_log: list[str] = Field(default_factory=list)
    quarantined_records: list[QuarantineRecord] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _remap_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Support both total_records / total_events
            if "total_records" in data and "total_events" not in data:
                data["total_events"] = data.pop("total_records")
            # Support both errors / error_log
            if "errors" in data and "error_log" not in data:
                data["error_log"] = data.pop("errors")
        return data

    @property
    def total_records(self) -> int:
        """Alias for total_events."""
        return self.total_events

    @property
    def errors(self) -> list[str]:
        """Alias for error_log."""
        return self.error_log

    def record_parsed(self) -> None:
        """Increment successfully parsed event counters."""
        self.total_events += 1
        self.parsed_events += 1

    def record_malformed(self, error_msg: str) -> None:
        """Increment malformed event counter and record error diagnostic."""
        self.total_events += 1
        self.malformed_events += 1
        self.error_log.append(error_msg)

    def record_quarantined(self, record: QuarantineRecord) -> None:
        """Increment quarantined event counter and retain quarantine record."""
        self.total_events += 1
        self.quarantined_events += 1
        self.quarantined_records.append(record)

    def record_duplicate(self) -> None:
        """Increment duplicate event counter."""
        self.total_events += 1
        self.duplicate_events += 1

    def finish(self) -> None:
        """Mark ingestion job as completed with current timestamp."""
        self.end_time = datetime.now(timezone.utc)
