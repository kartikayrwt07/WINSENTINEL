"""Base interfaces and data structures for forensic log ingestion."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generator

from app.models.stats import ImportStatistics


@dataclass
class RawRecord:
    """Represents an unparsed or raw event payload extracted from an event file.

    Attributes:
        record_id: Optional native event record identifier (e.g. EventRecordID).
        raw_payload: Complete raw text representation (XML string, JSON string, etc.).
        format: Ingestion format indicator ('evtx', 'xml', 'json', 'jsonl').
        metadata: Extraction metadata, parser flags, or quarantine diagnostic details.
    """

    record_id: int | None
    raw_payload: str
    format: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class ParserError(Exception):
    """Base exception for parsing and extraction failures."""

    def __init__(
        self,
        message: str,
        record_id: int | None = None,
        raw_payload: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.record_id = record_id
        self.raw_payload = raw_payload


# Alias for backward/plan compatibility
ParserRecordError = ParserError


class BaseParser(ABC):
    """Abstract base class for streaming forensic log parsers."""

    @abstractmethod
    def stream_records(
        self,
        file_path: Path,
        stats: ImportStatistics | None = None,
    ) -> Generator[RawRecord, None, None]:
        """Stream raw event records from a target file.

        Args:
            file_path: Validated path to the log file.
            stats: Optional ImportStatistics tracker to update during ingestion.

        Yields:
            RawRecord instances extracted from the source stream.
        """
        pass
