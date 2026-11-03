"""Streaming JSON and newline-delimited JSONL log parser."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Generator

from app.ingestion.base import BaseParser, RawRecord
from app.models.stats import ImportStatistics
from app.utils.security import sanitize_input_path

logger = logging.getLogger(__name__)


def _extract_record_id(obj: dict[str, Any]) -> int | None:
    """Attempt to extract an integer event record ID from common JSON representations."""
    candidate = (
        obj.get("record_id")
        or obj.get("EventRecordID")
        or obj.get("RecordId")
        or obj.get("event_record_id")
    )
    if candidate is None and isinstance(obj.get("System"), dict):
        candidate = obj["System"].get("EventRecordID") or obj["System"].get("record_id")

    if candidate is not None:
        try:
            return int(candidate)
        except (ValueError, TypeError):
            return None
    return None


class JSONParser(BaseParser):
    """Streaming parser supporting both JSON array files and newline-delimited JSONL files."""

    def stream_records(
        self,
        file_path: Path,
        stats: ImportStatistics | None = None,
    ) -> Generator[RawRecord, None, None]:
        """Stream raw event records from a JSON or JSONL file.

        Args:
            file_path: Path to the .json or .jsonl file.
            stats: Optional ImportStatistics tracker.

        Yields:
            RawRecord instances with metadata and parsed payloads.
        """
        validated_path = sanitize_input_path(
            file_path,
            allowed_extensions=[".json", ".jsonl"],
        )

        # Probe first non-whitespace character to distinguish array vs line-delimited
        is_array = False
        with open(validated_path, "r", encoding="utf-8", errors="replace") as probe:
            while True:
                ch = probe.read(1)
                if not ch:
                    break
                if not ch.isspace():
                    is_array = (ch == "[")
                    break

        if is_array:
            try:
                with open(validated_path, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)

                if not isinstance(data, list):
                    raise ValueError(f"Expected JSON array in {validated_path.name}, got {type(data).__name__}")

                for item in data:
                    if isinstance(item, dict):
                        record_id = _extract_record_id(item)
                        raw_payload = json.dumps(item)
                        if stats is not None:
                            stats.total_events += 1
                        yield RawRecord(
                            record_id=record_id,
                            raw_payload=raw_payload,
                            format="json",
                            metadata={"parsed_json": item},
                        )
                    else:
                        if stats is not None:
                            stats.record_malformed(f"Non-dict record in JSON array: {item!r}")
                        yield RawRecord(
                            record_id=None,
                            raw_payload=json.dumps(item),
                            format="json",
                            metadata={"error": "Record is not a JSON object", "is_corrupt": True},
                        )

            except (json.JSONDecodeError, ValueError, Exception) as err:
                logger.warning("Error reading JSON array from %s: %s", validated_path, err)
                if stats is not None:
                    stats.record_malformed(str(err))
                yield RawRecord(
                    record_id=None,
                    raw_payload="",
                    format="json",
                    metadata={"error": str(err), "is_corrupt": True},
                )
        else:
            with open(validated_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue

                    try:
                        obj = json.loads(stripped)
                        if not isinstance(obj, dict):
                            raise ValueError(f"JSON line is not an object: {stripped[:50]}")

                        record_id = _extract_record_id(obj)
                        if stats is not None:
                            stats.total_events += 1

                        yield RawRecord(
                            record_id=record_id,
                            raw_payload=stripped,
                            format="jsonl",
                            metadata={"parsed_json": obj},
                        )
                    except (json.JSONDecodeError, ValueError, Exception) as err:
                        logger.warning("Error parsing JSON line in %s: %s", validated_path, err)
                        if stats is not None:
                            stats.record_malformed(str(err))
                        yield RawRecord(
                            record_id=None,
                            raw_payload=stripped,
                            format="jsonl",
                            metadata={"error": str(err), "is_corrupt": True},
                        )
