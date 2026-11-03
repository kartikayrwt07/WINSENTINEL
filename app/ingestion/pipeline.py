"""Unified ingestion and normalization pipeline for WinSentinel."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.ingestion.base import BaseParser, RawRecord
from app.ingestion.evtx_parser import EVTXParser
from app.ingestion.json_parser import JSONParser
from app.ingestion.xml_parser import XMLParser, parse_event_xml
from app.models.events import NormalizedEvent
from app.models.fingerprint import compute_event_fingerprint
from app.models.stats import ImportStatistics, QuarantineRecord
from app.normalization.dispatcher import NormalizerDispatcher
from app.utils.security import sanitize_input_path

logger = logging.getLogger(__name__)


def _extract_json_fields(obj: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Separate JSON object into system header fields and data fields."""
    if "System" in obj and isinstance(obj["System"], dict):
        system_fields = dict(obj["System"])
        data_fields: dict[str, Any] = {}
        if "EventData" in obj and isinstance(obj["EventData"], dict):
            data_fields.update(obj["EventData"])
        elif "UserData" in obj and isinstance(obj["UserData"], dict):
            data_fields.update(obj["UserData"])

        for k, v in obj.items():
            if k not in ("System", "EventData", "UserData"):
                data_fields[k] = v
        return system_fields, data_fields

    # Flat representation
    known_system_keys = {
        "provider", "providername", "providerguid",
        "eventid", "id", "qualifiers",
        "timecreated", "systemtime", "utctime", "timestamp",
        "eventrecordid", "record_id", "recordid",
        "computer", "machinename", "channel",
        "processid", "threadid", "execution",
        "userid", "security", "activityid", "relatedactivityid", "correlation",
    }
    system_fields = {}
    data_fields = {}
    for k, v in obj.items():
        if k.lower() in known_system_keys:
            system_fields[k] = v
        else:
            data_fields[k] = v
    return system_fields, data_fields


class IngestionPipeline:
    """Coordinates parsing, deduplication, normalization, and auditing of telemetry files."""

    def __init__(
        self,
        base_dir: Path | None = None,
        dispatcher: NormalizerDispatcher | None = None,
    ) -> None:
        self.base_dir = base_dir
        self.dispatcher = dispatcher or NormalizerDispatcher()
        self.seen_hashes: set[str] = set()

    def reset_deduplication(self) -> None:
        """Clear seen event fingerprints cache."""
        self.seen_hashes.clear()

    def ingest_file(
        self,
        file_path: str | Path,
        base_dir: Path | None = None,
    ) -> tuple[list[NormalizedEvent], ImportStatistics]:
        """Ingest, deduplicate, and normalize a log file.

        Args:
            file_path: Path to the log file (.evtx, .xml, .json, .jsonl).
            base_dir: Optional base directory to enforce path confinement.

        Returns:
            Tuple of (normalized_events_list, import_statistics).
        """
        effective_base_dir = base_dir if base_dir is not None else self.base_dir
        resolved_path = sanitize_input_path(
            user_path=file_path,
            base_dir=effective_base_dir,
            allowed_extensions=[".evtx", ".xml", ".json", ".jsonl"],
        )

        stats = ImportStatistics(
            file_path=str(resolved_path),
            start_time=datetime.now(timezone.utc),
        )

        # Select appropriate parser
        suffix = resolved_path.suffix.lower()
        parser: BaseParser
        if suffix == ".evtx":
            parser = EVTXParser()
        elif suffix == ".xml":
            parser = XMLParser()
        elif suffix in (".json", ".jsonl"):
            parser = JSONParser()
        else:
            err = f"Unsupported file extension: {suffix}"
            stats.record_malformed(err)
            stats.finish()
            return [], stats

        normalized_events: list[NormalizedEvent] = []

        try:
            for raw_record in parser.stream_records(resolved_path, stats=None):
                # Handle parser-level corruption/errors
                if raw_record.metadata.get("is_corrupt") or raw_record.metadata.get("error"):
                    err_msg = str(raw_record.metadata.get("error", "Corrupt record in stream"))
                    stats.record_malformed(err_msg)
                    stats.quarantined_records.append(
                        QuarantineRecord(
                            event_id=None,
                            record_id=raw_record.record_id,
                            raw_payload=raw_record.raw_payload,
                            error_reasons=[err_msg],
                            file_path=str(resolved_path),
                        )
                    )
                    continue

                # Parse raw payload into system and data field dictionaries
                system_fields: dict[str, Any] = {}
                data_fields: dict[str, Any] = {}

                if raw_record.format in ("xml", "evtx"):
                    try:
                        system_fields, data_fields = parse_event_xml(raw_record.raw_payload)
                    except Exception as err:
                        err_msg = f"XML structure parse error: {err}"
                        stats.record_malformed(err_msg)
                        stats.quarantined_records.append(
                            QuarantineRecord(
                                event_id=None,
                                record_id=raw_record.record_id,
                                raw_payload=raw_record.raw_payload,
                                error_reasons=[err_msg],
                                file_path=str(resolved_path),
                            )
                        )
                        continue

                elif raw_record.format in ("json", "jsonl"):
                    parsed_obj = raw_record.metadata.get("parsed_json")
                    if parsed_obj is None:
                        try:
                            parsed_obj = json.loads(raw_record.raw_payload)
                        except Exception as err:
                            err_msg = f"JSON parse error: {err}"
                            stats.record_malformed(err_msg)
                            stats.quarantined_records.append(
                                QuarantineRecord(
                                    event_id=None,
                                    record_id=raw_record.record_id,
                                    raw_payload=raw_record.raw_payload,
                                    error_reasons=[err_msg],
                                    file_path=str(resolved_path),
                                )
                            )
                            continue

                    if not isinstance(parsed_obj, dict):
                        err_msg = f"JSON item is not an object: {type(parsed_obj).__name__}"
                        stats.record_malformed(err_msg)
                        stats.quarantined_records.append(
                            QuarantineRecord(
                                event_id=None,
                                record_id=raw_record.record_id,
                                raw_payload=raw_record.raw_payload,
                                error_reasons=[err_msg],
                                file_path=str(resolved_path),
                            )
                        )
                        continue

                    system_fields, data_fields = _extract_json_fields(parsed_obj)

                # Determine record_id and compute fingerprint
                rec_id = raw_record.record_id
                if rec_id is None:
                    candidate = (
                        system_fields.get("EventRecordID")
                        or system_fields.get("record_id")
                        or system_fields.get("RecordId")
                    )
                    if candidate is not None and str(candidate).isdigit():
                        rec_id = int(str(candidate))

                computer = str(
                    system_fields.get("Computer")
                    or system_fields.get("computer")
                    or "UnknownComputer"
                )
                provider = str(
                    system_fields.get("Provider")
                    or system_fields.get("provider")
                    or "UnknownProvider"
                )
                channel = str(
                    system_fields.get("Channel")
                    or system_fields.get("channel")
                    or "UnknownChannel"
                )

                fingerprint = compute_event_fingerprint(
                    computer=computer,
                    provider=provider,
                    channel=channel,
                    record_id=rec_id,
                    raw_payload=raw_record.raw_payload,
                )

                # Deduplication check
                if fingerprint in self.seen_hashes:
                    stats.record_duplicate()
                    continue

                self.seen_hashes.add(fingerprint)

                # Dispatch normalization
                norm_event = self.dispatcher.dispatch(
                    system_fields=system_fields,
                    data_fields=data_fields,
                    raw_payload=raw_record.raw_payload,
                )

                if norm_event.is_quarantined:
                    stats.record_quarantined(
                        QuarantineRecord(
                            event_id=norm_event.event_id,
                            record_id=norm_event.record_id,
                            raw_payload=norm_event.raw_payload,
                            error_reasons=norm_event.quarantine_reasons,
                            file_path=str(resolved_path),
                        )
                    )
                    stats.error_log.extend(norm_event.quarantine_reasons)
                else:
                    stats.record_parsed()

                normalized_events.append(norm_event)

        except Exception as err:
            logger.exception("Unexpected error during ingestion of %s: %s", resolved_path, err)
            stats.record_malformed(f"Fatal ingestion error: {err}")

        stats.finish()
        return normalized_events, stats
