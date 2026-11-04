"""Unified ingestion and normalization pipeline for WinSentinel."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.analyzers.lineage_detector import LineageAnomaly, LineageAnomalyDetector
from app.analyzers.process_analyzer import ProcessTreeGraph
from app.database.connection import DatabaseManager
from app.database.repository import EventRepository, ImportJobRepository, ProcessRepository
from app.ingestion.base import BaseParser, RawRecord
from app.ingestion.evtx_parser import EVTXParser
from app.ingestion.json_parser import JSONParser
from app.ingestion.xml_parser import XMLParser, parse_event_xml
from app.models.events import EventCategory, NormalizedEvent
from app.models.fingerprint import compute_event_fingerprint
from app.models.stats import ImportStatistics, QuarantineRecord
from app.normalization.dispatcher import NormalizerDispatcher
from app.utils.security import sanitize_input_path

logger = logging.getLogger(__name__)


class IngestionResult(tuple):
    """Result container for ingest_and_persist: (events, stats, job_id).

    Provides property accessors and duplicate/inserted counts, as well as
    reconstructed process tree and detected lineage anomalies.
    """

    def __new__(
        cls,
        events: list[NormalizedEvent],
        stats: ImportStatistics,
        job_id: int,
        inserted_count: int = 0,
        duplicate_count: int = 0,
        process_tree: ProcessTreeGraph | None = None,
        anomalies: list[LineageAnomaly] | None = None,
    ):
        instance = super().__new__(cls, (events, stats, job_id))
        instance._events = events
        instance._stats = stats
        instance._job_id = job_id
        instance._inserted_count = inserted_count
        instance._duplicate_count = duplicate_count
        instance._process_tree = process_tree
        instance._anomalies = anomalies if anomalies is not None else []
        return instance

    @property
    def events(self) -> list[NormalizedEvent]:
        return self._events

    @property
    def stats(self) -> ImportStatistics:
        return self._stats

    @property
    def job_id(self) -> int:
        return self._job_id

    @property
    def inserted_count(self) -> int:
        return self._inserted_count

    @property
    def duplicate_count(self) -> int:
        return self._duplicate_count

    @property
    def process_tree(self) -> ProcessTreeGraph | None:
        return self._process_tree

    @property
    def anomalies(self) -> list[LineageAnomaly]:
        return self._anomalies

    def to_stats_tuple(self) -> tuple[ImportStatistics, int, int]:
        return (self._stats, self._job_id, self._inserted_count)


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
        db_manager: DatabaseManager | None = None,
        process_repo: ProcessRepository | None = None,
    ) -> None:
        self.base_dir = base_dir
        self.dispatcher = dispatcher or NormalizerDispatcher()
        self.db_manager = db_manager
        self.event_repo = EventRepository(db_manager) if db_manager is not None else None
        self.job_repo = ImportJobRepository(db_manager) if db_manager is not None else None
        self._process_repo = process_repo if process_repo is not None else (
            ProcessRepository(db_manager) if db_manager is not None else None
        )
        self._detector = LineageAnomalyDetector()
        self.seen_hashes: set[str] = set()

    @property
    def process_repo(self) -> ProcessRepository | None:
        """Process repository access."""
        return self._process_repo

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

    def ingest_and_persist(
        self,
        file_path: str | Path,
        base_dir: Path | None = None,
        chunk_size: int = 1000,
        db_manager: DatabaseManager | None = None,
        return_events: bool = True,
        sync_processes: bool = True,
    ) -> IngestionResult | tuple[ImportStatistics, int, int]:
        """Ingest a log file, audit file and job lifecycles, and persist events to SQLite.

        Coordinates:
        1. Path sanitization and SHA-256 file hashing.
        2. Creation or update of imported_files and import_jobs records.
        3. Streaming ingestion and normalization.
        4. High-throughput chunked batch insertion into the database with duplicate suppression.
        5. Reconciliation of job metrics and marking status COMPLETED (or FAILED on error).
        6. Optional process tree reconstruction, suspicious lineage detection, and SQLite persistence.

        Returns:
            IngestionResult (unpackable as (events, stats, job_id)) or
            tuple of (stats, job_id, inserted_count) if return_events is False.
        """
        if isinstance(base_dir, DatabaseManager):
            db_manager = base_dir
            base_dir = None

        active_db = db_manager or self.db_manager
        if active_db is None:
            raise ValueError(
                "DatabaseManager must be configured on IngestionPipeline or passed to ingest_and_persist"
            )

        event_repo = (
            self.event_repo
            if (active_db is self.db_manager and self.event_repo is not None)
            else EventRepository(active_db)
        )
        job_repo = (
            self.job_repo
            if (active_db is self.db_manager and self.job_repo is not None)
            else ImportJobRepository(active_db)
        )
        process_repo = (
            self.process_repo
            if (active_db is self.db_manager and self.process_repo is not None)
            else ProcessRepository(active_db)
        )

        effective_base_dir = base_dir if base_dir is not None else self.base_dir
        resolved_path = sanitize_input_path(
            user_path=file_path,
            base_dir=effective_base_dir,
            allowed_extensions=[".evtx", ".xml", ".json", ".jsonl"],
        )

        # Compute SHA-256 hash and file size
        sha256 = hashlib.sha256()
        with open(resolved_path, "rb") as f:
            for block in iter(lambda: f.read(65536), b""):
                sha256.update(block)
        file_hash = sha256.hexdigest()
        file_size = resolved_path.stat().st_size

        file_id = job_repo.create_or_get_imported_file(
            file_path=str(resolved_path),
            file_name=resolved_path.name,
            file_size_bytes=file_size,
            file_hash_sha256=file_hash,
        )

        job_id = job_repo.create_import_job(
            file_id=file_id,
            file_path=str(resolved_path),
            status="RUNNING",
        )

        try:
            normalized_events, stats = self.ingest_file(
                file_path=resolved_path,
                base_dir=effective_base_dir,
            )
        except Exception as err:
            logger.exception("Ingestion failed in ingest_and_persist: %s", err)
            job_repo.update_import_job(
                job_id=job_id,
                status="FAILED",
                total_events=0,
                parsed_events=0,
                malformed_events=1,
                quarantined_events=0,
                duplicate_events=0,
                error_log=[f"Ingestion failure: {err}"],
            )
            raise

        try:
            inserted, duplicates = event_repo.insert_events_batch(
                events=normalized_events,
                import_job_id=job_id,
                chunk_size=chunk_size,
            )

            # Reconcile database duplicates
            if duplicates > 0:
                stats.parsed_events = max(0, stats.parsed_events - duplicates)
                stats.duplicate_events += duplicates

            job_repo.update_import_job(
                job_id=job_id,
                status="COMPLETED",
                total_events=stats.total_events,
                parsed_events=stats.parsed_events,
                malformed_events=stats.malformed_events,
                quarantined_events=len(stats.quarantined_records),
                duplicate_events=stats.duplicate_events,
                error_log=stats.error_log if stats.error_log else None,
            )
        except Exception as err:
            logger.exception("Database persistence failed in ingest_and_persist: %s", err)
            job_repo.update_import_job(
                job_id=job_id,
                status="FAILED",
                total_events=stats.total_events,
                parsed_events=stats.parsed_events,
                malformed_events=stats.malformed_events + 1,
                quarantined_events=len(stats.quarantined_records),
                duplicate_events=stats.duplicate_events,
                error_log=stats.error_log + [f"Persistence failure: {err}"],
            )
            raise

        process_tree: ProcessTreeGraph | None = None
        anomalies: list[LineageAnomaly] = []

        if sync_processes:
            try:
                process_events = [
                    e for e in normalized_events
                    if e.event_category == EventCategory.PROCESS
                ]
                if process_events:
                    process_tree = ProcessTreeGraph()
                    process_tree.build_from_events(process_events)
                    anomalies = self._detector.evaluate_graph(process_tree)
                    nodes_to_persist = list(process_tree._nodes.values())
                    if nodes_to_persist:
                        process_repo.upsert_processes_batch(
                            nodes=nodes_to_persist,
                            chunk_size=chunk_size,
                        )

                    for event in process_events:
                        if event.event_id == 5 or event.event_type in ("PROCESS_TERMINATE", "PROCESS_TERMINATION"):
                            exit_code = None
                            if event.extra_fields and "ExitCode" in event.extra_fields:
                                try:
                                    exit_code = int(str(event.extra_fields["ExitCode"]), 0)
                                except (ValueError, TypeError):
                                    exit_code = None
                            process_repo.update_process_termination(
                                computer=event.computer,
                                pid=event.process_id,
                                termination_time=event.timestamp,
                                exit_code=exit_code,
                                process_guid=event.process_guid,
                            )
            except Exception as err:
                logger.exception("Process sync failed in ingest_and_persist: %s", err)
                raise

        if not return_events:
            return (stats, job_id, inserted)

        return IngestionResult(
            events=normalized_events,
            stats=stats,
            job_id=job_id,
            inserted_count=inserted,
            duplicate_count=stats.duplicate_events,
            process_tree=process_tree,
            anomalies=anomalies,
        )
