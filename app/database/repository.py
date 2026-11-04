"""Forensic repository access layer for WinSentinel.

Provides high-throughput bulk event persistence, duplicate suppression,
audit tracking of imported files/jobs, and alert evidence management.
"""

from __future__ import annotations

import json
import logging
import math
from datetime import datetime, timezone
from typing import Any

import sqlite3

from app.analyzers.process_analyzer import ProcessNode, ProcessTreeGraph
from app.database.connection import DatabaseManager
from app.database.query import (
    AlertFilter,
    EventFilter,
    PaginatedResult,
    build_alert_where_clause,
    build_event_where_clause,
)
from app.models.events import EventCategory, NormalizedEvent

logger = logging.getLogger(__name__)

EVENT_COLUMNS = [
    "import_job_id",
    "event_id",
    "record_id",
    "provider",
    "channel",
    "computer",
    "timestamp_utc",
    "event_category",
    "event_type",
    "process_guid",
    "process_id",
    "image",
    "command_line",
    "current_directory",
    "user",
    "logon_guid",
    "logon_id",
    "integrity_level",
    "hashes_json",
    "parent_process_guid",
    "parent_process_id",
    "parent_image",
    "parent_command_line",
    "parent_user",
    "target_process_guid",
    "target_process_id",
    "target_image",
    "granted_access",
    "call_trace",
    "source_ip",
    "source_port",
    "source_hostname",
    "destination_ip",
    "destination_port",
    "destination_hostname",
    "protocol",
    "query_name",
    "query_status",
    "query_results",
    "target_filename",
    "image_loaded",
    "signed",
    "signature",
    "signature_status",
    "registry_event_type",
    "registry_target_object",
    "registry_details",
    "registry_new_name",
    "wmi_operation",
    "wmi_consumer",
    "wmi_filter",
    "wmi_query",
    "service_name",
    "service_file_name",
    "task_name",
    "task_content",
    "script_block_text",
    "script_block_id",
    "script_path",
    "extra_fields_json",
    "raw_payload",
    "event_hash",
    "is_quarantined",
    "quarantine_reasons_json",
]

_EVENT_COLUMNS_STR = ", ".join(EVENT_COLUMNS)
_EVENT_PLACEHOLDERS_STR = ", ".join("?" for _ in EVENT_COLUMNS)
INSERT_EVENT_SQL = (
    f"INSERT OR IGNORE INTO events ({_EVENT_COLUMNS_STR}) "
    f"VALUES ({_EVENT_PLACEHOLDERS_STR});"
)

INSERT_PROCESS_IGNORE_SQL = """
INSERT OR IGNORE INTO processes (
    process_guid, process_id, computer, image, command_line,
    current_directory, user, integrity_level, parent_process_guid,
    parent_process_id, parent_image, parent_command_line,
    start_time, end_time, exit_code, is_synthesized,
    is_orphaned, is_anomalous, anomaly_reasons_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

UPSERT_PROCESS_SQL = """
INSERT INTO processes (
    process_guid, process_id, computer, image, command_line,
    current_directory, user, integrity_level, parent_process_guid,
    parent_process_id, parent_image, parent_command_line,
    start_time, end_time, exit_code, is_synthesized,
    is_orphaned, is_anomalous, anomaly_reasons_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(process_guid) DO UPDATE SET
    end_time = coalesce(excluded.end_time, processes.end_time),
    exit_code = coalesce(excluded.exit_code, processes.exit_code),
    is_synthesized = CASE 
        WHEN processes.is_synthesized = 1 AND excluded.is_synthesized = 0 THEN 0 
        ELSE processes.is_synthesized 
    END,
    process_id = CASE 
        WHEN processes.is_synthesized = 1 AND excluded.is_synthesized = 0 THEN excluded.process_id 
        ELSE processes.process_id 
    END,
    start_time = CASE 
        WHEN processes.is_synthesized = 1 AND excluded.is_synthesized = 0 THEN excluded.start_time 
        ELSE processes.start_time 
    END,
    is_orphaned = CASE 
        WHEN processes.is_synthesized = 1 AND excluded.is_synthesized = 0 THEN excluded.is_orphaned 
        ELSE processes.is_orphaned 
    END,
    image = CASE 
        WHEN processes.is_synthesized = 1 AND excluded.is_synthesized = 0 THEN excluded.image 
        ELSE processes.image 
    END,
    command_line = CASE
        WHEN excluded.command_line IS NOT NULL THEN excluded.command_line
        ELSE processes.command_line
    END,
    user = CASE
        WHEN excluded.user IS NOT NULL THEN excluded.user
        ELSE processes.user
    END,
    parent_process_guid = CASE
        WHEN excluded.parent_process_guid IS NOT NULL THEN excluded.parent_process_guid
        ELSE processes.parent_process_guid
    END,
    parent_process_id = CASE
        WHEN excluded.parent_process_id IS NOT NULL THEN excluded.parent_process_id
        ELSE processes.parent_process_id
    END,
    parent_image = CASE
        WHEN excluded.parent_image IS NOT NULL THEN excluded.parent_image
        ELSE processes.parent_image
    END,
    parent_command_line = CASE
        WHEN excluded.parent_command_line IS NOT NULL THEN excluded.parent_command_line
        ELSE processes.parent_command_line
    END,
    is_anomalous = max(processes.is_anomalous, excluded.is_anomalous),
    anomaly_reasons_json = CASE
        WHEN excluded.anomaly_reasons_json IS NOT NULL AND excluded.anomaly_reasons_json != '[]' THEN excluded.anomaly_reasons_json
        ELSE processes.anomaly_reasons_json
    END;
"""


class ImportJobRepository:
    """Manages file import tracking and job execution audits."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db_manager = db_manager

    def create_or_get_imported_file(
        self,
        file_path: str,
        file_name: str,
        file_size_bytes: int,
        file_hash_sha256: str,
    ) -> int:
        """Register an imported file or update its last imported timestamp if already seen."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT id FROM imported_files WHERE file_hash_sha256 = ?;",
                (file_hash_sha256,),
            )
            row = cur.fetchone()
            if row is not None:
                file_id = int(row["id"])
                cur.execute(
                    """
                    UPDATE imported_files
                    SET file_path = ?, file_name = ?, file_size_bytes = ?, last_imported_at = ?
                    WHERE id = ?;
                    """,
                    (file_path, file_name, file_size_bytes, now_utc, file_id),
                )
                return file_id

            cur.execute(
                """
                INSERT INTO imported_files (
                    file_path, file_name, file_size_bytes, file_hash_sha256,
                    first_imported_at, last_imported_at
                ) VALUES (?, ?, ?, ?, ?, ?);
                """,
                (file_path, file_name, file_size_bytes, file_hash_sha256, now_utc, now_utc),
            )
            return int(cur.lastrowid)

    def create_import_job(
        self,
        file_id: int | None,
        file_path: str,
        status: str = "RUNNING",
    ) -> int:
        """Create a new import job record in status RUNNING."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO import_jobs (
                    file_id, file_path, status, start_time,
                    total_events, parsed_events, malformed_events,
                    quarantined_events, duplicate_events
                ) VALUES (?, ?, ?, ?, 0, 0, 0, 0, 0);
                """,
                (file_id, file_path, status, now_utc),
            )
            return int(cur.lastrowid)

    def update_import_job(
        self,
        job_id: int,
        status: str,
        total_events: int,
        parsed_events: int,
        malformed_events: int,
        quarantined_events: int,
        duplicate_events: int,
        error_log: list[str] | None = None,
    ) -> None:
        """Update job metrics, completion timestamp, status, and error logs."""
        now_utc = datetime.now(timezone.utc).isoformat()
        error_log_json = json.dumps(error_log) if error_log is not None else None
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE import_jobs
                SET status = ?, end_time = ?, total_events = ?, parsed_events = ?,
                    malformed_events = ?, quarantined_events = ?, duplicate_events = ?,
                    error_log_json = ?
                WHERE id = ?;
                """,
                (
                    status,
                    now_utc,
                    total_events,
                    parsed_events,
                    malformed_events,
                    quarantined_events,
                    duplicate_events,
                    error_log_json,
                    job_id,
                ),
            )

    def get_import_job(self, job_id: int) -> dict[str, Any] | None:
        """Fetch import job details by ID."""
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM import_jobs WHERE id = ?;", (job_id,))
            row = cur.fetchone()
            if row is None:
                return None
            res = dict(row)
            if res.get("error_log_json"):
                try:
                    res["error_log"] = json.loads(res["error_log_json"])
                except Exception:
                    res["error_log"] = []
            else:
                res["error_log"] = []
            return res


# Alias to match plan specification
ImportedFileRepository = ImportJobRepository


class EventRepository:
    """High-throughput bulk persistence and forensic retrieval for NormalizedEvent records."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db_manager = db_manager

    @staticmethod
    def _event_to_row(
        event: NormalizedEvent,
        import_job_id: int | None = None,
    ) -> tuple[Any, ...]:
        """Convert a NormalizedEvent to a 64-element row tuple matching the events schema."""
        return (
            import_job_id,
            event.event_id,
            event.record_id,
            event.provider,
            event.channel,
            event.computer,
            event.timestamp.isoformat(),
            event.event_category.value,
            event.event_type,
            event.process_guid,
            event.process_id,
            event.image,
            event.command_line,
            event.current_directory,
            event.user,
            event.logon_guid,
            event.logon_id,
            event.integrity_level,
            json.dumps(event.hashes) if event.hashes else None,
            event.parent_process_guid,
            event.parent_process_id,
            event.parent_image,
            event.parent_command_line,
            event.parent_user,
            event.target_process_guid,
            event.target_process_id,
            event.target_image,
            event.granted_access,
            event.call_trace,
            event.source_ip,
            event.source_port,
            event.source_hostname,
            event.destination_ip,
            event.destination_port,
            event.destination_hostname,
            event.protocol,
            event.query_name,
            event.query_status,
            event.query_results,
            event.target_filename,
            event.image_loaded,
            event.signed,
            event.signature,
            event.signature_status,
            event.registry_event_type,
            event.registry_target_object,
            event.registry_details,
            event.registry_new_name,
            event.wmi_operation,
            event.wmi_consumer,
            event.wmi_filter,
            event.wmi_query,
            event.service_name,
            event.service_file_name,
            event.task_name,
            event.task_content,
            event.script_block_text,
            event.script_block_id,
            event.script_path,
            json.dumps(event.extra_fields) if event.extra_fields else None,
            event.raw_payload,
            event.event_hash,
            1 if event.is_quarantined else 0,
            json.dumps(event.quarantine_reasons) if event.quarantine_reasons else None,
        )

    @staticmethod
    def _row_to_event(row: Any) -> NormalizedEvent:
        """Convert a database row into an immutable NormalizedEvent model."""
        hashes = (
            json.loads(row["hashes_json"])
            if row["hashes_json"]
            else {}
        )
        extra_fields = (
            json.loads(row["extra_fields_json"])
            if row["extra_fields_json"]
            else {}
        )
        quarantine_reasons = (
            json.loads(row["quarantine_reasons_json"])
            if row["quarantine_reasons_json"]
            else []
        )
        cat_str = row["event_category"]
        category = (
            EventCategory(cat_str)
            if cat_str in EventCategory._value2member_map_
            else EventCategory.GENERIC
        )

        return NormalizedEvent(
            event_id=row["event_id"],
            record_id=row["record_id"],
            provider=row["provider"],
            channel=row["channel"],
            computer=row["computer"],
            timestamp=row["timestamp_utc"],
            event_category=category,
            event_type=row["event_type"],
            process_guid=row["process_guid"],
            process_id=row["process_id"],
            image=row["image"],
            command_line=row["command_line"],
            current_directory=row["current_directory"],
            user=row["user"],
            logon_guid=row["logon_guid"],
            logon_id=row["logon_id"],
            integrity_level=row["integrity_level"],
            hashes=hashes,
            parent_process_guid=row["parent_process_guid"],
            parent_process_id=row["parent_process_id"],
            parent_image=row["parent_image"],
            parent_command_line=row["parent_command_line"],
            parent_user=row["parent_user"],
            target_process_guid=row["target_process_guid"],
            target_process_id=row["target_process_id"],
            target_image=row["target_image"],
            granted_access=row["granted_access"],
            call_trace=row["call_trace"],
            source_ip=row["source_ip"],
            source_port=row["source_port"],
            source_hostname=row["source_hostname"],
            destination_ip=row["destination_ip"],
            destination_port=row["destination_port"],
            destination_hostname=row["destination_hostname"],
            protocol=row["protocol"],
            query_name=row["query_name"],
            query_status=row["query_status"],
            query_results=row["query_results"],
            target_filename=row["target_filename"],
            image_loaded=row["image_loaded"],
            signed=row["signed"],
            signature=row["signature"],
            signature_status=row["signature_status"],
            registry_event_type=row["registry_event_type"],
            registry_target_object=row["registry_target_object"],
            registry_details=row["registry_details"],
            registry_new_name=row["registry_new_name"],
            wmi_operation=row["wmi_operation"],
            wmi_consumer=row["wmi_consumer"],
            wmi_filter=row["wmi_filter"],
            wmi_query=row["wmi_query"],
            service_name=row["service_name"],
            service_file_name=row["service_file_name"],
            task_name=row["task_name"],
            task_content=row["task_content"],
            script_block_text=row["script_block_text"],
            script_block_id=row["script_block_id"],
            script_path=row["script_path"],
            extra_fields=extra_fields,
            raw_payload=row["raw_payload"],
            event_hash=row["event_hash"],
            is_quarantined=bool(row["is_quarantined"]),
            quarantine_reasons=quarantine_reasons,
        )

    def insert_events_batch(
        self,
        events: list[NormalizedEvent],
        import_job_id: int | None = None,
        chunk_size: int = 1000,
    ) -> tuple[int, int]:
        """Insert normalized events in bounded chunk transactions.

        Suppresses duplicate event_hash values atomically using INSERT OR IGNORE.

        Returns:
            Tuple of (inserted_count, duplicate_count).
        """
        if not events:
            return 0, 0

        total_inserted = 0
        total_duplicates = 0
        safe_chunk_size = max(1, chunk_size)

        for i in range(0, len(events), safe_chunk_size):
            chunk = events[i : i + safe_chunk_size]
            rows = [self._event_to_row(e, import_job_id) for e in chunk]

            with self.db_manager.get_connection() as conn:
                cur = conn.cursor()
                cur.executemany(INSERT_EVENT_SQL, rows)
                chunk_inserted = cur.rowcount
                # sqlite3 cursor.rowcount returns the number of rows inserted
                chunk_duplicates = len(chunk) - chunk_inserted

                total_inserted += chunk_inserted
                total_duplicates += chunk_duplicates

        return total_inserted, total_duplicates

    def get_event_by_hash(self, event_hash: str) -> NormalizedEvent | None:
        """Fetch a single normalized event by its unique SHA-256 fingerprint."""
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM events WHERE event_hash = ?;", (event_hash,))
            row = cur.fetchone()
            if row is None:
                return None
            return self._row_to_event(row)

    def get_event_by_id(self, event_id: int) -> NormalizedEvent | None:
        """Fetch a single normalized event by its database primary key ID."""
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM events WHERE id = ?;", (event_id,))
            row = cur.fetchone()
            if row is None:
                return None
            return self._row_to_event(row)

    def get_db_id_by_hash(self, event_hash: str) -> int | None:
        """Fetch internal database primary key integer ID for an event hash."""
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM events WHERE event_hash = ?;", (event_hash,))
            row = cur.fetchone()
            if row is None:
                return None
            return int(row["id"])

    def query_events(
        self,
        filter_params: EventFilter | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> PaginatedResult[NormalizedEvent]:
        """Perform a two-step paginated query for events matching the given filter.

        1. COUNT(*) via B-tree index traversal.
        2. If count > 0 and page within bounds, paginated SELECT with LIMIT and OFFSET.
        """
        where_clause, base_params = build_event_where_clause(filter_params)
        safe_page = max(1, page)
        safe_page_size = max(1, page_size)

        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            # Step 1: Direct count
            cur.execute(f"SELECT COUNT(*) FROM events WHERE {where_clause};", base_params)
            total_count = int(cur.fetchone()[0])
            total_pages = math.ceil(total_count / safe_page_size) if total_count > 0 else 0

            # Step 2: Skip fetch if 0 rows or page is out of bounds
            if total_count == 0 or safe_page > total_pages:
                return PaginatedResult(
                    items=[],
                    total_count=total_count,
                    page=safe_page,
                    page_size=safe_page_size,
                    total_pages=total_pages,
                )

            offset = (safe_page - 1) * safe_page_size
            select_sql = (
                f"SELECT * FROM events WHERE {where_clause} "
                "ORDER BY timestamp_utc DESC LIMIT ? OFFSET ?;"
            )
            cur.execute(select_sql, base_params + [safe_page_size, offset])
            rows = cur.fetchall()
            items = [self._row_to_event(r) for r in rows]

            return PaginatedResult(
                items=items,
                total_count=total_count,
                page=safe_page,
                page_size=safe_page_size,
                total_pages=total_pages,
            )


class AlertRepository:
    """Manages threat detection alerts, triage status lifecycles, evidence, and notes."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db_manager = db_manager

    def create_alert(
        self,
        title: str,
        severity: str,
        computer: str,
        status: str = "New",
        rule_id: str | None = None,
        description: str | None = None,
        user: str | None = None,
        process_guid: str | None = None,
        first_seen: datetime | str | None = None,
        last_seen: datetime | str | None = None,
        event_count: int = 1,
        mitre_tactics: list[str] | None = None,
        mitre_techniques: list[str] | None = None,
    ) -> int:
        """Create a new alert record and return its primary key ID."""
        now_utc = datetime.now(timezone.utc).isoformat()
        first_seen_str = (
            first_seen.isoformat()
            if isinstance(first_seen, datetime)
            else (str(first_seen) if first_seen else now_utc)
        )
        last_seen_str = (
            last_seen.isoformat()
            if isinstance(last_seen, datetime)
            else (str(last_seen) if last_seen else now_utc)
        )
        tactics_json = json.dumps(mitre_tactics) if mitre_tactics is not None else None
        techniques_json = (
            json.dumps(mitre_techniques) if mitre_techniques is not None else None
        )

        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO alerts (
                    rule_id, title, severity, status, description,
                    computer, user, process_guid, first_seen, last_seen,
                    event_count, created_at, updated_at,
                    mitre_tactics_json, mitre_techniques_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    rule_id,
                    title,
                    severity,
                    status,
                    description,
                    computer,
                    user,
                    process_guid,
                    first_seen_str,
                    last_seen_str,
                    event_count,
                    now_utc,
                    now_utc,
                    tactics_json,
                    techniques_json,
                ),
            )
            return int(cur.lastrowid)

    def update_alert_status(self, alert_id: int, status: str) -> None:
        """Update an alert's triage status and touch updated_at."""
        now_utc = datetime.now(timezone.utc).isoformat()
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?;",
                (status, now_utc, alert_id),
            )

    def touch_alert(
        self,
        alert_id: int,
        last_seen: str | datetime,
        count_increment: int = 1,
    ) -> None:
        """Atomically increment event_count and update last_seen and updated_at timestamps."""
        now_utc = datetime.now(timezone.utc).isoformat()
        last_seen_str = (
            last_seen.isoformat()
            if isinstance(last_seen, datetime)
            else str(last_seen)
        )
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE alerts
                SET event_count = event_count + ?,
                    last_seen = ?,
                    updated_at = ?
                WHERE id = ?;
                """,
                (count_increment, last_seen_str, now_utc, alert_id),
            )

    def link_alert_evidence(
        self,
        alert_id: int,
        event_id: int,
        matched_field: str | None = None,
        matched_value: str | None = None,
        explanation: str | None = None,
    ) -> int:
        """Link a normalized event as forensic evidence supporting an alert."""
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT OR IGNORE INTO alert_evidence (
                    alert_id, event_id, matched_field, matched_value, explanation
                ) VALUES (?, ?, ?, ?, ?);
                """,
                (alert_id, event_id, matched_field, matched_value, explanation),
            )
            return int(cur.lastrowid)

    def add_analyst_note(
        self,
        author: str,
        note_text: str,
        alert_id: int | None = None,
        investigation_id: int | None = None,
    ) -> int:
        """Attach an auditable analyst investigation note."""
        if alert_id is None and investigation_id is None:
            raise ValueError("Either alert_id or investigation_id must be provided")

        now_utc = datetime.now(timezone.utc).isoformat()
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO analyst_notes (
                    alert_id, investigation_id, author, note_text, created_at
                ) VALUES (?, ?, ?, ?, ?);
                """,
                (alert_id, investigation_id, author, note_text, now_utc),
            )
            return int(cur.lastrowid)

    def get_alert(self, alert_id: int) -> dict[str, Any] | None:
        """Fetch complete alert details including evidence links and analyst notes."""
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM alerts WHERE id = ?;", (alert_id,))
            row = cur.fetchone()
            if row is None:
                return None

            alert_dict = dict(row)
            if alert_dict.get("mitre_tactics_json"):
                try:
                    alert_dict["mitre_tactics"] = json.loads(alert_dict["mitre_tactics_json"])
                except Exception:
                    alert_dict["mitre_tactics"] = []
            else:
                alert_dict["mitre_tactics"] = []

            if alert_dict.get("mitre_techniques_json"):
                try:
                    alert_dict["mitre_techniques"] = json.loads(alert_dict["mitre_techniques_json"])
                except Exception:
                    alert_dict["mitre_techniques"] = []
            else:
                alert_dict["mitre_techniques"] = []

            # Fetch linked evidence
            cur.execute("SELECT * FROM alert_evidence WHERE alert_id = ?;", (alert_id,))
            alert_dict["evidence"] = [dict(r) for r in cur.fetchall()]

            # Fetch analyst notes
            cur.execute(
                "SELECT * FROM analyst_notes WHERE alert_id = ? ORDER BY created_at ASC;",
                (alert_id,),
            )
            alert_dict["notes"] = [dict(r) for r in cur.fetchall()]

            return alert_dict

    def delete_alert(self, alert_id: int) -> bool:
        """Delete an alert and cascade-delete its evidence and notes."""
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM alerts WHERE id = ?;", (alert_id,))
            return cur.rowcount > 0

    def query_alerts(
        self,
        filter_params: AlertFilter | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> PaginatedResult[dict[str, Any]]:
        """Paginated search for alerts matching filter criteria."""
        where_clause, base_params = build_alert_where_clause(filter_params)
        safe_page = max(1, page)
        safe_page_size = max(1, page_size)

        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(f"SELECT COUNT(*) FROM alerts WHERE {where_clause};", base_params)
            total_count = int(cur.fetchone()[0])
            total_pages = math.ceil(total_count / safe_page_size) if total_count > 0 else 0

            if total_count == 0 or safe_page > total_pages:
                return PaginatedResult(
                    items=[],
                    total_count=total_count,
                    page=safe_page,
                    page_size=safe_page_size,
                    total_pages=total_pages,
                )

            offset = (safe_page - 1) * safe_page_size
            select_sql = (
                f"SELECT * FROM alerts WHERE {where_clause} "
                "ORDER BY created_at DESC LIMIT ? OFFSET ?;"
            )
            cur.execute(select_sql, base_params + [safe_page_size, offset])
            rows = cur.fetchall()
            items = []
            for r in rows:
                item = dict(r)
                if item.get("mitre_tactics_json"):
                    try:
                        item["mitre_tactics"] = json.loads(item["mitre_tactics_json"])
                    except Exception:
                        item["mitre_tactics"] = []
                else:
                    item["mitre_tactics"] = []

                if item.get("mitre_techniques_json"):
                    try:
                        item["mitre_techniques"] = json.loads(item["mitre_techniques_json"])
                    except Exception:
                        item["mitre_techniques"] = []
                else:
                    item["mitre_techniques"] = []
                items.append(item)

            return PaginatedResult(
                items=items,
                total_count=total_count,
                page=safe_page,
                page_size=safe_page_size,
                total_pages=total_pages,
            )


class InvestigationRepository:
    """Manages forensic investigations, incident escalations, and status tracking."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db_manager = db_manager

    def create_investigation(
        self,
        title: str,
        priority: str = "Medium",
        lead_analyst: str | None = None,
        summary: str | None = None,
        status: str = "Open",
        created_at: datetime | str | None = None,
    ) -> int:
        """Create a new investigation record and return its primary key ID."""
        now_utc = datetime.now(timezone.utc).isoformat()
        created_at_str = (
            created_at.isoformat()
            if isinstance(created_at, datetime)
            else (str(created_at) if created_at else now_utc)
        )
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO investigations (
                    title, status, priority, lead_analyst, summary,
                    created_at, updated_at, closed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL);
                """,
                (title, status, priority, lead_analyst, summary, created_at_str, now_utc),
            )
            return int(cur.lastrowid)

    def get_investigation(self, investigation_id: int) -> dict[str, Any] | None:
        """Fetch investigation record and all associated analyst notes."""
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM investigations WHERE id = ?;", (investigation_id,))
            row = cur.fetchone()
            if row is None:
                return None
            inv_dict = dict(row)
            cur.execute(
                "SELECT * FROM analyst_notes WHERE investigation_id = ? ORDER BY created_at ASC;",
                (investigation_id,),
            )
            inv_dict["notes"] = [dict(r) for r in cur.fetchall()]
            return inv_dict

    def list_investigations(
        self,
        status: str | None = None,
        priority: str | None = None,
    ) -> list[dict[str, Any]]:
        """List investigations with optional status and priority filtering."""
        query = "SELECT * FROM investigations"
        clauses: list[str] = []
        params: list[Any] = []

        if status:
            clauses.append("status = ?")
            params.append(status)
        if priority:
            clauses.append("priority = ?")
            params.append(priority)

        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC;"

        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            return [dict(r) for r in cur.fetchall()]

    def update_investigation_status(
        self,
        investigation_id: int,
        status: str,
        closed_at: datetime | str | None = None,
    ) -> bool:
        """Update investigation status and set closed_at timestamp if closing."""
        now_utc = datetime.now(timezone.utc).isoformat()
        closed_at_str: str | None = None
        if closed_at is not None:
            closed_at_str = (
                closed_at.isoformat()
                if isinstance(closed_at, datetime)
                else str(closed_at)
            )
        elif status.lower() in ("closed", "resolved", "completed"):
            closed_at_str = now_utc

        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                UPDATE investigations
                SET status = ?,
                    updated_at = ?,
                    closed_at = coalesce(?, closed_at)
                WHERE id = ?;
                """,
                (status, now_utc, closed_at_str, investigation_id),
            )
            return cur.rowcount > 0


class ProcessRepository:
    """Manages SQLite persistence for reconstructed process nodes and lifespans."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db_manager = db_manager

    def upsert_process(self, conn: sqlite3.Connection, node: ProcessNode) -> None:
        """Insert or update a process record idempotently inside an active connection."""
        # Ensure parent exists if parent_process_guid is referenced to satisfy foreign key constraint
        if node.parent_process_guid:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM processes WHERE process_guid = ?;", (node.parent_process_guid,))
            if cur.fetchone() is None:
                cur.execute(
                    """
                    INSERT OR IGNORE INTO processes (
                        process_guid, process_id, computer, image, command_line,
                        start_time, is_synthesized, is_orphaned
                    ) VALUES (?, ?, ?, ?, ?, ?, 1, 1);
                    """,
                    (
                        node.parent_process_guid,
                        node.parent_process_id or 0,
                        node.computer,
                        node.parent_image or "UNKNOWN_PARENT.EXE",
                        node.parent_command_line,
                        node.start_time.isoformat(),
                    ),
                )

        conn.execute(
            UPSERT_PROCESS_SQL,
            (
                node.process_guid,
                node.process_id,
                node.computer,
                node.image,
                node.command_line,
                node.current_directory,
                node.user,
                node.integrity_level,
                node.parent_process_guid,
                node.parent_process_id,
                node.parent_image,
                node.parent_command_line,
                node.start_time.isoformat(),
                node.end_time.isoformat() if node.end_time else None,
                node.exit_code,
                1 if node.is_synthesized else 0,
                1 if node.is_orphaned else 0,
                1 if node.is_anomalous else 0,
                json.dumps(node.anomaly_reasons),
            ),
        )

    def upsert_processes_batch(
        self,
        nodes: list[ProcessNode],
        chunk_size: int = 1000,
    ) -> int:
        """Batch insert or update process records in atomic chunked transactions using executemany."""
        if not nodes:
            return 0

        total_processed = 0
        safe_chunk = max(1, chunk_size)

        for i in range(0, len(nodes), safe_chunk):
            chunk = nodes[i : i + safe_chunk]
            with self.db_manager.get_connection() as conn:
                # Ensure foreign key placeholder parents exist (only for parents outside this chunk)
                chunk_guids = {n.process_guid for n in chunk}
                parent_guids = {
                    n.parent_process_guid
                    for n in chunk
                    if n.parent_process_guid and n.parent_process_guid not in chunk_guids
                }
                if parent_guids:
                    cur = conn.cursor()
                    placeholders = ",".join("?" for _ in parent_guids)
                    cur.execute(
                        f"SELECT process_guid FROM processes WHERE process_guid IN ({placeholders});",
                        list(parent_guids),
                    )
                    existing = {row[0] for row in cur.fetchall()}
                    missing = parent_guids - existing
                    if missing:
                        missing_nodes = {
                            n.parent_process_guid: n
                            for n in chunk
                            if n.parent_process_guid in missing
                        }
                        placeholder_params = [
                            (
                                guid,
                                n.parent_process_id or 0,
                                n.computer,
                                n.parent_image or "UNKNOWN_PARENT.EXE",
                                n.parent_command_line,
                                n.start_time.isoformat(),
                            )
                            for guid, n in missing_nodes.items()
                        ]
                        conn.executemany(
                            """
                            INSERT OR IGNORE INTO processes (
                                process_guid, process_id, computer, image, command_line,
                                start_time, is_synthesized, is_orphaned
                            ) VALUES (?, ?, ?, ?, ?, ?, 1, 1);
                            """,
                            placeholder_params,
                        )

                params = [
                    (
                        node.process_guid,
                        node.process_id,
                        node.computer,
                        node.image,
                        node.command_line,
                        node.current_directory,
                        node.user,
                        node.integrity_level,
                        node.parent_process_guid,
                        node.parent_process_id,
                        node.parent_image,
                        node.parent_command_line,
                        node.start_time.isoformat(),
                        node.end_time.isoformat() if node.end_time else None,
                        node.exit_code,
                        1 if node.is_synthesized else 0,
                        1 if node.is_orphaned else 0,
                        1 if node.is_anomalous else 0,
                        json.dumps(node.anomaly_reasons) if node.anomaly_reasons else "[]",
                    )
                    for node in chunk
                ]
                cur = conn.cursor()
                cur.executemany(UPSERT_PROCESS_SQL, params)
                total_processed += len(chunk)

        return total_processed

    def update_process_termination(
        self,
        computer: str,
        pid: int,
        termination_time: datetime,
        exit_code: int | None = None,
        process_guid: str | None = None,
    ) -> bool:
        """Update termination timestamp and exit code in SQLite for specified process."""
        term_iso = (
            termination_time.isoformat()
            if isinstance(termination_time, datetime)
            else str(termination_time)
        )
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            if process_guid:
                cur.execute(
                    """
                    UPDATE processes
                    SET end_time = ?, exit_code = coalesce(?, exit_code)
                    WHERE process_guid = ?;
                    """,
                    (term_iso, exit_code, process_guid),
                )
                return cur.rowcount > 0
            else:
                cur.execute(
                    """
                    UPDATE processes
                    SET end_time = ?, exit_code = coalesce(?, exit_code)
                    WHERE process_guid = (
                        SELECT process_guid FROM processes
                        WHERE computer = ? AND process_id = ?
                          AND start_time <= ?
                          AND (end_time IS NULL OR end_time >= ?)
                        ORDER BY start_time DESC
                        LIMIT 1
                    );
                    """,
                    (term_iso, exit_code, computer, pid, term_iso, term_iso),
                )
                return cur.rowcount > 0

    def get_process_by_guid(self, process_guid: str) -> ProcessNode | None:
        """Retrieve a single ProcessNode by GUID."""
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM processes WHERE process_guid = ?;", (process_guid,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_node(row)

    def get_processes_by_computer(self, computer: str) -> list[ProcessNode]:
        """Retrieve all processes for a given host ordered by start_time ASC."""
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM processes WHERE computer = ? ORDER BY start_time ASC;",
                (computer,),
            )
            return [self._row_to_node(row) for row in cur.fetchall()]

    def get_all_processes(self, limit: int = 10000) -> list[ProcessNode]:
        """Retrieve all processes across hosts ordered by start_time ASC up to limit."""
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM processes ORDER BY start_time ASC LIMIT ?;",
                (limit,),
            )
            return [self._row_to_node(row) for row in cur.fetchall()]

    def hydrate_tree_graph(
        self,
        computer: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> ProcessTreeGraph:
        """Reconstruct a connected ProcessTreeGraph from persisted SQLite process records."""
        query = "SELECT * FROM processes"
        clauses: list[str] = []
        params: list[Any] = []

        if computer:
            clauses.append("computer = ?")
            params.append(computer)
        if start_time:
            clauses.append("start_time >= ?")
            params.append(start_time.isoformat())
        if end_time:
            clauses.append("start_time <= ?")
            params.append(end_time.isoformat())

        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY start_time ASC;"

        tree = ProcessTreeGraph()
        with self.db_manager.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            for row in cur.fetchall():
                node = self._row_to_node(row)
                tree.add_process(node)

        return tree

    # Alias for method name in plan
    hydrate_process_tree = hydrate_tree_graph

    def _row_to_node(self, row: sqlite3.Row) -> ProcessNode:
        """Map SQLite row columns back to an immutable ProcessNode instance."""
        keys = row.keys() if hasattr(row, "keys") else []
        raw_anomaly = row["anomaly_reasons_json"] if "anomaly_reasons_json" in keys else None
        anomaly_reasons = []
        if raw_anomaly:
            try:
                anomaly_reasons = json.loads(raw_anomaly)
            except Exception:
                anomaly_reasons = []

        return ProcessNode(
            process_guid=row["process_guid"],
            process_id=row["process_id"],
            computer=row["computer"] if "computer" in keys else "UNKNOWN",
            image=row["image"],
            command_line=row["command_line"],
            current_directory=row["current_directory"],
            user=row["user"],
            integrity_level=row["integrity_level"],
            hashes={},
            parent_process_guid=row["parent_process_guid"],
            parent_process_id=row["parent_process_id"],
            parent_image=row["parent_image"],
            parent_command_line=row["parent_command_line"],
            parent_user=row["parent_user"] if "parent_user" in keys else None,
            start_time=datetime.fromisoformat(row["start_time"]),
            end_time=datetime.fromisoformat(row["end_time"]) if ("end_time" in keys and row["end_time"]) else None,
            exit_code=row["exit_code"],
            is_synthesized=bool(row["is_synthesized"]) if "is_synthesized" in keys else False,
            is_orphaned=bool(row["is_orphaned"]),
            is_anomalous=bool(row["is_anomalous"]),
            anomaly_reasons=anomaly_reasons,
        )
