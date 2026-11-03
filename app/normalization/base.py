"""Base normalizer interface and common extraction utilities for WinSentinel."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from app.models.events import NormalizedEvent, parse_windows_timestamp
from app.models.fingerprint import compute_event_fingerprint


class BaseNormalizer(ABC):
    """Abstract base class for event normalizers."""

    @abstractmethod
    def normalize(
        self,
        system_fields: dict[str, Any],
        data_fields: dict[str, Any],
        raw_payload: str,
    ) -> NormalizedEvent:
        """Normalize raw system and event data fields into a strongly-typed NormalizedEvent.

        Args:
            system_fields: Dictionary of Windows System header fields.
            data_fields: Dictionary of EventData / UserData key-value fields.
            raw_payload: Unmodified raw event string for forensic provenance.

        Returns:
            An immutable NormalizedEvent instance.
        """

    @staticmethod
    def get_field_case_insensitive(fields: dict[str, Any], *candidates: str) -> str | None:
        """Retrieve a field value case-insensitively from a dictionary.

        Args:
            fields: Source key-value dictionary.
            candidates: List of candidate key names in priority order.

        Returns:
            The string value if found, or None.
        """
        if not fields:
            return None

        # Build lowercased lookup map
        lowered_map: dict[str, Any] = {k.lower(): v for k, v in fields.items()}
        for cand in candidates:
            cand_lower = cand.lower()
            if cand_lower in lowered_map:
                val = lowered_map[cand_lower]
                if val is not None:
                    s_val = str(val).strip()
                    if s_val:
                        return s_val
        return None

    @staticmethod
    def get_int_field_case_insensitive(fields: dict[str, Any], *candidates: str) -> int | None:
        """Retrieve and convert an integer field case-insensitively.

        Handles decimal strings and hexadecimal strings ('0x1f4').
        """
        raw_val = BaseNormalizer.get_field_case_insensitive(fields, *candidates)
        if raw_val is None or raw_val == "-":
            return None

        try:
            if raw_val.lower().startswith("0x"):
                return int(raw_val, 16)
            return int(raw_val, 10)
        except (ValueError, TypeError):
            # Attempt hex fallback if decimal failed on alphanumeric hex
            try:
                return int(raw_val, 16)
            except (ValueError, TypeError):
                return None

    def extract_common_system(
        self,
        system_fields: dict[str, Any],
        raw_payload: str,
    ) -> tuple[dict[str, Any], bool, list[str]]:
        """Extract core Windows System header fields and check for required telemetry.

        Returns:
            Tuple of:
                - Dict with extracted system properties (event_id, record_id, provider, channel, computer, timestamp, event_hash)
                - Boolean flag is_quarantined
                - List of quarantine reason strings
        """
        quarantine_reasons: list[str] = []
        is_quarantined = False

        # 1. EventID
        raw_eid = self.get_field_case_insensitive(system_fields, "EventID", "event_id", "Id")
        event_id = 0
        if raw_eid is not None:
            try:
                event_id = int(raw_eid)
            except ValueError:
                is_quarantined = True
                quarantine_reasons.append(f"Invalid non-integer EventID: {raw_eid}")
        else:
            is_quarantined = True
            quarantine_reasons.append("Missing required EventID in System fields")

        # 2. RecordID
        raw_rec_id = self.get_field_case_insensitive(
            system_fields,
            "EventRecordID",
            "record_id",
            "RecordId",
        )
        record_id: int | None = None
        if raw_rec_id is not None:
            try:
                record_id = int(raw_rec_id)
            except ValueError:
                record_id = None

        # 3. Provider
        provider = self.get_field_case_insensitive(
            system_fields,
            "Provider",
            "ProviderName",
            "provider",
        )
        if not provider:
            provider = "UnknownProvider"
            is_quarantined = True
            quarantine_reasons.append("Missing required Provider name in System fields")

        # 4. Channel
        channel = self.get_field_case_insensitive(
            system_fields,
            "Channel",
            "channel",
        )
        if not channel:
            channel = "UnknownChannel"

        # 5. Computer
        computer = self.get_field_case_insensitive(
            system_fields,
            "Computer",
            "computer",
            "MachineName",
        )
        if not computer:
            computer = "UnknownComputer"

        # 6. TimeCreated
        raw_time = self.get_field_case_insensitive(
            system_fields,
            "TimeCreated",
            "SystemTime",
            "timestamp",
            "UtcTime",
        )
        if raw_time:
            try:
                timestamp = parse_windows_timestamp(raw_time, fallback_on_error=False)
            except ValueError as err:
                is_quarantined = True
                quarantine_reasons.append(f"Invalid timestamp format '{raw_time}': {err}")
                timestamp = datetime.now(timezone.utc)
        else:
            is_quarantined = True
            quarantine_reasons.append("Missing required TimeCreated timestamp in System fields")
            timestamp = datetime.now(timezone.utc)

        # 7. Compute deterministic fingerprint
        event_hash = compute_event_fingerprint(
            computer=computer,
            provider=provider,
            channel=channel,
            record_id=record_id,
            raw_payload=raw_payload,
        )

        extracted = {
            "event_id": event_id,
            "record_id": record_id,
            "provider": provider,
            "channel": channel,
            "computer": computer,
            "timestamp": timestamp,
            "event_hash": event_hash,
        }
        return extracted, is_quarantined, quarantine_reasons
