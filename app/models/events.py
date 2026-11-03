"""Normalized event schema and parsing utilities for WinSentinel."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventCategory(str, Enum):
    """Broad categories for Windows telemetry events."""

    PROCESS = "PROCESS"
    NETWORK = "NETWORK"
    DRIVER = "DRIVER"
    IMAGE_LOAD = "IMAGE_LOAD"
    REMOTE_THREAD = "REMOTE_THREAD"
    PROCESS_ACCESS = "PROCESS_ACCESS"
    FILE = "FILE"
    REGISTRY = "REGISTRY"
    WMI = "WMI"
    DNS = "DNS"
    SECURITY = "SECURITY"
    POWERSHELL = "POWERSHELL"
    GENERIC = "GENERIC"


def parse_windows_timestamp(
    ts_val: str | int | float | datetime | None,
    fallback_on_error: bool = False,
) -> datetime:
    """Parse heterogeneous Windows timestamp formats into a timezone-aware UTC datetime.

    Supports:
    - Python datetime objects (naive or aware)
    - Unix epoch timestamps (seconds or milliseconds as int/float/numeric string)
    - ISO-8601 with 7-digit nanosecond precision (e.g. '2023-04-10T14:22:15.1234567Z')
    - Sysmon space-delimited timestamps (e.g. '2023-04-10 14:22:15.120')
    """
    if ts_val is None or ts_val == "":
        if fallback_on_error:
            return datetime.now(timezone.utc)
        raise ValueError("Timestamp value cannot be empty or None")

    if isinstance(ts_val, datetime):
        if ts_val.tzinfo is None:
            return ts_val.replace(tzinfo=timezone.utc)
        return ts_val.astimezone(timezone.utc)

    if isinstance(ts_val, (int, float)):
        try:
            # Check if timestamp is in milliseconds (> 1e11 corresponds to year 1973+)
            if ts_val > 1e11:
                return datetime.fromtimestamp(ts_val / 1000.0, tz=timezone.utc)
            return datetime.fromtimestamp(ts_val, tz=timezone.utc)
        except (OSError, OverflowError, ValueError) as err:
            if fallback_on_error:
                return datetime.now(timezone.utc)
            raise ValueError(f"Invalid numeric timestamp: {ts_val}") from err

    ts_str = str(ts_val).strip()

    # Check for numeric string (epoch)
    if re.fullmatch(r"^-?\d+(\.\d+)?$", ts_str):
        try:
            num_val = float(ts_str) if "." in ts_str else int(ts_str)
            if num_val > 1e11:
                return datetime.fromtimestamp(num_val / 1000.0, tz=timezone.utc)
            return datetime.fromtimestamp(num_val, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            pass

    # Replace space with T for ISO compliance
    ts_iso = ts_str.replace(" ", "T")

    # Truncate Windows 7-digit (or more) subsecond fractional digits to 6 (microseconds)
    ts_iso = re.sub(r"(\.\d{6})\d+", r"\1", ts_iso)

    # Standardize 'Z' or 'z' UTC suffix to +00:00 for robust parsing
    if ts_iso.endswith(("Z", "z")):
        ts_iso = ts_iso[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(ts_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except ValueError as err:
        if fallback_on_error:
            return datetime.now(timezone.utc)
        raise ValueError(f"Unable to parse timestamp '{ts_val}': {err}") from err


def parse_sysmon_hashes(val: str | dict[str, str] | None) -> dict[str, str]:
    """Convert Sysmon Hashes string into a lowercase key dictionary.

    Example inputs:
    - 'SHA256=B89D...,MD5=123...,IMPHASH=456...'
    - 'SHA256=B89D... MD5=123...'
    - 'SHA256=B89D..., MD5=123...'
    - {'SHA256': 'B89D'}

    Returns:
    - {'sha256': 'b89d...', 'md5': '123...', 'imphash': '456...'}
    """
    if not val:
        return {}

    if isinstance(val, dict):
        return {str(k).strip().lower(): str(v).strip() for k, v in val.items()}

    if not isinstance(val, str):
        return {}

    result: dict[str, str] = {}
    # Split on commas, semicolons, or whitespace delimiters between hash pairs
    # Tokens look like 'KEY=VALUE'
    tokens = re.findall(r"([A-Za-z0-9_-]+)=([^\s,;]+)", val)
    for k, v in tokens:
        result[k.lower()] = v.strip()

    return result


# Alias for compatibility with plan specification
parse_hashes_string = parse_sysmon_hashes


class NormalizedEvent(BaseModel):
    """Immutable, strongly-typed representation of a normalized Windows event.

    Preserves raw uncompressed payload for forensic provenance (D-02) and uses
    frozen Pydantic v2 configuration to ensure tamper-resistant processing.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # Core System Metadata
    event_id: int
    record_id: int | None = None
    provider: str
    channel: str
    computer: str
    timestamp: datetime
    event_category: EventCategory
    event_type: str

    # Subject / Actor Process Attributes
    process_guid: str | None = None
    process_id: int | None = None
    image: str | None = None
    command_line: str | None = None
    current_directory: str | None = None
    user: str | None = None
    logon_guid: str | None = None
    logon_id: str | None = None
    integrity_level: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)

    # Parent Process Attributes (Process Creation Ancestry)
    parent_process_guid: str | None = None
    parent_process_id: int | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    parent_user: str | None = None

    # Target Process Attributes (Injection, Access, Remote Threads)
    target_process_guid: str | None = None
    target_process_id: int | None = None
    target_image: str | None = None
    granted_access: str | None = None
    call_trace: str | None = None

    # Network Attributes
    source_ip: str | None = None
    source_port: int | None = None
    source_hostname: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    destination_hostname: str | None = None
    protocol: str | None = None

    # DNS Attributes
    query_name: str | None = None
    query_status: str | None = None
    query_results: str | None = None

    # File & Driver Attributes
    target_filename: str | None = None
    image_loaded: str | None = None
    signed: str | None = None
    signature: str | None = None
    signature_status: str | None = None

    # Registry Attributes
    registry_event_type: str | None = None
    registry_target_object: str | None = None
    registry_details: str | None = None
    registry_new_name: str | None = None

    # WMI Attributes
    wmi_operation: str | None = None
    wmi_consumer: str | None = None
    wmi_filter: str | None = None
    wmi_query: str | None = None

    # Security & Persistence Attributes
    service_name: str | None = None
    service_file_name: str | None = None
    task_name: str | None = None
    task_content: str | None = None

    # PowerShell Specific Attributes
    script_block_text: str | None = None
    script_block_id: str | None = None
    script_path: str | None = None

    # Forensic Provenance & Quarantine Metadata
    extra_fields: dict[str, Any] = Field(default_factory=dict)
    raw_payload: str
    event_hash: str
    is_quarantined: bool = False
    quarantine_reasons: list[str] = Field(default_factory=list)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _validate_timestamp(cls, v: Any) -> datetime:
        return parse_windows_timestamp(v)

    @field_validator("hashes", mode="before")
    @classmethod
    def _validate_hashes(cls, v: Any) -> dict[str, str]:
        if isinstance(v, str):
            return parse_sysmon_hashes(v)
        if isinstance(v, dict):
            return {str(k).strip().lower(): str(val).strip() for k, val in v.items()}
        return {}
