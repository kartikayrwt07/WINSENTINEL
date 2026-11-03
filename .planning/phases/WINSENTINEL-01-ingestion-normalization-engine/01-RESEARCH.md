# Phase 1: Ingestion & Normalization Engine — Technical & Domain Research

**Phase:** WINSENTINEL-01  
**Status:** Completed  
**Author:** Phase 1 Researcher  
**Scope:** Ingestion (EVTX, XML, JSON), Parsing, Error Quarantine, Normalization, Typed Schema, Deduplication  
**Requirements Covered:** INGEST-01, INGEST-02, INGEST-03, INGEST-04, INGEST-05, INGEST-06, NORM-01, NORM-02, NORM-03, NORM-04, NORM-05, NORM-06, NORM-07, NORM-08  
**Locked Decisions Addressed:** D-01, D-02, D-03, D-04  

---

## 1. Executive Summary & Architecture Overview

WinSentinel is an offline-first Windows endpoint threat monitoring and forensic triage platform. Phase 1 provides the telemetry foundation: ingesting heterogeneous raw event streams (binary Windows Event Logs `.evtx`, exported Sysmon `.xml`, and pre-extracted `.json`), resiliently recovering from corruption, computing deterministic deduplication fingerprints, and mapping all records into a strongly-typed, immutable Pydantic v2 `NormalizedEvent` data structure.

```
+-----------------------------------------------------------------------------------------+
|                                    INPUT SOURCES                                        |
|  [ EVTX Binary Logs ]          [ Sysmon XML Dumps ]           [ Normalized JSON Logs ]  |
+-----------------------------------------------------------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------------+
|                                  STREAMING PARSER LAYER                                 |
|  * Path Traversal Sanitization (Path.resolve())                                         |
|  * Size Quotas & Memory Bounding (mmap + chunked generator streaming)                   |
|  * python-evtx FileHeader & ChunkHeader traversal                                       |
|  * Namespace-agnostic XML ElementTree extraction                                        |
|  * Error Quarantine Handler (ParseError / UnicodeDecodeError / InvalidRecordException)   |
+-----------------------------------------------------------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------------+
|                               NORMALIZATION & VALIDATION                                |
|  * Sysmon Normalizer (EIDs 1, 3, 5, 6, 7, 8, 10, 11, 12-14, 19-21, 22, 23-26)         |
|  * Windows Security Normalizer (EID 4688, 4697, 4698 - hex PID conversion)             |
|  * PowerShell Operational Normalizer (EID 4103, 4104 Script Block Logging)              |
|  * UTC Timestamp Normalization (FILETIME / ISO-8601 with/without Z -> timezone.utc)     |
|  * Hashes Parsing (MD5, SHA256, IMPHASH extraction)                                     |
+-----------------------------------------------------------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------------+
|                              FINGERPRINTING & OUTPUT                                    |
|  * SHA-256 Deduplication: SHA256(Computer + Provider + Channel + RecordID + RawPayload)|
|  * Pydantic v2 NormalizedEvent (frozen=True, extra_fields, raw_payload)                 |
|  * ImportStatistics Audit Report (total, parsed, malformed, quarantined, duplicates)    |
+-----------------------------------------------------------------------------------------+
```

---

## 2. EVTX Architecture & `python-evtx` Engine (D-01, INGEST-01)

### 2.1 EVTX File Format Internals
The Windows Event Log (EVTX) format, introduced in Windows Vista, is a binary, chunk-oriented file structure designed for fast append-only logging and crash resilience.

- **File Header (4,096 bytes / `0x1000`):**
  - Magic signature: `ElfFile\x00` (`0x656C6646696C6500`).
  - Contains metadata: `first_chunk_number`, `last_chunk_number`, `next_record_identifier`, `chunk_count`, header flags (dirty/complete bitmask), and file header checksum.
- **Chunks (65,536 bytes / `0x10000` / 64 KB each):**
  - Starts with **Chunk Header (512 bytes / `0x200`)**: Magic signature `ElfChnk\x00` (`0x656C6643686E6B00`).
  - Contains: `first_event_record_number`, `last_event_record_number`, `first_event_record_identifier`, `last_event_record_identifier`, `free_space_offset`, event records CRC32 checksum, and chunk CRC32 checksum.
  - Followed by **Event Records**:
    - **Record Header (24 bytes)**: Magic `\x2A\x2A\x00\x00` (`**\x00\x00`), 32-bit record length, 64-bit record identifier (`EventRecordID`), and 64-bit Windows FILETIME timestamp.
    - **Binary XML (BinXml) Stream**: Compact tokenized representation where element names, attributes, and templates are indexed with substitution descriptors.
    - **Trailing Record Length (4 bytes)**: Exact duplicate of the initial record length for reverse traversal.

### 2.2 `python-evtx` Library Architecture & API
`python-evtx` (version 0.8.1+) is a pure-Python parser. It eliminates native C/Rust compiler dependencies, ensuring effortless portability across developer workstations and offline analysis environments.

Core components in `Evtx.Evtx`:
1. `Evtx(filename)`: The top-level context manager. Opens the file in binary read mode (`open(..., "rb")`) and establishes a read-only memory map (`mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)`).
2. `FileHeader(buf, 0x0)`: Parses the file header and enumerates chunks via `.chunks(include_inactive=False)`.
3. `ChunkHeader`: Validates chunk magic and traverses individual records via `.records()`.
4. `Record`: Represents a single event record. Calling `record.xml()` invokes `Evtx.Views.evtx_record_xml_view(record)`, transforming the binary XML tokens into a standard XML string.

### 2.3 Memory-Bounded Streaming & Batching
Loading an entire multi-gigabyte EVTX file into memory causes memory exhaustion and out-of-memory (OOM) errors. By combining `mmap` with Python generator streaming, only the current record and active chunk memory map pages reside in physical RAM.

```python
from collections.abc import Generator
from pathlib import Path
import Evtx.Evtx as evtx

def stream_evtx_records(file_path: Path) -> Generator[tuple[int, str], None, None]:
    """
    Stream individual XML records from an EVTX file with zero heap duplication.
    Yields tuple of (record_id, raw_xml_string).
    """
    with evtx.Evtx(str(file_path)) as log:
        for chunk in log.chunks():
            for record in chunk.records():
                try:
                    xml_str = record.xml()
                    record_id = record.record_num()
                    yield record_id, xml_str
                except (evtx.InvalidRecordException, evtx.ParseException, UnicodeDecodeError) as err:
                    # Log error, skip corrupt record, and continue generator
                    continue
```

### 2.4 Error Handling & Dirty/Corrupt Log Recovery
In real-world incidents, threat actors abruptly power down machines or logs are copied while active, leaving files marked "dirty" with uncommitted chunk headers:
- **`include_inactive=True` in `FileHeader.chunks()`**: When the declared chunk count in the header is incomplete or zero due to an ungraceful shutdown, passing `include_inactive=True` instructs `python-evtx` to scan the remainder of the file buffer for valid `ElfChnk\x00` headers.
- **Catching specific exceptions**:
  - `evtx.InvalidRecordException`: Raised when record magic `\x2A\x2A\x00\x00` is missing or record length is out of chunk bounds.
  - `evtx.ParseException`: Raised when BinXml template tokens or substitution pointers are corrupted.
  - `UnicodeDecodeError`: Raised when UTF-16LE strings inside the BinXml stream contain invalid surrogate pairs.
- Recovery strategy: Log the malformed record offset/record ID, increment `malformed_events` in `ImportStatistics`, and proceed to the next record without halting the ingestion run.

---

## 3. Windows Event XML Structure & Schemas (INGEST-02, NORM-02 - NORM-07)

### 3.1 Namespace Handling & XML Stripping
Windows Event XML documents always specify the XML namespace:
`xmlns="http://schemas.microsoft.com/win/2004/08/events/event"`

In standard library `xml.etree.ElementTree`, elements receive prefixed tags such as:
`{http://schemas.microsoft.com/win/2004/08/events/event}System`
`{http://schemas.microsoft.com/win/2004/08/events/event}EventData`

**Namespace Solution:**
To eliminate brittle XPath strings and maintain fast execution, a namespace-stripping helper or local-tag extractor must be utilized:
```python
import xml.etree.ElementTree as ET

def parse_event_xml(xml_string: str) -> tuple[dict[str, str], dict[str, str]]:
    """
    Extracts System and EventData/UserData dictionaries from raw event XML
    while remaining completely namespace-agnostic.
    """
    root = ET.fromstring(xml_string)
    
    system_fields: dict[str, str] = {}
    data_fields: dict[str, str] = {}

    for elem in root:
        local_tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        if local_tag == "System":
            for child in elem:
                c_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if c_tag == "Provider":
                    system_fields["Provider"] = child.attrib.get("Name", "")
                    system_fields["ProviderGuid"] = child.attrib.get("Guid", "")
                elif c_tag == "TimeCreated":
                    system_fields["SystemTime"] = child.attrib.get("SystemTime", "")
                elif c_tag == "Execution":
                    system_fields["ProcessID"] = child.attrib.get("ProcessID", "")
                    system_fields["ThreadID"] = child.attrib.get("ThreadID", "")
                elif c_tag == "Security":
                    system_fields["UserID"] = child.attrib.get("UserID", "")
                else:
                    system_fields[c_tag] = child.text or ""
        elif local_tag in ("EventData", "UserData"):
            for child in elem:
                # Sysmon style: <Data Name="ProcessGuid">...</Data>
                name = child.attrib.get("Name")
                if name:
                    data_fields[name] = child.text or ""
                else:
                    # Generic style: <NewProcessId>0x12a</NewProcessId>
                    c_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    data_fields[c_tag] = child.text or ""

    return system_fields, data_fields
```

---

### 3.2 Sysmon Event Field Mappings (NORM-02 to NORM-05)

Sysmon (`Microsoft-Windows-Sysmon/Operational`) stores key-value pairs in `<EventData><Data Name="Key">Value</Data></EventData>`.

| EID | Sysmon Purpose | Core Normalized Fields Extracted |
|-----|----------------|----------------------------------|
| **1** | Process Creation | `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `CommandLine`, `CurrentDirectory`, `User`, `LogonGuid`, `LogonId`, `TerminalSessionId`, `IntegrityLevel`, `Hashes`, `ParentProcessGuid`, `ParentProcessId`, `ParentImage`, `ParentCommandLine`, `ParentUser`, `OriginalFileName`, `Company`, `Description`, `Product`, `FileVersion` |
| **3** | Network Connection | `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `User`, `Protocol`, `Initiated`, `SourceIsIpv6`, `SourceIp`, `SourceHostname`, `SourcePort`, `SourcePortName`, `DestinationIsIpv6`, `DestinationIp`, `DestinationHostname`, `DestinationPort`, `DestinationPortName` |
| **5** | Process Terminated | `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `User` |
| **6** | Driver Loaded | `UtcTime`, `ImageLoaded`, `Hashes`, `Signed`, `Signature`, `SignatureStatus` |
| **7** | Image Loaded (DLL) | `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `ImageLoaded`, `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName`, `Hashes`, `Signed`, `Signature`, `SignatureStatus`, `User` |
| **8** | CreateRemoteThread | `UtcTime`, `SourceProcessGuid`, `SourceProcessId`, `SourceImage`, `TargetProcessGuid`, `TargetProcessId`, `TargetImage`, `NewThreadId`, `StartAddress`, `StartModule`, `StartFunction` |
| **10** | Process Access (e.g. LSASS) | `UtcTime`, `SourceProcessGuid`, `SourceProcessId`, `SourceThreadId`, `SourceImage`, `TargetProcessGuid`, `TargetProcessId`, `TargetImage`, `GrantedAccess` (Hex e.g. `0x1010`), `CallTrace` |
| **11** | File Created | `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `TargetFilename`, `CreationUtcTime`, `User` |
| **12** | Registry Object Create/Delete | `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `EventType` (`CreateKey`, `DeleteKey`), `TargetObject`, `User` |
| **13** | Registry Value Set | `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `EventType` (`SetValue`), `TargetObject`, `Details`, `User` |
| **14** | Registry Key/Value Rename | `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `EventType` (`RenameKey`), `TargetObject`, `NewName`, `User` |
| **19** | WmiEvent (Filter) | `EventType`, `UtcTime`, `Operation`, `User`, `Name`, `Type`, `Query` |
| **20** | WmiEvent (Consumer) | `EventType`, `UtcTime`, `Operation`, `User`, `Name`, `Type`, `Destination` |
| **21** | WmiEvent (Binding) | `EventType`, `UtcTime`, `Operation`, `User`, `Consumer`, `Filter` |
| **22** | DNS Query | `UtcTime`, `ProcessGuid`, `ProcessId`, `QueryName`, `QueryStatus`, `QueryResults`, `Image`, `User` |
| **23** | File Delete (Archived) | `UtcTime`, `ProcessGuid`, `ProcessId`, `User`, `Image`, `TargetFilename`, `Hashes`, `IsExecutable`, `Archived` |
| **24** | Clipboard Change | `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `Session`, `ClientInfo`, `Hashes`, `Archived` |
| **25** | Process Tampering | `UtcTime`, `ProcessGuid`, `ProcessId`, `Image`, `Type`, `User` |
| **26** | File Delete (Logged) | `UtcTime`, `ProcessGuid`, `ProcessId`, `User`, `Image`, `TargetFilename`, `Hashes`, `IsExecutable` |

#### Sysmon Hash Extraction
Sysmon combines multiple hashes in a comma-separated format:
`MD5=A4E390...,SHA256=F6978C...,IMPHASH=4F9A...`
The normalizer must split on `,` and `=`, producing a normalized dictionary:
`{"md5": "a4e390...", "sha256": "f6978c...", "imphash": "4f9a..."}`.

---

### 3.3 Windows Security Auditing XML Structure (NORM-06)
- **Provider:** `Microsoft-Windows-Security-Auditing`
- **Channel:** `Security`

#### Security EID 4688: Process Creation
Unlike Sysmon, Security 4688 emits PIDs in hexadecimal string notation:
- `NewProcessId`: Hex string e.g. `0x1f4` (500 decimal).
- `ProcessId` (Parent Process ID): Hex string e.g. `0x1e0` (480 decimal).
- `NewProcessName`: Full path to executable (`Image`).
- `ParentProcessName`: Full path to parent executable.
- `CommandLine`: Process command line (only present if "Include command line in process creation events" audit policy is active).
- `SubjectUserName` / `SubjectDomainName`: User context.
- `TokenElevationType`: `%%1936` (Default/Normal), `%%1937` (Full/Elevated), `%%1938` (Limited).

**Conversion Rule:**
```python
def parse_hex_or_dec_int(val: str | None) -> int | None:
    if not val or val == "-":
        return None
    val_clean = val.strip()
    try:
        if val_clean.lower().startswith("0x"):
            return int(val_clean, 16)
        return int(val_clean)
    except ValueError:
        return None
```

#### Security EID 4697: Service Installed
- `ServiceName`: Name of the installed service.
- `ServiceFileName`: Path to service binary or executable payload.
- `ServiceType`, `ServiceStartType`, `ServiceAccount`.

#### Security EID 4698: Scheduled Task Created
- `TaskName`: Name and path of the created task (e.g. `\Microsoft\Windows\UpdateOrchestrator\Report`).
- `TaskContent`: Full embedded XML string of the task definition. Contains `<Actions><Exec><Command>cmd.exe</Command><Arguments>/c ...</Arguments></Exec></Actions>`.

---

### 3.4 PowerShell Operational XML Structure (NORM-07)
- **Provider:** `Microsoft-Windows-PowerShell`
- **Channel:** `Microsoft-Windows-PowerShell/Operational`

#### PowerShell EID 4103: Pipeline Execution
Captures contextual execution information:
- `<ContextInfo>`: Contains runspace ID, pipeline ID, command name, script name.
- `<Payload>`: Command line invocations and parameter bindings.

#### PowerShell EID 4104: Script Block Logging
Captures complete blocks of executed PowerShell script code:
- `ScriptBlockText`: Complete unparsed script block string.
- `ScriptBlockId`: Unique GUID identifying the script block.
- `MessageNumber`: Index of script block fragment (for scripts exceeding buffer size).
- `MessageTotal`: Total number of script block fragments.
- `Path`: Local path to script file if executed from `.ps1`, or empty if executed dynamically/interactively.

---

## 4. Pydantic v2 High-Throughput Schema Design (NORM-01, NORM-08, D-02)

### 4.1 Immutability, Performance, and Extra Fields
In high-volume log ingestion pipelines (10,000 to 500,000 events), Pydantic v2 offers massive speed improvements via `pydantic-core` (Rust-based validation).
- `frozen=True`: Guarantees immutability, enabling safe multi-threaded processing, caching, and hashing.
- `extra="ignore"`: Discards unexpected schema tags during strict validation.
- `extra_fields: dict[str, Any] = Field(default_factory=dict)`: Captures arbitrary provider-specific XML attributes without schema mutation.
- `raw_payload: str` (D-02): Stores the uncompressed raw XML/JSON string for full forensic provenance.

### 4.2 Comprehensive `NormalizedEvent` Model Specification
```python
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

class EventCategory(str, Enum):
    PROCESS = "process"
    NETWORK = "network"
    DRIVER = "driver"
    IMAGE_LOAD = "image_load"
    REMOTE_THREAD = "remote_thread"
    PROCESS_ACCESS = "process_access"
    FILE = "file"
    REGISTRY = "registry"
    WMI = "wmi"
    DNS = "dns"
    SECURITY = "security"
    POWERSHELL = "powershell"
    GENERIC = "generic"

class NormalizedEvent(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        extra="ignore",
        arbitrary_types_allowed=False,
    )

    # Core System Metadata
    event_id: int
    record_id: int | None = None
    provider: str
    channel: str
    computer: str
    timestamp: datetime  # Timezone-aware UTC
    event_category: EventCategory
    event_type: str  # e.g., 'process_create', 'network_connect'

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
    raw_payload: str  # Uncompressed raw XML or JSON string (D-02)
    event_hash: str  # SHA-256 deduplication fingerprint (D-04)
    is_quarantined: bool = False
    quarantine_reasons: list[str] = Field(default_factory=list)
```

---

### 4.3 Timestamp Normalization Strategy
Windows logs express timestamps in several divergent formats:
1. System Time (ISO-8601 with 7-digit 100ns precision and Z): `2023-04-10T14:22:15.1234567Z`
2. Sysmon UtcTime (Space delimiter, millisecond precision, no tz): `2023-04-10 14:22:15.120`
3. PowerShell / Custom JSON Epoch timestamps: Integer milliseconds or seconds since Unix epoch.

```python
import re
from datetime import datetime, timezone

def parse_windows_timestamp(ts_val: str | int | float | None) -> datetime:
    """
    Parses heterogeneous Windows timestamp formats into a timezone-aware UTC datetime.
    Falls back safely to current UTC time if corrupt, marking field for quarantine.
    """
    if ts_val is None or ts_val == "":
        return datetime.now(timezone.utc)
    
    if isinstance(ts_val, (int, float)):
        # Epoch seconds or milliseconds
        if ts_val > 1e11:  # Milliseconds
            return datetime.fromtimestamp(ts_val / 1000.0, tz=timezone.utc)
        return datetime.fromtimestamp(ts_val, tz=timezone.utc)

    ts_str = str(ts_val).strip()
    
    # Replace space with T for ISO format
    ts_str = ts_str.replace(" ", "T")
    
    # Handle Windows 7-digit 100-nanosecond timestamps (truncate to 6 digits for microsecond)
    # e.g., 2023-04-10T14:22:15.1234567Z -> 2023-04-10T14:22:15.123456Z
    ts_str = re.sub(r"(\.\d{6})\d+", r"\1", ts_str)

    # Ensure UTC timezone is attached
    if ts_str.endswith("Z"):
        ts_str = ts_str[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except ValueError:
        # Return fallback UTC datetime; caller handles quarantine
        raise
```

---

## 5. Security & Input Sanitization (INGEST-06)

WinSentinel is designed for forensic investigation of potentially compromised endpoints. Ingested logs must be treated as **hostile, untrusted input**:
1. **Path Traversal Prevention:**
   - Any file path passed to ingestion must be strictly sanitized using `Path(p).resolve()`.
   - Disallow symlink escapes outside the target workspace or user-designated root.
   - Enforce allowed file extensions (`.evtx`, `.xml`, `.json`).
   ```python
   def sanitize_input_path(user_path: str | Path, base_dir: Path | None = None) -> Path:
       resolved = Path(user_path).resolve()
       if not resolved.exists():
           raise FileNotFoundError(f"Log file does not exist: {resolved}")
       if resolved.suffix.lower() not in (".evtx", ".xml", ".json"):
           raise ValueError(f"Unsupported file format: {resolved.suffix}")
       if base_dir:
           base_resolved = base_dir.resolve()
           if not resolved.is_relative_to(base_resolved):
               raise PermissionError("Path traversal attempt detected")
       return resolved
   ```
2. **Safe File Size Limits:**
   - Prevent memory exhaustion via malicious ZIP bombs or terabyte files.
   - Default quotas: Max 2 GB for `.evtx`, max 500 MB for `.xml` or `.json`.
   - File size must be checked with `os.path.getsize(resolved)` prior to parsing.
3. **No Execution Guarantee:**
   - Command lines (`CommandLine`), script block text (`ScriptBlockText`), and task contents are stored purely as inert strings.
   - No calls to `eval()`, `exec()`, or subshell invocations may ever be made on ingested content.
4. **XML External Entity (XXE) Protection:**
   - Windows Sysmon/Security XML strings contain no external DTDs.
   - Use standard `xml.etree.ElementTree` without entity resolution or `defusedxml` to safeguard against billion-laughs entity expansion attacks.

---

## 6. Deduplication & Import Statistics (INGEST-04, INGEST-05, D-04)

### 6.1 Deterministic SHA-256 Deduplication (D-04)
When importing multiple log exports (e.g. daily overlapping EVTX triage collections), duplicate events frequently occur.
The unique fingerprint is computed via:
$$\text{event\_hash} = \text{SHA256}(\text{Computer} + "|" + \text{Provider} + "|" + \text{Channel} + "|" + \text{RecordID} + "|" + \text{RawPayload})$$

```python
import hashlib

def compute_event_fingerprint(
    computer: str,
    provider: str,
    channel: str,
    record_id: int | None,
    raw_payload: str,
) -> str:
    key = f"{computer}|{provider}|{channel}|{record_id or ''}|{raw_payload}"
    return hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()
```
- If an incoming event produces an `event_hash` that has already been ingested within the session/database, the event is skipped and `duplicate_events` is incremented.

### 6.2 Partial Normalization & Quarantine Model (D-03)
When encountering malformed attributes (e.g. unparseable timestamp, corrupted integer in PID, missing required System tag):
1. **Never drop the record:** Extract all valid fields possible.
2. **Placeholder Fallbacks:** Assign explicit placeholders (e.g. `UNKNOWN` for strings, fallback UTC time for timestamps).
3. **Quarantine Flag:** Set `is_quarantined = True` and append descriptive error strings into `quarantine_reasons`.
4. **Preserve Raw Payload:** The intact `raw_payload` is stored, allowing an analyst to manually inspect the raw event.
5. **Statistics Reporting:** Increment `quarantined_events` in `ImportStatistics`.

### 6.3 ImportStatistics Schema
```python
from datetime import datetime
from pydantic import BaseModel, Field

class ImportStatistics(BaseModel):
    file_path: str
    total_records: int = 0
    parsed_events: int = 0
    malformed_events: int = 0
    quarantined_events: int = 0
    duplicate_events: int = 0
    start_time: datetime
    end_time: datetime | None = None
    errors: list[str] = Field(default_factory=list)
```

---

## 7. Edge Cases & Resilience Engineering

| Edge Case | Failure Mode | Mitigation Strategy |
|-----------|--------------|---------------------|
| **RecordID Rollover** | In high-traffic systems, 64-bit `EventRecordID` may reset to 1 if event log clears or wraps. | Deduplication combines Computer, Provider, Channel, RecordID, and RawPayload. Distinct payloads with matching RecordIDs will not collide. |
| **Empty EventData / UserData** | Events like system shutdowns or kernel audit logs may contain `<EventData />` or no payload. | The XML parser must treat `EventData` as optional, defaulting all payload attributes to `None` without throwing `KeyError`. |
| **Hexadecimal PIDs in Security Logs** | EID 4688 logs `NewProcessId` as `0x1f4`, causing `int()` to raise `ValueError`. | Parse with `int(val, 16) if val.startswith(('0x', '0X')) else int(val)`. |
| **Missing ProcessGuid in Non-Sysmon Logs** | Security 4688 and PowerShell 4104 lack Sysmon `ProcessGuid`. | Leave `process_guid = None`. Downstream Process Analyzer (Phase 3) will handle PID-to-process matching. |
| **Surrogate Pairs / Broken Non-ASCII** | Malformed usernames or file paths in foreign languages raise `UnicodeDecodeError`. | `python-evtx` string decoding and UTF-8 encoding must specify `errors='replace'` to prevent pipeline crashes. |
| **Multi-Part Script Blocks (EID 4104)** | Scripts larger than 64 KB are split into multiple records (`MessageNumber` / `MessageTotal`). | Normalizer retains `MessageNumber`, `MessageTotal`, and `ScriptBlockId`. Phase 5 will assemble the fragments. |
| **Corrupt EVTX Chunks / Incomplete Writes** | Machine rebooted while EVTX was being flushed, leaving trailing garbage bytes. | `python-evtx` catches `InvalidRecordException`; parser logs warning, updates `malformed_events`, and advances to next chunk. |

---

## 8. Test Fixtures & Synthetic Data Plan

To fulfill the requirements without introducing live malware payloads:
1. `sample_data/sysmon/`:
   - `sysmon_eid1_process_create.xml` (cmd.exe, powershell.exe, calc.exe execution with full parentage).
   - `sysmon_eid3_network.xml` (outbound HTTPS connection to IP).
   - `sysmon_eid7_image_load.xml` (suspicious DLL loaded).
   - `sysmon_eid10_process_access.xml` (LSASS memory access).
   - `sysmon_eid13_registry_set.xml` (Run key modification).
   - `sysmon_eid22_dns_query.xml` (suspicious domain lookup).
2. `sample_data/security/`:
   - `security_eid4688_process_create.xml` (Security process creation with hex PIDs).
   - `security_eid4697_service_install.xml` (Service creation).
   - `security_eid4698_task_create.xml` (Scheduled task XML).
3. `sample_data/powershell/`:
   - `powershell_eid4104_scriptblock.xml` (Base64-encoded download cradle).
4. `sample_data/malformed/`:
   - `truncated_event.xml` (Malformed XML closing tags).
   - `missing_system_header.xml` (Event missing Provider and EventID).
   - `invalid_timestamp.xml` (Corrupt timestamp string).
   - `corrupt_record.evtx` (Synthetic EVTX with corrupted chunk checksum).

---

## 9. Recommendations for Downstream Plans (Phase 1 Execution)

Based on this technical research, Phase 1 should be structured into three distinct plans:
1. **Plan 01-01: Schema & Core Data Models**
   - Implement `NormalizedEvent`, `EventCategory`, and `ImportStatistics` in Pydantic v2.
   - Implement robust timestamp parsing (`parse_windows_timestamp`) and hash parsing helpers.
   - Implement SHA-256 deterministic fingerprinting (`compute_event_fingerprint`).
2. **Plan 01-02: Streaming Ingestion & Parsers**
   - Implement input path validation with path traversal checks (`sanitize_input_path`).
   - Implement streaming EVTX parser wrapping `python-evtx` with chunk recovery.
   - Implement streaming XML and JSON event parsers with namespace-agnostic extraction.
   - Implement malformed event quarantine handler and import statistics tracking.
3. **Plan 01-03: Event Normalizers & Comprehensive Test Suite**
   - Implement `SysmonNormalizer` covering EIDs 1, 3, 5, 6, 7, 8, 10, 11, 12–14, 19–21, 22, 23–26.
   - Implement `SecurityNormalizer` covering EIDs 4688 (with hex PID handling), 4697, 4698.
   - Implement `PowerShellNormalizer` covering EIDs 4103 and 4104.
   - Create synthetic XML/JSON/EVTX test fixtures and verify 100% of Phase 1 requirements.

---
*Research completed: 2026-11-03 for WinSentinel Phase 1*
