# Phase 1: Ingestion & Normalization Engine - Context

**Gathered:** 2026-11-03  
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 1 delivers the offline ingestion and normalization foundation for WinSentinel:
- Parsing Windows EVTX files using `python-evtx`, Sysmon XML exports, and normalized JSON log dumps.
- Strongly-typed Pydantic normalization mapping Sysmon events (EID 1, 3, 5, 6, 7, 8, 10, 11, 12–14, 19–21, 22, 23–26), Windows Security auditing (4688, 4697, 4698), and PowerShell Operational (4103, 4104).
- Safe offline execution without administrator privilege requirements, with path traversal prevention and resource-bounded generator streaming.
- Preserving raw event payloads and generating detailed import statistics with malformed record handling and deduplication.

</domain>

<decisions>
## Implementation Decisions

### EVTX Parsing Engine & Performance
- **D-01:** Use `python-evtx` with chunked generator streaming as the core parsing engine. Keeps the project in pure Python 3.11+, avoids fragile C/Rust native compiler toolchains on developer machines, and provides reliable chunk-by-chunk streaming to avoid memory exhaustion on large log exports.

### Raw Event Payload Retention
- **D-02:** Store the full uncompressed raw XML/JSON string in the `raw_payload` attribute of each `NormalizedEvent` record. This provides immediate forensic provenance and drill-down fidelity for analysts without decompression CPU overhead.

### Malformed Record Handling & Quarantine Log
- **D-03:** Implement partial normalization with structured error logging. When an event record has partial corruption or missing optional fields, extract all parseable standard attributes, populate missing essential attributes with explicit fallback indicators (e.g. `UNKNOWN`), preserve the raw payload untouched, and log the incident to an import job audit report with descriptive diagnostics.

### Event Deduplication Mechanism
- **D-04:** Compute a deterministic SHA-256 fingerprint from `(Computer + Provider + Channel + RecordID + RawPayload)`. Duplicate records encountered across overlapping log exports increment the `duplicate_events` counter in import statistics and are suppressed from inserting duplicate rows in the SQLite repository.

### Developer & Agent Discretion
- Batch size for generator streaming (e.g. 500–1,000 records per chunk) is determined by the implementation for optimal I/O throughput.
- Field normalization naming conventions follow strict snake_case aligned with the Pydantic schema in [`.planning/REQUIREMENTS.md`](file:///c:/Users/karti/OneDrive/Desktop/WINSENTINEL/.planning/REQUIREMENTS.md).

</decisions>

<specifics>
## Specific Ideas & Test Coverage

- Provide synthetic Sysmon XML and EVTX test fixtures in `sample_data/` covering process creation (EID 1), network connection (EID 3), registry modification (EID 13), and PowerShell script block logging (EID 4104).
- Include intentionally malformed XML/EVTX snippets in test fixtures to verify parser error recovery and import statistics accuracy.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing:**
- `.planning/PROJECT.md` — Master project identity, constraints, and architecture.
- `.planning/REQUIREMENTS.md` — Formal INGEST-01 through INGEST-06 and NORM-01 through NORM-08 requirements.
- `.planning/ROADMAP.md` — Phase 1 goals, success criteria, and plans breakdown.

</canonical_refs>

