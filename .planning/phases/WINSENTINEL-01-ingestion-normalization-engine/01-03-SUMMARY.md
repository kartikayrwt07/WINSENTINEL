# Plan 01-03 Summary: Event Normalizers, Dispatcher, and Unified Ingestion Pipeline

**Phase:** WINSENTINEL-01 Ingestion & Normalization Engine  
**Plan:** 01-03  
**Status:** Completed  
**Commit:** `9a0376a` (`feat(01-03): implement Sysmon, Security, and PowerShell normalizers with unified ingestion pipeline`)  

---

## 1. Executive Summary

Plan 01-03 completed Wave 3 and finalized Phase 1 by implementing specialized normalizers, dynamic dispatching, the high-level `IngestionPipeline`, synthetic test fixtures, and comprehensive integration testing:
- **Base Normalizer (`app/normalization/base.py`):** Created `BaseNormalizer(ABC)` with `extract_common_system` parsing core System header metadata (EventID, RecordID, Provider, Channel, Computer, TimeCreated) and computing deterministic SHA-256 event fingerprints (`compute_event_fingerprint`). Fallbacks assign default values and mark `is_quarantined=True` with detailed reasons for corrupt or missing headers (D-03).
- **Sysmon Normalizer (`app/normalization/sysmon.py`):** Normalizes Sysmon EID 1 (Process Create), 3 (Network), 5 (Process Terminate), 6 (Driver Load), 7 (Image Load), 8 (CreateRemoteThread), 10 (Process Access), 11 (File Create), 12-14 (Registry Events), 19-21 (WMI Filter/Consumer/Binding), 22 (DNS Query), 23 & 26 (File Delete), 24 (Clipboard), and 25 (Process Tampering). Parses hash strings to lowercased dictionaries and handles case-insensitive field variants.
- **Windows Security Normalizer (`app/normalization/security.py`):** Safely handles hexadecimal process IDs (e.g., `NewProcessId` `0x1f4` -> `500`, `ProcessId` `0x4` -> `4`) without crashing (T-01-08) for EID 4688 (Process Creation). Accurately normalizes EID 4697 (Service Installation) and EID 4698 (Scheduled Task Creation) with XML task definitions.
- **PowerShell Normalizer (`app/normalization/powershell.py`):** Normalizes EID 4103 (Pipeline Execution) and EID 4104 (Script Block Logging) extracting script block code, script block ID, and script file path.
- **Normalizer Dispatcher (`app/normalization/dispatcher.py`):** Routes incoming event dictionaries dynamically to registered normalizers based on provider name (`Microsoft-Windows-Sysmon`, `Microsoft-Windows-Security-Auditing`, `Microsoft-Windows-PowerShell`), with `GenericNormalizer` as fallback for unrecognized providers.
- **Unified Ingestion Pipeline (`app/ingestion/pipeline.py`):** Orchestrates path sanitization (`sanitize_input_path`), streaming parser selection (`.evtx`, `.xml`, `.json`, `.jsonl`), payload extraction, SHA-256 fingerprint deduplication (D-04), normalizer dispatching, quarantine tracking, and `ImportStatistics` generation.
- **Synthetic Test Fixtures (`sample_data/`):** Created authentic test cases for Sysmon EID 1, 3, 7, 10, 13, 22; Security EID 4688, 4697, 4698; PowerShell EID 4104; and malformed/truncated records.

---

## 2. Requirements Addressed

| Requirement | Implementation Details |
|-------------|------------------------|
| **NORM-02** | `SysmonNormalizer` maps EID 1, 3, 5, 6, 7, 8, 10, 11 into `NormalizedEvent` with correct `EventCategory` and parsed `hashes`. |
| **NORM-03** | `SysmonNormalizer` maps EID 12, 13, 14 into `EventCategory.REGISTRY` with `registry_target_object` and `registry_details`. |
| **NORM-04** | `SysmonNormalizer` maps EID 19, 20, 21 into `EventCategory.WMI` with filter, consumer, and query extraction. |
| **NORM-05** | `SysmonNormalizer` maps EID 22 into `EventCategory.DNS` and EIDs 23-26 into `EventCategory.FILE` / `EventCategory.PROCESS`. |
| **NORM-06** | `SecurityNormalizer` normalizes Security EID 4688 with hex PID conversion (`0x1f4` -> `500`), EID 4697 service installs, and EID 4698 scheduled tasks. |
| **NORM-07** | `PowerShellNormalizer` extracts script block text, script block GUID, and path from EIDs 4103 and 4104. |
| **INGEST-04** | `ImportStatistics` tracks parsed, duplicate, malformed, and quarantined events with diagnostic reasons. |
| **INGEST-05** | `IngestionPipeline` suppresses duplicate imports using composite SHA-256 event fingerprints without re-processing. |

---

## 3. Artifacts Created & Modified

- `app/normalization/base.py`: Base normalizer class and common System extraction logic.
- `app/normalization/sysmon.py`: Sysmon EID 1 through 26 normalizer.
- `app/normalization/security.py`: Windows Security normalizer with hex PID conversion.
- `app/normalization/powershell.py`: PowerShell Operational script block normalizer.
- `app/normalization/dispatcher.py`: Dynamic normalizer dispatcher and generic fallback normalizer.
- `app/normalization/__init__.py`: Package exports for normalizer suite.
- `app/ingestion/pipeline.py`: Unified ingestion and normalization pipeline orchestrator.
- `app/ingestion/__init__.py`: Added `IngestionPipeline` export.
- `sample_data/sysmon/`: Synthetic XML fixtures for Sysmon EIDs 1, 3, 7, 10, 13, 22.
- `sample_data/security/`: Synthetic XML fixtures for Security EIDs 4688, 4697, 4698.
- `sample_data/powershell/`: Synthetic XML fixture for PowerShell EID 4104.
- `sample_data/malformed/`: Synthetic fixtures for truncated XML, missing System header XML, and invalid timestamp JSON.
- `tests/unit/test_sysmon_normalizer.py`: 8 unit tests covering all Sysmon EID categories and partial quarantine.
- `tests/unit/test_security_pwsh_normalizer.py`: 8 unit tests covering Security and PowerShell normalizers.
- `tests/integration/test_ingestion_pipeline.py`: 6 integration tests validating complete end-to-end ingestion, deduplication, and error quarantine.

---

## 4. Verification Results

Full test suite execution:
```
python -m pytest tests/ -v
============================= 73 passed in 0.65s ==============================
```

All 73 unit and integration tests across the entire codebase passed with 100% pass rate.
