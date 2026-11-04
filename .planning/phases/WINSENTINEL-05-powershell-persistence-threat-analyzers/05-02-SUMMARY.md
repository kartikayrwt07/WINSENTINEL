# Phase 5 Plan 02: Multi-Source Persistence Analyzer & Pipeline Integration Summary

**Plan ID:** `05-02`  
**Phase:** `WINSENTINEL-05-powershell-persistence-threat-analyzers`  
**Completed At:** 2026-11-04  
**Status:** Completed  

---

## 1. Executive Summary

Plan `05-02` delivers the multi-source persistence threat analyzer (`PersistenceAnalyzer`), typed persistence forensic models (`PersistenceArtifact`, `PersistenceType`), and comprehensive integration of both PowerShell and Persistence threat analyzers into `IngestionPipeline` with SQLite alert and evidence persistence.

Adversaries establish persistence across Windows hosts to maintain continuous access through system reboots, user logoffs, and administrative credential rotations. WinSentinel now correlates forensic telemetry across 5 dedicated channels:
1. **Registry Auto-Runs & IFEO Hijacking** (Sysmon EID 12, 13, 14)
2. **Services & Driver Installation** (Security EID 4697, Sysmon EID 6)
3. **Scheduled Tasks** (Authoritative Security EID 4698 XML and Task Scheduler Operational logs EID 106, 140)
4. **WMI Event Subscriptions** (Sysmon EID 19, 20, 21)
5. **Startup Folder File Drops** (Sysmon EID 11)

Crucially, this analyzer enforces the **Strict Project Invariant** that scheduled task persistence is evaluated strictly from authoritative task telemetry sources (Security 4698 XML and Task Scheduler operational events) and **NEVER** inferred solely from Sysmon registry modifications (`Schedule\TaskCache`), eliminating high-volume background noise and false alarms caused by routine Windows updates.

Both analyzers connect directly into `IngestionPipeline.ingest_and_persist()`, dynamically creating records in SQLite `alerts` and `alert_evidence` tables without requiring schema modifications or external dependencies.

---

## 2. Implemented Components

### 2.1 Persistence Data Models (`app/models/persistence.py`)
- **`PersistenceType(str, Enum)`**: Defines standard categories: `REGISTRY`, `SERVICE`, `DRIVER`, `SCHEDULED_TASK`, `WMI_SUBSCRIPTION`, `STARTUP_FOLDER`.
- **`PersistenceArtifact(BaseModel)`**: Immutable, frozen Pydantic v2 forensic artifact model capturing:
  - Telemetry identity: `persistence_type`, `event_id`, `record_id`, `event_db_id`, `computer`, `timestamp_utc`, `process_guid`, `user`.
  - Persistence specifics: `target_name`, `payload`, `severity`, `mitre_tactics`, `mitre_techniques`, `evidence_fields`, `explanation`, `investigation_steps`.
- **SQLite Bridging Methods**:
  - `to_alert_dict()`: Maps forensic persistence findings directly into `AlertRepository.create_alert()` kwargs with rule format `PERS-<TYPE>-001`.
  - `to_evidence_dicts(alert_id)`: Generates forensic evidence mappings linking target name, payload, and telemetry metadata into `AlertRepository.link_alert_evidence()`.

### 2.2 Multi-Source Persistence Analyzer (`app/analyzers/persistence_analyzer.py`)
- **`PersistenceAnalyzer`** implements 5 specialized sub-detectors:
  1. `check_registry_persistence(event)`:
     - Detects modifications to `\CurrentVersion\Run`, `\RunOnce`, `\RunOnceEx`, `\Policies\Explorer\Run`.
     - Detects Winlogon hijacking (`\Winlogon\Userinit`, `\Winlogon\Shell`).
     - Detects Image File Execution Options (IFEO) debugger hijacking (`\Image File Execution Options\<image>\Debugger`).
     - Detects `AppInit_DLLs` persistence.
     - Automatically escalates severity to High when payload references temporary directories (`\Temp\`, `\Users\`, `\AppData\`), script extensions (`.vbs`, `.ps1`, `.bat`), or LOLBAS binaries.
  2. `check_service_driver_persistence(event)`:
     - Flags Security EID 4697 service installations, escalating to High/Critical if service points to temporary directories or script/LOLBAS interpreters.
     - Flags Sysmon EID 6 driver loads when driver signature is invalid/unsigned or loaded from outside `System32\drivers`.
  3. `check_scheduled_task_persistence(event)`:
     - Evaluates Security EID 4698 and Task Scheduler Operational logs (EID 106, 140).
     - Safely parses `task_content` XML using an entity-neutral XML parser (zero XXE risk) to extract `<Command>` and `<Arguments>`.
     - **Strict Invariant Enforced**: Automatically rejects and ignores Sysmon registry events modifying `Schedule\TaskCache` or `Microsoft\Windows\Tasks`.
  4. `check_wmi_persistence(event)`:
     - Detects Sysmon EID 19 (`EventFilter`), EID 20 (`EventConsumer`), and EID 21 (`FilterToConsumerBinding`).
     - Marks completed filter-to-consumer bindings as High-severity persistence.
  5. `check_startup_folder_persistence(event)`:
     - Detects Sysmon EID 11 file creation in user or all-users `\Start Menu\Programs\Startup\` folders containing executable or script extensions (`.exe`, `.dll`, `.bat`, `.cmd`, `.vbs`, `.js`, `.wsf`, `.ps1`, `.lnk`).
  - `analyze_event(event, event_db_id)`: Unified dispatcher routing normalized events across the 5 detector channels with cross-category fallbacks.

### 2.3 IngestionPipeline Integration (`app/ingestion/pipeline.py`)
- **Analyzer Hooks in `IngestionPipeline`**:
  - `__init__()`: Accepts optional `powershell_analyzer` and `persistence_analyzer` instances, lazily instantiating default instances if omitted.
  - `IngestionResult`: Extended with properties `powershell_results: list[PowerShellAnalysisResult]`, `persistence_artifacts: list[PersistenceArtifact]`, and `analyzer_alerts_created: int`.
  - `ingest_and_persist(..., run_analyzers: bool = True)`:
    - Evaluates streaming normalized events through `PowerShellThreatAnalyzer`. When `risk_score >= 30`, creates an alert in SQLite `alerts` and links forensic evidence in `alert_evidence`.
    - Evaluates streaming normalized events through `PersistenceAnalyzer`. When an artifact is detected, creates an alert in SQLite `alerts` and links forensic evidence in `alert_evidence`.
    - Employs `_ensure_detection_rule()` to satisfy database foreign-key constraints on `alerts.rule_id REFERENCES detection_rules(id)`.
    - Supports `run_analyzers=False` to selectively bypass analyzer execution.

---

## 3. Verification & Test Execution Results

- **Unit Tests (`tests/unit/test_persistence_analyzer.py`):**
  - 12 unit tests validating all 5 persistence mechanisms, XML task parsing, and the strict invariant prohibiting registry-only task inferences (100% passed).
- **Integration Tests (`tests/integration/test_analyzers_pipeline_integration.py`):**
  - 8 integration tests validating end-to-end ingestion, SQLite alerts/evidence creation, benign command filtering, `run_analyzers=False` toggling, and mixed attack telemetry processing (100% passed).
- **Full Regression Test Suite:**
  - 274 total tests passed across all repository modules in 10.89 seconds with 0 failures and 0 errors.

---

## 4. Key Links & Artifacts

- Models & Schema:
  - `app/models/persistence.py`
  - `app/models/__init__.py`
- Analyzers:
  - `app/analyzers/persistence_analyzer.py`
  - `app/analyzers/__init__.py`
- Pipeline Integration:
  - `app/ingestion/pipeline.py`
- Test Suites:
  - `tests/unit/test_persistence_analyzer.py`
  - `tests/integration/test_analyzers_pipeline_integration.py`
