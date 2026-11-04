# Roadmap: WinSentinel

## Overview

WinSentinel is built incrementally as a modular, offline-first Windows Endpoint Threat Monitoring and Investigation Platform. Starting with core ingestion and normalization of Windows Sysmon and Security event logs into a SQLite database, the system builds upward into graph-based process relationship reconstruction, a Sigma-inspired YAML detection engine, dedicated PowerShell and persistence analyzers, multi-event correlation, false-positive benchmarking, and culminates in a rich Streamlit SOC investigation dashboard.

## Phases

- [x] **Phase 1: Ingestion & Normalization Engine** - Parse EVTX, XML, and JSON logs; validate and normalize Sysmon and Security events into a unified typed schema. (completed 2026-11-04)
- [x] **Phase 2: Database Layer & Persistent Storage** - Implement SQLite schema, migrations, indexed queries, and audit/import logging. (completed 2026-11-04)
- [x] **Phase 3: Process Relationship Analyzer** - Build process tree reconstruction using Sysmon ProcessGuid, handling PID reuse and anomalous parentage. (completed 2026-11-04)
- [x] **Phase 4: Detection Rule Engine & Sysmon Core Library** - Create Sigma-inspired YAML rule parser, matching engine, exclusions, and Sysmon detection rules. (completed 2026-11-04)
- [x] **Phase 5: PowerShell & Persistence Threat Analyzers** - Specialized detection for obfuscated PowerShell, download cradles, registry Run keys, services, WMI, and scheduled tasks. (completed 2026-11-04)
- [ ] **Phase 6: Event Correlation & Alert Management** - Correlate multi-stage events across process lineage and time windows; manage alert lifecycle in SQLite.
- [ ] **Phase 7: False-Positive & Rule Evaluation Engine** - Benchmark detection rules against labeled synthetic datasets; calculate Precision, Recall, F1, and FPR.
- [ ] **Phase 8: SOC Investigation Dashboard & Timeline** - Build 10-page Streamlit dashboard featuring Event Explorer, Process Tree graphs, Timeline, Alerts, and Evaluation reports.

---

## Phase Details

### Phase 1: Ingestion & Normalization Engine

**Goal**: Ingest EVTX, XML, and JSON event files, handle corrupt/malformed records gracefully, and normalize events into a strongly-typed `NormalizedEvent` structure.  
**Depends on**: Nothing (First phase)  
**Requirements**: INGEST-01, INGEST-02, INGEST-03, INGEST-04, INGEST-05, INGEST-06, NORM-01, NORM-02, NORM-03, NORM-04, NORM-05, NORM-06, NORM-07, NORM-08  
**Success Criteria**:
  1. EVTX, XML, and JSON event files parse without errors into `NormalizedEvent` models.
  2. Sysmon EIDs 1, 3, 5, 6, 7, 8, 10, 11, 12–14, 19–21, 22, 23–26 and Security 4688/4697/4698 & PowerShell 4103/4104 are accurately normalized.
  3. Malformed records do not crash the pipeline; import errors are logged with detailed statistics.
  4. Raw event payloads are preserved alongside normalized fields for full evidence provenance.

**Plans**: 3/3 plans complete

Plans:
- [x] 01-01: Normalized Event Pydantic Schema, SHA-256 Fingerprinting, and Import Statistics (Wave 1)
- [x] 01-02: Streaming Ingestion Engine & Safe Parsers for EVTX, XML, and JSON (Wave 2)
- [x] 01-03: Sysmon, Security, and PowerShell Normalizers, Pipeline, and Test Fixtures (Wave 3)

### Phase 2: Database Layer & Persistent Storage

**Goal**: Implement a robust, thread-safe SQLite storage engine with migrations, foreign keys, indexes, and parameterized queries.  
**Depends on**: Phase 1  
**Requirements**: ALERT-01  
**Success Criteria**:
  1. SQLite schema handles `imported_files`, `import_jobs`, `events`, `processes`, `detection_rules`, `alerts`, `alert_evidence`, and `investigations`.
  2. Composite indexing enables fast queries on timestamps, `process_guid`, `event_id`, and `computer`.
  3. Batch insertion supports bulk importing of thousands of events efficiently.

**Plans**: 2/2 plans complete

Plans:
- [x] 02-01: SQLite Connection Manager, WAL Configuration, and Versioned Migration Runner (Wave 1)
- [x] 02-02: Event & Alert Repositories, Parameterized Query Builder, and Bulk Ingestion (Wave 2)

### Phase 3: Process Relationship Analyzer

**Goal**: Reconstruct full parent-child process execution trees and ancestry using Sysmon `ProcessGuid` as the invariant key, handling PID reuse and missing parents.  
**Depends on**: Phase 1, Phase 2  
**Requirements**: PROC-01, PROC-02, PROC-03, PROC-04, PROC-05  
**Success Criteria**:
  1. Multi-generational process ancestry is correctly assembled from `ProcessGuid` and `ParentProcessGuid`.
  2. PID reuse within the same dataset is isolated using temporal process lifespans (creation to termination).
  3. Orphaned processes and incomplete parent event sequences are handled gracefully without exceptions.
  4. Process tree converts to NetworkX digraph for downstream visualization and path traversal.

**Plans**: 2/2 plans complete

Plans:
- [x] 03-01: Process Tree Graph Model, Synthetic GUIDs, PID Resolver, and Process Repository (Wave 1)
- [x] 03-02: Suspicious Lineage Anomaly Detector, Tree Serialization, and Pipeline Integration (Wave 2)

### Phase 4: Detection Rule Engine & Sysmon Core Library

**Goal**: Implement a Sigma-inspired YAML detection rule loader, validator, matcher, and core Sysmon rule library producing explainable detections.  
**Depends on**: Phase 1, Phase 2  
**Requirements**: RULE-01, RULE-02, RULE-03, RULE-04, RULE-05  
**Success Criteria**:
  1. YAML detection rules are validated against a strict Pydantic rule schema.
  2. Rule matcher evaluates exact, regex, contains, wildcards, case-insensitivity, and exclusion baselines.
  3. Every rule hit produces a structured `DetectionMatch` containing the matched fields, values, rule ID, and investigation guidance.
  4. Core library of at least 15 verified rules targeting Sysmon activity runs against test data.

**Plans**: 3/3 plans complete

Plans:
- [x] 04-01: YAML rule schema definition, validation, and rule loader.
- [x] 04-02: Condition evaluation engine (field matching, logic operators, exclusions).
- [x] 04-03: Core Sysmon detection rule repository (Process injection, LSASS access, Suspicious DLLs).

### Phase 5: PowerShell & Persistence Threat Analyzers

**Goal**: Deliver specialized analyzers for PowerShell script block analysis and multi-source persistence mechanisms.  
**Depends on**: Phase 3, Phase 4  
**Requirements**: PWSH-01, PWSH-02, PWSH-03, PWSH-04, PWSH-05, PERS-01, PERS-02, PERS-03, PERS-04, PERS-05  
**Success Criteria**:
  1. Base64 encoded PowerShell commands are safely decoded without executing any payload.
  2. Download cradles, execution policy bypass, and hidden windows are detected with contextual scoring.
  3. Persistence mechanisms across Registry Run keys, Services, WMI subscriptions, and Scheduled Tasks (from EID 4698/Task logs) are flagged with evidence.

**Plans**: 2/2 plans complete

Plans:
- [x] 05-01: PowerShell analyzer with safe de-obfuscation and multi-pattern threat scoring.
- [x] 05-02: Persistence analyzer correlating Registry, Service, Task Scheduler, and WMI telemetry.

### Phase 6: Event Correlation & Alert Management

**Goal**: Link multi-stage attack indicators into correlated incident alerts and provide complete alert lifecycle management.  
**Depends on**: Phase 4, Phase 5  
**Requirements**: CORR-01, CORR-02, CORR-03, CORR-04, ALERT-02, ALERT-03, ALERT-04  
**Success Criteria**:
  1. Multi-step attack sequences (e.g. Word -> PowerShell -> Network -> Run Key) are correlated into compound alerts.
  2. Correlation engine respects temporal windows and process lineage without excessive noise.
  3. Alerts persist in SQLite with full evidence references and status workflow (`New` -> `Resolved` / `False Positive`).

**Plans**: 2 plans

Plans:
- [ ] 06-01: Event correlation engine with sliding time-window and process tree linking.
- [ ] 06-02: Alert management service, deduplication, and evidence traceability repository.

### Phase 7: False-Positive & Rule Evaluation Engine

**Goal**: Implement a scientific evaluation harness to measure detection efficacy against labeled test datasets.  
**Depends on**: Phase 4, Phase 6  
**Requirements**: EVAL-01, EVAL-02, EVAL-03, EVAL-04  
**Success Criteria**:
  1. Test harness runs rules against labeled ground-truth event datasets (attacks vs. benign admin noise).
  2. Automated calculation of TP, FP, TN, FN, Precision, Recall, F1 score, and False Positive Rate per rule.
  3. Rule performance reports generated in JSON and structured Markdown for detection engineering tuning.

**Plans**: 2 plans

Plans:
- [ ] 07-01: Evaluation runner, labeled dataset fixtures, and confusion matrix calculator.
- [ ] 07-02: Evaluation reporting, tuning recommendation generator, and benchmark CLI.

### Phase 8: SOC Investigation Dashboard & Timeline

**Goal**: Build a 10-page Streamlit SOC investigation dashboard with Plotly timelines and NetworkX process graphs.  
**Depends on**: Phase 2, Phase 3, Phase 6, Phase 7  
**Requirements**: UI-01, UI-02, UI-03, UI-04, UI-05, UI-06, UI-07, UI-08, UI-09, UI-10  
**Success Criteria**:
  1. All 10 SOC pages render cleanly: Overview, Event Explorer, Alerts, Process Tree, Investigation Timeline, Persistence Analysis, Detection Rules, Evaluation, Import History, Settings.
  2. Interactive process graphs and timelines display nodes with full forensic drill-down.
  3. UI cleanly isolates presentation from backend detection services and SQLite storage.

**Plans**: 3 plans

Plans:
- [ ] 08-01: Streamlit layout shell, state management, Overview, and Event Explorer pages.
- [ ] 08-02: Process Tree visualization, Timeline view, and Persistence analysis pages.
- [ ] 08-03: Alert management, Detection Rules, Evaluation metrics, and Import history pages.

---
*Roadmap defined: 2026-11-03*
