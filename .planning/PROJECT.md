# WinSentinel — Windows Endpoint Threat Monitoring & Investigation Platform

## What This Is

WinSentinel is a modular, offline-first Python-based Windows Endpoint Threat Monitoring and Investigation platform. It processes Windows Sysmon and Security event log exports (EVTX, XML, JSON), reconstructs process execution hierarchies via Sysmon ProcessGuid tracking, runs a Sigma-inspired YAML detection rule engine, correlates multi-stage attack indicators, and delivers an explainable SOC-style investigation dashboard in Streamlit backed by local SQLite storage.

## Core Value

Every detection must have explainable, traceable supporting evidence tying matched rule conditions directly back to raw event fields, process lineage, and correlation logic without black-box inferences or alert fabrications.

## Requirements

### Validated

(None yet — ship to validate)

### Active

- [ ] **INGEST-01**: Ingestion engine for Windows EVTX exports, Sysmon XML exports, and normalized JSON logs with malformed record handling and import statistics.
- [ ] **NORM-01**: Typed event normalization pipeline mapping heterogeneous event sources into a unified `NormalizedEvent` schema with raw payload preservation.
- [ ] **PROC-01**: Graph-backed Process Relationship Analyzer tracking parent-child process ancestry via Sysmon `ProcessGuid` / `ParentProcessGuid`, handling PID reuse and missing parent events.
- [ ] **RULE-01**: Sigma-inspired YAML detection rule engine supporting field-level matching, string transformations, regex/wildcards, exclusions, and structured hit explanations.
- [ ] **RULE-02**: Out-of-the-box detection rule library targeting Sysmon events (Process Creation, Network, DLL Load, Process Access, Registry, WMI, File Tampering).
- [ ] **PWSH-01**: PowerShell threat detection analyzer targeting encoded commands, download cradles, execution policy bypass, and operational script block logs (EID 4103/4104).
- [ ] **PERS-01**: Persistence detection analyzer monitoring Registry Run keys, Services, Task Scheduler activity (EID 4698 / Task Operational), and WMI event consumers.
- [ ] **CORR-01**: Event Correlation Engine linking multi-stage activity across configurable time windows, host/user context, and process lineage to generate unified alerts without duplicate noise.
- [ ] **ALERT-01**: Alert Management and SQLite persistence tracking alert lifecycle (New, Investigating, Escalated, Resolved, False Positive) with analyst notes.
- [ ] **EVAL-01**: Detection Rule Evaluation Engine measuring Precision, Recall, F1 score, and False-Positive Rate against labeled synthetic test datasets.
- [ ] **UI-01**: Streamlit SOC investigation dashboard featuring Overview, Event Explorer, Alerts, Process Tree, Investigation Timeline, Persistence Analysis, Detection Rules, Evaluation, Import History, and Settings.

### Out of Scope (MVP)

- Live endpoint real-time agent/kernel driver collection — MVP operates strictly on exported log files (EVTX, XML, JSON).
- Enterprise EDR active automated containment/response (process killing, network isolation) — WinSentinel is a defensive monitoring and offline investigation platform.
- Cloud synchronization, SaaS ingestion, multi-tenant clustering, Kubernetes — MVP uses local embedded SQLite.
- Black-box Machine Learning / AI classification models — MVP relies on deterministic, auditable, explainable Sigma-style YAML rules.
- Administrator privilege requirement for execution — parsing and investigation must run safely in standard user context.

## Context

- Target OS: Windows endpoint analysis (runs locally on Windows Python 3.11+).
- Input primary telemetry: Windows Sysmon (EIDs 1, 3, 5, 6, 7, 8, 10, 11, 12–14, 19–21, 22, 23–26).
- Secondary telemetry: Windows PowerShell Operational (4103, 4104), Windows Security (4688, 4697, 4698), Task Scheduler Operational.
- Security-first design: Imported logs are treated as untrusted data; commands and payloads are never executed.

## Constraints

- **Language & Runtime**: Python 3.11+, virtual environment managed.
- **Dependencies**: Minimal dependencies (`python-evtx`, `pydantic`, `pyyaml`, `networkx`, `pandas`, `plotly`, `streamlit`, `pytest`).
- **Storage**: Embedded SQLite with parameterized queries, indexed for forensic queries.
- **Execution**: Strictly offline analysis; no unprompted network telemetry or external API leaks.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| ProcessGuid as Primary Process Key | Windows PIDs are reused quickly by the OS kernel; Sysmon ProcessGuid guarantees unique process lifecycle identification. | — Pending Approval |
| Sigma-Inspired YAML Format | Industry standard familiarity for detection engineers while avoiding full Sigma compiler overhead for MVP. | — Pending Approval |
| Streamlit Multi-Page UI | Clean SOC investigation interface without requiring complex frontend framework dependencies. | — Pending Approval |
| Deterministic Synthetic Testing | Enables automated regression and false-positive evaluation without introducing live malware payloads. | — Pending Approval |

---
*Last updated: 2026-11-03 after GSD new-project initialization*

