# Requirements: WinSentinel

**Defined:** 2026-11-03  
**Core Value:** Every detection must have explainable, traceable supporting evidence tying matched rule conditions directly back to raw event fields, process lineage, and correlation logic without black-box inferences.

## v1 Requirements

### 1. Ingestion Engine (INGEST)
- [ ] **INGEST-01**: Parser for Windows EVTX binary log files using `python-evtx` with error recovery for corrupt/truncated records.
- [ ] **INGEST-02**: Parser for Sysmon XML exports preserving raw XML strings and attributes.
- [ ] **INGEST-03**: Parser for pre-extracted/normalized JSON event exports.
- [ ] **INGEST-04**: Malformed event error logging and import statistics reporting (total events, parsed, malformed, skipped, duplicate).
- [ ] **INGEST-05**: Duplicate event suppression/detection using composite key (provider, channel, record_id, computer, timestamp).
- [ ] **INGEST-06**: Safe offline file loading without requiring Administrator privileges and preventing path traversal.

### 2. Event Normalization & Validation (NORM)
- [ ] **NORM-01**: Typed Pydantic data model `NormalizedEvent` containing unified fields across all supported event types.
- [ ] **NORM-02**: Sysmon EID 1 (Process Creation), 3 (Network), 5 (Process Termination), 6 (Driver Load), 7 (Image Load), 8 (CreateRemoteThread), 10 (Process Access), 11 (File Creation) normalization.
- [ ] **NORM-03**: Sysmon EID 12, 13, 14 (Registry Object/Value Activity) normalization.
- [ ] **NORM-04**: Sysmon EID 19, 20, 21 (WMI Filter/Consumer/Binding) normalization.
- [ ] **NORM-05**: Sysmon EID 22 (DNS Query) and 23–26 (File Delete/Tampering) normalization.
- [ ] **NORM-06**: Windows Security EID 4688 (Process Creation with Command Line), 4697 (Service Install), 4698 (Scheduled Task Creation) normalization.
- [ ] **NORM-07**: PowerShell Operational EID 4103 and 4104 (Script Block Logging) normalization.
- [ ] **NORM-08**: Storage of raw event payload alongside normalized attributes for full forensic provenance.

### 3. Process Relationship Analyzer (PROC)
- [ ] **PROC-01**: Reconstruct process ancestry tree using Sysmon `ProcessGuid` and `ParentProcessGuid` as primary keys.
- [ ] **PROC-02**: Handle PID reuse gracefully by scoping temporal process lifespans (creation EID 1 to termination EID 5).
- [ ] **PROC-03**: Detect and handle orphaned processes and missing parent process records.
- [ ] **PROC-04**: Flag anomalous parent-child execution lineages (e.g., Office apps spawning `cmd.exe`/`powershell.exe`, web servers spawning shell interpreters).
- [ ] **PROC-05**: Export process hierarchy into NetworkX digraph representation for graph queries and visualization.

### 4. Detection Rule Engine (RULE)
- [ ] **RULE-01**: YAML-based Sigma-inspired rule schema parser with strict validation (rule metadata, event selection, conditions, severity, exclusions).
- [ ] **RULE-02**: Field-matching engine supporting exact match, case-insensitive match, substring contains, regex patterns, and wildcards.
- [ ] **RULE-03**: Rule exclusion filtering to eliminate known benign administrative baselines.
- [ ] **RULE-04**: Detection match output containing matched rule ID, matched event records, exact matching field/value pairs, detection explanation, and investigation guidance.
- [ ] **RULE-05**: Core rule library for process execution, privilege escalation, credential dumping access (EID 10 targeting LSASS), and lateral movement indicators.

### 5. PowerShell Threat Detection (PWSH)
- [ ] **PWSH-01**: Detection of Base64-encoded command arguments (`-enc`, `-EncodedCommand`) with safe, non-executing string decoding for inspection.
- [ ] **PWSH-02**: Detection of download cradles (`Net.WebClient`, `Invoke-WebRequest`, `IWR`, `Start-BitsTransfer`).
- [ ] **PWSH-03**: Detection of execution policy bypass flags (`-ep bypass`, `-ExecutionPolicy Unrestricted`, `-nop`).
- [ ] **PWSH-04**: Detection of obfuscation, hidden window modes (`-w hidden`), and multi-line script-block execution patterns from EID 4104.
- [ ] **PWSH-05**: Contextual scoring preventing benign administrative PowerShell scripts from generating high-severity false alarms.

### 6. Persistence Detection (PERS)
- [ ] **PERS-01**: Detection of Registry persistence modifications (CurrentVersion\Run, RunOnce, Winlogon, Image File Execution Options / IFEO).
- [ ] **PERS-02**: Detection of Service installation and suspicious driver loads (Sysmon EID 6, Security EID 4697).
- [ ] **PERS-03**: Detection of Scheduled Task creation via Task Scheduler Operational logs and Security EID 4698 (not inferring tasks purely from Sysmon registry events).
- [ ] **PERS-04**: Detection of WMI event subscriptions (Sysmon EID 19, 20, 21: EventFilter, EventConsumer, FilterToConsumerBinding).
- [ ] **PERS-05**: Detection of suspicious binary placement in Startup folders and system directories.

### 7. Event Correlation Engine (CORR)
- [ ] **CORR-01**: Multi-stage attack chain correlation linking process lineage, subsequent network egress, persistence installation, and script execution within configurable time windows.
- [ ] **CORR-02**: Correlation scoping by `ProcessGuid`, host computer, user account, and time window.
- [ ] **CORR-03**: Alert de-duplication to prevent repeated matches from flooding the alert repository.
- [ ] **CORR-04**: Generation of compound incidents linking individual rule matches with an explainable chronological summary.

### 8. Storage & Alert Management (ALERT)
- [ ] **ALERT-01**: SQLite schema with migrations storing raw/normalized events, process trees, detection rules, alerts, evidence references, and analyst notes.
- [ ] **ALERT-02**: Alert lifecycle tracking with status transitions: `New`, `Investigating`, `Escalated`, `Resolved`, `False Positive`.
- [ ] **ALERT-03**: Analyst annotation interface to append notes and investigation disposition to alerts.
- [ ] **ALERT-04**: Forensic evidence drill-down returning original event records and field values backing any alert.

### 9. False-Positive & Rule Evaluation Engine (EVAL)
- [ ] **EVAL-01**: Benchmark runner executing detection rules against labeled synthetic or public event datasets.
- [ ] **EVAL-02**: Calculation of Confusion Matrix metrics per rule and globally: True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN).
- [ ] **EVAL-03**: Performance reporting: Precision, Recall, F1-Score, and False-Positive Rate (FPR).
- [ ] **EVAL-04**: Test suite containing benign administrative noise to validate suppression logic and prevent alert fatigue.

### 10. SOC Investigation Dashboard (UI)
- [ ] **UI-01**: Multi-page Streamlit application structure separating presentation logic from detection services.
- [ ] **UI-02**: Overview dashboard summarizing import jobs, total events, alert counts by severity, and threat breakdown.
- [ ] **UI-03**: Event Explorer with multi-field filtering (EID, host, process, user, time range) and tabular/JSON record inspection.
- [ ] **UI-04**: Alert Management view with search, severity badges, status updating, and evidence inspector.
- [ ] **UI-05**: Interactive Process Tree graph visualization powered by Plotly/NetworkX displaying node metadata and command lines.
- [ ] **UI-06**: Chronological Investigation Timeline chart mapping multi-source events along an interactive timeline.
- [ ] **UI-07**: Persistence Analysis view summarizing registry modifications, services, scheduled tasks, and WMI consumers.
- [ ] **UI-08**: Detection Rule Manager displaying active rules, test status, and metadata.
- [ ] **UI-09**: Detection Evaluation view rendering rule benchmark metrics, confusion matrices, and tuning guidance.
- [ ] **UI-10**: Import History view showing imported files, error counts, parser logs, and import stats.

## v2 Requirements (Deferred)

- **LIVE-01**: Real-time Windows Event Log streaming subscription via Windows Event Log API (`EvtSubscribe`).
- **LIVE-02**: Kernel ETW provider direct capture.
- **ENT-01**: Multi-host distributed collection agent and central server architecture.
- **INTEL-01**: External Threat Intelligence API integration (VirusTotal, AbuseIPDB, AlienVault OTX).
- **EXPORT-01**: Export alerts and timeline to standard formats (MITRE ATT&CK Navigator JSON, STIX/TAXII, CSV/PDF report).

## Out of Scope

| Feature | Reason |
|---------|--------|
| Live Kernel EDR Agent / Active Prevention | Out of scope for offline investigation MVP; active prevention risks host stability. |
| Machine Learning / Deep Learning Classification | Black-box ML lacks explainability; MVP requires deterministic, verifiable rule matching. |
| Cloud / SaaS multi-tenant infrastructure | MVP targets local offline forensic triage without external network dependencies. |
| Automatic live remediation (Process killing / isolation) | MVP is an investigation and detection platform, not an endpoint remediation tool. |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| INGEST-01, INGEST-02, INGEST-03, INGEST-04, INGEST-05, INGEST-06 | Phase 1 | Pending |
| NORM-01, NORM-02, NORM-03, NORM-04, NORM-05, NORM-06, NORM-07, NORM-08 | Phase 1 | Pending |
| ALERT-01 | Phase 2 | Pending |
| PROC-01, PROC-02, PROC-03, PROC-04, PROC-05 | Phase 3 | Pending |
| RULE-01, RULE-02, RULE-03, RULE-04, RULE-05 | Phase 4 | Pending |
| PWSH-01, PWSH-02, PWSH-03, PWSH-04, PWSH-05 | Phase 5 | Pending |
| PERS-01, PERS-02, PERS-03, PERS-04, PERS-05 | Phase 5 | Pending |
| CORR-01, CORR-02, CORR-03, CORR-04 | Phase 6 | Pending |
| ALERT-02, ALERT-03, ALERT-04 | Phase 6 | Pending |
| EVAL-01, EVAL-02, EVAL-03, EVAL-04 | Phase 7 | Pending |
| UI-01, UI-02, UI-03, UI-04, UI-05, UI-06, UI-07, UI-08, UI-09, UI-10 | Phase 8 | Pending |

**Coverage:**
- v1 requirements: 48 total
- Mapped to phases: 48
- Unmapped: 0

---
*Requirements defined: 2026-11-03*
