# Phase 8: SOC Investigation Dashboard & Timeline - Research

**Date:** 2026-11-05  
**Author:** WinSentinel Core Engineering  
**Status:** Complete & Approved for Planning  

---

## 1. Executive Summary & Goals

Phase 8 completes the offline-first Windows Endpoint Threat Monitoring & Forensic Triage Platform by delivering the **10-page SOC Investigation Dashboard**. 

SOC analysts investigating endpoint incidents require rapid, intuitive visibility into telemetry:
- High-level threat postures (KPIs, MITRE ATT&CK distribution, severity breakdowns).
- Interactive forensic drill-downs (process hierarchy trees, multi-source chronological timelines, persistence analyses).
- Alert triage and disposition (FSM lifecycle updates, analyst notes, raw evidence inspectors).
- Detection engineering controls (rule management, false-positive benchmarking, and ingestion auditing).

To guarantee testability, maintainability, and environmental resilience (offline airgapped environments without mandatory live GUI sessions), Phase 8 implements a **Decoupled Architecture**:
1. **Backend Presentation Services (`app/ui/services/`)**: High-performance SQLite query services, data transformers, NetworkX tree builders, and timeline generators that are 100% testable via pytest without Streamlit runtime dependencies.
2. **Interactive Visualizers (`app/ui/components/`)**: Self-contained, responsive SVG and HTML diagram builders for process execution trees and investigation timelines that render cleanly across any browser.
3. **Multi-Page Streamlit App (`app/ui/main.py` & `app/ui/pages/`)**: Clean, structured SOC presentation shell covering all 10 required views (`UI-01` through `UI-10`).

---

## 2. Page Specifications & Feature Mapping

| Page # | Route / File | Requirement | Key Capabilities & Visualizations |
|--------|--------------|-------------|-----------------------------------|
| **Page 1** | `01_overview.py` | **UI-02** | Total events, alert counts by severity (Critical, High, Medium, Low), active compound incidents, imported file count, MITRE tactic/technique distribution, top targeted hosts. |
| **Page 2** | `02_events.py` | **UI-03** | Multi-field filtering (EID, computer, user, image, time window), paginated tabular event view, raw XML/JSON record inspector, forensic field breakdown. |
| **Page 3** | `03_alerts.py` | **UI-04** | Alert triage table with severity badges, FSM status transitions (`New` -> `Investigating` -> `Escalated` -> `Resolved` / `False Positive`), analyst notes attachment, evidence drill-down. |
| **Page 4** | `04_process_tree.py` | **UI-05** | Interactive process lineage tree powered by NetworkX, displaying parent-child PID/ProcessGuid chains, command lines, users, and threat highlights with node drill-down. |
| **Page 5** | `05_timeline.py` | **UI-06** | Chronological multi-source event sequence (Processes, Network egress, Registry edits, Files, DNS), time window zoom, sequential forensic evidence cards. |
| **Page 6** | `06_persistence.py` | **UI-07** | Persistence breakdown: Registry Run/IFEO, Windows Services, Scheduled Tasks (EID 4698), WMI Event Subscriptions, and Startup folder drops. |
| **Page 7** | `07_rules.py` | **UI-08** | Detection rule catalog inspector: YAML view, condition AST summary, MITRE mapping, severity, and investigation guidance steps. |
| **Page 8** | `08_evaluation.py` | **UI-09** | Benchmark evaluation metrics (TP, FP, TN, FN, Precision, Recall, F1, FPR, Accuracy), rule health classifications (Healthy, Dead, Noisy), and tuning suggestions. |
| **Page 9** | `09_import_history.py` | **UI-10** | Ingestion audit log: imported file paths, formats (EVTX, XML, JSONL), parse statistics (parsed, malformed, duplicate, skipped), error details. |
| **Page 10** | `10_settings.py` | **UI-01** | Database path management, correlation sliding window tuning (default 30 min), rule directory reloader, and cache controls. |

---

## 3. Architecture & Decoupled Service Layer

### 3.1 Design Principle: Presentation Decoupling
To avoid fragile GUI testing and ensure instant headless test execution, all business logic, database queries, graph algorithms, and timeline sequencing are isolated in `app/ui/services/`:

```
app/ui/
├── main.py                          # Streamlit application entrypoint & sidebar
├── state.py                         # App session state & database connection manager
├── components/                      # Reusable UI widgets
│   ├── badges.py                    # Severity, status, and category pill badges
│   ├── cards.py                     # Metric summary cards
│   ├── visualizers.py               # Responsive SVG process tree and timeline generator
│   └── tables.py                    # Tabular pagination and formatting helpers
├── services/                        # Decoupled backend query and analytics services
│   ├── overview_service.py          # KPIs, alert severity tallies, MITRE breakdown
│   ├── event_explorer_service.py    # Multi-field filtering and pagination
│   ├── alert_ui_service.py          # Triage, status FSM transitions, evidence drill-down
│   ├── process_graph_service.py     # NetworkX tree traversal and SVG generator
│   ├── timeline_service.py          # Multi-source chronological event sequencer
│   ├── persistence_ui_service.py    # Persistence categories & evidence aggregator
│   ├── rule_ui_service.py           # Sigma rules introspection and AST summaries
│   ├── evaluation_ui_service.py     # EvaluationRunner wrapper and benchmark reporting
│   ├── import_ui_service.py         # Import job history and audit stats
│   └── settings_service.py          # Platform config, DB health, and cache controls
└── pages/                           # Streamlit multi-page views (thin presentation)
    ├── 01_overview.py
    ├── 02_events.py
    ├── 03_alerts.py
    ├── 04_process_tree.py
    ├── 05_timeline.py
    ├── 06_persistence.py
    ├── 07_rules.py
    ├── 08_evaluation.py
    ├── 09_import_history.py
    └── 10_settings.py
```

### 3.2 NetworkX-to-SVG Interactive Visualizer
For `04_process_tree.py`, WinSentinel uses NetworkX to construct directed acyclic process trees (`ProcessTreeGraph`), then calculates hierarchical tree layouts (root to leaves) and renders a responsive, high-contrast SVG diagram:
- Nodes represent processes: colored by threat status (normal: slate gray; alert/malicious: crimson red; suspicious: amber).
- Edge arrows represent parent $\rightarrow$ child creation.
- Tooltips / info cards display: PID, ProcessGuid, Image basename, Command Line, User, Integrity Level.
- Cleanly embedded into Streamlit via `st.components.v1.html` or `st.markdown(..., unsafe_allow_html=True)`.

### 3.3 Chronological Multi-Source Timeline Generator
For `05_timeline.py`, `TimelineService` executes a unified temporal query across the `events` table ordered by `timestamp ASC`:
- Groups events by phase and category (Process Creation, Network Egress, Registry Mutation, Driver Load, DNS).
- Generates an interactive visual sequence with expandable cards for raw forensic inspection.

---

## 4. Phase Breakdown & Execution Strategy

### Plan 08-01: Framework Shell, State Management, Overview, and Event Explorer (Wave 1)
- Core shell and session state: `app/ui/state.py`, `app/ui/main.py`.
- Reusable UI component library: `app/ui/components/badges.py`, `cards.py`, `tables.py`.
- Services: `OverviewService`, `EventExplorerService`, `SettingsService`.
- Pages: `01_overview.py`, `02_events.py`, `10_settings.py`.
- Unit tests: `tests/unit/ui/test_overview_service.py`, `test_event_explorer_service.py`, `test_settings_service.py`.

### Plan 08-02: Process Tree Visualizer, Investigation Timeline, and Persistence View (Wave 2)
- Visualizer components: `app/ui/components/visualizers.py` (SVG process graph and timeline builders).
- Services: `ProcessGraphService`, `TimelineService`, `PersistenceUIService`.
- Pages: `04_process_tree.py`, `05_timeline.py`, `06_persistence.py`.
- Unit tests: `tests/unit/ui/test_process_graph_service.py`, `test_timeline_service.py`, `test_persistence_ui_service.py`.

### Plan 08-03: Alert Management, Rules Catalog, Benchmark Evaluation, and Import History (Wave 3)
- Services: `AlertUIService`, `RuleUIService`, `EvaluationUIService`, `ImportUIService`.
- Pages: `03_alerts.py`, `07_rules.py`, `08_evaluation.py`, `09_import_history.py`.
- Unit tests: `tests/unit/ui/test_alert_ui_service.py`, `test_rule_ui_service.py`, `test_evaluation_ui_service.py`, `test_import_ui_service.py`.
- Full Integration Smoke Test: `tests/integration/test_ui_smoke.py` verifying all 10 pages render without runtime exceptions.

---

## 5. Requirement Traceability Matrix

| Requirement | Plan | File / Service | Verification Method |
|---|---|---|---|
| **UI-01** | Plan 08-01 | `app/ui/main.py`, `app/ui/state.py` | App loads, navigation routes across 10 pages, state maintains DB connection. |
| **UI-02** | Plan 08-01 | `01_overview.py`, `OverviewService` | Unit test validates event, alert, and MITRE KPI aggregation. |
| **UI-03** | Plan 08-01 | `02_events.py`, `EventExplorerService` | Unit test validates multi-field filter, pagination, and JSON viewer. |
| **UI-04** | Plan 08-03 | `03_alerts.py`, `AlertUIService` | Unit test validates triage listing, FSM status transitions, and notes. |
| **UI-05** | Plan 08-02 | `04_process_tree.py`, `ProcessGraphService` | Unit test validates NetworkX ancestry graph build and SVG generation. |
| **UI-06** | Plan 08-02 | `05_timeline.py`, `TimelineService` | Unit test validates chronological multi-source timeline extraction. |
| **UI-07** | Plan 08-02 | `06_persistence.py`, `PersistenceUIService` | Unit test validates registry, service, task, and WMI persistence queries. |
| **UI-08** | Plan 08-03 | `07_rules.py`, `RuleUIService` | Unit test validates rule catalog loading and YAML inspection. |
| **UI-09** | Plan 08-03 | `08_evaluation.py`, `EvaluationUIService` | Unit test validates benchmark metrics reporting and tuning advice. |
| **UI-10** | Plan 08-03 | `09_import_history.py`, `ImportUIService` | Unit test validates import audit log and parser statistics. |

---

*Research concluded. Proceeding to author execution plans 08-01, 08-02, and 08-03.*
