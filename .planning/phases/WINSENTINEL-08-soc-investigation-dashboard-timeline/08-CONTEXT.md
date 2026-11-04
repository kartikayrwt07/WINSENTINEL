# Phase 8: SOC Investigation Dashboard & Timeline - Context

**Gathered:** 2026-11-05  
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 8 delivers the complete, production-grade 10-page SOC Investigation Dashboard and timeline visualization for WinSentinel:
- **Architecture & Decoupled Presentation Layer (`app/ui/`):**
  - Presentation services layer (`app/ui/services/`): Backend query and analytical services that isolate UI presentation from SQLite storage and detection services. All analytical methods are testable via standard unit tests without requiring a running browser.
  - Streamlit multi-page application structure (`app/ui/main.py` and `app/ui/pages/`): A clean, intuitive sidebar navigation shell supporting dark SOC aesthetic, session state management, and unified styling.
- **The 10 Required SOC Pages (UI-01 through UI-10):**
  1. **Page 1: Overview Dashboard (`UI-02`)**:
     - System KPIs: Total events ingested, alerts by severity (Critical, High, Medium, Low), active incidents, imported files count.
     - Severity breakdown bar/donut charts.
     - MITRE ATT&CK tactic/technique distribution.
     - Top targeted hosts, top alert rules, and recent high-severity incident summary.
  2. **Page 2: Event Explorer (`UI-03`)**:
     - Fast multi-field filtering: Event ID, host computer, process name/image, user account, channel/provider, and time range.
     - Tabular view with pagination.
     - Deep forensic record inspector rendering raw XML/JSON and formatted normalized field breakdowns.
  3. **Page 3: Alert Management (`UI-04`)**:
     - Alert triage view with severity badges, status filtering (`New`, `Investigating`, `Escalated`, `Resolved`, `False Positive`).
     - Alert detail drill-down showing linked raw event evidence, matched rule criteria, and explanation.
     - Analyst workflow actions: update status with disposition notes and investigator name.
  4. **Page 4: Process Tree Visualizer (`UI-05`)**:
     - Process ancestry and hierarchy graph powered by NetworkX.
     - Interactive SVG/Plotly rendering displaying parent-child lineages with node metadata (Process ID, ProcessGuid, command line, user, integrity level).
     - Visual indicators for processes associated with detections or alerts.
  5. **Page 5: Chronological Investigation Timeline (`UI-06`)**:
     - Chronological timeline charting multi-source events (Process creation, Network connections, File writes, Registry modifications, DNS queries).
     - Zoomable/filterable time slider.
     - Click-to-inspect forensic detail modal/expander.
  6. **Page 6: Persistence Analysis (`UI-07`)**:
     - Specialized view summarizing persistence mechanisms across Registry Run keys, IFEO debuggers, Service installations, Scheduled Tasks, and WMI subscriptions.
     - Filter by persistence category and host computer.
  7. **Page 7: Detection Rule Manager (`UI-08`)**:
     - Rule catalog browser showing all loaded Sigma-style rules, status, severity, and MITRE mapping.
     - Rule detail inspector showing YAML definition, selection conditions, and investigation guidance steps.
  8. **Page 8: Detection Evaluation & Benchmarking (`UI-09`)**:
     - Evaluation dashboard displaying confusion matrix metrics (TP, FP, TN, FN, Precision, Recall, F1, FPR, Accuracy).
     - Per-rule health breakdown (Healthy, Dead, Noisy).
     - Automated rule tuning recommendations and candidate suppression suggestions from `RuleTuner`.
  9. **Page 9: Import History & Health (`UI-10`)**:
     - Ingestion job audit history: imported file paths, formats (EVTX, XML, JSONL), parsed count, malformed count, duplicate count, error logs.
     - Database health and storage statistics.
  10. **Page 10: Platform Settings & DB Management (`UI-01`)**:
      - Database configuration, correlation sliding window adjustment, rule path reload, and cache clearance.

</domain>

<decisions>
## Implementation Decisions

### Decoupled Service Architecture
- **D-01:** Implement a decoupled analytical service layer in `app/ui/services/`:
  - `OverviewService`: Ingestion stats, alert severity tallies, MITRE breakdown.
  - `EventExplorerService`: Fast paginated event filtering across multiple fields.
  - `AlertUIService`: Alert listing, status transitions, evidence drill-down.
  - `ProcessGraphService`: Builds NetworkX tree structures and translates them into interactive SVG and Plotly graph specifications.
  - `TimelineService`: Extracts and sequences chronological events across disparate providers.
  - `PersistenceUIService`: Queries and categorizes persistence indicators.
  - `RuleUIService`: Introspects loaded detection rules and metadata.
  - `EvaluationUIService`: Runs/loads benchmark reports and exposes metrics to UI.
  - `ImportUIService`: Queries import jobs and parser logs.
  - **Advantage:** Enables 100% automated pytest coverage of all data transformation, querying, and graph-building logic without requiring a live Streamlit runtime.

### Hybrid Interactive Visualizations
- **D-02:** Hybrid SVG and Plotly rendering:
  - Generate clean, self-contained SVG/HTML markup using NetworkX for process graphs and chronological timelines that render universally in Streamlit (via `st.components.v1.html` or `st.markdown`).
  - Provide Plotly figure generation methods when Plotly is present, falling back gracefully to SVG/HTML markup.

### SQLite Direct Query & Pagination
- **D-03:** Direct SQLite Service Layer:
  - Repository queries utilize `LIMIT` / `OFFSET` pagination, indexed lookups (`timestamp`, `computer`, `event_id`, `process_guid`), and efficient aggregations.
  - Avoid loading entire multi-gigabyte log collections into frontend memory.

</decisions>

<specifics>
## Specific Ideas & Test Coverage

- Unit tests for all UI services in `tests/unit/ui/`:
  - `test_overview_service.py`
  - `test_event_explorer_service.py`
  - `test_alert_ui_service.py`
  - `test_process_graph_service.py`
  - `test_timeline_service.py`
  - `test_persistence_ui_service.py`
  - `test_rule_ui_service.py`
  - `test_evaluation_ui_service.py`
  - `test_import_ui_service.py`
- Integration tests in `tests/integration/test_ui_pages_smoke.py`:
  - Verifies that all 10 page modules import cleanly and execute their render routines with mocked Streamlit state.
  - Verifies end-to-end data flow from SQLite database through UI services to formatted components.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing:**
- `.planning/PROJECT.md` — Section 6 Module J (SOC Investigation Dashboard) and Section 8 (UI Architecture).
- `.planning/REQUIREMENTS.md` — UI-01 through UI-10.
- `.planning/ROADMAP.md` — Phase 8 goals, success criteria, and plans breakdown.
- `app/database/repository.py` — `EventRepository`, `AlertRepository`, `InvestigationRepository`, `ProcessTreeRepository`.
- `app/analyzers/process_analyzer.py` — `ProcessTreeGraph` traversal methods.
- `app/evaluation/runner.py` — `EvaluationRunner` and `EvaluationReport`.

</canonical_refs>
