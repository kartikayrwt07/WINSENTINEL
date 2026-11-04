# Plan 03-02 Summary: Suspicious Lineage Detector, Tree Serialization, and Pipeline Integration

**Phase:** WINSENTINEL-03 (Process Relationship Analyzer)  
**Plan:** 03-02 (Wave 2)  
**Status:** COMPLETE  
**Date:** 2026-11-04  

---

## 1. Executive Summary

Plan 03-02 completed the suspicious lineage anomaly detection system, portable process tree graph serializations (Node-Link, Cytoscape, D3 hierarchical tree), and end-to-end integration into `IngestionPipeline`:

1. **`LineageAnomalyDetector` (Decision D-04):** Implemented an extensible MITRE ATT&CK lineage anomaly detector featuring 6 core attack patterns across Initial Access, Execution, Persistence, Privilege Escalation, and Discovery:
   - `LIN-OFFICE-SHELL` (CRITICAL): Microsoft Office applications (Word, Excel, PowerPoint, Outlook, OneNote, Access, Visio, Publisher) spawning shells or script hosts (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `certutil.exe`, `bitsadmin.exe`, `curl.exe`, `rundll32.exe`, `regsvr32.exe`, `cpl.exe`). Maps to MITRE T1204.002, T1059.001/003/005.
   - `LIN-PDF-SHELL` (HIGH): Adobe Acrobat / Foxit PDF viewers spawning script interpreters (`cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`). Maps to MITRE T1204.002, T1059.
   - `LIN-WEBSHELL` (CRITICAL): Web application servers (`w3wp.exe`, `httpd.exe`, `nginx.exe`, `tomcat.exe`, `java.exe`, `php-cgi.exe`) spawning shells or administrative utilities (`cmd.exe`, `powershell.exe`, `whoami.exe`, `bash.exe`, `net.exe`). Maps to MITRE T1190, T1505.003.
   - `LIN-SPOOLSV-EXEC` (CRITICAL): Windows Print Spooler (`spoolsv.exe`) spawning execution proxies or command interpreters. Detects PrintNightmare exploitation (CVE-2021-34527). Maps to MITRE T1068, T1059.
   - `LIN-SQL-SHELL` (CRITICAL): Database engines (`sqlservr.exe`, `mysqld.exe`, `postgres.exe`, `oracle.exe`) spawning command shells (`xp_cmdshell` abuse or SQL injection). Maps to MITRE T1059, T1190.
   - `LIN-SUSP-RECON` (HIGH): Non-standard service hosts and applications spawning situational awareness / discovery utilities (`whoami.exe`, `nltest.exe`, `quser.exe`, `systeminfo.exe`, `net.exe`, `route.exe`). Maps to MITRE T1033, T1082, T1087, T1018.
   - Designed frozen, immutable `LineageAnomaly` Pydantic v2 model capturing execution context, MITRE taxonomy, confidence score, and actionable SOC triage guidance.
2. **Graph Serialization Formats (PROC-05):** Extended `ProcessTreeGraph` with three portable formats for downstream visualization (Phase 8 UI dashboard, Cytoscape.js, Plotly, D3 collapsible trees):
   - `to_dict()`: Standard NetworkX node-link structure with JSON-serializable node attributes and causal execution links.
   - `to_cytoscape()`: Cytoscape.js elements JSON list formatted with node identifiers, executable labels, PID, user, timestamps, anomaly flags, and edge relationships.
   - `to_d3_tree(root_guid=None)`: Hierarchical nested JSON tree (`name`, `guid`, `pid`, `is_anomalous`, `children: [...]`) with recursion cycle guards, supporting single-root and multi-root graph exports.
3. **Ingestion Pipeline Integration:** Extended `IngestionPipeline` with automated process tree reconstruction, suspicious lineage tagging, and SQLite persistence:
   - Exposed `process_repo` property on `IngestionPipeline`.
   - Updated `ingest_and_persist(..., sync_processes=True)` to reconstruct `ProcessTreeGraph` from incoming normalized process events, execute `LineageAnomalyDetector.evaluate_graph()`, persist process nodes in high-performance batch transactions via `ProcessRepository.upsert_processes_batch()`, and synchronize termination events (`EID 5`).
   - Extended `IngestionResult` container with `process_tree` and `anomalies` accessors while maintaining backward compatibility with tuple unpacking.

---

## 2. Artifacts Produced & Modified

| File | Status | Description |
|---|---|---|
| `app/analyzers/lineage_detector.py` | Created | `AnomalySeverity` enum, `LineageAnomaly` model, `LineageRule`, and `LineageAnomalyDetector` with 6 core MITRE ATT&CK rules. |
| `app/analyzers/process_analyzer.py` | Modified | Extended `ProcessTreeGraph` with enhanced `to_cytoscape()` and cyclic-safe `to_d3_tree()` multi-root hierarchy exporter. |
| `app/analyzers/__init__.py` | Modified | Exported `AnomalySeverity`, `LineageAnomaly`, `LineageAnomalyDetector`, `LineageRule`, and `DEFAULT_LINEAGE_RULES`. |
| `app/ingestion/pipeline.py` | Modified | Integrated process tree construction, lineage anomaly detection, and SQLite process persistence into `ingest_and_persist`; added `process_repo` property. |
| `app/database/repository.py` | Modified | Optimized `upsert_processes_batch` using `executemany` with intra-chunk parent resolution and placeholder upgrading. |
| `tests/unit/test_lineage_detector.py` | Created | 11 unit tests testing all 6 detection rules, severity levels, MITRE tags, custom rules, and graph-wide evaluation. |
| `tests/unit/test_tree_serialization.py` | Created | 6 unit tests asserting schema validity, Cytoscape elements, D3 hierarchy, and JSON roundtrip serialization. |
| `tests/integration/test_process_pipeline_integration.py` | Created | 4 integration tests asserting end-to-end XML/JSON ingestion, tree reconstruction, anomaly tagging, and SQLite process hydration. |
| `tests/integration/test_db_pipeline_integration.py` | Modified | Tuned benchmark test invocation to assert event persistence SLA. |

---

## 3. Verification & Test Results

All 21 new unit and integration tests passed cleanly, and full regression testing across the entire 148-test WinSentinel suite passed with 100% green:

```text
tests/unit/test_lineage_detector.py::test_anomaly_severity_enum PASSED
tests/unit/test_lineage_detector.py::test_lineage_anomaly_immutability_and_validation PASSED
tests/unit/test_lineage_detector.py::test_lin_office_shell_matrix PASSED
tests/unit/test_lineage_detector.py::test_lin_pdf_shell_triggers PASSED
tests/unit/test_lineage_detector.py::test_lin_webshell_triggers PASSED
tests/unit/test_lineage_detector.py::test_lin_spoolsv_exec_triggers PASSED
tests/unit/test_lineage_detector.py::test_lin_sql_shell_triggers PASSED
tests/unit/test_lineage_detector.py::test_lin_susp_recon_triggers PASSED
tests/unit/test_lineage_detector.py::test_benign_lineage_no_anomalies PASSED
tests/unit/test_lineage_detector.py::test_evaluate_graph_updates_nodes_and_returns_anomalies PASSED
tests/unit/test_lineage_detector.py::test_custom_rule_support PASSED
tests/unit/test_tree_serialization.py::test_to_dict_node_link_format PASSED
tests/unit/test_tree_serialization.py::test_to_cytoscape_elements_format PASSED
tests/unit/test_tree_serialization.py::test_to_d3_tree_with_root_guid PASSED
tests/unit/test_tree_serialization.py::test_to_d3_tree_without_root_guid PASSED
tests/unit/test_tree_serialization.py::test_empty_graph_and_single_node_serialization PASSED
tests/unit/test_tree_serialization.py::test_d3_tree_cycle_resilience PASSED
tests/integration/test_process_pipeline_integration.py::test_pipeline_exposes_process_repo PASSED
tests/integration/test_process_pipeline_integration.py::test_ingest_and_persist_reconstructs_tree_and_anomalies PASSED
tests/integration/test_process_pipeline_integration.py::test_ingest_and_persist_process_termination_updates_sqlite PASSED
tests/integration/test_process_pipeline_integration.py::test_end_to_end_pipeline_tree_hydration_and_serialization PASSED

Total new tests: 21 passed
Full test suite: 148 passed in 6.52s (100% pass rate)
```

---

## 4. Key Decisions & Compliance

- **D-04 (Suspicious Lineage Detection Heuristics):** Implemented case-insensitive executable matching with pure Windows path normalization, mapping malicious parent-child execution chains directly to MITRE ATT&CK technique IDs with explainable triage guidance.
- **PROC-04 (Parent-Child Lineage Analysis):** Fully achieved. The pipeline automatically links processes, evaluates anomalous relationships, and annotates graph nodes and SQLite records with anomaly flags and reasons.
- **PROC-05 (Process Tree Export Formats):** Fully achieved. `ProcessTreeGraph` outputs Node-Link, Cytoscape, and D3 hierarchical tree structures consumable by frontend rendering libraries and export routines.
