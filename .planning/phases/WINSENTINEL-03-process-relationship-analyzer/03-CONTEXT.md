# Phase 3: Process Relationship Analyzer - Context

**Gathered:** 2026-11-04  
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 3 delivers the graph-based process execution hierarchy, ancestry tracking, and anomalous lineage analyzer for WinSentinel:
- Construct directed acyclic process trees using Sysmon `ProcessGuid` as the invariant key.
- Deterministic synthetic GUID generation (`UUID5`) for non-Sysmon events (Security 4688) lacking native Sysmon GUIDs.
- Graceful handling of missing parent processes by synthesizing placeholder parent nodes (`is_synthesized=True`) to maintain unbroken ancestry trees.
- Temporal process lifespan modeling (creation EID 1 to termination EID 5) to isolate and resolve OS PID recycling across time.
- NetworkX `DiGraph` integration for ancestry walking, subtree extraction, root discovery, and graph serialization.
- Dedicated `LineageAnomalyDetector` with built-in heuristic matrix targeting MITRE ATT&CK techniques (T1059, T1204, T1190: Office/Spooler/SQL/Web servers spawning command shells/script engines).

</domain>

<decisions>
## Implementation Decisions

### Process Node Identity & Non-Sysmon Invariant Key
- **D-01:** Sysmon `ProcessGuid` is strictly prioritized as the primary invariant node identifier. When non-Sysmon events (e.g. Windows Security EID 4688) lack a `ProcessGuid`, compute a deterministic synthetic GUID using `uuid.uuid5(uuid.NAMESPACE_DNS, f"{computer}:{pid}:{timestamp_iso}")`. This ensures 100% of process nodes have a valid UUID key, unifying Sysmon and Security events into a single graph model.

### Missing Parent & Orphan Handling
- **D-02:** When a child process event references a `ParentProcessGuid` whose creation event is missing from the dataset (e.g. created before log collection started), construct a placeholder parent node flagged with `is_synthesized=True`. Populate known metadata from child attributes (`parent_image`, `parent_process_id`, `parent_user`). This preserves continuous ancestry walks from child up to the known ancestor without dropping nodes or breaking graph connectivity.

### PID Reuse Resolution Across Time
- **D-03:** Model process nodes with temporal lifespans: `start_time` (from Sysmon EID 1 / Security 4688) and `end_time` (from Sysmon EID 5 / termination). When querying or resolving a process by `(Computer, PID, Timestamp)`, evaluate `start_time <= event_timestamp <= (end_time or infinity)`. This cleanly differentiates distinct processes that reused the same operating system PID at different times.

### Suspicious Lineage Detection Strategy
- **D-04:** Implement a dedicated `LineageAnomalyDetector` in `app/analyzers/process_analyzer.py` with an extensible MITRE matrix. Automatically detect and produce structured `LineageAnomaly` findings (with rule ID, severity, confidence, parent/child paths, command line, and MITRE tactic/technique) for classic anomalous execution chains:
  - Document/Productivity apps (`winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, `acrobat.exe`) spawning shell/script interpreters (`cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`).
  - Web servers (`w3wp.exe`, `httpd.exe`, `nginx.exe`, `tomcat.exe`) spawning shells (web shell indicator).
  - System service processes (`spoolsv.exe`, `sqlservr.exe`) spawning command interpreters (PrintNightmare / SQL exploitation indicator).
  - Shell interpreters spawning suspicious reconnaissance utilities (`whoami.exe`, `nltest.exe`, `net.exe`, `quser.exe`).

### Developer & Agent Discretion
- Graph representation: Build an in-memory NetworkX `DiGraph` representation where edges point from parent to child (`parent_guid -> child_guid`).
- Persistence integration: Store reconstructed process nodes and lifespans into the SQLite `processes` table created in Phase 2.
- Tree serialization: Expose `to_dict()` and `to_cytoscape()` / `to_d3()` JSON structures for downstream dashboard visualization in Phase 8.

</decisions>

<specifics>
## Specific Ideas & Test Coverage

- Unit tests verifying multi-generational ancestry walking (Grandparent -> Parent -> Child -> Grandchild).
- PID reuse test with two distinct processes sharing PID 4096 four hours apart, asserting lookups by timestamp retrieve the correct unique process node.
- Synthetic parent synthesis test asserting missing parents become `is_synthesized=True` nodes rather than disconnected orphans.
- Anomaly detection tests validating hits for Word spawning PowerShell, Spooler spawning cmd, and benign parentage (explorer.exe spawning notepad.exe) remaining clean.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing:**
- `.planning/PROJECT.md` — Section 6 Module C (Process Relationship Analyzer).
- `.planning/REQUIREMENTS.md` — PROC-01 through PROC-05.
- `.planning/ROADMAP.md` — Phase 3 goals, success criteria, and plans breakdown.
- `.planning/phases/WINSENTINEL-02-database-layer-persistent-storage/02-VERIFICATION.md` — Schema and repository persistence contracts.

</canonical_refs>
