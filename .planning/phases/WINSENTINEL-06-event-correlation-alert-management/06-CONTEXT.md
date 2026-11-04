# Phase 6: Event Correlation & Alert Management - Context

**Gathered:** 2026-11-04  
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 6 delivers the multi-stage attack correlation engine, compound incident generator, alert deduplication mechanism, and alert lifecycle management for WinSentinel:
- **Event Correlation Engine:**
  - Multi-stage attack chain correlation traversing process tree lineage (`ProcessTreeGraph`) across a configurable sliding time window (default 30 minutes).
  - Predefined multi-stage attack chain patterns:
    1. Phishing / Malicious Document Execution (`Office/Reader -> PowerShell/CMD -> Network Egress/Persistence`)
    2. Web Shell / Remote Exploitation (`Web Server -> CMD/PowerShell -> Reconnaissance/Persistence`)
    3. Credential Dumping to Lateral Movement (`LSASS Access -> Network Connection/Service Creation`)
    4. Living-off-the-Land (LotL) Download to Persistence (`Certutil/Bitsadmin Download -> File Drop -> Registry Run/Task/WMI`)
  - Compound Incident generation promoting correlated chains to `Critical` severity with an explainable chronological narrative story linking all stage alerts and raw events.
- **Alert Deduplication & Aggregation:**
  - In-memory and database-backed sliding window deduplication grouping alerts by `(rule_id, computer, process_guid)` to prevent alert fatigue from beaconing or repetitive loop activity.
  - Updates `event_count`, refreshes `last_seen`, and appends new forensic evidence to `alert_evidence`.
- **Alert Lifecycle Management & Forensic Drill-Down:**
  - Enforces formal alert status workflow transitions: `New` -> `Investigating` -> `Escalated` -> `Resolved` / `False Positive`.
  - Analyst annotation and disposition interface (attaching notes and investigator metadata).
  - Complete forensic drill-down returning original event records and field values backing any alert or compound incident.

</domain>

<decisions>
## Implementation Decisions

### Correlation Scope & Sliding Time Window Model
- **D-01:** Implement a lineage-aware correlation engine scoped by `ProcessTreeGraph` ancestor-descendant relationships within a configurable sliding time window (default: 30 minutes, `correlation_window_minutes = 30`).
  - Correlation traverses the directed acyclic graph built in Phase 3 (`ProcessTreeGraph`), evaluating whether child, sibling, or parent processes within the temporal window satisfy multi-stage threat criteria.
  - Scoped by host (`computer`) and user account to prevent cross-host or unrelated background noise from falsely compounding.

### Predefined Multi-Stage Attack Chain Templates
- **D-02:** Implement a declarative, extensible `AttackChainEngine` equipped with 4 core production attack chain patterns:
  1. **Chain 1: Malicious Document / Phishing Execution (T1204.002 -> T1059 -> T1105/T1547)**
     - Stage 1: Productivity software execution (`winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, `acrobat.exe`).
     - Stage 2: Spawning of script/command interpreters (`powershell.exe`, `cmd.exe`, `mshta.exe`, `cscript.exe`).
     - Stage 3: Outbound network egress (Sysmon EID 3) OR persistence installation (Registry Run/Task).
  2. **Chain 2: Web Shell / Server Exploitation (T1190 -> T1505.003 -> T1082/T1087)**
     - Stage 1: Web server host process (`w3wp.exe`, `httpd.exe`, `nginx.exe`, `tomcat.exe`).
     - Stage 2: Spawning interactive shell or PowerShell interpreter.
     - Stage 3: Reconnaissance utilities (`whoami.exe`, `net.exe`, `nltest.exe`, `quser.exe`) OR persistence installation.
  3. **Chain 3: Credential Dumping to Lateral Movement (T1003.001 -> T1021/T1569.002)**
     - Stage 1: Process access / injection targeting `lsass.exe` (Sysmon EID 10 with suspicious mask or EID 8).
     - Stage 2: Outbound network connection to private RFC1918 address (Sysmon EID 3) OR service installation (Security EID 4697).
  4. **Chain 4: Living-off-the-Land Download to Persistence (T1105 -> T1547.001/T1053.005)**
     - Stage 1: Ingress tool transfer via LOLBin (`certutil.exe -urlcache`, `bitsadmin.exe /transfer`).
     - Stage 2: File creation in user-writable directory (Sysmon EID 11).
     - Stage 3: Auto-start persistence via Registry `Run`/`IFEO` (Sysmon EID 12-14) or Scheduled Task (Security EID 4698).

### Compound Incident Representation & Narrative Story
- **D-03:** When an attack chain pattern is satisfied, generate a `CompoundIncident` object:
  - Automatically escalated to `Critical` severity.
  - Constructs a chronological, human-readable forensic summary explaining each stage of the attack from initial entry to objective.
  - References the collection of participating `Alert` records and underlying `NormalizedEvent` records.
  - Persisted into SQLite `investigations` and `alerts` tables with direct evidence foreign keys.

### Alert Deduplication & Aggregation
- **D-04:** Provide sliding-window alert deduplication in `AlertManager`:
  - When a detection rule triggers for `(rule_id, computer, process_guid)` within a 60-minute window, suppress duplicate alert creation.
  - Atomically update existing alert: increment `event_count`, update `last_seen` timestamp, and link new `alert_evidence` entries without creating redundant alert rows.

### Alert Lifecycle Management & Forensic Drill-Down
- **D-05:** Implement complete lifecycle management in `AlertManager` and `AlertRepository`:
  - Enforce status transitions: `New` -> `Investigating` -> `Escalated` -> `Resolved` or `False Positive`.
  - Provide analyst note annotations (`analyst_notes` table) with timestamps, author attribution, and disposition rationales.
  - Provide forensic drill-down API returning complete raw/normalized event payloads and process tree lineage context backing any alert or incident.

### Developer & Agent Discretion
- Code organization:
  - Place correlation logic in `app/correlation/chain_engine.py` and `app/correlation/chains.py`.
  - Place deduplication and lifecycle management in `app/correlation/alert_manager.py`.
  - Place models in `app/models/incident.py`.
- Pipeline integration: Wire correlation and alert management into `IngestionPipeline` so files ingested automatically trigger correlation and alert consolidation.

</decisions>

<specifics>
## Specific Ideas & Test Coverage

- Unit tests for each of the 4 attack chain templates asserting positive match when stages occur within 30 minutes, and rejection when stages exceed the window.
- Unit tests verifying non-lineage events (unrelated processes on same host) do not trigger process-scoped chains.
- Unit tests for alert deduplication asserting 5 repeated events within 10 minutes result in 1 alert record with `event_count=5` and 5 evidence records.
- Unit tests for alert status transitions verifying valid status updates and analyst note creation.
- Integration tests verifying end-to-end telemetry ingestion with multi-stage attack yielding correlated compound incidents in SQLite.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing:**
- `.planning/PROJECT.md` — Section 6 Module G (Event Correlation Engine) and Module H (Alert Generation & Management).
- `.planning/REQUIREMENTS.md` — CORR-01 through CORR-04, ALERT-02 through ALERT-04.
- `.planning/ROADMAP.md` — Phase 6 goals, success criteria, and plans breakdown.
- `.planning/phases/WINSENTINEL-02-database-layer-persistent-storage/02-VERIFICATION.md` — Relational schema for `alerts`, `alert_evidence`, `investigations`, `analyst_notes`.
- `.planning/phases/WINSENTINEL-03-process-relationship-analyzer/03-VERIFICATION.md` — `ProcessTreeGraph` ancestry walking.
- `.planning/phases/WINSENTINEL-04-detection-rule-engine-sysmon-core-library/04-VERIFICATION.md` — Detection rule engine and `DetectionMatch`.
- `.planning/phases/WINSENTINEL-05-powershell-persistence-threat-analyzers/05-VERIFICATION.md` — PowerShell threat and persistence analyzer models.

</canonical_refs>
