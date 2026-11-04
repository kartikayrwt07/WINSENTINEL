# Phase 6: Event Correlation & Alert Management - Research & Architectural Blueprint

**Date:** 2026-11-04  
**Author:** WinSentinel Engineering Agent  
**Status:** Complete — Ready for Phase 6 Planning  
**Relevant Requirements:** CORR-01, CORR-02, CORR-03, CORR-04, ALERT-02, ALERT-03, ALERT-04  
**Upstream Dependencies:** Phase 2 (Storage & SQLite Schema), Phase 3 (Process Relationship Analyzer), Phase 4 (Detection Rule Engine), Phase 5 (PowerShell & Persistence Analyzers)

---

## 1. Executive Summary & Phase Mission

Phase 6 elevates WinSentinel from isolated atomic detection alerts to **connected multi-stage threat intelligence** and **enterprise-grade alert management**. 

In modern Windows enterprise intrusions, adversaries execute multi-step attack campaigns (e.g., weaponized Office document -> PowerShell download cradle -> persistent scheduled task / registry run key -> outbound lateral movement). Evaluating detections as disconnected alerts causes alert fatigue, hides the broader attack context, and burdens SOC analysts with manual timeline reconstruction.

Phase 6 delivers:
1. **Lineage-Aware Attack Chain Correlation Engine** (`app/correlation/chain_engine.py`): Leverages NetworkX `ProcessTreeGraph` ancestor-descendant graph walking combined with a sliding temporal window (default 30 minutes) scoped by host and user context.
2. **Four Predefined Core Attack Chains** (`app/correlation/chains.py`):
   - Chain 1: Malicious Document / Phishing Execution (`T1204.002` -> `T1059` -> `T1105/T1547`)
   - Chain 2: Web Shell / Server Exploitation (`T1190` -> `T1505.003` -> `T1082/T1087`)
   - Chain 3: Credential Dumping to Lateral Movement (`T1003.001` -> `T1021/T1569.002`)
   - Chain 4: Living-off-the-Land (LotL) Download to Persistence (`T1105` -> `T1547.001/T1053.005`)
3. **Compound Incident & Narrative Generator** (`app/models/incident.py`): Automatically promotes satisfied multi-stage attack chains to `Critical` severity `CompoundIncident`s and synthesizes explainable, chronological narrative stories linking all stage alerts, process nodes, and raw telemetry records.
4. **Sliding-Window Alert Deduplication** (`app/correlation/alert_manager.py`): Suppresses repetitive rule triggers matching `(rule_id, computer, process_guid)` within a 60-minute window, atomically updating `event_count`, refreshing `last_seen`, and appending evidence items without alert table bloat.
5. **Alert Lifecycle Management & Forensic Drill-Down** (`app/correlation/alert_manager.py` & `AlertRepository`): Formal status workflow enforcement (`New` -> `Investigating` -> `Escalated` -> `Resolved` / `False Positive`), analyst note annotations with disposition rationale, and complete forensic drill-down returning original event records and process lineage.
6. **Unified Ingestion Pipeline Integration**: Wires correlation and alert management into `IngestionPipeline` so that EVTX/JSON batch imports automatically deduplicate alerts and trigger attack chain correlation.

---

## 2. Architecture & Component Breakdown

```
+---------------------------------------------------------------------------------------------------+
|                                      IngestionPipeline                                            |
|                                                                                                   |
|  NormalizedEvents   +-------------------+  ProcessNodes   +------------------------------------+  |
|  -----------------> | ProcessTreeGraph  | --------------> | ProcessRepository (SQLite upsert)  |  |
|         |           +-------------------+                 +------------------------------------+  |
|         v                                                                                         |
|  +---------------------------------------------------------------------------------------------+  |
|  | Detection Evaluators: DetectionEngine, PowerShellThreatAnalyzer, PersistenceAnalyzer        |  |
|  +---------------------------------------------------------------------------------------------+  |
|         | Matches / Analyzer Results                                                              |
|         v                                                                                         |
|  +---------------------------------------------------------------------------------------------+  |
|  | AlertManager (app/correlation/alert_manager.py)                                             |  |
|  | - Windowed Deduplication (rule_id, computer, process_guid within 60 min)                     |  |
|  | - Persists unique alerts & links alert_evidence                                             |  |
|  | - Enforces Lifecycle Transitions (New -> Investigating -> Escalated -> Resolved / FP)       |  |
|  | - Analyst Notes & Forensic Drill-Down Provider                                              |  |
|  +---------------------------------------------------------------------------------------------+  |
|         | Consolidated Alerts & Raw Events                                                        |
|         v                                                                                         |
|  +---------------------------------------------------------------------------------------------+  |
|  | AttackChainEngine (app/correlation/chain_engine.py)                                          |  |
|  | - Sliding Temporal Window Evaluation (default 30 min)                                       |  |
|  | - NetworkX ProcessTreeGraph Lineage Traversal (ancestor/descendant checks)                  |  |
|  | - Evaluates Predefined Attack Chains (app/correlation/chains.py)                            |  |
|  +---------------------------------------------------------------------------------------------+  |
|         | Matched Chains                                                                          |
|         v                                                                                         |
|  +---------------------------------------------------------------------------------------------+  |
|  | Compound Incident & Narrative Generator (app/models/incident.py)                            |  |
|  | - Promotes to Severity: Critical                                                            |  |
|  | - Synthesizes Chronological Story Narrative                                                 |  |
|  | - Persists to investigations and alerts tables with full evidence links                    |  |
|  +---------------------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------------------+
```

### 2.1 Lineage-Aware Correlation Engine (`app/correlation/chain_engine.py`)

#### Responsibilities
- Receives batch telemetry events, detection matches, and the reconstructed `ProcessTreeGraph`.
- Indexes events and alerts chronologically in a sliding temporal buffer per host (`computer`).
- Traverses process ancestry and descendant trees to determine whether candidate activities share a causal execution relationship.
- Evaluates multi-stage transition criteria across temporal sliding windows (default: 30 minutes, configurable via `correlation_window_minutes = 30`).
- Produces `CompoundIncident` objects when all stages of a chain definition are satisfied.

#### Process Tree Traversal Algorithms
- **Forward Traversal (Root to Leaf)**:
  Given a candidate root process $P_{root}$ (e.g. `WINWORD.EXE`), query `process_tree.get_descendants_tree(P_{root}.process_guid)`. 
  This returns all descendant processes in generational BFS order. The engine restricts matching to descendants whose `start_time` satisfies:
  $$P_{root}.start\_time \le P_{descendant}.start\_time \le P_{root}.start\_time + \Delta t_{window}$$
- **Backward Traversal (Leaf to Ancestor)**:
  When an alert or suspicious event arrives (e.g. `powershell.exe` execution), query `process_tree.get_ancestors_lineage(P_{leaf}.process_guid)`.
  This returns the ordered root-to-leaf chain `[Root, ..., Grandparent, Parent, Self]`. The engine checks whether any ancestor matches Stage 1 criteria within the temporal window.
- **Associated Event Attribution**:
  Non-process events (Network EID 3, Process Access EID 10, File Creation EID 11, Registry EID 12-14) carry `process_guid`. An event $E$ belongs to the process lineage if:
  $$E.process\_guid \in \{P_{root}.process\_guid\} \cup \{P_{descendant}.process\_guid\}$$

### 2.2 Attack Chain Definitions (`app/correlation/chains.py`)

Each attack chain is declaratively specified as an `AttackChainDefinition` containing:
- `chain_id`: Unique identifier (e.g. `CHAIN-PHISH-001`)
- `name`: Display name
- `description`: Threat context
- `mitre_tactics`: MITRE ATT&CK tactics covered
- `mitre_techniques`: MITRE ATT&CK techniques covered
- `stages`: Ordered list of `ChainStageDefinition`s
- `window_minutes`: Configurable correlation window (default: 30)

#### Chain 1: Malicious Document / Phishing Execution (`CHAIN-PHISH-001`)
- **Stage 1 (Initial Access / Execution - T1204.002)**:
  - Process creation of productivity / document software:
    - Images: `winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, `acrobat.exe`, `acrord32.exe`, `eqnedt32.exe`.
- **Stage 2 (Execution - T1059)**:
  - Process creation of script or shell interpreter spawned as a direct child or descendant of Stage 1:
    - Images: `powershell.exe`, `pwsh.exe`, `cmd.exe`, `mshta.exe`, `cscript.exe`, `wscript.exe`, `certutil.exe`, `bash.exe`, `wmic.exe`.
    - Temporal requirement: $\Delta t \le 30\text{ min}$ from Stage 1.
- **Stage 3 (C2 / Persistence - T1105 / T1547)**:
  - Occurring from Stage 2 process or its descendants within 30 min:
    - Outbound Network Egress (Sysmon EID 3) to non-loopback IP, OR
    - Persistence Installation (Sysmon EID 12-14 Run Key, Security EID 4698 Scheduled Task, Security EID 4697 Service), OR
    - PowerShell Threat Analyzer high/critical result.

#### Chain 2: Web Shell / Server Exploitation (`CHAIN-WEBSHELL-001`)
- **Stage 1 (Initial Access / Execution - T1190)**:
  - Web server daemon or application worker process:
    - Images: `w3wp.exe`, `httpd.exe`, `nginx.exe`, `tomcat*.exe`, `java.exe` (with server cmdline), `php-cgi.exe`.
- **Stage 2 (Persistence / Command Execution - T1505.003 / T1059)**:
  - Interactive shell or script interpreter spawned as a direct child or descendant of Stage 1:
    - Images: `cmd.exe`, `powershell.exe`, `pwsh.exe`, `sh.exe`, `bash.exe`.
    - Temporal requirement: $\Delta t \le 30\text{ min}$ from Stage 1.
- **Stage 3 (Discovery / Reconnaissance / Persistence - T1082 / T1087 / T1547)**:
  - Reconnaissance command execution spawned from Stage 2 or persistence creation:
    - Images: `whoami.exe`, `net.exe`, `net1.exe`, `nltest.exe`, `quser.exe`, `ipconfig.exe`, `systeminfo.exe`, `tasklist.exe`, OR
    - Persistence artifact creation within 30 min of Stage 2.

#### Chain 3: Credential Dumping to Lateral Movement (`CHAIN-CREDDUMP-LAT-001`)
- **Stage 1 (Credential Access - T1003.001)**:
  - Process access or injection targeting `lsass.exe`:
    - Sysmon EID 10 targeting `lsass.exe` with suspicious access rights (`0x1010`, `0x1038`, `0x1410`, `0x1fffff`), OR
    - Sysmon EID 8 (CreateRemoteThread) targeting `lsass.exe`, OR
    - Existing alert for rule `SYS-PROC-003` (LSASS memory access).
- **Stage 2 (Lateral Movement / Remote Execution - T1021 / T1569.002)**:
  - Subsequent activity from same host and user within 30 min:
    - Outbound network connection (Sysmon EID 3) to private RFC1918 address space (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), OR
    - Remote service installation (Security EID 4697) or scheduled task (Security EID 4698).

#### Chain 4: Living-off-the-Land Download to Persistence (`CHAIN-LOTL-PERSIST-001`)
- **Stage 1 (Ingress Tool Transfer - T1105)**:
  - Living-off-the-Land download execution:
    - `certutil.exe` with `-urlcache` / `-split`, OR `bitsadmin.exe` with `/transfer` / `/create`, OR PowerShell download cradle alert (`PWSH-02`).
- **Stage 2 (File Creation - T1059 / T1105)**:
  - File creation (Sysmon EID 11) in user-writable or temporary directories:
    - `target_filename` containing `\AppData\`, `\Temp\`, `\Users\Public\`, `\ProgramData\`, with executable/script extension (`.exe`, `.dll`, `.vbs`, `.ps1`, `.bat`).
    - Temporal requirement: $\Delta t \le 30\text{ min}$ from Stage 1.
- **Stage 3 (Persistence Installation - T1547.001 / T1053.005)**:
  - Auto-start persistence configuration:
    - Registry Run/IFEO modification (Sysmon EID 12-14), Scheduled Task (Security EID 4698), or Service (Security EID 4697) referencing the dropped file or installed by the executing user within 30 min of Stage 2.

---

### 2.3 Compound Incident & Narrative Generator (`app/models/incident.py`)

#### Incident Schema
```python
class IncidentStage(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    stage_number: int
    stage_name: str
    tactic: str
    technique: str
    timestamp: datetime
    process_guid: str | None
    image: str | None
    command_line: str | None
    event_ids: list[int]
    alert_ids: list[int]
    narrative: str

class CompoundIncident(BaseModel):
    model_config = ConfigDict(frozen=True)
    
    incident_id: str                      # Deterministic or UUID
    chain_id: str                         # e.g. CHAIN-PHISH-001
    chain_name: str                       # e.g. "Malicious Document to C2 Egress"
    severity: str = "Critical"           # Always elevated to Critical per D-03
    status: str = "New"                   # Lifecycle triage status
    computer: str
    user: str | None
    first_seen: datetime
    last_seen: datetime
    stages: list[IncidentStage]
    participating_alert_ids: list[int]
    participating_event_ids: list[int]
    summary_narrative: str
    mitre_tactics: list[str]
    mitre_techniques: list[str]
```

#### Narrative Generation Algorithm
The narrative generator constructs an explainable, forensic prose summary following a strict template:
1. **Headline**: Summarizes the chain, host, primary user, and execution time window.
2. **Chronological Progression**:
   - `[Timestamp] Stage 1 (Initial Access)`: Details parent process, user, and command line.
   - `[Timestamp] Stage 2 (Execution)`: Explains child interpreter spawning, PID, and arguments.
   - `[Timestamp] Stage 3 (Persistence/C2)`: Explains the objective achieved (destination IP/port or persistence registry/task target).
3. **Forensic Traceability**: Explicitly lists contributing `alert_id`s and `event_id`s with record IDs for courtroom/audit readiness.

#### Database Persistence
Persisted into SQLite using existing Phase 2 schema:
- **`investigations` table**:
  - `title`: `f"Compound Incident: {chain_name} on {computer}"`
  - `status`: `"Open"`
  - `priority`: `"Critical"`
  - `summary`: `summary_narrative`
  - `lead_analyst`: `None` (assigned upon triage)
- **`alerts` table**:
  - Inserted as a top-level `Critical` alert row with `rule_id = chain_id`.
- **`alert_evidence` table**:
  - Foreign key linked to all participating normalized event IDs with explicit matched explanations.

---

### 2.4 Alert Deduplication & Lifecycle Manager (`app/correlation/alert_manager.py`)

#### Sliding-Window Deduplication Logic (D-04)
- **Composite Key**: `(rule_id, computer, process_guid or "GLOBAL")`
- **Deduplication Window**: 60 minutes (`dedup_window_minutes = 60`)
- **Algorithm**:
  1. Check in-memory index or query SQLite for an existing alert with matching `(rule_id, computer, process_guid)` where:
     $$|event\_timestamp - alert.last\_seen| \le 60\text{ minutes}$$
  2. **If match found (Duplicate)**:
     - Atomically update existing alert row:
       - `event_count = event_count + 1`
       - `last_seen = max(last_seen, event_timestamp)`
       - `updated_at = utcnow()`
     - Link new evidence items into `alert_evidence` table (`INSERT OR IGNORE INTO alert_evidence ...`).
     - Suppress creation of redundant alert rows.
     - Return existing `alert_id` and `is_duplicate=True`.
  3. **If no match found (New Alert)**:
     - Insert new record into `alerts` table with `status="New"` and `event_count=1`.
     - Link initial evidence into `alert_evidence`.
     - Index in sliding window cache.
     - Return new `alert_id` and `is_duplicate=False`.

#### Alert Lifecycle Management (D-05)
Formal Finite State Machine (FSM):
```
       [ New ]
          │
          ▼
   [ Investigating ] <──────────────────────┐
      │     │     │                         │ (Re-open)
      │     │     └──────────────┐          │
      ▼     ▼                    ▼          │
[ Escalated ] [ Resolved ] [ False Positive ]
      │             ▲                 ▲
      └─────────────┴─────────────────┘
```

- **Allowed Transitions**:
  - `New` -> `Investigating`
  - `Investigating` -> `Escalated`, `Resolved`, `False Positive`
  - `Escalated` -> `Investigating`, `Resolved`, `False Positive`
  - `Resolved` -> `Investigating` (re-opened upon new evidence)
  - `False Positive` -> `Investigating` (re-opened upon tuning review)
- **Disallowed Transitions**:
  - Direct jump from `New` to `Resolved` or `False Positive` (bypasses investigation audit trail).
  - Transition from `Resolved` to `Escalated` directly (must pass through `Investigating`).
  - Transition to unknown status strings.
- **Enforcement**:
  Calling `alert_manager.update_status(alert_id, new_status, author, note=None)` validates the transition against `VALID_TRANSITIONS` map. Raises `InvalidStatusTransitionError` on illegal moves.

#### Analyst Notes & Disposition Interface
- Method: `add_analyst_note(alert_id, author, note_text, disposition=None)`
- Stores note in `analyst_notes` table with timestamp and author attribution.
- If `disposition` is provided (e.g. `"Confirmed True Positive: Cobalt Strike Beacon"`, `"Benign Administrator Activity"`), it is recorded alongside status updates.

#### Forensic Drill-Down API
- Method: `get_alert_forensic_drilldown(alert_id: int) -> AlertDrilldown`
- Fetches:
  1. Complete alert record (metadata, timestamps, MITRE tags).
  2. All linked evidence records from `alert_evidence`.
  3. Full raw and normalized event objects from `events` table for all linked evidence `event_id`s.
  4. Process tree lineage context: If `process_guid` is present, fetches parent, siblings, and child processes from `ProcessTreeGraph` or `processes` table.
  5. All historical analyst notes from `analyst_notes`.

---

### 2.5 IngestionPipeline Integration Workflow

In `IngestionPipeline.ingest_and_persist`:
1. **Parse & Normalize**: Raw EVTX/JSON -> `NormalizedEvent` list.
2. **Event Persistence**: Bulk insert into `events` table.
3. **Process Graph Sync**: Build `ProcessTreeGraph`, evaluate lineage anomalies, bulk upsert into `processes` table.
4. **Detection & Analyzer Execution**:
   - `DetectionEngine.evaluate_event(...)`
   - `PowerShellThreatAnalyzer.analyze_event(...)`
   - `PersistenceAnalyzer.analyze_event(...)`
5. **Alert Consolidation via AlertManager**:
   - Instead of direct calls to `alert_repo.create_alert()`, route all matches through `AlertManager.process_match()` or `AlertManager.process_matches_batch()`.
   - Sliding-window deduplication applies automatically.
6. **Correlation via AttackChainEngine**:
   - Pass normalized events, alerts, and `ProcessTreeGraph` to `AttackChainEngine.correlate(...)`.
   - Generates `CompoundIncident`s.
   - Persists incidents to `investigations` and `alerts` tables.
7. **Return IngestionResult**:
   - Enriched with `incidents: list[CompoundIncident]`, `deduplicated_alerts: list[dict]`, and summary metrics.

---

## 3. Technical Risks, Traps & Landmines

| Risk / Trap | Impact | Root Cause | Architectural Mitigation |
|:---|:---|:---|:---|
| **Out-of-Order Telemetry Arrival** | False negatives in attack chain evaluation | Multi-source logs (Sysmon, Security, PowerShell) or chunked imports have interleaved timestamps. | `AttackChainEngine` sorts candidate events and alerts by `timestamp_utc` ascending prior to sliding-window evaluation. Window comparisons use absolute time delta $\Delta t \le window$. |
| **Process Tree Combinatorial Explosion** | Memory spikes / CPU throttling ($O(N^2)$ traversal) | Generic processes (`svchost.exe`, `explorer.exe`) spawn thousands of children over days. | Traversal starts *only* from specific trigger nodes (Office apps, Web servers, LOLBins) matching Stage 1. Descendant searches are bounded by $\Delta t \le 30\text{ min}$ from root creation. |
| **Duplicate Compound Incident Spawning** | Alert noise; multiple identical incidents for same attack | Multiple detection alerts trigger across stages of the same attack chain (e.g. download cradle + Run key). | Deduplicate incidents using composite key `(chain_id, computer, root_process_guid)`. Subsequent stage alerts update the existing incident rather than spawning a duplicate. |
| **SQLite Foreign Key Deadlocks / Failures** | Foreign key violation when linking evidence | Alert evidence links `events.id`, but events are inserted in bulk via `executemany` which doesn't return auto-generated IDs directly. | Use `event_repo.get_db_ids_by_hashes(hashes)` to efficiently resolve SQLite primary keys in a single indexed query before linking evidence. |
| **Timezone Comparison Inconsistencies** | Inaccurate window calculations (e.g. 5.5 hour offset in IST vs UTC) | Windows event logs contain mix of UTC ISO strings and naive datetimes. | Enforce strict UTC normalization via `ensure_utc()` on all timestamps before computing `(t2 - t1).total_seconds()`. |

---

## 4. Test Strategy & Plan Recommendations

Phase 6 should be split into **2 focused execution plans**:

### Plan 06-01: Lineage-Aware Event Correlation Engine, Attack Chains & Compound Incidents
- **Focus**:
  - `app/models/incident.py`: Pydantic models for `CompoundIncident`, `IncidentStage`, narrative schema.
  - `app/correlation/chains.py`: Declarative definitions for the 4 core attack chains (Phishing, Web Shell, Credential Dumping -> Lateral, LotL -> Persistence).
  - `app/correlation/chain_engine.py`: Lineage-aware correlation engine with NetworkX graph traversal and sliding-window temporal matching.
  - Forensic narrative generation formatting.
- **Test Deliverables**:
  - `tests/unit/test_correlation_engine.py`:
    - Positive match for Phishing chain (Word -> PowerShell -> Egress within 30 min).
    - Positive match for Web Shell chain (w3wp -> cmd -> whoami within 30 min).
    - Positive match for Credential Dumping to Lateral Movement (lsass access -> RFC1918 egress within 30 min).
    - Positive match for LotL to Persistence (certutil download -> temp file drop -> Run key within 30 min).
    - Temporal rejection: stages exceeding 30 minutes reject correlation.
    - Lineage rejection: independent processes on same host do not trigger chain.
    - Chronological narrative generation correctness.

### Plan 06-02: Windowed Alert Deduplication, Lifecycle Management, Forensic Drill-Down & Pipeline Integration
- **Focus**:
  - `app/correlation/alert_manager.py`: Sliding-window deduplication (60-min window for `(rule_id, computer, process_guid)`), lifecycle transition state machine, analyst notes, forensic drill-down API.
  - `app/database/repository.py`: Enhancements to `AlertRepository` (status transition checks, atomic increment of `event_count`, batch hash lookup).
  - `app/ingestion/pipeline.py`: Integrate `AlertManager` and `AttackChainEngine` into `ingest_and_persist`.
- **Test Deliverables**:
  - `tests/unit/test_alert_manager.py`:
    - Deduplication: 5 identical rule matches within 10 minutes produce 1 alert with `event_count=5` and 5 evidence items.
    - Window expiration: matches occurring 65 minutes apart produce 2 distinct alerts.
    - Lifecycle transitions: valid transitions succeed; invalid transitions raise `InvalidStatusTransitionError`.
    - Analyst notes and disposition recording.
    - Forensic drill-down returns complete event payloads and process lineage.
  - `tests/integration/test_correlation_pipeline_integration.py`:
    - End-to-end ingestion of multi-stage attack log stream yields deduplicated alerts and correlated `CompoundIncident`s persisted in SQLite `investigations` and `alerts`.

---

## 5. Verification Checklist & Success Criteria

- [ ] All 7 Phase 6 requirements addressed:
  - **CORR-01**: Multi-stage attack chain correlation linking process lineage, network egress, persistence, and scripts within time windows.
  - **CORR-02**: Correlation scoped by `ProcessGuid`, computer, user, and temporal window.
  - **CORR-03**: Alert deduplication preventing repeated matches from flooding alert repository.
  - **CORR-04**: Compound incidents linking individual rule matches with explainable chronological summary.
  - **ALERT-02**: Alert lifecycle tracking with status transitions (`New`, `Investigating`, `Escalated`, `Resolved`, `False Positive`).
  - **ALERT-03**: Analyst annotation interface appending notes and investigation disposition.
  - **ALERT-04**: Forensic evidence drill-down returning original event records and field values.
- [ ] No regression across existing 274 test cases.
- [ ] Comprehensive unit and integration test coverage for all new modules.
