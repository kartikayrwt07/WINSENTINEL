# Phase 6 Plan 01 Summary: Compound Incident Model, Attack Chains, and Lineage Correlation Engine

**Executed:** 2026-11-04  
**Status:** Completed successfully  
**Requirements Satisfied:** CORR-01, CORR-02, CORR-04

---

## 1. Executive Summary

Plan 06-01 establishes the foundational event correlation and compound threat incident engine for WinSentinel. It transforms atomic, isolated detection alerts into connected multi-stage threat intelligence by walking directed process hierarchies (`ProcessTreeGraph`) across a configurable sliding temporal window (default 30 minutes), strictly scoped by host (`computer`) and user context.

Key outcomes:
- **Pydantic v2 Immutable Incident Schemas (`app/models/incident.py`)**: Defined `IncidentStage` and `CompoundIncident` capturing chronological intrusion stages, MITRE ATT&CK tactic/technique mappings, forensic traceability links, and SQLite persistence bridges (`to_investigation_dict`, `to_alert_dict`, `to_evidence_dicts`).
- **Explainable Forensic Narrative Generator (`generate_incident_narrative`)**: Synthesizes structured, human-readable chronological story narratives detailing headlines, execution duration, step-by-step process/command-line actions, and underlying contributing event/alert IDs.
- **Four Core Attack Chain Definitions (`app/correlation/chains.py`)**:
  1. `CHAIN-PHISH-001`: Malicious Document / Phishing Execution (`T1204.002` -> `T1059.001` -> `T1105`/`T1547.001`)
  2. `CHAIN-WEBSHELL-001`: Web Shell / Server Exploitation (`T1190` -> `T1505.003` -> `T1082`/`T1087`)
  3. `CHAIN-CREDDUMP-LAT-001`: Credential Dumping to Lateral Movement (`T1003.001` -> `T1021.002`/`T1569.002`)
  4. `CHAIN-LOTL-PERSIST-001`: Living-off-the-Land Download to Persistence (`T1105` -> `T1547.001`/`T1053.005`)
- **Lineage-Aware Correlation Engine (`app/correlation/chain_engine.py`)**: `AttackChainEngine` evaluates streaming or batch events, walking `ProcessTreeGraph` ancestor-descendant relationships within a 30-minute sliding window per host, enforcing process lineage and user context, deduplicating repetitive alerts on the same root process, and elevating correlated chains to `Critical` severity `CompoundIncident`s.

---

## 2. Implemented Components & Architecture

### 2.1 Models (`app/models/incident.py`, exported in `app/models/__init__.py`)
- `IncidentStage`: Immutable representation of a single stage in an attack chain with `stage_number`, `stage_name`, `tactic`, `technique`, UTC `timestamp`, `process_guid`, `image`, `command_line`, `event_ids`, `alert_ids`, and `narrative`.
- `CompoundIncident`: Immutable representation of a correlated multi-stage threat with `incident_id`, `chain_id`, `chain_name`, `severity="Critical"`, `status="New"`, `computer`, `user`, `root_process_guid`, `first_seen`, `last_seen`, `duration_seconds`, `stages`, `mitre_tactics`, `mitre_techniques`, `summary_narrative`, `narrative_story`, `participating_event_ids`, `participating_alert_ids`, and `investigation_steps`.
  - Bridges:
    - `to_investigation_dict()`: Prepares dict for SQLite `investigations` table insertion.
    - `to_alert_dict()`: Prepares kwargs for `AlertRepository.create_alert()`.
    - `to_evidence_dicts(alert_id)`: Prepares list of kwargs for `AlertRepository.link_alert_evidence()`.
- `generate_incident_narrative()`: Generates courtroom-ready forensic summaries tracing each stage chronologically with command lines, process images, timestamps, and contributing IDs.

### 2.2 Attack Chains (`app/correlation/chains.py`)
- `ChainStageDefinition`: Defines individual stage criteria, required lineage constraints, and links to stage predicate functions.
- `AttackChainDefinition`: Defines chain metadata, sliding window, MITRE mappings, ordered stages, and SOC investigation playbooks.
- Robust Predicates:
  - `is_phishing_root`: Office & document viewers (`winword.exe`, `excel.exe`, `acrobat.exe`, etc.).
  - `is_script_interpreter`: Shells & interpreters (`powershell.exe`, `cmd.exe`, `mshta.exe`, `cscript.exe`, etc.).
  - `is_egress_or_persistence`: Outbound non-loopback network connections (Sysmon EID 3), Run keys (EID 12-14), or tasks/services (EID 4698/4697).
  - `is_web_server_root`: Web server processes (`w3wp.exe`, `httpd.exe`, `nginx.exe`, `tomcat`, java servers).
  - `is_recon_command`: Recon utilities (`whoami.exe`, `net.exe`, `nltest.exe`, etc.).
  - `is_lsass_access`: Sysmon EID 10 suspicious masks (`0x1010`, `0x1038`, `0x1410`, `0x1fffff`) and EID 8 targeting `lsass.exe`.
  - `is_rfc1918_egress_or_remote_exec`: Private RFC1918 IP connections or service creation.
  - `is_lolbin_download`: Ingress download cradles via `certutil`, `bitsadmin`, or PowerShell web clients.
  - `is_suspicious_file_drop`: Executable/script file creation (EID 11) in writable paths (`\AppData\`, `\Temp\`, `\Users\Public\`, `\ProgramData\`).
  - `is_persistence_installation`: Run/IFEO registry keys, scheduled tasks, or services.
- `get_default_attack_chains()`: Returns instances of all 4 predefined attack chains.

### 2.3 Attack Chain Engine (`app/correlation/chain_engine.py`, exported in `app/correlation/__init__.py`)
- `AttackChainEngine`:
  - `evaluate(events, matches, process_tree, alerts)` / `correlate(...)`.
  - Partitions telemetry by `computer`.
  - Chronologically traverses events within sliding window $\Delta t \le 30\text{ min}$.
  - Lineage checking: queries `ptree.get_descendants_tree(root_guid)` to verify causal ancestry DAG.
  - Strict host and user context scoping.
  - Deduplicates matched incidents by `(chain_id, computer, root_process_guid)`.

---

## 3. Test Execution Results

- **Unit Tests (`test_compound_incident.py`)**: 9 / 9 passed (validation, immutability, duration calculation, serialization, narrative generation).
- **Unit Tests (`test_attack_chains.py`)**: 12 / 12 passed (predicate accuracy, RFC1918 checks, case-insensitivity, default chains).
- **Unit Tests (`test_chain_engine.py`)**: 10 / 10 passed (Phishing, WebShell, Credential Dumping, LotL correlation, sliding window rejection, lineage check enforcement, host/user scoping, deduplication, forensic traceability).
- **Correlation Suite Subtotal**: 31 / 31 passed in 0.73s.
- **Full Project Regression Suite**: 305 / 305 passed in 11.10s.

---

## 4. Verification Check

| Must-Have Item | Status | Verification Detail |
|---|---|---|
| `CompoundIncident` and `IncidentStage` Pydantic v2 models | PASS | Implemented in `app/models/incident.py`, validated in `tests/unit/test_compound_incident.py` |
| `generate_incident_narrative` chronological story | PASS | Formats headline, execution window, stages, forensic evidence IDs |
| 4 Core Attack Chain Definitions | PASS | `CHAIN-PHISH-001`, `CHAIN-WEBSHELL-001`, `CHAIN-CREDDUMP-LAT-001`, `CHAIN-LOTL-PERSIST-001` in `app/correlation/chains.py` |
| Lineage-aware graph walking | PASS | BFS ancestry walk using `ProcessTreeGraph.get_descendants_tree` in `app/correlation/chain_engine.py` |
| 30-minute sliding window enforcement | PASS | Verified in `test_sliding_temporal_window_rejection` (>30 min rejected) |
| Host and user scoping | PASS | Verified in `test_host_scoping_prevents_cross_host_correlation` and `test_user_scoping_prevents_unrelated_user_correlation` |
| Incident deduplication | PASS | Verified in `test_incident_deduplication_on_repeated_events` |
