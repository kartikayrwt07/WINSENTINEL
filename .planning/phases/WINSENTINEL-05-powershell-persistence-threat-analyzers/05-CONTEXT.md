# Phase 5: PowerShell & Persistence Threat Analyzers - Context

**Gathered:** 2026-11-04  
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 5 delivers specialized threat analysis modules for suspicious PowerShell activity and multi-source persistence mechanisms in WinSentinel:
- **PowerShell Threat Analyzer:**
  - Safe, non-executing de-obfuscation: UTF-16LE Base64 argument decoding (`-enc`, `-EncodedCommand`), backtick escape neutralization, and string concatenation flattening.
  - Multi-pattern threat detection: Download cradles (`Net.WebClient`, `Invoke-WebRequest`, `IWR`, `Start-BitsTransfer`), execution policy bypass flags (`-ep bypass`, `-ExecutionPolicy Unrestricted`, `-nop`), hidden window execution (`-w hidden`), and multi-line script-block patterns from EID 4104.
  - Contextual composite risk scoring (0-100) with tiered severity mapping and administrative reductions to eliminate false alarms on benign maintenance scripts.
- **Persistence Threat Analyzer:**
  - Multi-source telemetry correlation across:
    - Registry persistence: `CurrentVersion\Run`, `RunOnce`, `Winlogon`, and Image File Execution Options (`IFEO`) via Sysmon EID 12-14.
    - Service installation and suspicious driver loads: Security EID 4697 and Sysmon EID 6.
    - Scheduled Task creation: Task Scheduler Operational logs and Security EID 4698 (strictly never inferring tasks purely from Sysmon registry modifications).
    - WMI event subscriptions: Sysmon EID 19 (EventFilter), EID 20 (EventConsumer), and EID 21 (FilterToConsumerBinding).
    - Startup directory binary placement: Sysmon EID 11 (File creation) in `\Startup\` and sensitive system paths.
- **Forensic Artifact Structuring & Persistence:**
  - Typed models for `PowerShellAnalysisResult` and `PersistenceArtifact` with exact matched fields, decoded payload strings, target keys/files/services, MITRE ATT&CK techniques, and investigation guidance.
  - Integration with `IngestionPipeline` and `AlertRepository`.

</domain>

<decisions>
## Implementation Decisions

### PowerShell Composite Risk Scoring Model
- **D-01:** Implement a multi-factor composite risk scoring algorithm (0-100 scale) for PowerShell process creation (EID 1 / Security 4688) and ScriptBlock execution (EID 4104):
  - Weighted Indicators:
    - Base64 encoded payload: +30 points
    - Download cradle (`Net.WebClient`, `IWR`, `Start-BitsTransfer`): +40 points
    - Execution policy bypass (`-ep bypass`, `-ExecutionPolicy Unrestricted`): +20 points
    - Hidden / Non-interactive window (`-w hidden`, `-noni`): +20 points
    - Suspicious API invocation (`VirtualAlloc`, `WriteProcessMemory`, `CreateThread`, `DownloadString`): +30 points
    - Obfuscation techniques (excessive backticks, string concat, high character entropy): +15 points
  - Tiered Severity Mapping:
    - `0 - 29`: Benign / Informational (logged for context; no alert generated).
    - `30 - 59`: **Medium Severity** alert (e.g., bypass flag alone in administrative context).
    - `60 - 84`: **High Severity** alert (e.g., encoded command + download cradle).
    - `85 - 100`: **Critical Severity** alert (e.g., encoded command + download cradle + hidden window + execution policy bypass).

### Benign Administrative Baseline Allowlisting & Reductions
- **D-02:** Prevent false alarms on legitimate administrative scripts by applying negative contextual offsets:
  - Standard read-only query cmdlets (`Get-Process`, `Get-Service`, `Get-WmiObject`, `Get-ItemProperty`): -30 points offset.
  - Standard Microsoft update and telemetry scripts (`$PSScriptRoot`, known maintenance script blocks): -30 points offset.
  - Safety Override: If explicit download cradles or memory injection indicators are detected, benign offsets are nullified to ensure active threats cannot masquerade as maintenance.

### Safe De-obfuscation Engine
- **D-03:** Build a safe, non-executing string de-obfuscation utility:
  - Base64 Decoding: Extracts argument values following `-enc`, `-EncodedCommand`, `-e` and decodes as `UTF-16LE` (standard Windows PowerShell encoding) with fallback to `UTF-8`.
  - Normalization: Strips backtick escape characters (`` `e`x`e`c `` -> `exec`), flattens adjacent string concatenations (`"down"+"load"` -> `"download"`), and normalizes whitespace.
  - Strict Safety Invariant: Telemetry is untrusted data. Under no circumstances is Python `exec()`, `eval()`, or any PowerShell interpreter spawned to evaluate de-obfuscated strings.

### Multi-Source Persistence Analyzer
- **D-04:** Implement a dedicated `PersistenceAnalyzer` that correlates evidence across multiple distinct Windows event categories:
  - **Registry Auto-Runs:** Sysmon EID 12, 13, 14 matching `CurrentVersion\Run`, `RunOnce`, `Winlogon\Userinit`, `Winlogon\Shell`, and `Image File Execution Options` (IFEO debugger hijacking).
  - **Service & Driver Creation:** Security EID 4697 (A service was installed in the system) and Sysmon EID 6 (Driver loaded).
  - **Scheduled Tasks:** Explicitly consume Security EID 4698 (A scheduled task was created) and Task Scheduler Operational logs. **Strict Project Invariant:** Never infer scheduled task creation solely from Sysmon registry modifications.
  - **WMI Event Subscriptions:** Sysmon EID 19 (EventFilter), EID 20 (EventConsumer), EID 21 (FilterToConsumerBinding), detecting persistent WMI consumers.
  - **Startup Folder Drops:** Sysmon EID 11 (File creation) targeting `\Start Menu\Programs\Startup` or Windows root directories.

### Forensic Artifact Structuring & Persistence
- **D-05:** Define typed models `PowerShellAnalysisResult` and `PersistenceArtifact`:
  - Captures rule ID, severity, host, process GUID, user, original and decoded command lines, extracted target persistence keys/files/services, MITRE ATT&CK mappings, and actionable investigation recommendations.
  - Integrates with `AlertRepository` to persist structured alerts and evidence links into SQLite `alerts` and `alert_evidence`.

### Developer & Agent Discretion
- Module organization: Place analyzers in `app/analyzers/powershell_analyzer.py` and `app/analyzers/persistence_analyzer.py`.
- Pipeline hooks: Expose `analyze_powershell()` and `analyze_persistence()` methods and integrate them into `IngestionPipeline.ingest_and_persist()`.
- Synthetic Ground-Truth Fixtures: Provide synthetic attack events and benign admin baseline events to verify 100% true-positive and 0% false-positive accuracy.

</decisions>

<specifics>
## Specific Ideas & Test Coverage

- Unit tests for UTF-16LE Base64 decoding verifying correct extraction from `-enc`, `-EncodedCommand`, `-e`, and malformed Base64 handling.
- Unit tests for backtick stripping and string concatenation flattening.
- Unit tests for PowerShell risk scoring: single flag -> Medium, encoded download cradle -> High, multi-stage hidden cradle -> Critical, benign `Get-Service` script -> 0 / no alert.
- Unit tests for Registry persistence: detection of `Run` key additions and `IFEO` debugger hijacks.
- Unit tests for Service and Driver installation: Security 4697 and Sysmon 6.
- Unit tests for Scheduled Task creation: Security 4698 and Task Scheduler logs, with explicit test asserting Sysmon registry events alone do not claim task creation.
- Unit tests for WMI persistence: Sysmon 19, 20, 21 consumer binding.
- Integration test for `IngestionPipeline` verifying PowerShell and Persistence alerts stored in SQLite with full forensic evidence records.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing:**
- `.planning/PROJECT.md` — Section 6 Module E (PowerShell Threat Detection) & Module F (Persistence Detection).
- `.planning/REQUIREMENTS.md` — PWSH-01 through PWSH-05, PERS-01 through PERS-05.
- `.planning/ROADMAP.md` — Phase 5 goals, success criteria, and plans breakdown.
- `.planning/phases/WINSENTINEL-04-detection-rule-engine-sysmon-core-library/04-VERIFICATION.md` — Detection rule engine, match models, and SQLite persistence.
- `app/models/events.py` — `NormalizedEvent` schema (script blocks, registry targets, task names, service names).
- `app/database/repository.py` — `AlertRepository` contracts.

</canonical_refs>

