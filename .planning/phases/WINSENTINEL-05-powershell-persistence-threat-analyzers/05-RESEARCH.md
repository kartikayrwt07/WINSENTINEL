# Phase 5: PowerShell & Persistence Threat Analyzers - Research & Architecture

**Document Type:** Technical Research & Architecture Specification  
**Phase:** 5 (PowerShell & Persistence Threat Analyzers)  
**Status:** Complete  
**Date:** 2026-11-04  

---

## 1. Executive Summary & Phase Mission

Phase 5 equips WinSentinel with two specialized, high-fidelity threat analyzers:
1. **PowerShell Threat Analyzer:** Designed to address the single most prevalent living-off-the-land (LotL) execution vehicle in Windows environments. It provides non-executing, safe de-obfuscation (UTF-16LE Base64 repair, backtick stripping, string concatenation flattening) combined with a 0–100 composite risk scoring engine that evaluates download cradles, execution policy bypasses, hidden windows, and suspicious native API invocations. Benign administrative query baselines receive contextual offsets to eliminate false positives while preserving a strict safety override for active threats.
2. **Persistence Threat Analyzer:** A multi-source telemetry correlation analyzer tracking the primary mechanisms adversaries use to maintain footholds across reboots: Registry Run/RunOnce/Winlogon/IFEO hijacking, Service installations and suspicious driver loads, Scheduled Task creation, WMI event filter-to-consumer bindings, and Startup folder file drops.

Both analyzers produce strongly typed forensic artifacts (`PowerShellAnalysisResult` and `PersistenceArtifact`) that bridge directly into `AlertRepository`, generating structured alerts and evidence links in SQLite without requiring any database schema alterations.

---

## 2. Architectural Analysis & Component Breakdown

```
                                  +---------------------------------------+
                                  |            NormalizedEvent            |
                                  +---------------------------------------+
                                                      |
                         +----------------------------+----------------------------+
                         |                                                         |
                         v                                                         v
       +-----------------------------------+                     +-----------------------------------+
       |     PowerShellThreatAnalyzer      |                     |        PersistenceAnalyzer        |
       |  (EID 1 / 4688, EID 4104, 4103)   |                     | (Sysmon 6,11,12-14,19-21, 4697/8) |
       +-----------------------------------+                     +-----------------------------------+
                         |                                                         |
       +-----------------+-----------------+                     +-----------------+-----------------+
       | Safe De-obfuscation Engine        |                     | 5 Dedicated Detector Strategies   |
       | - Base64 (UTF-16LE / UTF-8)       |                     | 1. Registry (Run, IFEO, Winlogon) |
       | - Padding Repair & Normalization  |                     | 2. Services & Driver Loads        |
       | - Backtick & Concat Stripping     |                     | 3. Scheduled Tasks (XML Action)   |
       +-----------------------------------+                     | 4. WMI Event Subscriptions        |
                         |                                       | 5. Startup Folder File Drops      |
       +-----------------+-----------------+                     +-----------------+-----------------+
       | Composite Risk Scorer (0 - 100)   |                                       |
       | - Indicators (+15 to +40)         |                                       v
       | - Admin Offsets (-30)             |                     +-----------------------------------+
       | - Active Threat Safety Override   |                     |        PersistenceArtifact        |
       +-----------------------------------+                     +-----------------------------------+
                         |                                                         |
                         v                                                         |
       +-----------------------------------+                                       |
       |    PowerShellAnalysisResult       |                                       |
       +-----------------------------------+                                       |
                         |                                                         |
                         +----------------------------+----------------------------+
                                                      |
                                                      v
                                     +----------------------------------+
                                     |  Alert & Evidence Persistence    |
                                     |  (AlertRepository -> SQLite)     |
                                     +----------------------------------+
```

### 2.1 Module 1: Safe PowerShell De-obfuscation Utility

Telemetry is untrusted data. Under no circumstances may Python `exec()`, `eval()`, or a live PowerShell subprocess (`powershell.exe -Command ...`) be invoked to de-obfuscate payloads. All parsing is deterministic, non-executing string manipulation and regex token transformation.

#### 2.1.1 Flag Parsing & Value Extraction
PowerShell CLI accepts flags with either `-` or `/` prefixes and allows case-insensitive prefixes as short as `-e`:
- Flags: `-e`, `-enc`, `-enco`, `-encod`, `-encodedcommand`, `/e`, `/enc`, `/encodedcommand`.
- Delimiters: Space (`-enc <payload>`), Colon (`-enc:<payload>`), Equals (`-enc=<payload>`), or quoted values (`-enc "<payload>"` or `-enc '<payload>'`).
- Regex pattern:
  ```python
  BASE64_FLAG_PATTERN = re.compile(
      r'(?:^|\s)(?:-|/)(?:enc(?:odedcommand)?|e)(?::|\s+|=)\s*["\']?([A-Za-z0-9+/=]{4,})["\']?',
      re.IGNORECASE
  )
  ```

#### 2.1.2 Base64 Padding Repair & Dual Encoding
In Windows PowerShell, `-EncodedCommand` encodes Unicode UTF-16LE byte sequences into Base64.
- **Padding Repair:** Command-line truncation or obfuscation frequently strips trailing `=` padding. Base64 strings must be a multiple of 4 bytes.
  ```python
  def repair_base64_padding(b64_str: str) -> str:
      clean = re.sub(r'[^A-Za-z0-9+/=]', '', b64_str.strip())
      missing_padding = (4 - len(clean) % 4) % 4
      return clean + ('=' * missing_padding)
  ```
- **Dual Encoding Decoding:**
  1. Decode Base64 to raw bytes.
  2. Attempt `bytes.decode('utf-16-le')`.
  3. If `UnicodeDecodeError` or if UTF-16LE yields invalid characters / empty strings, attempt `bytes.decode('utf-8')`.
  4. Fallback to `bytes.decode('latin-1', errors='replace')` as a fail-safe.
  5. Trap `binascii.Error` and `ValueError` gracefully, returning `None` instead of throwing exceptions.

#### 2.1.3 Backtick Escape Stripping
In PowerShell, backtick (`` ` ``) is the escape character used by adversaries to break token detection (e.g., `` I`E`X `N`e`w-`O`b`j`e`c`t ``).
- Standalone backticks escaping alphanumerics, hyphens, and quotes can be stripped safely without affecting semantic tokens:
  ```python
  def strip_backticks(text: str) -> str:
      # Strip backticks preceding alphanumeric or common syntax characters
      return re.sub(r'`([a-zA-Z0-9_\-\"\'\$])', r'\1', text)
  ```

#### 2.1.4 String Concatenation Flattening
Adversaries evade signature scanning by splitting strings into concatenated fragments:
`"down" + "load" + "string"` or `'Ne' + 'w-Obj' + 'ect'`.
- Normalization collapses adjacent quotes separated by `+`:
  ```python
  def flatten_concatenation(text: str) -> str:
      # Matches 'foo' + 'bar' or "foo" + "bar"
      pattern = r'(["\'])\s*\+\s*\1'
      previous = None
      current = text
      # Iterate until fixpoint (handles chained concats: 'a'+'b'+'c')
      for _ in range(10):
          previous = current
          current = re.sub(pattern, '', current)
          if current == previous:
              break
      return current
  ```

#### 2.1.5 Format String Detection
Format strings (`"{1}{0}" -f 'load','down'`) are common obfuscation patterns. While complete static AST evaluation of arbitrary format expressions is fragile, the presence of `-f` format operators combined with index braces (`\{\d+\}`) provides a strong signal of obfuscation (+15 score).

---

### 2.2 Module 2: PowerShell Composite Risk Scorer

#### 2.2.1 Scoring Model & Indicator Weights (D-01)
The analyzer inspects both `command_line` (from Process Creation: Sysmon EID 1 / Security EID 4688) and `script_block_text` (from Script Block Logging: EID 4104). The composite risk score is computed on a 0–100 scale:

| Indicator Category | Weight | Regex / Matching Heuristics |
|--------------------|--------|------------------------------|
| **Base64 Payload** | +30 | Presence of `-enc`, `-EncodedCommand` flags with valid decodable Base64 payload |
| **Download Cradle** | +40 | `Net.WebClient`, `DownloadString`, `DownloadFile`, `DownloadData`, `Invoke-WebRequest`, `\biwr\b`, `Start-BitsTransfer`, `Invoke-RestMethod`, `\birm\b`, `Net.Sockets.TcpClient` |
| **Execution Policy Bypass** | +20 | `-ep bypass`, `-executionpolicy unrestricted`, `-executionpolicy bypass`, `-nop`, `-noprofile` |
| **Hidden / Non-Interactive Window** | +20 | `-w hidden`, `-windowstyle hidden`, `-w 1`, `-noni`, `-noninteractive` |
| **Suspicious Native APIs** | +30 | `VirtualAlloc`, `VirtualProtect`, `WriteProcessMemory`, `CreateThread`, `RtlMoveMemory`, `GetProcAddress`, `LoadLibrary`, `QueueUserAPC`, `MapViewOfFile` |
| **Obfuscation Techniques** | +15 | Excessive backticks (>3), string concatenation chains, high special-character entropy, `[char[]]`, `[convert]::FromBase64String`, `-join` |

#### 2.2.2 Benign Administrative Baselines & Safety Override (D-02)
- **Baseline Offsets:**
  - Standard read-only query cmdlets (`Get-Process`, `Get-Service`, `Get-WmiObject`, `Get-CimInstance`, `Get-ItemProperty`, `Get-WinEvent`, `Get-ChildItem`): **-30 points offset**.
  - Standard Microsoft update and telemetry scripts (`$PSScriptRoot`, known maintenance script blocks, `Defender`, `CCM`, `Intune`): **-30 points offset**.
- **Safety Override Invariant:**
  - If an active download cradle (+40) or suspicious native memory injection API (+30) is present, any administrative negative offset is **immediately nullified** (offset = 0). Attackers cannot evade detection by appending `Get-Process` to a malicious dropper.

#### 2.2.3 Tiered Severity Mapping
- `0 - 29`: **Benign / Informational** (no alert created; logged for audit).
- `30 - 59`: **Medium Severity** alert (e.g., bypass flag used alone or isolated suspicious flag).
- `60 - 84`: **High Severity** alert (e.g., Base64 payload + download cradle: 30 + 40 = 70).
- `85 - 100`: **Critical Severity** alert (e.g., Base64 payload + download cradle + hidden window + execution policy bypass: 30 + 40 + 20 + 20 = 100 clamped).

---

### 2.3 Module 3: Multi-Source Persistence Analyzer

The `PersistenceAnalyzer` processes events across five distinct persistence channels, enforcing strict source attribution and correlation.

```
+-----------------------------------------------------------------------------------------+
|                               PersistenceAnalyzer Sub-Detectors                         |
+-----------------------------------------------------------------------------------------+
| 1. Registry Auto-Runs:                                                                  |
|    - Sysmon EID 12, 13, 14                                                              |
|    - Keys: Run, RunOnce, Winlogon (Userinit/Shell), IFEO (Debugger), AppInit_DLLs       |
+-----------------------------------------------------------------------------------------+
| 2. Services & Driver Loads:                                                             |
|    - Security EID 4697 ("A service was installed in the system")                        |
|    - Sysmon EID 6 (Driver loaded - unsigned or unexpected path)                         |
+-----------------------------------------------------------------------------------------+
| 3. Scheduled Tasks (Authoritative Task Sources Only):                                   |
|    - Security EID 4698 ("A scheduled task was created" - parse TaskContent XML)         |
|    - Task Scheduler Operational logs (EID 106/140)                                      |
|    - STRICT RULE: Never infer task creation from Sysmon Registry modifications alone!   |
+-----------------------------------------------------------------------------------------+
| 4. WMI Event Subscriptions:                                                             |
|    - Sysmon EID 19 (EventFilter created/modified)                                       |
|    - Sysmon EID 20 (EventConsumer created: CommandLineEventConsumer/ActiveScript)       |
|    - Sysmon EID 21 (FilterToConsumerBinding - high severity persistent consumer)        |
+-----------------------------------------------------------------------------------------+
| 5. Startup Folder Drops:                                                                |
|    - Sysmon EID 11 (File creation in User or AllUsers Startup directories)              |
|    - Targets: .exe, .dll, .bat, .cmd, .vbs, .js, .ps1, .lnk                             |
+-----------------------------------------------------------------------------------------+
```

#### 2.3.1 Strategy 1: Registry Auto-Runs (PERS-01)
- **Telemetry:** Sysmon EID 12, 13, 14 (`registry_target_object`, `registry_details`, `registry_event_type`).
- **Monitored Key Paths (Case-Insensitive):**
  - Run Keys: `\CurrentVersion\Run`, `\CurrentVersion\RunOnce`, `\CurrentVersion\RunOnceEx`, `\Policies\Explorer\Run`.
  - Winlogon Keys: `\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`, `\Winlogon\Shell`.
  - Image File Execution Options (IFEO): `\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<image>\Debugger` (used for sticky-key persistence like `sethc.exe`).
  - Boot/Logon Execution: `\Windows NT\CurrentVersion\Windows\AppInit_DLLs`, `\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`.
- **Heuristic Severity:**
  - High if payload points to `\AppData\`, `\Temp\`, script files (`.vbs`, `.ps1`, `.bat`), or LOLBAS binaries (`powershell.exe`, `cmd.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`).
  - Medium for general Run/RunOnce modifications.

#### 2.3.2 Strategy 2: Services & Driver Loads (PERS-02)
- **Telemetry:**
  - Security EID 4697 (`service_name`, `service_file_name`) - service installation.
  - Sysmon EID 6 (`target_filename`, `hashes`, `signed`, `signature_status`) - driver load.
- **Heuristic Severity:**
  - Critical/High if service binary executes out of user profiles (`\Users\`), `\Temp\`, or launches cmd/powershell.
  - High for unsigned driver loads (`signed` == "false" or `signature_status` != "Valid") or drivers loaded from non-System32 paths.

#### 2.3.3 Strategy 3: Scheduled Tasks (PERS-03)
- **Telemetry:**
  - Security EID 4698 (`task_name`, `task_content` - raw task definition XML).
  - Task Scheduler Operational logs (EID 106 "Task registered", EID 140 "Task updated").
- **Strict Project Invariant:**
  - **NEVER infer scheduled task creation solely from Sysmon registry modifications!** Modifications to `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache` occur during routine Windows telemetry and updates, leading to false positives. Only Security EID 4698 and Task Scheduler logs constitute valid task persistence evidence.
- **Task Action Parsing:**
  - Safely extract `<Actions><Exec><Command>` and `<Arguments>` from `task_content` XML.
  - Flag tasks running powershell, cmd, or binaries located in temporary/user directories.

#### 2.3.4 Strategy 4: WMI Event Subscriptions (PERS-04)
- **Telemetry:** Sysmon EID 19, 20, 21.
- **Correlation:**
  - EID 19: `EventFilter` creation (`wmi_filter`, `wmi_query`).
  - EID 20: `EventConsumer` creation (`wmi_consumer` - `CommandLineEventConsumer` or `ActiveScriptEventConsumer`).
  - EID 21: `FilterToConsumerBinding` linking filter to consumer.
  - EID 21 represents completed WMI persistence (MITRE T1546.003) and triggers **High/Critical** severity.

#### 2.3.5 Strategy 5: Startup Folder Drops (PERS-05)
- **Telemetry:** Sysmon EID 11 (`target_filename`).
- **Target Directories:**
  - `\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` (User startup).
  - `\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\` (All users startup).
- **Target Extensions:** `.exe`, `.dll`, `.bat`, `.cmd`, `.vbs`, `.js`, `.wsf`, `.ps1`, `.lnk`.
- Trigger **High Severity** alert if executable or script is dropped into startup.

---

### 2.4 Module 4: Data Models & SQLite Bridging

#### 2.4.1 `PowerShellAnalysisResult` (Pydantic Model)
```python
class PowerShellAnalysisResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: int
    record_id: int | None = None
    event_db_id: int | None = None
    computer: str
    timestamp_utc: datetime
    process_guid: str | None = None
    user: str | None = None
    raw_command: str
    decoded_command: str | None = None
    deobfuscated_command: str | None = None
    risk_score: int  # 0 to 100
    severity: str    # "Informational", "Medium", "High", "Critical"
    indicators: list[str]  # e.g. ["Base64Payload", "DownloadCradle"]
    matched_patterns: dict[str, list[str]]
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    investigation_steps: list[str]

    def to_alert_dict(self) -> dict[str, Any]:
        """Convert into kwargs for AlertRepository.create_alert()."""
        ...

    def to_evidence_dicts(self, alert_id: int) -> list[dict[str, Any]]:
        """Convert into kwargs for AlertRepository.link_alert_evidence()."""
        ...
```

#### 2.4.2 `PersistenceArtifact` (Pydantic Model)
```python
class PersistenceType(str, Enum):
    REGISTRY = "REGISTRY"
    SERVICE = "SERVICE"
    DRIVER = "DRIVER"
    SCHEDULED_TASK = "SCHEDULED_TASK"
    WMI_SUBSCRIPTION = "WMI_SUBSCRIPTION"
    STARTUP_FOLDER = "STARTUP_FOLDER"

class PersistenceArtifact(BaseModel):
    model_config = ConfigDict(frozen=True)

    persistence_type: PersistenceType
    event_id: int
    record_id: int | None = None
    event_db_id: int | None = None
    computer: str
    timestamp_utc: datetime
    process_guid: str | None = None
    user: str | None = None
    target_name: str    # Reg key, service name, task name, consumer name, or file path
    payload: str | None # Command line, binary path, script block, WMI query
    severity: str       # "Low", "Medium", "High", "Critical"
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    evidence_fields: dict[str, Any]
    explanation: str
    investigation_steps: list[str]

    def to_alert_dict(self) -> dict[str, Any]:
        ...

    def to_evidence_dicts(self, alert_id: int) -> list[dict[str, Any]]:
        ...
```

#### 2.4.3 SQLite Schema Compatibility
Both models map cleanly into existing tables in `001_initial_schema.sql`:
- `alerts`: `rule_id` (`PWSH-COMPOSITE-001`, `PERS-REG-001`, `PERS-SVC-001`, etc.), `title`, `severity`, `status='New'`, `description`, `computer`, `user`, `process_guid`, `first_seen`, `last_seen`, `event_count`, `mitre_tactics_json`, `mitre_techniques_json`.
- `alert_evidence`: `alert_id`, `event_id`, `matched_field`, `matched_value`, `explanation`.
No DDL schema migration is needed for Phase 5.

---

### 2.5 Module 5: Ingestion Pipeline Integration

In `app/ingestion/pipeline.py`:
- In `IngestionPipeline.__init__()`, instantiate:
  - `self.powershell_analyzer = PowerShellThreatAnalyzer()`
  - `self.persistence_analyzer = PersistenceAnalyzer()`
- In `IngestionPipeline.ingest_and_persist()`, add parameter:
  - `run_analyzers: bool = True`
- Execution flow:
  1. Events are parsed, normalized, and batch-inserted into SQLite.
  2. If `sync_processes`: Process tree and lineage anomalies are analyzed.
  3. If `run_detections`: DetectionEngine evaluates YAML Sigma rules.
  4. If `run_analyzers`:
     - Evaluate events with `PowerShellThreatAnalyzer`. If `risk_score >= 30`, persist alert and evidence in SQLite.
     - Evaluate events with `PersistenceAnalyzer`. If persistence artifact detected, persist alert and evidence in SQLite.
  5. Include analyzer alerts and artifacts in `IngestionResult`.

---

## 3. Technical Risks, Traps & Landmines

| Risk / Landmine | Severity | Mitigation Strategy |
|-----------------|----------|---------------------|
| **Base64 Padding & Truncation** | High | Automatically calculate missing padding `=`/`==` modulo 4. Strip whitespace/quotes before decoding. Catch `binascii.Error` gracefully. |
| **UTF-16LE vs UTF-8 Variations** | High | Windows PowerShell defaults to UTF-16LE for `-enc`. Decode UTF-16LE first; if decoding fails or yields invalid replacement characters, fall back to UTF-8, then Latin-1. |
| **Regular Expression Denial of Service (ReDoS)** | Critical | Script blocks in EID 4104 can exceed 100 KB. Never use nested quantifier regexes like `(.*[a-z]+)*`. Use pre-token checks (e.g. `if "webclient" in text.lower():`) before running regexes, or use bounded non-greedy regexes. |
| **Event Source Attribution (Tasks vs Registry)** | High | **Strict Project Invariant**: Registry modifications (Sysmon 12-14) must NEVER be reported as scheduled task creation. Only Security 4698 and Task Scheduler logs may generate scheduled task persistence alerts. |
| **Benign Administrative Noise & Alert Fatigue** | High | Default Windows background scripts frequently use PowerShell and Scheduled Tasks. Apply -30 point offset for `Get-*` read-only cmdlets and Microsoft maintenance scripts. Nullify offsets immediately if active download cradles or memory injection APIs are detected. |
| **Untrusted Input Code Execution** | Critical | NEVER use Python `eval()`, `exec()`, or invoke PowerShell subprocesses to unpack or de-obfuscate payloads. Use purely static parsing. |

---

## 4. Test Strategy & Plan Recommendations

Phase 5 should be split into **2 sequential plans across 2 waves**:

### Wave 1: Plan 05-01 (PowerShell Threat Analyzer)
- **Scope:**
  - Build `app/analyzers/powershell_deobfuscator.py` (safe Base64 decode, padding repair, backtick stripping, concat flattening).
  - Build `app/analyzers/powershell_analyzer.py` (composite scoring model, weighted indicators, benign offsets, safety override).
  - Define `PowerShellAnalysisResult` in `app/models/powershell.py`.
  - Comprehensive unit test suite in `tests/unit/test_powershell_analyzer.py`.
- **Test Scenarios:**
  - Base64 variations: `-enc`, `-EncodedCommand`, `-e`, unpadded, UTF-16LE, UTF-8.
  - De-obfuscation: backtick stripping (`` I`E`X ``), concat flattening (`'a'+'b'`).
  - Scoring validation:
    - Benign query (`Get-Service`): score 0 (Benign/No alert).
    - Isolated flag (`-ep bypass`): score 20 (Benign/Informational).
    - Encoded cradle (`-enc ... (New-Object Net.WebClient).DownloadString(...)`): score 70 (High).
    - Full evasion cradle (`-w hidden -noni -ep bypass -enc ...`): score 100 (Critical).
    - Camouflaged attack (`Get-Process; (New-Object Net.WebClient).DownloadString(...)`): safety override nullifies offset, score 40+ (Alert generated).
    - EID 4104 ScriptBlock multi-line detection.

### Wave 2: Plan 05-02 (Persistence Threat Analyzer & Pipeline Integration)
- **Scope:**
  - Build `app/analyzers/persistence_analyzer.py` with 5 sub-detectors:
    - Registry (Run, RunOnce, Winlogon, IFEO via Sysmon 12-14).
    - Services & Drivers (Security 4697, Sysmon 6).
    - Scheduled Tasks (Security 4698 XML parsing & Task Scheduler logs).
    - WMI Subscriptions (Sysmon 19, 20, 21 binding).
    - Startup Folder Drops (Sysmon 11).
  - Define `PersistenceArtifact` in `app/models/persistence.py`.
  - Integrate analyzers into `IngestionPipeline.ingest_and_persist()` in `app/ingestion/pipeline.py`.
  - Unit tests in `tests/unit/test_persistence_analyzer.py`.
  - Integration tests in `tests/integration/test_analyzer_pipeline_integration.py`.
- **Test Scenarios:**
  - Registry persistence: Run key addition, IFEO debugger hijack.
  - Service installation: Security 4697 with suspicious payload in Temp.
  - Scheduled task: Security 4698 XML parsing of Command/Arguments; explicit test asserting Sysmon registry events alone do NOT produce scheduled task persistence.
  - WMI subscription: Sysmon 19+20+21 binding detection.
  - Startup folder drop: Sysmon 11 file drop in `Start Menu\Programs\Startup`.
  - Full pipeline integration: Ingest EVTX/JSON with PowerShell & Persistence threats, verify SQLite alerts and evidence links created properly.

---

## 5. Verification Checklist & Success Criteria

1. [ ] Base64 encoded PowerShell commands are safely extracted and decoded without executing payloads (PWSH-01).
2. [ ] Download cradles (`Net.WebClient`, `IWR`, `Start-BitsTransfer`) are detected with high confidence (PWSH-02).
3. [ ] Execution policy bypass flags (`-ep bypass`, `-nop`) are identified (PWSH-03).
4. [ ] De-obfuscation normalizes backticks and string concatenations, detecting hidden windows and multi-line script blocks from EID 4104 (PWSH-04).
5. [ ] Contextual scoring prevents benign administrative scripts (`Get-Process`, `$PSScriptRoot`) from alerting, with active-threat safety override (PWSH-05).
6. [ ] Registry persistence modifications (Run, RunOnce, Winlogon, IFEO) are detected via Sysmon 12–14 (PERS-01).
7. [ ] Service installation (Security 4697) and suspicious driver loads (Sysmon 6) are detected (PERS-02).
8. [ ] Scheduled task creation is detected via Security 4698 XML and Task logs, never inferring tasks from registry alone (PERS-03).
9. [ ] WMI event subscriptions (Sysmon 19, 20, 21) are detected (PERS-04).
10. [ ] Startup folder drops (Sysmon 11) are detected (PERS-05).
11. [ ] Analyzers bridge directly into SQLite `alerts` and `alert_evidence` via `AlertRepository`.
