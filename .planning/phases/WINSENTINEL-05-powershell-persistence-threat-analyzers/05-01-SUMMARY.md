# Phase 5 Plan 01: PowerShell Safe De-obfuscation & Threat Analyzer Summary

**Plan ID:** `05-01`  
**Phase:** `WINSENTINEL-05-powershell-persistence-threat-analyzers`  
**Completed At:** 2026-11-04  
**Status:** Completed  

---

## 1. Executive Summary

Plan `05-01` delivers the safe, zero-eval PowerShell de-obfuscation engine, typed forensic analysis data models, and composite risk scoring threat analyzer for WinSentinel.

PowerShell is the primary living-off-the-land (LotL) execution tool exploited by adversaries on Windows endpoints. To address this threat surface safely, all payload parsing and decoding operates deterministically via regex tokenization, padding repair, and multi-encoding bytes reconstruction—guaranteeing 100% zero invocation of Python `eval()`, `exec()`, or external PowerShell subprocesses. The analyzer computes a deterministic 0–100 composite risk score evaluating download cradles, Base64 payloads, execution policy bypasses, hidden windows, suspicious native APIs, and obfuscation syntax. Benign administrative query baselines receive contextual offsets to eliminate false positives on routine maintenance scripts, backed by a strict safety override that nullifies offsets whenever active droppers or memory injection primitives are detected.

---

## 2. Implemented Components

### 2.1 Safe PowerShell De-obfuscator Engine (`app/analyzers/powershell_deobfuscator.py`)
- **`DeobfuscationResult(BaseModel)`**: Immutable Pydantic v2 model capturing `raw_text`, `extracted_base64`, `decoded_text`, `normalized_text`, and boolean flags `has_base64`, `has_backticks`, `has_concatenation`, `has_format_operator`.
- **`PowerShellDeobfuscator`**:
  - `repair_base64_padding(b64_str)`: Strips non-Base64 characters and calculates missing `=` padding modulo 4.
  - `extract_base64_payload(command)`: Robustly identifies encoded command flags (`-enc`, `-EncodedCommand`, `-e`, `/enc`, `/e`, `-enco`, etc.) across whitespace, colon, and equals delimiters with optional quoting.
  - `decode_base64_payload(b64_str)`: Decodes Base64 payloads, prioritizing UTF-16LE (PowerShell default) with fallback to UTF-8 and Latin-1. Traps `binascii.Error` and malformed byte sequences gracefully.
  - `strip_backticks(text)`: Safely removes obfuscating backtick characters preceding alphanumerics, hyphens, and quotes without altering valid syntax.
  - `flatten_concatenation(text)`: Collapses adjacent quoted strings separated by `+` iteratively up to 10 passes until reaching a stable fixpoint.
  - `detect_format_operator(text)`: Flags `-f` format strings with positional index braces (`"{1}{0}" -f`).
  - `deobfuscate(text)`: Combines Base64 decoding, backtick stripping, and concat flattening into a normalized string without code execution.

### 2.2 Forensic Analysis Data Models (`app/models/powershell.py`)
- **`PowerShellAnalysisResult(BaseModel)`**: Immutable model tracking `event_id`, `record_id`, `event_db_id`, `computer`, `timestamp_utc`, `process_guid`, `user`, `raw_command`, `decoded_command`, `deobfuscated_command`, `risk_score` (0–100 clamped), `severity` (`Informational`, `Medium`, `High`, `Critical`), `indicators`, `matched_patterns`, `mitre_tactics`, `mitre_techniques`, and `investigation_steps`.
- **SQLite Bridging Methods**:
  - `to_alert_dict()`: Maps forensic findings directly into `AlertRepository.create_alert()` parameters under rule ID `PWSH-COMPOSITE-001`.
  - `to_evidence_dicts(alert_id)`: Maps raw commands, de-obfuscated script blocks, matched indicator patterns, and risk scores into `AlertRepository.link_alert_evidence()` rows linked to the normalized event ID.

### 2.3 PowerShell Threat Analyzer (`app/analyzers/powershell_analyzer.py`)
- **Weighted Indicator Scoring Engine**:
  - `DownloadCradle` (+40): Matches `Net.WebClient`, `DownloadString`, `DownloadFile`, `DownloadData`, `Invoke-WebRequest`, `iwr`, `Start-BitsTransfer`, `Invoke-RestMethod`, `irm`, and `Net.Sockets.TcpClient`.
  - `Base64Payload` (+30): Flags encoded command payloads extracted and decoded from CLI flags.
  - `SuspiciousNativeApi` (+30): Flags memory allocation and injection APIs (`VirtualAlloc`, `VirtualProtect`, `WriteProcessMemory`, `CreateThread`, `RtlMoveMemory`, `GetProcAddress`, `LoadLibrary`, `QueueUserAPC`, `MapViewOfFile`).
  - `ExecutionPolicyBypass` (+20): Flags `-ep bypass`, `-executionpolicy unrestricted`, `-nop`, `-noprofile`.
  - `HiddenWindow` (+20): Flags `-w hidden`, `-windowstyle hidden`, `-w 1`, `-noni`, `-noninteractive`.
  - `ObfuscationTechniques` (+15): Flags excessive backticks (>3), concat chains, format strings (`-f`), `[char[]]`, `[convert]::FromBase64String`, and `-join`.
- **Benign Baseline Offsets & Safety Override (D-02)**:
  - `-30` offset applied for read-only administrative queries (`Get-Process`, `Get-Service`, `Get-WmiObject`, `Get-CimInstance`, `Get-ItemProperty`, `Get-WinEvent`, `Get-ChildItem`) and management scripts (`$PSScriptRoot`, `Defender`, `Intune`, `CCM`).
  - **Safety Override Invariant**: If an active download cradle (+40) or suspicious native API (+30) is present, the benign offset is strictly nullified (offset = 0) to prevent adversary allowlist evasion.
- **Severity Mapping**:
  - `0 - 29`: `Informational`
  - `30 - 59`: `Medium`
  - `60 - 84`: `High`
  - `85 - 100`: `Critical`
- **Telemetry Routing (`analyze_event`)**:
  - Evaluates PowerShell script-block logging (EID 4104 / EID 4103) and process creation (Sysmon EID 1 / Security EID 4688) for PowerShell binaries (`powershell.exe`, `pwsh.exe`, `powershell_ise.exe`), returning `None` for non-PowerShell events.

---

## 3. Verification & Test Execution Results

- **Unit Tests Added:**
  - `tests/unit/test_powershell_deobfuscator.py` (9 tests, 100% passed)
  - `tests/unit/test_powershell_analyzer.py` (13 tests, 100% passed)
- **Full Repository Test Suite:**
  - 254 tests passed, 0 failures, 0 errors in 8.59 seconds.
  - Zero regressions across ingestion pipeline, normalizers, SQLite persistence, and detection engines.

---

## 4. Key Links & Artifacts

- Implementation:
  - `app/analyzers/powershell_deobfuscator.py`
  - `app/models/powershell.py`
  - `app/analyzers/powershell_analyzer.py`
- Package Exports:
  - `app/models/__init__.py`
  - `app/analyzers/__init__.py`
- Tests:
  - `tests/unit/test_powershell_deobfuscator.py`
  - `tests/unit/test_powershell_analyzer.py`
