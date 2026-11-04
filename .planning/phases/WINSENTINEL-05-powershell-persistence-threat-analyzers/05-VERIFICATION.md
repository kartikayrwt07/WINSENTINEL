---
phase: "05"
verified: 2026-11-04T18:00:00Z
status: passed
score: 10/10 must-haves verified
---

# Phase 5: PowerShell & Persistence Threat Analyzers — Verification Report

**Date:** 2026-11-04  
**Phase:** WINSENTINEL-05 PowerShell & Persistence Threat Analyzers  
**Status:** PASS (Requirements PWSH-01..05 & PERS-01..05 verified, 274/274 tests passing)  
**Verifier:** gsd-verifier  

---

## 1. Executive Summary

Phase 5 implemented the specialized threat analyzers for PowerShell execution and multi-source Windows persistence mechanisms in WinSentinel. The phase delivers safe non-executing string de-obfuscation (UTF-16LE Base64 decoding, padding repair, backtick stripping, and string concatenation flattening), a 0-100 composite risk scoring engine for process creation (EID 1 / 4688) and ScriptBlock Logging (EID 4104), and a multi-source persistence correlation analyzer monitoring Registry Auto-Runs/IFEO, Services & Drivers, Scheduled Tasks (from authoritative XML and Task Scheduler operational logs without false registry inferences), WMI subscriptions, and Startup folder drops. Both analyzers are integrated into `IngestionPipeline`, persisting high-confidence alerts and structured forensic evidence into SQLite without requiring database schema changes.

Goal-backward verification confirms that Requirements **PWSH-01**, **PWSH-02**, **PWSH-03**, **PWSH-04**, **PWSH-05**, **PERS-01**, **PERS-02**, **PERS-03**, **PERS-04**, and **PERS-05** and all architectural contracts defined in `05-CONTEXT.md` and `05-01-PLAN.md` / `05-02-PLAN.md` are completely implemented, verified with automated unit and integration tests, and benchmarked. The test suite executes 274 tests with a 100% pass rate in 10.74 seconds.

---

## 2. Requirement Verification Matrix

| Requirement | Target Capability | Implementation Evidence | Verification Status |
|---|---|---|---|
| **PWSH-01** | Detection of Base64-encoded command arguments (`-enc`, `-EncodedCommand`) with safe, non-executing string decoding for inspection. | `app/analyzers/powershell_deobfuscator.py`: `PowerShellDeobfuscator.extract_base64_payload()` extracts encoded arguments across `-enc`, `-EncodedCommand`, `-e`, `/enc`, `/e`, etc. with whitespace, colon, or equals delimiters. `decode_base64_payload()` repairs padding and decodes UTF-16LE with UTF-8 and Latin-1 fallbacks. Zero `eval()`, `exec()`, or subprocess calls are used. | **VERIFIED (PASS)** |
| **PWSH-02** | Detection of download cradles (`Net.WebClient`, `Invoke-WebRequest`, `IWR`, `Start-BitsTransfer`). | `app/analyzers/powershell_analyzer.py`: `PowerShellThreatAnalyzer` implements comprehensive regex patterns matching WebClient methods (`DownloadString`, `DownloadFile`, `DownloadData`), cmdlet cradles (`Invoke-WebRequest`, `iwr`, `Invoke-RestMethod`, `irm`, `Start-BitsTransfer`), and `Net.Sockets.TCPClient`. Assigns +40 points. | **VERIFIED (PASS)** |
| **PWSH-03** | Detection of execution policy bypass flags (`-ep bypass`, `-ExecutionPolicy Unrestricted`, `-nop`). | `app/analyzers/powershell_analyzer.py`: Detects bypass arguments (`-executionpolicy bypass`, `-ep bypass`, `-executionpolicy unrestricted`, `-nop`, `-noprofile`) across both raw and normalized command lines. Assigns +20 points. | **VERIFIED (PASS)** |
| **PWSH-04** | Detection of obfuscation, hidden window modes (`-w hidden`), and multi-line script-block execution patterns from EID 4104. | `app/analyzers/powershell_deobfuscator.py` & `powershell_analyzer.py`: Detects hidden windows (`-w hidden`, `-windowstyle hidden`, `-noni`), backtick obfuscation (`strip_backticks`), string concatenation (`flatten_concatenation`), format operators (`detect_format_operator`), and evaluates EID 4104 ScriptBlock telemetry (`script_block_text`). | **VERIFIED (PASS)** |
| **PWSH-05** | Contextual scoring preventing benign administrative PowerShell scripts from generating high-severity false alarms. | `app/analyzers/powershell_analyzer.py`: Computes 0-100 composite risk score with -30 point contextual offsets for benign read-only administrative cmdlets (`Get-Process`, `Get-Service`, `Get-WmiObject`, `Get-CimInstance`) and maintenance scripts (`$PSScriptRoot`, `Defender`, `Intune`). Enforces safety override: active download cradles or memory injection APIs instantly nullify offsets to 0. | **VERIFIED (PASS)** |
| **PERS-01** | Detection of Registry persistence modifications (CurrentVersion\Run, RunOnce, Winlogon, Image File Execution Options / IFEO). | `app/analyzers/persistence_analyzer.py`: `check_registry_persistence()` evaluates Sysmon EID 12, 13, 14 against `CurrentVersion\Run`, `RunOnce`, `Winlogon\Userinit`, `Winlogon\Shell`, and `IFEO` (Debugger hijacking), flagging suspicious values and escalating severity for Temp/script payloads. | **VERIFIED (PASS)** |
| **PERS-02** | Detection of Service installation and suspicious driver loads (Sysmon EID 6, Security EID 4697). | `app/analyzers/persistence_analyzer.py`: `check_service_driver_persistence()` evaluates Security EID 4697 (service install) and Sysmon EID 6 (driver loaded), detecting binary paths in user-writable/temp folders and unsigned/revoked drivers. | **VERIFIED (PASS)** |
| **PERS-03** | Detection of Scheduled Task creation via Task Scheduler Operational logs and Security EID 4698 (not inferring tasks purely from Sysmon registry events). | `app/analyzers/persistence_analyzer.py`: `check_scheduled_task_persistence()` evaluates Security EID 4698 XML (safely parsing `<Actions><Exec><Command>` and `<Arguments>`) and Task Scheduler EID 106/140. **Strict Invariant Verified:** Sysmon registry modifications (`Schedule\TaskCache`) are explicitly forbidden from being claimed as scheduled task persistence. Tested in `tests/unit/test_persistence_analyzer.py`. | **VERIFIED (PASS)** |
| **PERS-04** | Detection of WMI event subscriptions (Sysmon EID 19, 20, 21: EventFilter, EventConsumer, FilterToConsumerBinding). | `app/analyzers/persistence_analyzer.py`: `check_wmi_persistence()` evaluates Sysmon EID 19 (`EventFilter`), EID 20 (`EventConsumer`), and EID 21 (`FilterToConsumerBinding`), extracting consumer names and queries. | **VERIFIED (PASS)** |
| **PERS-05** | Detection of suspicious binary placement in Startup folders and system directories. | `app/analyzers/persistence_analyzer.py`: `check_startup_folder_persistence()` evaluates Sysmon EID 11 (File creation) in user and system Startup folders (`\Start Menu\Programs\Startup`), detecting dropped executables and scripts. | **VERIFIED (PASS)** |

---

## 3. Architecture & Pipeline Integration Verification

| Component | Target Capability | Implementation Evidence | Verification Status |
|---|---|---|---|
| **Safe De-obfuscation Engine** | Non-executing UTF-16LE Base64 decoding and string normalization. | `app/analyzers/powershell_deobfuscator.py`: `PowerShellDeobfuscator.deobfuscate()` repairs padding, decodes UTF-16LE payloads, strips backticks, and flattens adjacent string concatenations iteratively to a fixpoint without executing any commands. Tested in `tests/unit/test_powershell_deobfuscator.py`. | **VERIFIED (PASS)** |
| **Forensic Data Models** | Structured forensic evidence and SQLite alert serialization. | `app/models/powershell.py` & `app/models/persistence.py`: `PowerShellAnalysisResult` and `PersistenceArtifact` capture target objects, payloads, matched indicators, and MITRE ATT&CK techniques, providing `to_alert_dict()` and `to_evidence_dicts()` for direct persistence. | **VERIFIED (PASS)** |
| **Streaming Pipeline Integration** | Ingestion pipeline coordinates with analyzers to persist alerts and evidence. | `app/ingestion/pipeline.py`: `IngestionPipeline` accepts `powershell_analyzer` and `persistence_analyzer`. In `ingest_and_persist(..., run_analyzers=True)`, normalized events are evaluated through both analyzers, linking alerts and evidence records into SQLite via `AlertRepository`. Tested end-to-end in `tests/integration/test_analyzers_pipeline_integration.py`. | **VERIFIED (PASS)** |

---

## 4. Test Suite Verification

Live test execution via `python -m pytest tests/ -v`:
- **Total Test Cases:** 274
- **Passed:** 274
- **Failed:** 0
- **Skipped:** 0
- **Execution Duration:** 10.74 seconds

### Test Breakdown for Phase 5 Additions:
1. `tests/unit/test_powershell_deobfuscator.py` (9 tests):
   - Extraction of Base64 across `-enc`, `-EncodedCommand`, `/enc`, `/e`, `-e`, and `-enco`.
   - Modulo 4 padding repair on unpadded Base64 strings.
   - Robust UTF-16LE decoding with UTF-8 and Latin-1 fallbacks.
   - Word boundary backtick stripping.
   - Iterative string concatenation flattening (`'down'+'load'` -> `'download'`).
   - Format operator detection (`-f`).
   - Clean handling of plain unencoded commands.
   - Malformed Base64 safety (no exceptions thrown).
   - Zero-eval verification (no code execution).
2. `tests/unit/test_powershell_analyzer.py` (13 tests):
   - WebClient and IWR download cradle detection (+40).
   - Base64 encoded payload detection (+30).
   - Execution policy bypass flag detection (+20).
   - Hidden window execution detection (+20).
   - Suspicious native API invocation detection (+30).
   - Multi-indicator compounding (High/Critical severity escalation).
   - Benign administrative query offset (-30) suppressing false alarms.
   - Active threat safety override nullifying benign offsets.
   - EID 4104 ScriptBlock logging evaluation.
   - Unrelated non-PowerShell events bypassed safely.
   - Forensic narrative explanation and MITRE ATT&CK tagging.
   - Database serialization dictionary conversions.
3. `tests/unit/test_persistence_analyzer.py` (12 tests):
   - Registry `Run` and `RunOnce` key modification detection (Sysmon 12, 13).
   - `IFEO` debugger hijacking detection (Sysmon 12, 14).
   - Service installation detection from Security EID 4697.
   - Driver loading from untrusted locations from Sysmon EID 6.
   - Scheduled task creation from Security EID 4698 with safe XML command/argument parsing.
   - Scheduled task creation from Task Scheduler Operational EID 106.
   - **Strict Negative Invariant Test:** Sysmon registry modifications targeting `TaskCache` are NOT classified as scheduled task persistence.
   - WMI `EventFilter` (EID 19), `EventConsumer` (EID 20), and `FilterToConsumerBinding` (EID 21).
   - Startup folder executable drops from Sysmon EID 11.
   - Unrelated events bypassed safely.
   - Database serialization dictionary conversions.
4. `tests/integration/test_analyzers_pipeline_integration.py` (8 tests):
   - Pipeline initialization and default analyzer instantiation.
   - PowerShell threat creating SQLite alert record.
   - PowerShell alert linking evidence records to events table.
   - Benign administrative PowerShell suppressed (0 alerts).
   - Persistence threat creating SQLite alert and evidence records.
   - `run_analyzers=False` toggle verification.
   - IngestionResult exposing typed analyzer result properties.
   - Mixed attack telemetry stream end-to-end integration.

---

## 5. Verification Conclusion

Phase 5 achieves **PASS** status across all specified criteria. All ten functional requirements (`PWSH-01` through `PWSH-05` and `PERS-01` through `PERS-05`) have been verified against running code and comprehensive unit/integration tests. The PowerShell threat analyzer and multi-source persistence analyzer are fully operational and ready for consumption by Phase 6 (Event Correlation & Alert Management).
