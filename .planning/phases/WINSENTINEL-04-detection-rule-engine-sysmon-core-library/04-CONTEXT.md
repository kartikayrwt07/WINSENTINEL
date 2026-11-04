# Phase 4: Detection Rule Engine & Sysmon Core Library - Context

**Gathered:** 2026-11-04  
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 4 delivers the detection rule parsing, validation, matching, and explainable alert generation engine for WinSentinel, along with a comprehensive out-of-the-box core library of Sysmon detection rules:
- Strict Pydantic schema validation for YAML-based Sigma-inspired detection rules.
- Safe, zero-eval recursive-descent / shunting-yard boolean condition evaluator supporting `and`, `or`, `not`, parentheses, `1 of selection*`, and `all of selection*`.
- Field-matching engine supporting case-insensitive matching by default, with modifiers `|contains`, `|startswith`, `|endswith`, `|re` (regex), and `|all`, handling list values as implicit OR.
- Rule exclusion and false-positive baseline filtering (`filter` selections).
- Transparent match explainability: Every detection hit generates a structured `DetectionMatch` containing the rule ID, matched event record, exact triggering field/value pairs, a human-readable detection rationale, and investigation guidance.
- Core library of 15+ verified Sysmon detection rules targeting high-fidelity threat techniques (Process injection, LSASS memory dumping, driver loading, DLL side-loading, LOLBin misuse, and registry persistence).
- Rule engine indexing by `(provider, event_id)` for fast dispatch during event ingestion.

</domain>

<decisions>
## Implementation Decisions

### Rule Syntax & Boolean Condition Evaluation Engine
- **D-01:** Implement a custom, safe recursive-descent / shunting-yard boolean expression evaluator without Python's `eval()` or `exec()`.
  - Supports boolean operators (`and`, `or`, `not`), nested parentheses `( ... )`, and Sigma-style wildcards (`1 of selection*`, `all of selection*`).
  - Evaluates arbitrary boolean logic over named selections and exclusion filters (e.g., `selection and not (filter1 or filter2)`).
  - Strongly validated to prevent infinite recursion, unmatched tokens, or syntax ambiguity.

### Field Matching & String Modifiers
- **D-02:** Standardize field-level value matching to be case-insensitive by default.
  - Modifiers supported:
    - Default (no modifier): exact case-insensitive equality.
    - `|contains`: substring search (case-insensitive).
    - `|startswith`: prefix match (case-insensitive).
    - `|endswith`: suffix match (case-insensitive).
    - `|re`: regular expression match using `re.compile(pattern, re.IGNORECASE)` with timeout/safe syntax guards.
    - `|all`: when paired with a list of values, requires all items in the list to be present in the target field; without `|all`, list values behave as implicit OR (any matching value satisfies the selection).
  - Missing or null fields fail matching gracefully rather than throwing exceptions.

### Rule Schema & Pydantic Validation
- **D-03:** Define a strict Pydantic v2 model `DetectionRule` validating all rule YAML files:
  - Required fields: `id` (UUID or unique string slug), `title`, `description`, `author`, `severity` (`informational`, `low`, `medium`, `high`, `critical`), `status` (`active`, `testing`, `deprecated`), `logsource` (`category`, `product`, `service`), `detection` (dictionary of selections, filters, and a `condition` string).
  - Optional enrichment: `mitre_attack` (tactics and techniques like `[T1003.001, T1059.001]`), `references` (list of URLs/reports), `falsepositives` (known benign contexts), and `investigation_steps` (step-by-step SOC analyst guidance).

### Match Explainability & Evidence Schema
- **D-04:** Every detection match must produce a structured `DetectionMatch` object:
  - Contains `rule_id`, `rule_title`, `severity`, `event_id`, `event_record_id`, `computer`, `timestamp_utc`.
  - Captures `matched_evidence`: a list of key-value pairs showing the exact fields, event values, and condition modifiers that triggered the detection.
  - Generates a human-readable `explanation` detailing why the event matched the rule and highlighting exclusions that were evaluated.
  - Includes `mitre_tactics`, `mitre_techniques`, and `investigation_steps` for downstream alert ingestion into SQLite `alerts` and `alert_evidence` tables.

### Sysmon Core Rule Library & Performance Indexing
- **D-05:** Deliver at least 15 production-ready, verified YAML detection rules stored in `rules/sysmon/<category>/`:
  - Process Creation (EID 1): LOLBins execution (certutil, mshta, bitsadmin, rundll32), UAC bypass execution, suspicious command-line flags.
  - Remote Thread Injection (EID 8): `CreateRemoteThread` targeting critical system processes (`lsass.exe`, `explorer.exe`, `svchost.exe`).
  - Process Access & Credential Dumping (EID 10): Access to `lsass.exe` with suspicious `GrantedAccess` masks (e.g., `0x1010`, `0x1410`, `0x1F0FFF`).
  - Driver & Image Loading (EID 6 & 7): Unsigned driver loads, suspicious DLL loading from user-writable directories (`AppData`, `Temp`).
  - Registry Persistence (EID 12, 13, 14): Additions or modifications to `CurrentVersion\Run`, `RunOnce`, and `Image File Execution Options`.
  - Network & DNS (EID 3 & 22): Suspicious outbound connections by non-browser binaries and dynamic DNS / fast-flux lookups.
- **D-06:** The rule engine maintains an in-memory index mapping `(provider, event_id)` to applicable rules, ensuring high-throughput ingestion skips irrelevant rules in $O(1)$ time.

### Developer & Agent Discretion
- Rule Loader: Automatically scans and loads `.yml` / `.yaml` files from configured directories (e.g., `rules/`).
- Database Sync: Provide an optional synchronizer to upsert loaded rule definitions into the SQLite `detection_rules` table.
- Test Fixtures: Provide synthetic ground-truth Sysmon events matching each rule in the core library to ensure 100% test verification.

</decisions>

<specifics>
## Specific Ideas & Test Coverage

- Unit tests for the boolean tokenizer and AST evaluator covering complex nested expressions: `(sel_a and sel_b) and not (filt_c or filt_d)`, `1 of sel_* and not filt`, and operator precedence.
- Unit tests for all string modifiers (`|contains`, `|startswith`, `|endswith`, `|re`, `|all`, list OR).
- Validation tests asserting invalid YAML schemas, missing required fields, or illegal condition operators fail with descriptive validation errors.
- Unit tests for `DetectionMatch` verifying evidence field extraction and forensic explanation string formatting.
- Integration tests running the core library of >= 15 Sysmon rules against sample synthetic telemetry, asserting positive hits for malicious patterns and zero false positives for benign baselines.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing:**
- `.planning/PROJECT.md` — Section 6 Module D (Detection Rule Engine).
- `.planning/REQUIREMENTS.md` — RULE-01 through RULE-05.
- `.planning/ROADMAP.md` — Phase 4 goals, success criteria, and plans breakdown.
- `.planning/phases/WINSENTINEL-01-ingestion-normalization-engine/01-VERIFICATION.md` — Normalized event models and schemas (`NormalizedEvent`).
- `.planning/phases/WINSENTINEL-02-database-layer-persistent-storage/02-VERIFICATION.md` — Relational schema for `detection_rules`, `alerts`, and `alert_evidence`.
- `.planning/phases/WINSENTINEL-03-process-relationship-analyzer/03-VERIFICATION.md` — Process tree nodes, ancestry, and temporal PID resolution.

</canonical_refs>

