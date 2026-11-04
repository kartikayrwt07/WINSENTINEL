---
phase: "5"
slug: "powershell-persistence-threat-analyzers"
status: draft
nyquist_compliant: true
wave_0_complete: false
created: "2026-11-04"
---

# Phase 5 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 9.x + pytest-cov |
| **Config file** | `pyproject.toml` |
| **Quick run command** | `python -m pytest tests/unit/ -v` |
| **Full suite command** | `python -m pytest tests/ -v --cov=app` |
| **Estimated runtime** | ~9 seconds |

---

## Sampling Rate

- **After every task commit:** Run targeted unit tests: `python -m pytest <test_file> -v`
- **After every plan wave:** Run full test suite: `python -m pytest tests/ -v`
- **Before `/gsd-verify-work`:** Full test suite must be green
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 05-01-01 | 01 | 1 | PWSH-01, PWSH-04 | T-05-01 | Safe UTF-16LE Base64 decoding, backtick stripping, and string concat normalization without code execution | unit | `python -m pytest tests/unit/test_powershell_deobfuscator.py -v` | ❌ W0 | ⬜ pending |
| 05-01-02 | 01 | 1 | PWSH-02, PWSH-03, PWSH-05 | T-05-02 | Composite risk scoring (0-100), tiered severity, download cradle/bypass detection, and benign admin offsets | unit | `python -m pytest tests/unit/test_powershell_analyzer.py -v` | ❌ W0 | ⬜ pending |
| 05-02-01 | 02 | 2 | PERS-01, PERS-02, PERS-03, PERS-04, PERS-05 | T-05-03 | Multi-source persistence correlation (Run keys, IFEO, Services 4697, Tasks 4698, WMI 19-21, Startup drops 11) | unit | `python -m pytest tests/unit/test_persistence_analyzer.py -v` | ❌ W0 | ⬜ pending |
| 05-02-02 | 02 | 2 | PWSH-01..05, PERS-01..05 | T-05-04 | IngestionPipeline integration: streaming analyzer execution and SQLite alerts/alert_evidence persistence | integration | `python -m pytest tests/integration/test_analyzers_pipeline_integration.py -v` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/unit/test_powershell_deobfuscator.py` — Stubs for PowerShellDeobfuscator and safe string normalization
- [ ] `tests/unit/test_powershell_analyzer.py` — Stubs for PowerShellThreatAnalyzer, composite scoring, and benign offset rules
- [ ] `tests/unit/test_persistence_analyzer.py` — Stubs for PersistenceAnalyzer, multi-source event detectors, and task separation
- [ ] `tests/integration/test_analyzers_pipeline_integration.py` — Stubs for end-to-end pipeline analyzer integration and SQLite persistence

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| None | — | — | All phase behaviors have automated verification. |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 10s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-11-04

