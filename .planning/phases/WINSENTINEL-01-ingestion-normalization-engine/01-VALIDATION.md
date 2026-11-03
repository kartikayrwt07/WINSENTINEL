---
phase: "1"
slug: "ingestion-normalization-engine"
status: draft
nyquist_compliant: true
wave_0_complete: false
created: "2026-11-03"
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 8.x + pytest-cov |
| **Config file** | `pyproject.toml` |
| **Quick run command** | `pytest tests/unit/ -v` |
| **Full suite command** | `pytest tests/ -v --cov=app` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `pytest tests/unit/ -v`
- **After every plan wave:** Run `pytest tests/ -v --cov=app`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 01-01-01 | 01 | 1 | NORM-01, NORM-08 | T-01-01 | Reject unvalidated payloads, enforce immutable fields | unit | `pytest tests/unit/test_models.py -v` | ❌ W0 | ⬜ pending |
| 01-01-02 | 01 | 1 | INGEST-04, INGEST-05 | T-01-02 | Deterministic SHA256 event fingerprinting | unit | `pytest tests/unit/test_fingerprint.py -v` | ❌ W0 | ⬜ pending |
| 01-02-01 | 02 | 2 | INGEST-02, INGEST-06 | T-01-03 | XML entity safety (defusedxml / no external entities), Path traversal block | unit | `pytest tests/unit/test_xml_parser.py -v` | ❌ W0 | ⬜ pending |
| 01-02-02 | 02 | 2 | INGEST-01, INGEST-06 | T-01-04 | Catch python-evtx exceptions, memory-bounded generator streaming | unit | `pytest tests/unit/test_evtx_parser.py -v` | ❌ W0 | ⬜ pending |
| 01-02-03 | 02 | 2 | INGEST-03, INGEST-04 | T-01-05 | JSON schema validation and corrupt line recovery | unit | `pytest tests/unit/test_json_parser.py -v` | ❌ W0 | ⬜ pending |
| 01-03-01 | 03 | 3 | NORM-02, NORM-03, NORM-04, NORM-05 | T-01-06 | Clean field mapping across Sysmon EID 1-26, handle missing attributes | unit | `pytest tests/unit/test_sysmon_normalizer.py -v` | ❌ W0 | ⬜ pending |
| 01-03-02 | 03 | 3 | NORM-06, NORM-07 | T-01-07 | Convert Security EID 4688 hex PIDs to int, parse PowerShell 4104 script blocks | unit | `pytest tests/unit/test_security_pwsh_normalizer.py -v` | ❌ W0 | ⬜ pending |
| 01-03-03 | 03 | 3 | INGEST-04, NORM-08 | T-01-08 | Ingestion pipeline end-to-end integration and error stats | integration | `pytest tests/integration/test_ingestion_pipeline.py -v` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/conftest.py` — Shared fixtures with synthetic Sysmon XML, Security XML, PowerShell XML, and EVTX samples
- [ ] `tests/unit/test_models.py` — Stubs for model validation
- [ ] `tests/unit/test_xml_parser.py` — Stubs for XML parser
- [ ] `tests/unit/test_evtx_parser.py` — Stubs for EVTX parser
- [ ] `tests/unit/test_json_parser.py` — Stubs for JSON parser
- [ ] `tests/unit/test_sysmon_normalizer.py` — Stubs for Sysmon normalization
- [ ] `tests/unit/test_security_pwsh_normalizer.py` — Stubs for Security/PowerShell normalization
- [ ] `tests/integration/test_ingestion_pipeline.py` — Stubs for full pipeline integration

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

**Approval:** approved 2026-11-03

