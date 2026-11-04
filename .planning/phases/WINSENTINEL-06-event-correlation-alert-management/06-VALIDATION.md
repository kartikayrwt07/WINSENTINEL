---
phase: "6"
slug: "event-correlation-alert-management"
status: draft
nyquist_compliant: true
wave_0_complete: false
created: "2026-11-04"
---

# Phase 6 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 9.x + pytest-cov |
| **Config file** | `pyproject.toml` |
| **Quick run command** | `python -m pytest tests/unit/ -v` |
| **Full suite command** | `python -m pytest tests/ -v --cov=app` |
| **Estimated runtime** | ~11 seconds |

---

## Sampling Rate

- **After every task commit:** Run targeted unit tests: `python -m pytest <test_file> -v`
- **After every plan wave:** Run full test suite: `python -m pytest tests/ -v`
- **Before `/gsd-verify-work`:** Full test suite must be green
- **Max feedback latency:** 12 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 06-01-01 | 01 | 1 | CORR-04 | T-06-01 | CompoundIncident and IncidentStage Pydantic v2 schemas and chronological narrative story generator | unit | `python -m pytest tests/unit/test_compound_incident.py -v` | ❌ W0 | ⬜ pending |
| 06-01-02 | 01 | 1 | CORR-01 | T-06-02 | 4 Core Attack Chain definitions (Phishing, Web Shell, Credential Dumping -> Lateral, LotL -> Persistence) | unit | `python -m pytest tests/unit/test_attack_chains.py -v` | ❌ W0 | ⬜ pending |
| 06-01-03 | 01 | 1 | CORR-01, CORR-02, CORR-04 | T-06-03 | AttackChainEngine with 30-min sliding window, host/user scoping, and ProcessTreeGraph traversal | unit | `python -m pytest tests/unit/test_chain_engine.py -v` | ❌ W0 | ⬜ pending |
| 06-02-01 | 02 | 2 | CORR-03, ALERT-02, ALERT-03, ALERT-04 | T-06-04 | AlertManager windowed deduplication, status workflow (New->Investigating->Escalated->Resolved/FP), notes & drill-down | unit | `python -m pytest tests/unit/test_alert_manager.py -v` | ❌ W0 | ⬜ pending |
| 06-02-02 | 02 | 2 | CORR-01..04, ALERT-02..04 | T-06-05 | IngestionPipeline integration: streaming detection -> alert deduplication -> correlation -> SQLite persistence | integration | `python -m pytest tests/integration/test_correlation_pipeline_integration.py -v` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/unit/test_compound_incident.py` — Stubs for CompoundIncident, IncidentStage, and narrative generator
- [ ] `tests/unit/test_attack_chains.py` — Stubs for 4 attack chain definitions and stage matching logic
- [ ] `tests/unit/test_chain_engine.py` — Stubs for AttackChainEngine, sliding window, and process ancestry traversal
- [ ] `tests/unit/test_alert_manager.py` — Stubs for AlertManager deduplication, lifecycle transitions, and drill-down
- [ ] `tests/integration/test_correlation_pipeline_integration.py` — Stubs for end-to-end pipeline correlation and SQLite persistence

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
- [x] Feedback latency < 12s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved 2026-11-04

