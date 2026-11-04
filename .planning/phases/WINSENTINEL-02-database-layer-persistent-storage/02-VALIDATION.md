---
phase: "2"
slug: "database-layer-persistent-storage"
status: draft
nyquist_compliant: true
wave_0_complete: false
created: "2026-11-04"
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 9.x + pytest-cov |
| **Config file** | `pyproject.toml` |
| **Quick run command** | `python -m pytest tests/unit/ -v` |
| **Full suite command** | `python -m pytest tests/ -v --cov=app` |
| **Estimated runtime** | ~5 seconds |

---

## Sampling Rate

- **After every task commit:** Run `python -m pytest tests/unit/ -v`
- **After every plan wave:** Run `python -m pytest tests/ -v --cov=app`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 02-01-01 | 01 | 1 | ALERT-01 | T-02-01 | Connection manager enforces WAL mode, foreign keys, busy timeout, and thread isolation | unit | `python -m pytest tests/unit/test_db_connection.py -v` | ❌ W0 | ⬜ pending |
| 02-01-02 | 01 | 1 | ALERT-01 | T-02-02 | Sequential SQL migrations execute transactionally with checksum verification and rollback on error | unit | `python -m pytest tests/unit/test_db_migrations.py -v` | ❌ W0 | ⬜ pending |
| 02-02-01 | 02 | 2 | ALERT-01 | T-02-03 | Bulk event insertion handles 1,000-chunk transactions with accurate deduplication and index performance | unit | `python -m pytest tests/unit/test_event_repository.py -v` | ❌ W0 | ⬜ pending |
| 02-02-02 | 02 | 2 | ALERT-01 | T-02-04 | Parameterized query builder sanitizes filters against SQL injection and supports LIMIT/OFFSET pagination | unit | `python -m pytest tests/unit/test_query_builder.py -v` | ❌ W0 | ⬜ pending |
| 02-02-03 | 02 | 2 | ALERT-01 | T-02-05 | End-to-end integration: IngestionPipeline writes to SQLite and queries return typed events and import jobs | integration | `python -m pytest tests/integration/test_db_pipeline_integration.py -v` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/unit/test_db_connection.py` — Stubs for DatabaseManager connection and pragma tests
- [ ] `tests/unit/test_db_migrations.py` — Stubs for MigrationRunner and schema DDL tests
- [ ] `tests/unit/test_event_repository.py` — Stubs for EventRepository insertion and deduplication tests
- [ ] `tests/unit/test_query_builder.py` — Stubs for parameterized query and SQLi prevention tests
- [ ] `tests/integration/test_db_pipeline_integration.py` — Stubs for pipeline-to-database integration tests

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

