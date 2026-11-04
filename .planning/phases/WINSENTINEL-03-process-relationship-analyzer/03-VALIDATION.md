---
phase: "3"
slug: "process-relationship-analyzer"
status: draft
nyquist_compliant: true
wave_0_complete: false
created: "2026-11-04"
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 9.x + pytest-cov |
| **Config file** | `pyproject.toml` |
| **Quick run command** | `python -m pytest tests/unit/ -v` |
| **Full suite command** | `python -m pytest tests/ -v --cov=app` |
| **Estimated runtime** | ~6 seconds |

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
| 03-01-01 | 01 | 1 | PROC-01, PROC-05 | T-03-01 | Reconstruct parent-child graph, handle missing parents with synthesized nodes, walk ancestry | unit | `python -m pytest tests/unit/test_process_tree.py -v` | ❌ W0 | ⬜ pending |
| 03-01-02 | 01 | 1 | PROC-02 | T-03-02 | Disambiguate PID recycling across time via sorted intervals and bisect lookup | unit | `python -m pytest tests/unit/test_pid_resolver.py -v` | ❌ W0 | ⬜ pending |
| 03-01-03 | 01 | 1 | PROC-01, PROC-03 | T-03-03 | ProcessRepository persistence, migration 002, and graph hydration from SQLite | unit | `python -m pytest tests/unit/test_process_repository.py -v` | ❌ W0 | ⬜ pending |
| 03-02-01 | 02 | 2 | PROC-04 | T-03-04 | Detect suspicious lineage combinations (Office/Spooler/IIS -> shells/recon) | unit | `python -m pytest tests/unit/test_lineage_detector.py -v` | ❌ W0 | ⬜ pending |
| 03-02-02 | 02 | 2 | PROC-05 | T-03-05 | Graph serialization to Cytoscape and D3 hierarchy formats without recursion loops | unit | `python -m pytest tests/unit/test_tree_serialization.py -v` | ❌ W0 | ⬜ pending |
| 03-02-03 | 02 | 2 | PROC-01, PROC-04 | T-03-06 | IngestionPipeline integration: auto-build process tree, detect anomalies, sync to DB | integration | `python -m pytest tests/integration/test_process_pipeline_integration.py -v` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/unit/test_process_tree.py` — Stubs for ProcessNode, ProcessTreeGraph, ancestry walking, and synthesized parent creation
- [ ] `tests/unit/test_pid_resolver.py` — Stubs for TemporalPIDResolver and PID reuse disambiguation
- [ ] `tests/unit/test_process_repository.py` — Stubs for ProcessRepository persistence and SQLite roundtripping
- [ ] `tests/unit/test_lineage_detector.py` — Stubs for LineageAnomalyDetector and MITRE rule evaluation
- [ ] `tests/unit/test_tree_serialization.py` — Stubs for Cytoscape and D3 graph export
- [ ] `tests/integration/test_process_pipeline_integration.py` — Stubs for end-to-end pipeline-to-process-graph integration

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

