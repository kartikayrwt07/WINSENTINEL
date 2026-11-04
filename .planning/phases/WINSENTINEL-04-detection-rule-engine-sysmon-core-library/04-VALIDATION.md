---
phase: "4"
slug: "detection-rule-engine-sysmon-core-library"
status: draft
nyquist_compliant: true
wave_0_complete: false
created: "2026-11-04"
---

# Phase 4 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 9.x + pytest-cov |
| **Config file** | `pyproject.toml` |
| **Quick run command** | `python -m pytest tests/unit/ -v` |
| **Full suite command** | `python -m pytest tests/ -v --cov=app` |
| **Estimated runtime** | ~8 seconds |

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
| 04-01-01 | 01 | 1 | RULE-01 | T-04-01 | Pydantic v2 DetectionRule schema validation, required fields, and YAML parsing | unit | `python -m pytest tests/unit/test_rule_schema.py -v` | ❌ W0 | ⬜ pending |
| 04-01-02 | 01 | 1 | RULE-01, RULE-02 | T-04-02 | Zero-eval recursive-descent boolean AST condition parser with strict operator precedence | unit | `python -m pytest tests/unit/test_condition_parser.py -v` | ❌ W0 | ⬜ pending |
| 04-01-03 | 01 | 1 | RULE-01 | T-04-03 | Directory rule loader, duplicate rule ID rejection, and SQLite detection_rules sync | unit | `python -m pytest tests/unit/test_rule_loader.py -v` | ❌ W0 | ⬜ pending |
| 04-02-01 | 02 | 2 | RULE-02, RULE-03 | T-04-04 | Case-insensitive field matcher with string modifiers (|contains, |startswith, |endswith, |re, |all) | unit | `python -m pytest tests/unit/test_field_matcher.py -v` | ❌ W0 | ⬜ pending |
| 04-02-02 | 02 | 2 | RULE-04 | T-04-05 | Forensic DetectionMatch evidence extraction, explanation generation, and AlertRepository conversion | unit | `python -m pytest tests/unit/test_detection_match.py -v` | ❌ W0 | ⬜ pending |
| 04-02-03 | 02 | 2 | RULE-01, RULE-04 | T-04-06 | DetectionEngine in-memory indexing by (provider, event_id) and multi-rule event evaluation | unit | `python -m pytest tests/unit/test_detection_engine.py -v` | ❌ W0 | ⬜ pending |
| 04-03-01 | 03 | 3 | RULE-05 | T-04-07 | Core Sysmon rule library: 16 YAML rules across EID 1, 6, 7, 8, 10, 12-14, 22 | unit | `python -m pytest tests/unit/test_sysmon_rules_library.py -v` | ❌ W0 | ⬜ pending |
| 04-03-02 | 03 | 3 | RULE-04, RULE-05 | T-04-08 | Synthetic test telemetry fixtures and ground-truth positive/negative detection evaluation | unit | `python -m pytest tests/unit/test_rule_eval_groundtruth.py -v` | ❌ W0 | ⬜ pending |
| 04-03-03 | 03 | 3 | RULE-04 | T-04-09 | Pipeline integration: streaming detection during ingest_and_persist, alert and evidence DB storage | integration | `python -m pytest tests/integration/test_detection_pipeline_integration.py -v` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `tests/unit/test_rule_schema.py` — Stubs for DetectionRule Pydantic model validation
- [ ] `tests/unit/test_condition_parser.py` — Stubs for AST condition tokenizer and evaluator
- [ ] `tests/unit/test_rule_loader.py` — Stubs for YAML rule loader and repository sync
- [ ] `tests/unit/test_field_matcher.py` — Stubs for field modifier pipeline and case-insensitivity
- [ ] `tests/unit/test_detection_match.py` — Stubs for DetectionMatch and evidence extraction
- [ ] `tests/unit/test_detection_engine.py` — Stubs for indexed DetectionEngine
- [ ] `tests/unit/test_sysmon_rules_library.py` — Stubs for 16 Sysmon detection rules validation
- [ ] `tests/unit/test_rule_eval_groundtruth.py` — Ground-truth positive/negative validation suite
- [ ] `tests/integration/test_detection_pipeline_integration.py` — End-to-end ingestion pipeline detection integration

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

