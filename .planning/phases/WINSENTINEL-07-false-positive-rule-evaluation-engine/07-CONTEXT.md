# Phase 7: False-Positive & Rule Evaluation Engine - Context

**Gathered:** 2026-11-05  
**Status:** Ready for planning

<domain>
## Phase Boundary

Phase 7 delivers a scientific detection evaluation and false-positive benchmarking harness for WinSentinel:
- **Benchmark Evaluation Runner (`EvaluationRunner`):**
  - Executes loaded Sigma-style detection rules and specialized threat analyzers against curated, labeled ground-truth event datasets.
  - Supports testing individual rules or the full rule catalog against attack telemetry and benign background noise.
- **Labeled Ground-Truth Benchmark Datasets:**
  - Dedicated JSONL benchmark datasets containing realistic Sysmon and Windows Security events.
  - Ground-truth annotations per record indicating maliciousness (`is_malicious: bool`), expected rule IDs triggered (`expected_rules: list[str]`), technique reference, and descriptive ground truth.
  - Rich benign administrative noise fixtures (e.g., standard SCCM/MECM software deployments, Windows Update agent runs, developer VS Code build tasks, legitimate admin PowerShell scripts, background service polling) specifically designed to stress-test suppression logic and measure false-positive resistance.
- **Confusion Matrix & Metric Calculation:**
  - Per-event granularity evaluation:
    - **True Positive (TP)**: Event is labeled as triggering Rule X, and Rule X fired.
    - **False Positive (FP)**: Event is NOT labeled as triggering Rule X (e.g. benign administrative noise or different threat), but Rule X fired.
    - **True Negative (TN)**: Event is NOT labeled as triggering Rule X, and Rule X did NOT fire.
    - **False Negative (FN)**: Event is labeled as triggering Rule X, but Rule X did NOT fire.
  - Standard detection metrics calculated globally and per-rule:
    - **Precision** = $\frac{TP}{TP + FP}$
    - **Recall** = $\frac{TP}{TP + FN}$
    - **F1-Score** = $2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$
    - **False Positive Rate (FPR)** = $\frac{FP}{FP + TN}$
    - **Accuracy** = $\frac{TP + TN}{TP + TN + FP + FN}$
- **Automated Tuning Recommendations & Performance Reports:**
  - Rule health diagnostic heuristics:
    - **High False Positive Alert**: Flag rules with $\text{FPR} > 0.05$ or $\text{Precision} < 0.80$ as prone to alert fatigue; suggest suppression fields or stricter condition baselines.
    - **Dead / Low Coverage Rule**: Flag rules with zero triggers against relevant attack datasets.
    - **High Confidence Rule**: Rules with $100\%$ precision and zero false positives against benign baselines.
  - Structured reporting output: exportable JSON report and formatted Markdown summary for detection engineers, plus data structures directly ready for the Phase 8 Streamlit Evaluation dashboard.

</domain>

<decisions>
## Implementation Decisions

### Confusion Matrix & Evaluation Granularity
- **D-01:** Evaluation uses **Per-Event Granularity**:
  - Each event in the benchmark dataset contains an expectation label.
  - For each rule evaluated against the dataset:
    - If event expects Rule X and Rule X matches $\rightarrow$ TP
    - If event does not expect Rule X but Rule X matches $\rightarrow$ FP
    - If event expects Rule X but Rule X does not match $\rightarrow$ FN
    - If event does not expect Rule X and Rule X does not match $\rightarrow$ TN
  - Aggregated metrics across all rules provide overall engine health, while per-rule breakdowns isolate problem detections.

### Labeled Ground-Truth Dataset Schema & Fixtures
- **D-02:** Store labeled datasets as JSONL files with a clear benchmark schema (`BenchmarkEvent`):
  - Standard normalized event fields matching `NormalizedEvent` / Sysmon telemetry.
  - Annotation fields:
    - `is_malicious: bool`
    - `expected_rules: list[str]` (list of rule IDs expected to match this specific event)
    - `scenario: str` (e.g., "lateral_movement_lsass", "benign_windows_update", "benign_sccm_deploy")
    - `description: str`
  - Provide at least two distinct corpora in `tests/data/benchmarks/` or `data/benchmarks/`:
    1. `attacks.jsonl`: True positive attack patterns covering process injection, credential dumping, LOLBins, persistence, PowerShell bypasses.
    2. `benign_admin_noise.jsonl`: Benign administrative workloads that often cause false alarms (e.g. `ccmexec.exe`, `gpupdate.exe`, scheduled defrag, IT admin diagnostics, package managers).

### Automated Tuning Diagnostics & Heuristics
- **D-03:** Provide automated heuristic rule health diagnostics in `EvaluationReport`:
  - **Dead Rule Warning**: Rules that produced 0 matches across the benchmark corpus.
  - **Noisy Rule / High FPR Warning**: Rules with $\text{FPR} > 5\%$ or $\text{Precision} < 80\%$.
  - **Suppression Suggestions**: For noisy rules, inspect false positive events to identify candidate suppression criteria (e.g. common parent process names, signed system directories, specific user accounts).
  - **Quality Gate Verification**: Support pass/fail evaluation thresholds (e.g. require zero false positives on benign noise dataset) for CI/CD gating.

### Architecture & Engine Design
- **D-04:** Organize components cleanly in `app/evaluation/`:
  - `app/models/evaluation.py`: Pydantic models for `BenchmarkEvent`, `ConfusionMatrix`, `RuleEvaluationMetrics`, `EvaluationReport`, `TuningRecommendation`.
  - `app/evaluation/metrics.py`: Pure mathematical confusion matrix calculator handling zero-division edge cases gracefully.
  - `app/evaluation/runner.py`: `EvaluationRunner` orchestrating rule loading, dataset ingestion, detection matching, confusion matrix accumulation, and report synthesis.
  - `app/evaluation/tuner.py`: Diagnostic analyzer generating rule tuning and suppression advice.
  - `app/evaluation/cli.py` / CLI entrypoint for running evaluation benchmarks and dumping reports to JSON/Markdown.

</decisions>

<specifics>
## Specific Ideas & Test Coverage

- Unit tests for `ConfusionMatrix` and metric calculations:
  - Perfect score (100% precision, 100% recall, 0% FPR).
  - Zero-division handling (zero positives, zero negatives).
  - High FP scenario verifying precision and FPR penalties.
- Unit tests for benchmark dataset loader validating schema compliance of labeled JSONL files.
- Integration tests running `EvaluationRunner` against real Sysmon rules and benchmark datasets, verifying accurate TP/FP/TN/FN counts.
- Benign noise tests verifying core Sysmon library produces 0 false positives against the benign administrative dataset.
- Report serialization tests verifying JSON export and Markdown generation.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing:**
- `.planning/PROJECT.md` — Section 6 Module I (False-Positive & Rule Evaluation Engine).
- `.planning/REQUIREMENTS.md` — EVAL-01 through EVAL-04.
- `.planning/ROADMAP.md` — Phase 7 goals, success criteria, and plans breakdown.
- `.planning/phases/WINSENTINEL-04-detection-rule-engine-sysmon-core-library/04-VERIFICATION.md` — `DetectionEngine`, `DetectionRule`, and `DetectionMatch` implementation.
- `rules/sysmon/` — Existing 16 verified Sysmon detection rules.

</canonical_refs>
