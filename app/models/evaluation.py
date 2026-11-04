"""Pydantic v2 data models for benchmark evaluation, confusion matrices, and reporting."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.events import NormalizedEvent


class TuningIssueType(str, Enum):
    """Categorization of detection rule tuning opportunities."""

    ZERO_COVERAGE = "ZERO_COVERAGE"
    HIGH_FALSE_POSITIVE_RATE = "HIGH_FALSE_POSITIVE_RATE"
    LOW_PRECISION = "LOW_PRECISION"
    LOW_RECALL = "LOW_RECALL"
    ALERT_FATIGUE = "ALERT_FATIGUE"


class BenchmarkLabel(BaseModel):
    """Ground truth annotation metadata for benchmark events."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    is_malicious: bool = False
    expected_rules: list[str] = Field(default_factory=list)
    scenario: str = ""
    description: str = ""
    mitre_attack: list[str] = Field(default_factory=list)


class BenchmarkEvent(BaseModel):
    """Event record pairing normalized Windows event payload with ground truth label."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event: NormalizedEvent
    label: BenchmarkLabel


class ConfusionMatrix(BaseModel):
    """Confusion matrix tallying binary classification counts."""

    model_config = ConfigDict(extra="forbid")

    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        """Total number of evaluated instances."""
        return self.tp + self.fp + self.tn + self.fn

    @property
    def actual_positives(self) -> int:
        """Ground truth positive count (TP + FN)."""
        return self.tp + self.fn

    @property
    def actual_negatives(self) -> int:
        """Ground truth negative count (FP + TN)."""
        return self.fp + self.tn

    @property
    def predicted_positives(self) -> int:
        """Detector positive trigger count (TP + FP)."""
        return self.tp + self.fp

    @property
    def predicted_negatives(self) -> int:
        """Detector negative silence count (TN + FN)."""
        return self.tn + self.fn


class RuleEvaluationMetrics(BaseModel):
    """Calculated efficacy metrics for a single detection rule."""

    model_config = ConfigDict(extra="forbid")

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

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    rule_title: str
    issue: str
    severity: str  # "HIGH", "MEDIUM", "LOW"
    description: str
    suggested_actions: list[str] = Field(default_factory=list)
    sample_fp_events: list[dict[str, Any]] = Field(default_factory=list)


class EvaluationReport(BaseModel):
    """Global evaluation benchmark summary containing aggregated and per-rule metrics."""

    model_config = ConfigDict(extra="forbid")

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
    overall_accuracy: float = 0.0
    rule_metrics: dict[str, RuleEvaluationMetrics] = Field(default_factory=dict)
    tuning_recommendations: list[TuningRecommendation] = Field(default_factory=list)
    passed_quality_gates: bool = True

    def to_markdown(self) -> str:
        """Format an evaluation report into a human-readable Markdown summary."""
        gate_status = "PASSED" if self.passed_quality_gates else "FAILED"
        lines = [
            "# WinSentinel Detection Evaluation Report",
            "",
            f"- **Dataset:** {self.dataset_name}",
            f"- **Timestamp:** {self.timestamp.isoformat()}",
            f"- **Quality Gate:** {gate_status}",
            f"- **Total Events:** {self.total_events} (Malicious: {self.malicious_events}, Benign: {self.benign_events})",
            f"- **Rules Evaluated:** {self.total_rules_evaluated}",
            "",
            "## Overall Detection Performance",
            "",
            "| Metric | Value |",
            "| :--- | :--- |",
            f"| **Precision** | {self.overall_precision:.2%} |",
            f"| **Recall** | {self.overall_recall:.2%} |",
            f"| **F1-Score** | {self.overall_f1_score:.2%} |",
            f"| **False Positive Rate (FPR)** | {self.overall_fpr:.2%} |",
            f"| **Accuracy** | {self.overall_accuracy:.2%} |",
            "",
            "### Confusion Matrix",
            "",
            "| Classification | Count |",
            "| :--- | :--- |",
            f"| True Positives (TP) | {self.overall_matrix.tp} |",
            f"| False Positives (FP) | {self.overall_matrix.fp} |",
            f"| True Negatives (TN) | {self.overall_matrix.tn} |",
            f"| False Negatives (FN) | {self.overall_matrix.fn} |",
            "",
            "## Per-Rule Breakdown",
            "",
            "| Rule ID | Title | Severity | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        if not self.rule_metrics:
            lines.append("| - | *No rules evaluated* | - | - | - | - | - | - | - | - | - | - |")
        else:
            for rid, rm in sorted(self.rule_metrics.items()):
                status = "ACTIVE"
                if rm.is_dead:
                    status = "DEAD"
                elif rm.is_noisy:
                    status = "NOISY"

                lines.append(
                    f"| `{rm.rule_id}` | {rm.rule_title} | {rm.severity.upper()} | "
                    f"{rm.matrix.tp} | {rm.matrix.fp} | {rm.matrix.tn} | {rm.matrix.fn} | "
                    f"{rm.precision:.2%} | {rm.recall:.2%} | {rm.f1_score:.2%} | {rm.false_positive_rate:.2%} | {status} |"
                )

        lines.append("")
        lines.append("## Tuning Recommendations")
        lines.append("")
        if not self.tuning_recommendations:
            lines.append("No tuning recommendations. All evaluated rules conform to detection thresholds.")
        else:
            for rec in self.tuning_recommendations:
                lines.append(f"### `{rec.rule_id}` - {rec.rule_title} [{rec.severity.upper()}]")
                lines.append(f"- **Issue:** {rec.issue}")
                lines.append(f"- **Description:** {rec.description}")
                if rec.suggested_actions:
                    lines.append("- **Suggested Actions:**")
                    for action in rec.suggested_actions:
                        lines.append(f"  - {action}")
                lines.append("")

        return "\n".join(lines)
