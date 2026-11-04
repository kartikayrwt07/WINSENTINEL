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
    rule_metrics: dict[str, RuleEvaluationMetrics] = Field(default_factory=dict)
    tuning_recommendations: list[TuningRecommendation] = Field(default_factory=list)
    passed_quality_gates: bool = True
