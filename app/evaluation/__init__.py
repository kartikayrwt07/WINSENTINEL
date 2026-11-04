"""Evaluation engine package for WinSentinel."""

from app.evaluation.loader import load_benchmark_dataset, save_benchmark_dataset
from app.evaluation.metrics import (
    aggregate_matrices,
    build_rule_metrics,
    calculate_metrics,
)
from app.evaluation.runner import EvaluationRunner
from app.evaluation.tuner import RuleTuner
from app.models.evaluation import (
    BenchmarkEvent,
    BenchmarkLabel,
    ConfusionMatrix,
    EvaluationReport,
    RuleEvaluationMetrics,
    TuningIssueType,
    TuningRecommendation,
)

__all__ = [
    "BenchmarkEvent",
    "BenchmarkLabel",
    "ConfusionMatrix",
    "EvaluationReport",
    "EvaluationRunner",
    "RuleEvaluationMetrics",
    "RuleTuner",
    "TuningIssueType",
    "TuningRecommendation",
    "aggregate_matrices",
    "build_rule_metrics",
    "calculate_metrics",
    "load_benchmark_dataset",
    "save_benchmark_dataset",
]
