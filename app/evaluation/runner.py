"""Benchmark evaluation runner executing detection rules against labeled datasets."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from app.detection.engine import DetectionEngine
from app.detection.loader import RuleLoader
from app.evaluation.loader import load_benchmark_dataset
from app.evaluation.metrics import aggregate_matrices, build_rule_metrics, calculate_metrics
from app.models.evaluation import (
    BenchmarkEvent,
    ConfusionMatrix,
    EvaluationReport,
    RuleEvaluationMetrics,
    TuningRecommendation,
)
from app.models.events import NormalizedEvent
from app.models.rule import DetectionRule


class EvaluationRunner:
    """Executes detection rules against labeled ground-truth datasets.

    Operates purely in-memory without modifying persistent SQLite storage,
    tallying True Positives (TP), False Positives (FP), True Negatives (TN),
    and False Negatives (FN) per rule and globally.
    """

    def __init__(
        self,
        engine: DetectionEngine | None = None,
        rules: Sequence[DetectionRule] | None = None,
    ) -> None:
        self.engine = engine or DetectionEngine()
        if rules:
            self.engine.load_rules(rules)

    def run_evaluation(
        self,
        dataset: Sequence[BenchmarkEvent] | Path | str,
        dataset_name: str = "",
        fpr_threshold: float = 0.05,
        precision_threshold: float = 0.80,
    ) -> EvaluationReport:
        """Run benchmark evaluation over a dataset and generate an EvaluationReport.

        Args:
            dataset: List of BenchmarkEvent instances or path to a JSONL dataset.
            dataset_name: Optional descriptive label for the report.
            fpr_threshold: Maximum acceptable False Positive Rate for tuning checks.
            precision_threshold: Minimum acceptable Precision for tuning checks.

        Returns:
            EvaluationReport containing overall and per-rule confusion matrix metrics.
        """
        # Load dataset if a path is provided
        resolved_name = dataset_name
        if isinstance(dataset, (str, Path)):
            path = Path(dataset)
            if not resolved_name:
                resolved_name = path.stem
            events = load_benchmark_dataset(path)
        else:
            events = list(dataset)
            if not resolved_name:
                resolved_name = "in_memory_benchmark"

        total_events = len(events)
        malicious_events = sum(1 for e in events if e.label.is_malicious)
        benign_events = total_events - malicious_events

        # Initialize matrices and FP sample collectors for each registered rule
        rule_matrices: dict[str, ConfusionMatrix] = {}
        fp_samples: dict[str, list[NormalizedEvent]] = defaultdict(list)

        registered_rules = list(self.engine.rules.values())
        for compiled_rule in registered_rules:
            rule_matrices[compiled_rule.rule.id] = ConfusionMatrix()

        # Evaluate every benchmark event
        for b_event in events:
            event = b_event.event
            label = b_event.label

            # Evaluate against all candidate rules in memory
            matches = self.engine.evaluate_event(event)
            matched_rule_ids = {m.rule_id for m in matches}
            expected_rule_ids = set(label.expected_rules)

            for compiled_rule in registered_rules:
                r_id = compiled_rule.rule.id
                matrix = rule_matrices[r_id]

                is_matched = r_id in matched_rule_ids
                is_expected = r_id in expected_rule_ids

                if is_matched and is_expected:
                    matrix.tp += 1
                elif is_matched and not is_expected:
                    matrix.fp += 1
                    fp_samples[r_id].append(event)
                elif not is_matched and is_expected:
                    matrix.fn += 1
                else:  # not is_matched and not is_expected
                    matrix.tn += 1

        # Calculate per-rule metrics
        rule_metrics: dict[str, RuleEvaluationMetrics] = {}
        for compiled_rule in registered_rules:
            r = compiled_rule.rule
            matrix = rule_matrices[r.id]
            rule_metrics[r.id] = build_rule_metrics(
                rule_id=r.id,
                rule_title=r.title,
                severity=r.severity.value if hasattr(r.severity, "value") else str(r.severity),
                matrix=matrix,
                fpr_threshold=fpr_threshold,
                precision_threshold=precision_threshold,
            )

        # Aggregate overall matrix
        if rule_matrices:
            overall_matrix = aggregate_matrices(list(rule_matrices.values()))
        else:
            overall_matrix = ConfusionMatrix()

        overall_precision, overall_recall, overall_f1, overall_fpr, _ = calculate_metrics(
            overall_matrix
        )

        # Lazy import RuleTuner to avoid circular dependencies
        from app.evaluation.tuner import RuleTuner

        tuner = RuleTuner(max_fpr=fpr_threshold, min_precision=precision_threshold)
        recommendations = tuner.analyze_rules(rule_metrics, fp_samples)

        # Quality gate passes if overall FP is 0 and no noisy rules were detected
        passed_quality_gates = (overall_matrix.fp == 0) and not any(
            rm.is_noisy for rm in rule_metrics.values()
        )

        return EvaluationReport(
            timestamp=datetime.now(timezone.utc),
            dataset_name=resolved_name,
            total_events=total_events,
            malicious_events=malicious_events,
            benign_events=benign_events,
            total_rules_evaluated=len(registered_rules),
            overall_matrix=overall_matrix,
            overall_precision=overall_precision,
            overall_recall=overall_recall,
            overall_f1_score=overall_f1,
            overall_fpr=overall_fpr,
            rule_metrics=rule_metrics,
            tuning_recommendations=recommendations,
            passed_quality_gates=passed_quality_gates,
        )
