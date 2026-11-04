"""Unit tests for ConfusionMatrix calculations and edge cases."""

import pytest

from app.evaluation.metrics import (
    aggregate_matrices,
    build_rule_metrics,
    calculate_metrics,
    calculate_overall_metrics,
)
from app.models.evaluation import ConfusionMatrix, RuleEvaluationMetrics


def test_calculate_metrics_standard():
    # 20 TP, 5 FP, 70 TN, 5 FN (total 100)
    cm = ConfusionMatrix(tp=20, fp=5, tn=70, fn=5)
    precision, recall, f1, fpr, accuracy = calculate_metrics(cm)

    # Precision = 20 / 25 = 0.8
    assert precision == pytest.approx(0.8)
    # Recall = 20 / 25 = 0.8
    assert recall == pytest.approx(0.8)
    # F1 = 2 * (0.8 * 0.8) / 1.6 = 0.8
    assert f1 == pytest.approx(0.8)
    # FPR = 5 / 75 = 0.06666...
    assert fpr == pytest.approx(5 / 75)
    # Accuracy = 90 / 100 = 0.9
    assert accuracy == pytest.approx(0.9)


def test_calculate_metrics_perfect():
    # Perfect detection: 50 TP, 0 FP, 50 TN, 0 FN
    cm = ConfusionMatrix(tp=50, fp=0, tn=50, fn=0)
    precision, recall, f1, fpr, accuracy = calculate_metrics(cm)

    assert precision == 1.0
    assert recall == 1.0
    assert f1 == 1.0
    assert fpr == 0.0
    assert accuracy == 1.0


def test_calculate_metrics_zero_total():
    # Completely empty matrix
    cm = ConfusionMatrix(tp=0, fp=0, tn=0, fn=0)
    precision, recall, f1, fpr, accuracy = calculate_metrics(cm)

    assert precision == 1.0
    assert recall == 1.0
    assert f1 == 1.0  # 2 * (1.0 * 1.0) / 2.0 = 1.0
    assert fpr == 0.0
    assert accuracy == 0.0


def test_calculate_metrics_all_false_negatives():
    # 0 TP, 0 FP, 10 TN, 10 FN
    cm = ConfusionMatrix(tp=0, fp=0, tn=10, fn=10)
    precision, recall, f1, fpr, accuracy = calculate_metrics(cm)

    assert precision == 1.0  # No false alarms
    assert recall == 0.0  # Missed all positives
    assert f1 == 0.0
    assert fpr == 0.0
    assert accuracy == 0.5


def test_calculate_metrics_all_false_positives():
    # 0 TP, 10 FP, 10 TN, 0 FN
    cm = ConfusionMatrix(tp=0, fp=10, tn=10, fn=0)
    precision, recall, f1, fpr, accuracy = calculate_metrics(cm)

    assert precision == 0.0
    assert recall == 1.0  # No ground truth positives missed
    assert f1 == 0.0
    assert fpr == 10 / 20  # 0.5
    assert accuracy == 0.5


def test_build_rule_metrics_dead_rule():
    # Dead rule: 0 TP, 0 FP, 100 TN, 10 FN
    cm = ConfusionMatrix(tp=0, fp=0, tn=100, fn=10)
    metrics = build_rule_metrics(
        rule_id="WS-SYS-001",
        rule_title="Certutil Download",
        severity="high",
        matrix=cm,
    )
    assert metrics.is_dead is True
    assert metrics.is_noisy is False


def test_build_rule_metrics_noisy_rule():
    # Noisy rule: 5 TP, 20 FP, 70 TN, 5 FN
    # FPR = 20 / 90 = 0.222 (> 0.05)
    # Precision = 5 / 25 = 0.2 (< 0.8)
    cm = ConfusionMatrix(tp=5, fp=20, tn=70, fn=5)
    metrics = build_rule_metrics(
        rule_id="WS-SYS-006",
        rule_title="Whoami Recon",
        severity="medium",
        matrix=cm,
        fpr_threshold=0.05,
        precision_threshold=0.80,
    )
    assert metrics.is_dead is False
    assert metrics.is_noisy is True


def test_aggregate_matrices():
    cm1 = ConfusionMatrix(tp=10, fp=2, tn=30, fn=3)
    cm2 = ConfusionMatrix(tp=5, fp=1, tn=40, fn=1)
    cm3 = ConfusionMatrix(tp=0, fp=0, tn=50, fn=0)

    agg = aggregate_matrices([cm1, cm2, cm3])
    assert agg.tp == 15
    assert agg.fp == 3
    assert agg.tn == 120
    assert agg.fn == 4
    assert agg.total == 142


def test_calculate_overall_metrics():
    cm1 = ConfusionMatrix(tp=10, fp=2, tn=80, fn=8)
    cm2 = ConfusionMatrix(tp=20, fp=3, tn=70, fn=7)

    rm1 = build_rule_metrics("R1", "Rule 1", "high", cm1)
    rm2 = build_rule_metrics("R2", "Rule 2", "medium", cm2)

    overall_cm, precision, recall, f1, fpr, accuracy = calculate_overall_metrics(
        {"R1": rm1, "R2": rm2}
    )

    assert overall_cm.tp == 30
    assert overall_cm.fp == 5
    assert overall_cm.tn == 150
    assert overall_cm.fn == 15
    assert overall_cm.total == 200

    # Precision: 30 / 35
    assert precision == pytest.approx(30 / 35)
    # Recall: 30 / 45
    assert recall == pytest.approx(30 / 45)
    # FPR: 5 / 155
    assert fpr == pytest.approx(5 / 155)
    # Accuracy: 180 / 200 = 0.9
    assert accuracy == pytest.approx(0.9)

