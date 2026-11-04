"""Unit tests for EvaluationUIService."""

from pathlib import Path
import pytest

from app.models.evaluation import ConfusionMatrix, EvaluationReport, RuleEvaluationMetrics
from app.ui.services.evaluation_ui_service import EvaluationUIService


def test_evaluation_ui_service_get_available_datasets():
    service = EvaluationUIService()
    datasets = service.get_available_datasets()
    assert len(datasets) >= 2
    assert "attacks" in datasets or "benign_admin_noise" in datasets


def test_evaluation_ui_service_run_and_format():
    service = EvaluationUIService(
        rules_dir="rules/sysmon",
        datasets_dir="tests/data/benchmarks",
    )
    # Run evaluation on benign admin noise (very fast, 0 FPs)
    report = service.run_benchmark(dataset_name="benign_admin_noise")

    assert report.total_events > 0
    assert report.overall_matrix.fp == 0
    assert report.passed_quality_gates is True

    # Test format_metrics_table
    table = service.format_metrics_table(report)
    assert len(table) > 0
    first_row = table[0]
    assert "rule_id" in first_row
    assert "precision" in first_row
    assert "status" in first_row

    # Test get_tuning_recommendations
    recs = service.get_tuning_recommendations(report)
    assert isinstance(recs, list)

