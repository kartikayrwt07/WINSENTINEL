"""Unit tests for evaluation Pydantic v2 data models."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from app.models.events import EventCategory, NormalizedEvent
from app.models.evaluation import (
    BenchmarkEvent,
    BenchmarkLabel,
    ConfusionMatrix,
    EvaluationReport,
    RuleEvaluationMetrics,
    TuningRecommendation,
)


def make_test_event(event_id: int = 1, command_line: str = "whoami.exe") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        record_id=100,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="ENDPOINT-01",
        timestamp=datetime.now(timezone.utc),
        event_category=EventCategory.PROCESS,
        event_type="ProcessCreate",
        process_guid="{AAAA-BBBB-CCCC-DDDD}",
        process_id=1234,
        image="C:\\Windows\\System32\\whoami.exe",
        command_line=command_line,
        user="CORP\\admin",
        raw_payload="<Event>test</Event>",
        event_hash="hash_123",
    )


def test_benchmark_label_and_event():
    label = BenchmarkLabel(
        is_malicious=True,
        expected_rules=["WS-SYS-006"],
        scenario="whoami_recon",
        description="Reconnaissance command execution",
        mitre_attack=["T1033"],
    )
    event = make_test_event()
    b_event = BenchmarkEvent(event=event, label=label)

    assert b_event.label.is_malicious is True
    assert b_event.label.expected_rules == ["WS-SYS-006"]
    assert b_event.event.command_line == "whoami.exe"

    # Verify immutability (frozen)
    with pytest.raises(ValidationError):
        b_event.label = BenchmarkLabel()  # type: ignore[misc]


def test_confusion_matrix_properties():
    cm = ConfusionMatrix(tp=10, fp=2, tn=80, fn=8)
    assert cm.total == 100
    assert cm.actual_positives == 18  # 10 + 8
    assert cm.actual_negatives == 82  # 2 + 80
    assert cm.predicted_positives == 12  # 10 + 2
    assert cm.predicted_negatives == 88  # 80 + 8


def test_rule_evaluation_metrics_and_report_serialization():
    cm = ConfusionMatrix(tp=10, fp=1, tn=85, fn=4)
    rule_metric = RuleEvaluationMetrics(
        rule_id="WS-SYS-006",
        rule_title="Whoami Reconnaissance",
        severity="medium",
        matrix=cm,
        precision=10 / 11,
        recall=10 / 14,
        f1_score=2 * (10 / 11) * (10 / 14) / ((10 / 11) + (10 / 14)),
        false_positive_rate=1 / 86,
        accuracy=95 / 100,
        is_dead=False,
        is_noisy=False,
    )

    tuning = TuningRecommendation(
        rule_id="WS-SYS-006",
        rule_title="Whoami Reconnaissance",
        issue="LOW_PRECISION",
        severity="MEDIUM",
        description="Minor false positives detected from admin scripts",
        suggested_actions=["Filter out interactive console sessions"],
    )

    report = EvaluationReport(
        dataset_name="attacks_v1",
        total_events=100,
        malicious_events=14,
        benign_events=86,
        total_rules_evaluated=1,
        overall_matrix=cm,
        overall_precision=10 / 11,
        overall_recall=10 / 14,
        overall_f1_score=0.8,
        overall_fpr=1 / 86,
        overall_accuracy=95 / 100,
        rule_metrics={"WS-SYS-006": rule_metric},
        tuning_recommendations=[tuning],
        passed_quality_gates=True,
    )

    # Test Markdown formatting
    md = report.to_markdown()
    assert "# WinSentinel Detection Evaluation Report" in md
    assert "WS-SYS-006" in md
    assert "LOW_PRECISION" in md
    assert "Filter out interactive console sessions" in md

    # Test JSON serialization roundtrip
    json_data = report.model_dump_json()
    deserialized = EvaluationReport.model_validate_json(json_data)
    assert deserialized.dataset_name == "attacks_v1"
    assert deserialized.overall_accuracy == pytest.approx(0.95)
    assert "WS-SYS-006" in deserialized.rule_metrics
    assert deserialized.rule_metrics["WS-SYS-006"].matrix.tp == 10
    assert len(deserialized.tuning_recommendations) == 1
