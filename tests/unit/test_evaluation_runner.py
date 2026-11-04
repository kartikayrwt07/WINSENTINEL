"""Unit tests for the EvaluationRunner."""

from datetime import datetime, timezone
from pathlib import Path
import pytest

from app.detection.engine import DetectionEngine
from app.detection.loader import RuleLoader
from app.evaluation.runner import EvaluationRunner
from app.models.evaluation import BenchmarkEvent, BenchmarkLabel
from app.models.events import EventCategory, NormalizedEvent


def make_test_event(image: str, command_line: str, event_id: int = 1) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        record_id=1,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="TEST-HOST",
        timestamp=datetime.now(timezone.utc),
        event_category=EventCategory.PROCESS,
        event_type="ProcessCreate",
        image=image,
        command_line=command_line,
        user="CORP\\test",
        raw_payload="<Event/>",
        event_hash="test_hash",
    )


def test_evaluation_runner_basic():
    # Load Sysmon rules
    loader = RuleLoader()
    rules = loader.load_rules_from_directory("rules/sysmon")
    runner = EvaluationRunner(rules=rules)

    # 1 expected whoami reconnaissance match (TP for WS-SYS-006, TN for all others)
    ev1 = make_test_event("C:\\Windows\\System32\\whoami.exe", "whoami.exe /priv")
    b1 = BenchmarkEvent(
        event=ev1,
        label=BenchmarkLabel(
            is_malicious=True,
            expected_rules=["WS-SYS-006"],
            scenario="whoami_test",
        ),
    )

    # 1 benign event that should match nothing (TN for all rules)
    ev2 = make_test_event("C:\\Windows\\System32\\notepad.exe", "notepad.exe text.txt")
    b2 = BenchmarkEvent(
        event=ev2,
        label=BenchmarkLabel(
            is_malicious=False,
            expected_rules=[],
            scenario="benign_test",
        ),
    )

    report = runner.run_evaluation([b1, b2], dataset_name="unit_test_dataset")

    assert report.total_events == 2
    assert report.malicious_events == 1
    assert report.benign_events == 1
    assert report.total_rules_evaluated == len(rules)

    # Check WS-SYS-006 metrics
    m6 = report.rule_metrics["WS-SYS-006"]
    assert m6.matrix.tp == 1
    assert m6.matrix.fp == 0
    assert m6.matrix.fn == 0
    assert m6.matrix.tn == 1
    assert m6.precision == 1.0
    assert m6.recall == 1.0
    assert m6.false_positive_rate == 0.0

    # Overall false positives should be 0
    assert report.overall_matrix.fp == 0
    assert report.overall_fpr == 0.0
    assert report.passed_quality_gates is True


def test_evaluation_runner_with_false_positive():
    loader = RuleLoader()
    rules = loader.load_rules_from_directory("rules/sysmon")
    runner = EvaluationRunner(rules=rules)

    # An event that matches whoami (WS-SYS-006), but label marked as benign (FP for WS-SYS-006)
    ev = make_test_event("C:\\Windows\\System32\\whoami.exe", "whoami.exe /all")
    b_fp = BenchmarkEvent(
        event=ev,
        label=BenchmarkLabel(
            is_malicious=False,
            expected_rules=[],  # We expected nothing!
            scenario="unexpected_recon",
        ),
    )

    report = runner.run_evaluation([b_fp], dataset_name="fp_test")
    m6 = report.rule_metrics["WS-SYS-006"]
    assert m6.matrix.fp == 1
    assert m6.matrix.tp == 0
    assert report.overall_matrix.fp == 1
    assert report.passed_quality_gates is False
    assert len(report.tuning_recommendations) >= 1
