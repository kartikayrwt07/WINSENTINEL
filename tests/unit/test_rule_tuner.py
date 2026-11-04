"""Unit tests for the RuleTuner diagnostic and suppression synthesis engine."""

from datetime import datetime, timezone
import pytest

from app.evaluation.tuner import RuleTuner
from app.models.evaluation import ConfusionMatrix, RuleEvaluationMetrics
from app.models.events import EventCategory, NormalizedEvent


def make_test_event(
    image: str = "C:\\Windows\\System32\\cmd.exe",
    parent_image: str | None = None,
    user: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=1,
        record_id=1,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="ENDPOINT-01",
        timestamp=datetime.now(timezone.utc),
        event_category=EventCategory.PROCESS,
        event_type="ProcessCreate",
        image=image,
        parent_image=parent_image,
        user=user,
        raw_payload="<Event/>",
        event_hash="hash",
    )


def test_tuner_detects_dead_rule():
    tuner = RuleTuner()
    # 0 TP, 0 FP, 50 TN, 5 FN -> Dead rule
    cm = ConfusionMatrix(tp=0, fp=0, tn=50, fn=5)
    rule_metric = RuleEvaluationMetrics(
        rule_id="WS-SYS-001",
        rule_title="Certutil Download",
        severity="high",
        matrix=cm,
        precision=1.0,
        recall=0.0,
        f1_score=0.0,
        false_positive_rate=0.0,
        accuracy=50 / 55,
        is_dead=True,
        is_noisy=False,
    )

    recommendations = tuner.analyze_rules({"WS-SYS-001": rule_metric})
    assert len(recommendations) == 1
    assert recommendations[0].issue == "ZERO_COVERAGE"
    assert recommendations[0].severity == "MEDIUM"
    assert "WS-SYS-001" in recommendations[0].description


def test_tuner_detects_high_fpr_and_suggests_suppression():
    tuner = RuleTuner(max_fpr=0.05)
    # 10 TP, 20 FP, 60 TN, 0 FN -> FPR = 20/80 = 25% (> 5%)
    cm = ConfusionMatrix(tp=10, fp=20, tn=60, fn=0)
    rule_metric = RuleEvaluationMetrics(
        rule_id="WS-SYS-006",
        rule_title="Whoami Recon",
        severity="medium",
        matrix=cm,
        precision=10 / 30,
        recall=1.0,
        f1_score=0.5,
        false_positive_rate=20 / 80,
        accuracy=70 / 90,
        is_dead=False,
        is_noisy=True,
    )

    # 15 of the 20 FP events have parent_image = C:\Windows\CCM\CcmExec.exe
    fp_events = [
        make_test_event(
            parent_image="C:\\Windows\\CCM\\CcmExec.exe",
            user="NT AUTHORITY\\SYSTEM",
        )
        for _ in range(15)
    ]
    # 5 have unrelated parent
    fp_events.extend([make_test_event(parent_image="C:\\Windows\\explorer.exe") for _ in range(5)])

    recommendations = tuner.analyze_rules(
        {"WS-SYS-006": rule_metric},
        fp_samples={"WS-SYS-006": fp_events},
    )

    assert len(recommendations) == 1
    rec = recommendations[0]
    assert rec.issue == "HIGH_FALSE_POSITIVE_RATE"
    assert rec.severity == "HIGH"

    # Check that suppression suggestion was generated for CcmExec.exe
    suggested = " ".join(rec.suggested_actions)
    assert "CcmExec.exe" in suggested
    assert len(rec.sample_fp_events) > 0


def test_tuner_detects_low_precision():
    tuner = RuleTuner(max_fpr=0.20, min_precision=0.80)
    # 2 TP, 5 FP, 90 TN, 1 FN -> Precision = 2/7 = 28.5% (< 80%), FPR = 5/95 = 5.2% (<= 20%)
    cm = ConfusionMatrix(tp=2, fp=5, tn=90, fn=1)
    rule_metric = RuleEvaluationMetrics(
        rule_id="WS-SYS-010",
        rule_title="LSASS Access",
        severity="high",
        matrix=cm,
        precision=2 / 7,
        recall=2 / 3,
        f1_score=0.4,
        false_positive_rate=5 / 95,
        accuracy=92 / 98,
        is_dead=False,
        is_noisy=True,
    )

    recommendations = tuner.analyze_rules({"WS-SYS-010": rule_metric})
    assert len(recommendations) == 1
    assert recommendations[0].issue == "LOW_PRECISION"
