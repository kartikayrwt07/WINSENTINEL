"""Rule health analysis and automated tuning recommendation engine."""

from __future__ import annotations

from collections import Counter
from typing import Any

from app.models.evaluation import RuleEvaluationMetrics, TuningRecommendation
from app.models.events import NormalizedEvent


class RuleTuner:
    """Heuristic analyzer diagnosing dead or noisy detection rules.

    Analyzes per-rule confusion matrix metrics to detect zero-coverage rules,
    rules prone to alert fatigue (FPR > max_fpr or precision < min_precision),
    and synthesizes candidate suppression filters based on recurring attributes
    in false-positive event samples.
    """

    def __init__(
        self,
        max_fpr: float = 0.05,
        min_precision: float = 0.80,
    ) -> None:
        self.max_fpr = max_fpr
        self.min_precision = min_precision

    def analyze_rules(
        self,
        rule_metrics: dict[str, RuleEvaluationMetrics],
        fp_samples: dict[str, list[NormalizedEvent]] | None = None,
    ) -> list[TuningRecommendation]:
        """Analyze calculated rule metrics and produce actionable tuning advice.

        Args:
            rule_metrics: Mapping of rule_id to calculated RuleEvaluationMetrics.
            fp_samples: Optional mapping of rule_id to list of false positive events.

        Returns:
            List of TuningRecommendation instances.
        """
        recommendations: list[TuningRecommendation] = []
        samples_by_rule = fp_samples or {}

        for rule_id, metric in rule_metrics.items():
            # 1. Dead Rule / Zero Coverage Check
            if metric.is_dead:
                recommendations.append(
                    TuningRecommendation(
                        rule_id=rule_id,
                        rule_title=metric.rule_title,
                        issue="ZERO_COVERAGE",
                        severity="MEDIUM",
                        description=(
                            f"Rule '{metric.rule_title}' ({metric.rule_id}) produced zero matches across the dataset."
                        ),
                        suggested_actions=[
                            "Verify if the evaluation dataset contains representative attack telemetry for this technique.",
                            "Inspect rule condition logic and selection field names for syntax discrepancies.",
                        ],
                    )
                )

            # 2. High False Positive Rate Check
            elif metric.false_positive_rate > self.max_fpr:
                fp_list = samples_by_rule.get(rule_id, [])
                suggested_filters, sample_dicts = self._synthesize_suppressions(fp_list)

                actions = [
                    f"Current FPR is {metric.false_positive_rate:.2%}, exceeding maximum threshold of {self.max_fpr:.2%}.",
                    "Add exclusion filter blocks targeting benign administrative parent processes, users, or paths.",
                ]
                actions.extend(suggested_filters)

                recommendations.append(
                    TuningRecommendation(
                        rule_id=rule_id,
                        rule_title=metric.rule_title,
                        issue="HIGH_FALSE_POSITIVE_RATE",
                        severity="HIGH",
                        description=(
                            f"Rule '{metric.rule_title}' exhibits a high false-positive rate "
                            f"({metric.false_positive_rate:.2%}) risking alert fatigue."
                        ),
                        suggested_actions=actions,
                        sample_fp_events=sample_dicts,
                    )
                )

            # 3. Low Precision Check (triggers alerts but mostly false positives)
            elif (
                (metric.matrix.tp + metric.matrix.fp > 0)
                and metric.precision < self.min_precision
            ):
                fp_list = samples_by_rule.get(rule_id, [])
                suggested_filters, sample_dicts = self._synthesize_suppressions(fp_list)

                actions = [
                    f"Current Precision is {metric.precision:.2%}, below minimum threshold of {self.min_precision:.2%}.",
                    "Refine selection conditions to make matching criteria more specific.",
                ]
                actions.extend(suggested_filters)

                recommendations.append(
                    TuningRecommendation(
                        rule_id=rule_id,
                        rule_title=metric.rule_title,
                        issue="LOW_PRECISION",
                        severity="HIGH",
                        description=(
                            f"Rule '{metric.rule_title}' has low precision ({metric.precision:.2%}); "
                            "the majority of emitted detections are false alarms."
                        ),
                        suggested_actions=actions,
                        sample_fp_events=sample_dicts,
                    )
                )

        return recommendations

    def _synthesize_suppressions(
        self,
        fp_events: list[NormalizedEvent],
    ) -> tuple[list[str], list[dict[str, Any]]]:
        """Analyze false-positive events to identify recurring attributes for suppression."""
        if not fp_events:
            return [], []

        total_fp = len(fp_events)
        sample_dicts = [
            {
                "event_id": e.event_id,
                "image": e.image,
                "command_line": e.command_line,
                "parent_image": e.parent_image,
                "user": e.user,
            }
            for e in fp_events[:5]  # Cap samples at 5
        ]

        parent_images = Counter(e.parent_image for e in fp_events if e.parent_image)
        users = Counter(e.user for e in fp_events if e.user)
        images = Counter(e.image for e in fp_events if e.image)

        suggestions: list[str] = []

        # If a parent image appears in >= 40% of FP events, suggest filtering it
        for parent_img, count in parent_images.most_common(2):
            if count / total_fp >= 0.40:
                suggestions.append(
                    f"Consider adding exclusion: filter_parent: parent_image: '{parent_img}' "
                    f"({count}/{total_fp} FP events)"
                )

        # If a specific user account appears in >= 50% of FP events
        for user, count in users.most_common(1):
            if count / total_fp >= 0.50:
                suggestions.append(
                    f"Consider adding exclusion: filter_user: user: '{user}' "
                    f"({count}/{total_fp} FP events)"
                )

        # If a specific actor image appears in >= 50% of FP events
        for img, count in images.most_common(1):
            if count / total_fp >= 0.50:
                suggestions.append(
                    f"Consider adding exclusion: filter_image: image: '{img}' "
                    f"({count}/{total_fp} FP events)"
                )

        return suggestions, sample_dicts
