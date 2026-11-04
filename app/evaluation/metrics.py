"""Pure mathematical confusion matrix calculations and metric synthesis for WinSentinel."""

from __future__ import annotations

from app.models.evaluation import ConfusionMatrix, RuleEvaluationMetrics


def calculate_metrics(matrix: ConfusionMatrix) -> tuple[float, float, float, float, float]:
    """Calculate detection evaluation metrics with safe zero-division handling.

    Returns:
        tuple of (precision, recall, f1_score, false_positive_rate, accuracy)
    """
    tp = matrix.tp
    fp = matrix.fp
    tn = matrix.tn
    fn = matrix.fn
    total = matrix.total

    # Precision: TP / (TP + FP)
    # If no positive predictions were made, precision is 1.0 (no false alarms emitted)
    predicted_positives = tp + fp
    if predicted_positives == 0:
        precision = 1.0
    else:
        precision = tp / predicted_positives

    # Recall: TP / (TP + FN)
    # If no ground-truth positives exist, recall is 1.0 (no target missed)
    actual_positives = tp + fn
    if actual_positives == 0:
        recall = 1.0
    else:
        recall = tp / actual_positives

    # F1 Score: 2 * (P * R) / (P + R)
    # If precision + recall is 0, F1 is 0.0
    if precision + recall == 0.0:
        f1_score = 0.0
    else:
        f1_score = 2.0 * (precision * recall) / (precision + recall)

    # False Positive Rate: FP / (FP + TN)
    # If no actual negatives exist, FPR is 0.0
    actual_negatives = fp + tn
    if actual_negatives == 0:
        fpr = 0.0
    else:
        fpr = fp / actual_negatives

    # Accuracy: (TP + TN) / Total
    if total == 0:
        accuracy = 0.0
    else:
        accuracy = (tp + tn) / total

    return precision, recall, f1_score, fpr, accuracy


def build_rule_metrics(
    rule_id: str,
    rule_title: str,
    severity: str,
    matrix: ConfusionMatrix,
    fpr_threshold: float = 0.05,
    precision_threshold: float = 0.80,
) -> RuleEvaluationMetrics:
    """Build a RuleEvaluationMetrics model for a specific detection rule.

    Calculates metrics and evaluates whether the rule is dead (zero matches across corpus)
    or noisy (FPR > threshold or poor precision).
    """
    precision, recall, f1, fpr, accuracy = calculate_metrics(matrix)

    # A rule is dead if it had 0 true positives and 0 false positives
    is_dead = (matrix.tp == 0) and (matrix.fp == 0)

    # A rule is noisy if its FPR exceeds the threshold, or if it triggered detections
    # but its precision is lower than the precision threshold
    is_noisy = (fpr > fpr_threshold) or (
        (matrix.tp + matrix.fp > 0) and (precision < precision_threshold)
    )

    return RuleEvaluationMetrics(
        rule_id=rule_id,
        rule_title=rule_title,
        severity=severity,
        matrix=matrix,
        precision=precision,
        recall=recall,
        f1_score=f1,
        false_positive_rate=fpr,
        accuracy=accuracy,
        is_dead=is_dead,
        is_noisy=is_noisy,
    )


def aggregate_matrices(matrices: list[ConfusionMatrix]) -> ConfusionMatrix:
    """Sum multiple ConfusionMatrix instances into a single aggregated matrix."""
    total_tp = sum(m.tp for m in matrices)
    total_fp = sum(m.fp for m in matrices)
    total_tn = sum(m.tn for m in matrices)
    total_fn = sum(m.fn for m in matrices)

    return ConfusionMatrix(
        tp=total_tp,
        fp=total_fp,
        tn=total_tn,
        fn=total_fn,
    )


def calculate_overall_metrics(
    rule_metrics_or_matrices: dict[str, RuleEvaluationMetrics] | list[ConfusionMatrix],
) -> tuple[ConfusionMatrix, float, float, float, float, float]:
    """Aggregate per-rule metrics or matrices and calculate global efficacy metrics.

    Returns:
        tuple of (overall_matrix, precision, recall, f1_score, fpr, accuracy)
    """
    if isinstance(rule_metrics_or_matrices, dict):
        matrices = [rm.matrix for rm in rule_metrics_or_matrices.values()]
    else:
        matrices = rule_metrics_or_matrices

    overall_matrix = aggregate_matrices(matrices)
    precision, recall, f1, fpr, accuracy = calculate_metrics(overall_matrix)

    return overall_matrix, precision, recall, f1, fpr, accuracy

