"""Detection Evaluation and benchmark presentation service for WinSentinel UI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.detection.loader import RuleLoader
from app.evaluation.runner import EvaluationRunner
from app.models.evaluation import EvaluationReport


class EvaluationUIService:
    """Powers detection rule benchmarking, confusion matrices, and tuning guidance."""

    def __init__(
        self,
        rules_dir: Path | str | None = None,
        datasets_dir: Path | str | None = None,
    ) -> None:
        self.rules_dir = Path(rules_dir) if rules_dir else Path("rules/sysmon")
        self.datasets_dir = Path(datasets_dir) if datasets_dir else Path("tests/data/benchmarks")
        self.loader = RuleLoader()

    def get_available_datasets(self) -> list[str]:
        """List available benchmark dataset filenames/stems in datasets directory."""
        if not self.datasets_dir.exists() or not self.datasets_dir.is_dir():
            return ["attacks", "benign_admin_noise"]

        found = []
        for p in self.datasets_dir.glob("*.jsonl"):
            found.append(p.stem)
        return sorted(found) if found else ["attacks", "benign_admin_noise"]

    def run_benchmark(
        self,
        dataset_name: str = "attacks",
        fpr_threshold: float = 0.05,
        precision_threshold: float = 0.80,
    ) -> EvaluationReport:
        """Execute detection rules against the specified benchmark dataset.

        Args:
            dataset_name: Name or stem of dataset (e.g. 'attacks' or 'benign_admin_noise').
            fpr_threshold: Maximum allowable false positive rate before tuning warning.
            precision_threshold: Minimum allowable precision before tuning warning.

        Returns:
            Completed EvaluationReport containing overall and per-rule metrics.
        """
        # Resolve dataset path
        ds_path = self.datasets_dir / f"{dataset_name}.jsonl"
        if not ds_path.exists():
            ds_path = Path(dataset_name)
            if not ds_path.exists():
                raise FileNotFoundError(f"Benchmark dataset not found: {dataset_name} at {ds_path}")

        rules = self.loader.load_rules_from_directory(self.rules_dir, recursive=True, strict=False)
        runner = EvaluationRunner(rules=rules)
        return runner.run_evaluation(
            dataset=ds_path,
            dataset_name=dataset_name,
            fpr_threshold=fpr_threshold,
            precision_threshold=precision_threshold,
        )

    def format_metrics_table(self, report: EvaluationReport) -> list[dict[str, Any]]:
        """Format per-rule performance metrics into structured dictionaries for UI tables."""
        rows: list[dict[str, Any]] = []

        for rule_id, metric in report.rule_metrics.items():
            if metric.is_dead:
                status = "Dead"
            elif metric.is_noisy:
                status = "Noisy"
            elif metric.precision >= 0.80 and metric.false_positive_rate <= 0.05:
                status = "Healthy"
            else:
                status = "Warning"

            rows.append({
                "rule_id": metric.rule_id,
                "rule_title": metric.rule_title,
                "severity": metric.severity,
                "tp": metric.matrix.tp,
                "fp": metric.matrix.fp,
                "fn": metric.matrix.fn,
                "precision": metric.precision,
                "recall": metric.recall,
                "f1_score": metric.f1_score,
                "fpr": metric.false_positive_rate,
                "status": status,
            })

        rows.sort(key=lambda r: (r["status"] != "Healthy", -r["fp"], r["rule_id"]))
        return rows

    def get_tuning_recommendations(self, report: EvaluationReport) -> list[dict[str, Any]]:
        """Extract and format actionable tuning recommendations from an evaluation report."""
        recs: list[dict[str, Any]] = []

        for rec in report.tuning_recommendations:
            recs.append({
                "rule_id": rec.rule_id,
                "rule_title": rec.rule_title,
                "issue": rec.issue,
                "severity": rec.severity,
                "description": rec.description,
                "suggested_actions": rec.suggested_actions,
                "sample_fp_count": len(rec.sample_fp_events),
            })

        return recs

