"""Command-line interface for WinSentinel rule benchmark evaluation."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from app.detection.loader import RuleLoader
from app.evaluation.runner import EvaluationRunner
from app.models.evaluation import EvaluationReport


def format_markdown_report(report: EvaluationReport) -> str:
    """Format an EvaluationReport as a clean GitHub Flavored Markdown document."""
    lines: list[str] = [
        f"# WinSentinel Detection Evaluation Report: {report.dataset_name}",
        "",
        f"**Generated:** {report.timestamp.isoformat()}  ",
        f"**Quality Gates:** {'PASSED' if report.passed_quality_gates else 'FAILED'}  ",
        "",
        "## Overall Summary",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Total Events | {report.total_events} |",
        f"| Malicious Events | {report.malicious_events} |",
        f"| Benign Events | {report.benign_events} |",
        f"| Evaluated Rules | {report.total_rules_evaluated} |",
        f"| Overall True Positives (TP) | {report.overall_matrix.tp} |",
        f"| Overall False Positives (FP) | {report.overall_matrix.fp} |",
        f"| Overall True Negatives (TN) | {report.overall_matrix.tn} |",
        f"| Overall False Negatives (FN) | {report.overall_matrix.fn} |",
        f"| Overall Precision | {report.overall_precision:.2%} |",
        f"| Overall Recall | {report.overall_recall:.2%} |",
        f"| Overall F1-Score | {report.overall_f1_score:.2%} |",
        f"| Overall False Positive Rate (FPR) | {report.overall_fpr:.2%} |",
        "",
        "## Per-Rule Breakdown",
        "",
        "| Rule ID | Rule Title | Severity | TP | FP | TN | FN | Precision | Recall | F1 | FPR | Status |",
        "|---------|------------|----------|----|----|----|----|-----------|--------|----|-----|--------|",
    ]

    for rule_id, rm in sorted(report.rule_metrics.items()):
        status = "HEALTHY"
        if rm.is_dead:
            status = "DEAD"
        elif rm.is_noisy:
            status = "NOISY"

        lines.append(
            f"| {rm.rule_id} | {rm.rule_title} | {rm.severity} | "
            f"{rm.matrix.tp} | {rm.matrix.fp} | {rm.matrix.tn} | {rm.matrix.fn} | "
            f"{rm.precision:.1%} | {rm.recall:.1%} | {rm.f1_score:.1%} | {rm.false_positive_rate:.1%} | "
            f"{status} |"
        )

    if report.tuning_recommendations:
        lines.extend([
            "",
            "## Tuning Recommendations",
            "",
        ])
        for rec in report.tuning_recommendations:
            lines.extend([
                f"### [{rec.severity}] {rec.rule_id}: {rec.rule_title} ({rec.issue})",
                "",
                f"{rec.description}",
                "",
                "**Suggested Actions:**",
            ])
            for action in rec.suggested_actions:
                lines.append(f"- {action}")
            lines.append("")

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser for evaluation runner."""
    parser = argparse.ArgumentParser(
        prog="python -m app.evaluation.cli",
        description="WinSentinel Detection Rule Benchmark Evaluation Runner",
    )
    parser.add_argument(
        "--rules",
        "-r",
        default="rules/sysmon",
        help="Directory containing detection rule YAML files (default: rules/sysmon)",
    )
    parser.add_argument(
        "--dataset",
        "-d",
        default="tests/data/benchmarks/attacks.jsonl",
        help="Path to benchmark JSONL dataset file",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output path to save full JSON evaluation report",
    )
    parser.add_argument(
        "--markdown",
        "-m",
        help="Output path to save formatted Markdown report (use '-' for stdout)",
    )
    parser.add_argument(
        "--fail-on-fp",
        action="store_true",
        help="Exit with non-zero code if any false positives are detected",
    )
    parser.add_argument(
        "--min-f1",
        type=float,
        default=0.0,
        help="Minimum required overall F1 score (0.0 to 1.0)",
    )
    parser.add_argument(
        "--min-precision",
        type=float,
        default=0.0,
        help="Minimum required overall precision (0.0 to 1.0)",
    )
    parser.add_argument(
        "--min-recall",
        type=float,
        default=0.0,
        help="Minimum required overall recall (0.0 to 1.0)",
    )
    return parser


def main(args: list[str] | None = None) -> int:
    """Entry point for the evaluation benchmark CLI."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    rules_dir = Path(parsed_args.rules)
    dataset_path = Path(parsed_args.dataset)

    if not rules_dir.is_dir():
        print(f"Error: Rules directory not found: {rules_dir}", file=sys.stderr)
        return 2

    if not dataset_path.is_file():
        print(f"Error: Dataset file not found: {dataset_path}", file=sys.stderr)
        return 2

    # Load rules and run evaluation
    loader = RuleLoader()
    rules = loader.load_rules_from_directory(rules_dir)
    runner = EvaluationRunner(rules=rules)

    report = runner.run_evaluation(dataset_path)

    # Print summary to console
    print(f"\nEvaluation Complete: {report.dataset_name}")
    print(f"Events: {report.total_events} (Malicious: {report.malicious_events}, Benign: {report.benign_events})")
    print(f"Rules: {report.total_rules_evaluated}")
    print(f"Overall Matrix: TP={report.overall_matrix.tp}, FP={report.overall_matrix.fp}, TN={report.overall_matrix.tn}, FN={report.overall_matrix.fn}")
    print(f"Overall Metrics: Precision={report.overall_precision:.2%}, Recall={report.overall_recall:.2%}, F1={report.overall_f1_score:.2%}, FPR={report.overall_fpr:.2%}")
    print(f"Quality Gates: {'PASSED' if report.passed_quality_gates else 'FAILED'}")

    # Output JSON report if requested
    if parsed_args.output:
        out_path = Path(parsed_args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        print(f"JSON report written to: {out_path}")

    # Output Markdown report if requested
    if parsed_args.markdown:
        md_text = format_markdown_report(report)
        if parsed_args.markdown == "-":
            print("\n" + md_text)
        else:
            md_path = Path(parsed_args.markdown)
            md_path.parent.mkdir(parents=True, exist_ok=True)
            md_path.write_text(md_text, encoding="utf-8")
            print(f"Markdown report written to: {md_path}")

    # Check failure conditions
    if parsed_args.fail_on_fp and report.overall_matrix.fp > 0:
        print(f"Gate Failure: Detected {report.overall_matrix.fp} false positives (--fail-on-fp specified)", file=sys.stderr)
        return 1

    if report.overall_f1_score < parsed_args.min_f1:
        print(f"Gate Failure: Overall F1 score ({report.overall_f1_score:.2%}) is below threshold ({parsed_args.min_f1:.2%})", file=sys.stderr)
        return 1

    if report.overall_precision < parsed_args.min_precision:
        print(f"Gate Failure: Overall precision ({report.overall_precision:.2%}) is below threshold ({parsed_args.min_precision:.2%})", file=sys.stderr)
        return 1

    if report.overall_recall < parsed_args.min_recall:
        print(f"Gate Failure: Overall recall ({report.overall_recall:.2%}) is below threshold ({parsed_args.min_recall:.2%})", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

