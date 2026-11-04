"""Page 8: Detection Evaluation & Benchmarking View."""

from __future__ import annotations

from typing import Any

try:
    import streamlit as st
    HAS_STREAMLIT = True
except ImportError:
    st = None
    HAS_STREAMLIT = False

from app.database.connection import DatabaseManager
from app.ui.components.badges import render_status_pill
from app.ui.components.cards import render_metric_card
from app.ui.components.tables import format_table_html
from app.ui.services.evaluation_ui_service import EvaluationUIService


def render_page(db_manager: DatabaseManager | None = None) -> dict[str, Any]:
    """Render the Detection Evaluation and Benchmarking view."""
    service = EvaluationUIService()
    available_datasets = service.get_available_datasets()

    dataset_choice = available_datasets[0] if available_datasets else "attacks"
    report = None
    table_rows = []
    tuning_recs = []

    if HAS_STREAMLIT and st is not None:
        st.markdown("## 📊 Detection Evaluation & Benchmarking")
        st.caption("Evaluate detection rules against ground-truth labeled attack telemetry and benign administrative noise.")

        col_ds, col_btn = st.columns([2, 1])
        with col_ds:
            dataset_choice = st.selectbox("Select Ground Truth Benchmark Dataset", available_datasets, index=0)
        with col_btn:
            run_btn = st.button("🚀 Run Benchmark Evaluation", type="primary")

        if run_btn or "eval_report" not in st.session_state:
            with st.spinner("Executing detection rules against benchmark dataset..."):
                try:
                    report = service.run_benchmark(dataset_name=dataset_choice)
                    st.session_state["eval_report"] = report
                    st.session_state["eval_dataset"] = dataset_choice
                except Exception as exc:
                    st.error(f"Failed to execute benchmark: {exc}")
        else:
            report = st.session_state.get("eval_report")

    # In headless / test mode if report not yet set, evaluate default dataset
    if report is None:
        try:
            report = service.run_benchmark(dataset_name=dataset_choice)
        except Exception:
            pass

    if report is not None:
        table_rows = service.format_metrics_table(report)
        tuning_recs = service.get_tuning_recommendations(report)

        if HAS_STREAMLIT and st is not None:
            gate_status = "✅ PASSED" if report.passed_quality_gates else "⚠️ FAILED"
            st.markdown(f"### Results for `{report.dataset_name}` ({gate_status})")

            # Overall metric KPI cards
            m1, m2, m3, m4, m5 = st.columns(5)
            with m1:
                st.markdown(render_metric_card("Precision", f"{report.overall_precision:.1%}", "Target >= 80%"), unsafe_allow_html=True)
            with m2:
                st.markdown(render_metric_card("Recall", f"{report.overall_recall:.1%}", "Target >= 80%"), unsafe_allow_html=True)
            with m3:
                st.markdown(render_metric_card("F1-Score", f"{report.overall_f1_score:.1%}"), unsafe_allow_html=True)
            with m4:
                st.markdown(render_metric_card("False Positive Rate", f"{report.overall_fpr:.2%}", "Target <= 5%"), unsafe_allow_html=True)
            with m5:
                st.markdown(render_metric_card("Accuracy", f"{report.overall_accuracy:.1%}"), unsafe_allow_html=True)

            st.write("")
            c_tp, c_fp, c_tn, c_fn = st.columns(4)
            c_tp.metric("True Positives (TP)", report.overall_matrix.tp)
            c_fp.metric("False Positives (FP)", report.overall_matrix.fp)
            c_tn.metric("True Negatives (TN)", report.overall_matrix.tn)
            c_fn.metric("False Negatives (FN)", report.overall_matrix.fn)

            # Per-rule breakdown table
            st.divider()
            st.markdown("### 📋 Per-Rule Detection Performance")
            headers = ["Rule ID", "Rule Title", "Severity", "TP", "FP", "FN", "Precision", "Recall", "F1", "FPR", "Health Status"]
            rows = []
            for r in table_rows:
                status_html = render_status_pill(r["status"])
                rows.append([
                    f"<code>{r['rule_id']}</code>",
                    r["rule_title"],
                    r["severity"],
                    str(r["tp"]),
                    str(r["fp"]),
                    str(r["fn"]),
                    f"{r['precision']:.1%}",
                    f"{r['recall']:.1%}",
                    f"{r['f1_score']:.1%}",
                    f"{r['fpr']:.2%}",
                    status_html,
                ])
            st.markdown(format_table_html(headers, rows), unsafe_allow_html=True)

            # Tuning recommendations
            st.divider()
            st.markdown(f"### 💡 Rule Tuning Recommendations ({len(tuning_recs)})")
            if tuning_recs:
                for rec in tuning_recs:
                    with st.expander(f"⚠️ [{rec['severity']}] {rec['rule_id']}: {rec['issue']} - {rec['rule_title']}"):
                        st.write(rec["description"])
                        if rec["suggested_actions"]:
                            st.markdown("**Suggested Actions:**")
                            for act in rec["suggested_actions"]:
                                st.markdown(f"- {act}")
            else:
                st.success("All active detection rules pass quality gates with optimal precision and zero noisy false positives!")

    return {
        "report": report,
        "table_rows": table_rows,
        "tuning_recs": tuning_recs,
    }

