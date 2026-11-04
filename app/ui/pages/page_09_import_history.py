"""Page 9: Import History & Audit View."""

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
from app.ui.components.tables import format_table_html
from app.ui.services.import_ui_service import ImportUIService


def render_page(db_manager: DatabaseManager | None = None) -> dict[str, Any]:
    """Render the Import History and Audit log view."""
    service = ImportUIService(db_manager=db_manager)

    jobs, total_count = service.get_import_history(limit=50, offset=0)
    selected_errors = []

    if HAS_STREAMLIT and st is not None:
        st.markdown("## 📥 Ingestion Audit & Import History")
        st.caption("Review event import jobs, parser throughput, deduplication, and malformed record logs.")

        st.markdown(f"**Total Import Jobs Logged: {total_count}**")

        if jobs:
            headers = ["Job ID", "File Name", "Status", "Timestamp", "Total", "Parsed", "Malformed", "Duplicates"]
            rows = []
            for j in jobs:
                stat_html = render_status_pill(j["status"])
                rows.append([
                    str(j["id"]),
                    f"<code>{j['file_name']}</code>",
                    stat_html,
                    str(j["start_time"])[:19],
                    str(j["total_events"]),
                    str(j["parsed_events"]),
                    str(j["malformed_events"]),
                    str(j["duplicate_events"]),
                ])

            st.markdown(format_table_html(headers, rows), unsafe_allow_html=True)

            job_options = [f"Job #{j['id']} ({j['file_name']}) — {j['status']}" for j in jobs]
            sel_idx = st.selectbox("Select Job to View Parser Error Logs", range(len(job_options)), format_func=lambda i: job_options[i])
            chosen_job_id = jobs[sel_idx]["id"]

            st.divider()
            summary = service.get_job_summary(chosen_job_id)
            selected_errors = service.get_import_errors(chosen_job_id)

            if summary:
                st.markdown(f"### 📋 Job #{chosen_job_id} Details: `{summary['file_name']}`")
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Total Events", summary["total_events"])
                c2.metric("Parsed Successfully", summary["parsed_events"])
                c3.metric("Malformed / Quarantined", summary["malformed_events"])
                c4.metric("Duplicates Skipped", summary["duplicate_events"])

            st.markdown(f"#### ⚠️ Parser Errors & Quarantine Records ({len(selected_errors)})")
            if selected_errors:
                err_headers = ["Index", "Record ID / Context", "Error Reason"]
                err_rows = []
                for idx, err in enumerate(selected_errors, 1):
                    rec_id = str(err.get("record_id", "-"))
                    msg = str(err.get("error", err.get("message", str(err))))
                    err_rows.append([str(idx), rec_id, f"<code>{msg}</code>"])
                st.markdown(format_table_html(err_headers, err_rows), unsafe_allow_html=True)
            else:
                st.success("No errors or malformed events recorded for this import job.")
        else:
            st.info("No import jobs recorded yet in the database.")

    return {
        "jobs": jobs,
        "total_count": total_count,
        "selected_errors": selected_errors,
    }

