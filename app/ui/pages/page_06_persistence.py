"""Page 6: Persistence Analysis View."""

from __future__ import annotations

from typing import Any

try:
    import streamlit as st
    HAS_STREAMLIT = True
except ImportError:
    st = None
    HAS_STREAMLIT = False

from app.database.connection import DatabaseManager
from app.ui.components.tables import format_table_html
from app.ui.services.persistence_ui_service import PersistenceUIService


def render_page(db_manager: DatabaseManager | None = None) -> dict[str, Any]:
    """Render the Persistence Analysis view."""
    service = PersistenceUIService(db_manager=db_manager)

    filter_computer = None
    if HAS_STREAMLIT and st is not None:
        st.markdown("## ⚓ Persistence Mechanism Analysis")
        st.caption("Inspect auto-start extensibility points (ASEPs) across Registry, Services, Tasks, and WMI.")
        filter_computer = st.text_input("Filter by Computer / Host", value="", placeholder="e.g. WORKSTATION-01") or None

    summary = service.get_persistence_summary(computer=filter_computer)

    if HAS_STREAMLIT and st is not None:
        tab_run, tab_ifeo, tab_svc, tab_task, tab_wmi, tab_drop = st.tabs([
            f"Registry Run ({len(summary['registry_run'])})",
            f"IFEO Debugger ({len(summary['ifeo_debugger'])})",
            f"Services & Drivers ({len(summary['services'])})",
            f"Scheduled Tasks ({len(summary['scheduled_tasks'])})",
            f"WMI Subscriptions ({len(summary['wmi'])})",
            f"Startup Drops ({len(summary['startup_drops'])})",
        ])

        with tab_run:
            if summary["registry_run"]:
                headers = ["Time", "Host", "Target Object / Key", "Details / Payload", "Image"]
                rows = [
                    [str(r["timestamp"])[:19], r["computer"], f"<code>{r['target']}</code>", f"<code>{r['details'] or ''}</code>", r["image"] or "-"]
                    for r in summary["registry_run"]
                ]
                st.markdown(format_table_html(headers, rows), unsafe_allow_html=True)
            else:
                st.info("No Registry Run / RunOnce persistence events recorded.")

        with tab_ifeo:
            if summary["ifeo_debugger"]:
                headers = ["Time", "Host", "Target Object", "Debugger Value", "Image"]
                rows = [
                    [str(r["timestamp"])[:19], r["computer"], f"<code>{r['target']}</code>", f"<code>{r['details'] or ''}</code>", r["image"] or "-"]
                    for r in summary["ifeo_debugger"]
                ]
                st.markdown(format_table_html(headers, rows), unsafe_allow_html=True)
            else:
                st.info("No IFEO Debugger persistence events recorded.")

        with tab_svc:
            if summary["services"]:
                headers = ["Time", "Host", "Service Name", "Service File", "Driver Loaded"]
                rows = [
                    [str(r["timestamp"])[:19], r["computer"], r["service_name"] or "-", f"<code>{r['service_file'] or ''}</code>", r["driver_loaded"] or "-"]
                    for r in summary["services"]
                ]
                st.markdown(format_table_html(headers, rows), unsafe_allow_html=True)
            else:
                st.info("No Service installation or untrusted driver load events recorded.")

        with tab_task:
            if summary["scheduled_tasks"]:
                headers = ["Time", "Host", "Task Name", "Task Content / Action"]
                rows = [
                    [str(r["timestamp"])[:19], r["computer"], f"<b>{r['task_name']}</b>", f"<code>{(r['task_content'] or '')[:100]}</code>"]
                    for r in summary["scheduled_tasks"]
                ]
                st.markdown(format_table_html(headers, rows), unsafe_allow_html=True)
            else:
                st.info("No Scheduled Task creation events recorded.")

        with tab_wmi:
            if summary["wmi"]:
                headers = ["Time", "Host", "Operation", "Consumer", "Filter", "Query"]
                rows = [
                    [str(r["timestamp"])[:19], r["computer"], r["operation"] or "WMI Activity", r["consumer"] or "-", r["filter"] or "-", f"<code>{r['query'] or ''}</code>"]
                    for r in summary["wmi"]
                ]
                st.markdown(format_table_html(headers, rows), unsafe_allow_html=True)
            else:
                st.info("No WMI subscription events recorded.")

        with tab_drop:
            if summary["startup_drops"]:
                headers = ["Time", "Host", "Dropped File", "Creating Image", "User"]
                rows = [
                    [str(r["timestamp"])[:19], r["computer"], f"<code>{r['target_filename']}</code>", r["image"] or "-", r["user"] or "-"]
                    for r in summary["startup_drops"]
                ]
                st.markdown(format_table_html(headers, rows), unsafe_allow_html=True)
            else:
                st.info("No Startup folder file creation events recorded.")

    return summary

