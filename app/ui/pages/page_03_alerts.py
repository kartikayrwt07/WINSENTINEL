"""Page 3: Alert Management & Triage View."""

from __future__ import annotations

from typing import Any

try:
    import streamlit as st
    HAS_STREAMLIT = True
except ImportError:
    st = None
    HAS_STREAMLIT = False

from app.database.connection import DatabaseManager
from app.ui.components.badges import render_severity_pill, render_status_pill
from app.ui.components.tables import format_table_html
from app.ui.services.alert_ui_service import AlertUIService


def render_page(db_manager: DatabaseManager | None = None) -> dict[str, Any]:
    """Render the Alert Management and Triage view."""
    service = AlertUIService(db_manager=db_manager)

    status_filter = "ALL"
    severity_filter = "ALL"
    search_query = None
    selected_alert_id = None

    if HAS_STREAMLIT and st is not None:
        st.markdown("## 🚨 Alert Management & Triage")
        st.caption("Investigate triggered detections, update analyst disposition, and review forensic evidence.")

        col_status, col_sev, col_srch = st.columns([1, 1, 2])
        with col_status:
            status_filter = st.selectbox(
                "Status",
                ["ALL", "New", "Investigating", "Escalated", "Resolved", "False Positive"],
                index=0,
            )
        with col_sev:
            severity_filter = st.selectbox(
                "Severity",
                ["ALL", "critical", "high", "medium", "low", "informational"],
                index=0,
            )
        with col_srch:
            search_query = st.text_input("Search Alert / Host / User", placeholder="e.g. whoami or WIN-SEC") or None

    alerts, total_count = service.get_alerts(
        status=status_filter if status_filter != "ALL" else None,
        severity=severity_filter if severity_filter != "ALL" else None,
        search=search_query,
        limit=50,
        offset=0,
    )

    alert_detail = None

    if HAS_STREAMLIT and st is not None:
        st.markdown(f"**Showing {len(alerts)} of {total_count} alerts**")

        if alerts:
            headers = ["ID", "Severity", "Status", "Rule ID", "Title", "Computer", "User", "Last Seen", "Events"]
            rows = []
            for a in alerts:
                sev_html = render_severity_pill(a["severity"])
                stat_html = render_status_pill(a["status"])
                rows.append([
                    str(a["id"]),
                    sev_html,
                    stat_html,
                    f"<code>{a['rule_id'] or '-'}</code>",
                    a["title"],
                    a["computer"],
                    a["user"] or "-",
                    str(a["last_seen"])[:19],
                    str(a["event_count"]),
                ])

            st.markdown(format_table_html(headers, rows), unsafe_allow_html=True)

            alert_options = [f"Alert #{a['id']}: {a['title']} ({a['computer']})" for a in alerts]
            selected_idx = st.selectbox("Select Alert for Deep Forensic Inspection", range(len(alert_options)), format_func=lambda i: alert_options[i])
            selected_alert_id = alerts[selected_idx]["id"]

            st.divider()
            alert_detail = service.get_alert_detail(selected_alert_id)
            if alert_detail and "alert" in alert_detail:
                al = alert_detail["alert"]
                st.markdown(f"### 🔍 Alert #{al['id']} Detail: {al['title']}")
                c1, c2, c3, c4 = st.columns(4)
                c1.markdown(f"**Status:** {render_status_pill(al['status'])}", unsafe_allow_html=True)
                c2.markdown(f"**Severity:** {render_severity_pill(al['severity'])}", unsafe_allow_html=True)
                c3.markdown(f"**Host:** `{al['computer']}`")
                c4.markdown(f"**User:** `{al['user'] or 'N/A'}`")

                if al.get("description"):
                    st.info(al["description"])

                # Evidence events
                evidence = alert_detail.get("evidence", [])
                st.markdown(f"#### 📄 Supporting Forensic Evidence ({len(evidence)} events)")
                if evidence:
                    ev_headers = ["Time", "EID", "Category", "Image / Target", "Command Line / Details"]
                    ev_rows = []
                    for ev in evidence:
                        ev_rows.append([
                            str(ev.get("timestamp_utc", ""))[:19],
                            str(ev.get("event_id", "")),
                            ev.get("event_category", ""),
                            f"<code>{ev.get('image', '')}</code>",
                            f"<code>{ev.get('command_line', '') or ev.get('target_object', '') or ''}</code>",
                        ])
                    st.markdown(format_table_html(ev_headers, ev_rows), unsafe_allow_html=True)

                # Analyst notes and disposition form
                st.markdown("#### 📝 Analyst Disposition & Lifecycle Transition")
                col_trans, col_note = st.columns([1, 2])
                with col_trans:
                    next_status = st.selectbox("New Status", ["Investigating", "Escalated", "Resolved", "False Positive"])
                    if st.button("Apply Status Transition"):
                        service.update_status(selected_alert_id, new_status=next_status, analyst="Analyst")
                        st.success(f"Alert transitioned to {next_status}")

                with col_note:
                    note_text = st.text_area("Add Investigation Note")
                    if st.button("Append Note"):
                        if note_text.strip():
                            service.add_note(selected_alert_id, note_text=note_text.strip(), analyst="Analyst")
                            st.success("Note recorded.")

                # Existing notes history
                notes = alert_detail.get("notes", [])
                if notes:
                    st.markdown("##### Previous Analyst Notes")
                    for n in notes:
                        st.caption(f"**{n.get('author', 'Analyst')}** at {str(n.get('created_at', ''))[:19]}: {n.get('note', '')}")
        else:
            st.info("No alerts match the selected filter criteria.")

    return {
        "alerts": alerts,
        "total_count": total_count,
        "selected_detail": alert_detail,
    }

