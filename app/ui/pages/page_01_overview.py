"""Page 1: SOC Overview Dashboard."""

from __future__ import annotations

from typing import Any

try:
    import streamlit as st
    HAS_STREAMLIT = True
except ImportError:
    st = None
    HAS_STREAMLIT = False

from app.database.connection import DatabaseManager
from app.ui.components.badges import render_severity_badge, render_status_badge
from app.ui.components.cards import render_metric_card
from app.ui.components.tables import format_table_html
from app.ui.services.overview_service import OverviewService


def render_page(db_manager: DatabaseManager | None = None) -> dict[str, Any]:
    """Render the Overview Dashboard view and return underlying analytical model data."""
    service = OverviewService(db_manager=db_manager)

    kpis = service.get_kpis()
    severities = service.get_severity_breakdown()
    hosts = service.get_top_targeted_hosts(limit=5)
    mitre = service.get_mitre_breakdown(limit=8)
    recent_alerts = service.get_recent_alerts(limit=5)

    if HAS_STREAMLIT and st is not None:
        st.markdown("## 📊 SOC Investigation Overview")
        st.caption("Real-time summary of ingested telemetry, active detections, and enterprise threat posture.")

        # Top 4 KPI Cards in columns
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(render_metric_card("Total Events", f"{kpis['total_events']:,}", border_color="#3b82f6"), unsafe_allow_html=True)
        with c2:
            st.markdown(render_metric_card("Active Alerts", f"{kpis['total_alerts']:,}", subtitle=f"Critical: {kpis['critical_alerts']} | High: {kpis['high_alerts']}", border_color="#ef4444"), unsafe_allow_html=True)
        with c3:
            st.markdown(render_metric_card("Incidents", f"{kpis['total_incidents']:,}", border_color="#f59e0b"), unsafe_allow_html=True)
        with c4:
            st.markdown(render_metric_card("Imported Files", f"{kpis['imported_files']:,}", border_color="#10b981"), unsafe_allow_html=True)

        st.markdown("---")

        col_left, col_right = st.columns([1, 1])

        with col_left:
            st.markdown("### 🎯 Alert Severity Breakdown")
            sev_headers = ["Severity", "Count"]
            sev_rows = [
                [render_severity_badge(s), str(count)]
                for s, count in severities.items()
            ]
            st.markdown(format_table_html(sev_headers, sev_rows), unsafe_allow_html=True)

            st.markdown("### 💻 Top Targeted Hosts")
            if hosts:
                host_headers = ["Computer / Host", "Alert Count"]
                host_rows = [[h["computer"], str(h["alert_count"])] for h in hosts]
                st.markdown(format_table_html(host_headers, host_rows), unsafe_allow_html=True)
            else:
                st.info("No host alert activity recorded.")

        with col_right:
            st.markdown("### 🥷 MITRE ATT&CK Techniques")
            if mitre:
                mitre_headers = ["Technique ID", "Detections"]
                mitre_rows = [[m["technique"], str(m["count"])] for m in mitre]
                st.markdown(format_table_html(mitre_headers, mitre_rows), unsafe_allow_html=True)
            else:
                st.info("No MITRE ATT&CK technique tags detected.")

        st.markdown("### 🚨 Recent Alert Activity")
        if recent_alerts:
            alert_headers = ["Rule ID", "Title", "Severity", "Status", "Computer", "Last Seen"]
            alert_rows = [
                [
                    f"<code>{a['rule_id']}</code>",
                    a["title"],
                    render_severity_badge(a["severity"]),
                    render_status_badge(a["status"]),
                    a["computer"],
                    str(a["last_seen"])[:19],
                ]
                for a in recent_alerts
            ]
            st.markdown(format_table_html(alert_headers, alert_rows), unsafe_allow_html=True)
        else:
            st.info("No alerts generated yet.")

    return {
        "kpis": kpis,
        "severities": severities,
        "hosts": hosts,
        "mitre": mitre,
        "recent_alerts": recent_alerts,
    }
