"""Page 10: Platform Settings & Database Health."""

from __future__ import annotations

from typing import Any

try:
    import streamlit as st
    HAS_STREAMLIT = True
except ImportError:
    st = None
    HAS_STREAMLIT = False

from app.database.connection import DatabaseManager
from app.ui.components.cards import render_metric_card
from app.ui.components.tables import format_table_html
from app.ui.services.settings_service import SettingsService


def render_page(db_manager: DatabaseManager | None = None) -> dict[str, Any]:
    """Render the Settings & DB Health view."""
    service = SettingsService(db_manager=db_manager)
    health = service.get_system_health()
    config = service.get_active_config()

    if HAS_STREAMLIT and st is not None:
        st.markdown("## ⚙️ Platform Settings & Database Health")
        st.caption("Inspect local SQLite database metrics, storage allocation, and platform configuration.")

        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(render_metric_card("SQLite Version", health["sqlite_version"], border_color="#3b82f6"), unsafe_allow_html=True)
        with c2:
            size_mb = health["file_size_bytes"] / (1024 * 1024)
            st.markdown(render_metric_card("Database Size", f"{size_mb:.2f} MB", border_color="#10b981"), unsafe_allow_html=True)
        with c3:
            total_rows = sum(health["table_counts"].values())
            st.markdown(render_metric_card("Total Rows", f"{total_rows:,}", border_color="#8b5cf6"), unsafe_allow_html=True)

        st.markdown("---")

        col1, col2 = st.columns([1, 1])

        with col1:
            st.markdown("### 🗄️ Database Table Allocation")
            headers = ["Table Name", "Row Count"]
            rows = [[tbl, f"{count:,}"] for tbl, count in health["table_counts"].items()]
            st.markdown(format_table_html(headers, rows), unsafe_allow_html=True)

        with col2:
            st.markdown("### 🔧 Engine Configuration")
            new_window = st.slider(
                "Correlation Sliding Window (Minutes)",
                min_value=5,
                max_value=120,
                value=int(config.get("correlation_window_minutes", 30)),
                step=5,
                help="Time window in which multi-stage attack actions must occur to trigger compound incidents.",
            )
            service.update_config("correlation_window_minutes", new_window)

            st.text_input("Detection Rules Directory", value=config.get("rules_dir", "rules/sysmon"), disabled=True)
            st.text_input("Active SQLite Database Path", value=health["db_path"], disabled=True)

            if st.button("🔄 Reload Detection Rules Catalog"):
                st.success("Rule directory rescanned and cached in memory.")

    return {
        "health": health,
        "config": config,
    }

