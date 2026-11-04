"""Page 5: Chronological Investigation Timeline."""

from __future__ import annotations

from typing import Any

try:
    import streamlit as st
    HAS_STREAMLIT = True
except ImportError:
    st = None
    HAS_STREAMLIT = False

from app.database.connection import DatabaseManager
from app.ui.components.badges import render_category_badge
from app.ui.services.timeline_service import TimelineService


def render_page(db_manager: DatabaseManager | None = None) -> list[dict[str, Any]]:
    """Render the Chronological Investigation Timeline view."""
    service = TimelineService(db_manager=db_manager)

    filter_computer = None
    filter_limit = 50

    if HAS_STREAMLIT and st is not None:
        st.markdown("## ⏱️ Chronological Investigation Timeline")
        st.caption("Inspect multi-source security events sequenced along an interactive unified timeline.")

        f_col1, f_col2 = st.columns([2, 1])
        with f_col1:
            filter_computer = st.text_input("Filter by Computer / Host", value="", placeholder="e.g. WORKSTATION-01") or None
        with f_col2:
            filter_limit = st.selectbox("Max Events", [25, 50, 100, 200], index=1)

    timeline_items = service.get_timeline(computer=filter_computer, limit=filter_limit)

    if HAS_STREAMLIT and st is not None:
        if timeline_items:
            # Render SVG diagram
            svg = service.render_timeline_svg(timeline_items)
            st.markdown(svg, unsafe_allow_html=True)

            st.markdown("---")
            st.markdown("### 📜 Sequential Event Stream")
            for item in timeline_items:
                alert_badge = "🚨 <b style='color: #ef4444;'>[ALERT DETECTED]</b> " if item["is_alert"] else ""
                header_text = f"{alert_badge}{item['timestamp']} — {item['title']}"

                with st.expander(header_text, expanded=item["is_alert"]):
                    st.markdown(f"**Category:** {render_category_badge(item['category'])} | **Host:** <code>{item['computer']}</code> | **User:** <code>{item['user'] or '-'}</code>", unsafe_allow_html=True)
                    st.markdown(f"**Image / Binary:** <code>{item['image'] or 'N/A'}</code>", unsafe_allow_html=True)
                    if item.get("command_line"):
                        st.markdown("**Command Line:**")
                        st.code(item["command_line"], language="powershell")
        else:
            st.info("No timeline events match the filter criteria.")

    return timeline_items
