"""Page 2: Event Explorer and Forensic Record Inspector."""

from __future__ import annotations

import json
from typing import Any

try:
    import streamlit as st
    HAS_STREAMLIT = True
except ImportError:
    st = None
    HAS_STREAMLIT = False

from app.database.connection import DatabaseManager
from app.ui.components.badges import render_category_badge
from app.ui.components.tables import format_table_html
from app.ui.services.event_explorer_service import EventExplorerService


def render_page(db_manager: DatabaseManager | None = None) -> dict[str, Any]:
    """Render the Event Explorer view with multi-field filtering and record inspection."""
    service = EventExplorerService(db_manager=db_manager)

    # Defaults
    filter_eid = None
    filter_computer = None
    filter_image = None
    filter_user = None
    filter_category = None
    filter_search = None
    limit = 50
    offset = 0

    if HAS_STREAMLIT and st is not None:
        st.markdown("## 🔍 Event Explorer & Forensic Log Inspector")
        st.caption("Search, filter, and inspect normalized Windows telemetry across all ingested logs.")

        with st.expander("Filter Options", expanded=True):
            f_col1, f_col2, f_col3, f_col4 = st.columns(4)
            with f_col1:
                eid_in = st.text_input("Event ID", value="", placeholder="e.g. 1, 3, 10")
                if eid_in.strip().isdigit():
                    filter_eid = int(eid_in.strip())
            with f_col2:
                filter_computer = st.text_input("Computer / Host", value="", placeholder="e.g. WORKSTATION-01") or None
            with f_col3:
                filter_user = st.text_input("User Account", value="", placeholder="e.g. Administrator") or None
            with f_col4:
                cat_options = ["ALL", "PROCESS", "NETWORK", "REGISTRY", "FILE", "DRIVER", "REMOTE_THREAD", "PROCESS_ACCESS", "DNS", "SECURITY"]
                sel_cat = st.selectbox("Category", cat_options, index=0)
                if sel_cat != "ALL":
                    filter_category = sel_cat

            s_col1, s_col2 = st.columns([3, 1])
            with s_col1:
                filter_search = st.text_input("Search Text", value="", placeholder="Search inside command lines, file paths, or raw payload...") or None
            with s_col2:
                limit = st.selectbox("Rows per page", [25, 50, 100], index=1)

    events, total_count = service.filter_events(
        event_id=filter_eid,
        computer=filter_computer,
        image=filter_image,
        user=filter_user,
        category=filter_category,
        search=filter_search,
        limit=limit,
        offset=offset,
    )

    if HAS_STREAMLIT and st is not None:
        st.markdown(f"**Found {total_count:,} matching events** (showing {len(events)}):")

        if events:
            table_headers = ["ID", "EID", "Timestamp", "Category", "Image", "Command Line", "User", "Host"]
            table_rows = [
                [
                    str(e["id"]),
                    f"<b>{e['event_id']}</b>",
                    str(e["timestamp"])[:19],
                    render_category_badge(e["category"]),
                    f"<code>{(e['image'] or '')[-30:]}</code>",
                    f"<code>{(e['command_line'] or '')[:60]}...</code>" if e['command_line'] and len(e['command_line']) > 60 else f"<code>{e['command_line'] or ''}</code>",
                    e["user"] or "-",
                    e["computer"],
                ]
                for e in events
            ]
            st.markdown(format_table_html(table_headers, table_rows), unsafe_allow_html=True)

            # Forensic detail inspector
            st.markdown("---")
            st.markdown("### 🔬 Forensic Record Inspector")
            event_ids = [e["id"] for e in events]
            sel_id = st.selectbox("Select Event Record to Inspect", event_ids, format_func=lambda x: f"Record #{x}")
            if sel_id:
                detail = service.get_event_detail(sel_id)
                if detail:
                    d_tab1, d_tab2 = st.tabs(["Normalized Fields", "Raw Unmodified Payload"])
                    with d_tab1:
                        st.json(detail)
                    with d_tab2:
                        raw = detail.get("raw_payload", "No raw payload stored.")
                        st.code(raw, language="xml")
        else:
            st.info("No events match the selected filter criteria.")

    return {
        "events": events,
        "total_count": total_count,
    }
