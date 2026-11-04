"""Page 4: Interactive Process Tree Graph Visualizer."""

from __future__ import annotations

from typing import Any

try:
    import streamlit as st
    HAS_STREAMLIT = True
except ImportError:
    st = None
    HAS_STREAMLIT = False

from app.database.connection import DatabaseManager
from app.ui.services.process_graph_service import ProcessGraphService
from app.ui.state import get_stream_state


def render_page(db_manager: DatabaseManager | None = None) -> dict[str, Any]:
    """Render the Interactive Process Tree view."""
    service = ProcessGraphService(db_manager=db_manager)
    state = get_stream_state()

    candidates = service.get_candidate_processes(limit=50)

    selected_guid = state.get("selected_process_guid")
    if not selected_guid and candidates:
        selected_guid = candidates[0]["process_guid"]

    tree_data: dict[str, Any] = {"nodes": [], "edges": [], "svg": "", "target_process": None}

    if HAS_STREAMLIT and st is not None:
        st.markdown("## 🌲 Interactive Process Tree Visualizer")
        st.caption("Inspect parent-child execution lineages, command line ancestry, and anomalous threat badges.")

        if candidates:
            # Process selector dropdown
            guid_to_label = {
                c["process_guid"]: f"{c['name']} (PID: {c['process_id']} | Host: {c['computer']})"
                for c in candidates
            }
            options = list(guid_to_label.keys())
            current_idx = options.index(selected_guid) if selected_guid in options else 0

            sel = st.selectbox(
                "Select Root / Target Process",
                options,
                index=current_idx,
                format_func=lambda x: guid_to_label.get(x, x),
            )
            selected_guid = sel
            state["selected_process_guid"] = sel
        else:
            st.info("No process execution records found in database.")

    if selected_guid:
        tree_data = service.build_process_tree(selected_guid)

    if HAS_STREAMLIT and st is not None:
        if tree_data.get("svg"):
            st.markdown("### 🕸️ Execution Lineage Hierarchy")
            st.markdown(tree_data["svg"], unsafe_allow_html=True)

        target = tree_data.get("target_process")
        if target:
            st.markdown("---")
            st.markdown("### 📋 Process Forensic Metadata")
            p_col1, p_col2 = st.columns(2)
            with p_col1:
                st.markdown(f"**Image Path:** <code>{target.get('image')}</code>", unsafe_allow_html=True)
                st.markdown(f"**Process ID (PID):** <code>{target.get('process_id')}</code>", unsafe_allow_html=True)
                st.markdown(f"**Parent PID:** <code>{target.get('parent_process_id')}</code>", unsafe_allow_html=True)
                st.markdown(f"**User Account:** <code>{target.get('user')}</code>", unsafe_allow_html=True)
            with p_col2:
                st.markdown(f"**Computer Host:** <code>{target.get('computer')}</code>", unsafe_allow_html=True)
                st.markdown(f"**Process GUID:** <code>{target.get('process_guid')}</code>", unsafe_allow_html=True)
                st.markdown(f"**Parent GUID:** <code>{target.get('parent_process_guid')}</code>", unsafe_allow_html=True)
                st.markdown(f"**Start Time:** <code>{target.get('start_time')}</code>", unsafe_allow_html=True)

            st.markdown(f"**Full Command Line:**")
            st.code(target.get("command_line") or "None", language="powershell")

    return tree_data

