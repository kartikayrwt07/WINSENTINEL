"""WinSentinel SOC Investigation Dashboard & Timeline - Streamlit Application Shell."""

from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path if not present
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    import streamlit as st
    HAS_STREAMLIT = True
except ImportError:
    st = None
    HAS_STREAMLIT = False

from app.ui.state import get_db_manager, get_stream_state, init_session_state

PAGE_NAMES = [
    "01. Overview",
    "02. Event Explorer",
    "03. Alert Management",
    "04. Process Tree",
    "05. Investigation Timeline",
    "06. Persistence Analysis",
    "07. Detection Rules",
    "08. Evaluation & Tuning",
    "09. Import History",
    "10. Settings & Health",
]

SOC_DARK_CSS = """
<style>
    /* Dark SOC Theme styling */
    .stApp {
        background-color: #0b0f19;
        color: #f1f5f9;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    .metric-card {
        background: #1e293b;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
        border-left: 4px solid #3b82f6;
    }
    .stSidebar {
        background-color: #0f172a !important;
        border-right: 1px solid #1e293b;
    }
</style>
"""


def setup_streamlit_ui():
    """Configure Streamlit page layout and custom styling."""
    if not HAS_STREAMLIT or st is None:
        return

    st.set_page_config(
        page_title="WinSentinel | SOC Investigation Platform",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.markdown(SOC_DARK_CSS, unsafe_allow_html=True)


def render_sidebar() -> str:
    """Render sidebar navigation menu and return active page name."""
    if not HAS_STREAMLIT or st is None:
        state = get_stream_state()
        return state.get("selected_page", PAGE_NAMES[0])

    st.sidebar.markdown(
        "<div style='text-align: center; padding: 10px 0;'>"
        "<h2 style='color: #38bdf8; margin: 0;'>🛡️ WinSentinel</h2>"
        "<p style='color: #94a3b8; font-size: 0.8rem; margin: 4px 0 0 0;'>Endpoint Forensic & Threat Investigation</p>"
        "</div>",
        unsafe_allow_html=True,
    )
    st.sidebar.markdown("---")

    state = get_stream_state()
    current_page = state.get("selected_page", PAGE_NAMES[0])
    current_idx = PAGE_NAMES.index(current_page) if current_page in PAGE_NAMES else 0

    selected = st.sidebar.radio(
        "Navigation",
        PAGE_NAMES,
        index=current_idx,
        label_visibility="collapsed",
    )
    state["selected_page"] = selected

    st.sidebar.markdown("---")
    st.sidebar.markdown(
        f"<div style='font-size: 0.75rem; color: #64748b; padding: 4px;'>"
        f"Database: <code>{Path(state.get('db_path', 'winsentinel.db')).name}</code><br/>"
        f"Mode: <b>Offline EDR</b>"
        f"</div>",
        unsafe_allow_html=True,
    )

    return selected


def route_page(page_name: str) -> None:
    """Dispatch to selected page module render function."""
    db = get_db_manager()

    if page_name.startswith("01."):
        from app.ui.pages import page_01_overview
        page_01_overview.render_page(db)
    elif page_name.startswith("02."):
        from app.ui.pages import page_02_events
        page_02_events.render_page(db)
    elif page_name.startswith("03."):
        from app.ui.pages import page_03_alerts
        page_03_alerts.render_page(db)
    elif page_name.startswith("04."):
        from app.ui.pages import page_04_process_tree
        page_04_process_tree.render_page(db)
    elif page_name.startswith("05."):
        from app.ui.pages import page_05_timeline
        page_05_timeline.render_page(db)
    elif page_name.startswith("06."):
        from app.ui.pages import page_06_persistence
        page_06_persistence.render_page(db)
    elif page_name.startswith("07."):
        from app.ui.pages import page_07_rules
        page_07_rules.render_page(db)
    elif page_name.startswith("08."):
        from app.ui.pages import page_08_evaluation
        page_08_evaluation.render_page(db)
    elif page_name.startswith("09."):
        from app.ui.pages import page_09_import_history
        page_09_import_history.render_page(db)
    elif page_name.startswith("10."):
        from app.ui.pages import page_10_settings
        page_10_settings.render_page(db)


def main():
    """Main Streamlit execution lifecycle."""
    init_session_state()
    setup_streamlit_ui()
    selected_page = render_sidebar()
    route_page(selected_page)


if __name__ == "__main__":
    main()
