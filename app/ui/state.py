"""Session state management and database connection lifecycle for WinSentinel UI."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.config import get_database_settings
from app.database.connection import DatabaseManager
from app.database.migrations import MigrationRunner

logger = logging.getLogger(__name__)

# Fallback module-level state for headless/testing environments
_FALLBACK_STATE: dict[str, Any] = {}
_DEFAULT_DB_MANAGER: DatabaseManager | None = None


def get_stream_state() -> Any:
    """Return streamlit.session_state if running under Streamlit, else fallback dict."""
    try:
        import streamlit as st
        # Accessing session_state will raise AttributeError/RuntimeError if outside Streamlit runtime
        return st.session_state
    except (ImportError, AttributeError, RuntimeError):
        return _FALLBACK_STATE


def init_session_state() -> None:
    """Initialize default session state keys if not already set."""
    state = get_stream_state()

    defaults: dict[str, Any] = {
        "db_path": str(get_database_settings().db_path),
        "rules_dir": "rules/sysmon",
        "selected_page": "Overview",
        "selected_alert_id": None,
        "selected_process_guid": None,
        "correlation_window_minutes": 30,
        "auto_refresh": False,
    }

    for key, value in defaults.items():
        if key not in state:
            state[key] = value

    if "db_manager" not in state or state["db_manager"] is None:
        db_path = state.get("db_path")
        mgr = DatabaseManager(db_path=db_path)
        # Auto-apply schema migrations
        try:
            runner = MigrationRunner(db_manager=mgr)
            runner.apply_migrations()
        except Exception as exc:
            logger.warning("Auto-migration during state init encountered: %s", exc)
        state["db_manager"] = mgr


def get_db_manager() -> DatabaseManager:
    """Retrieve the active DatabaseManager singleton from session state or default."""
    global _DEFAULT_DB_MANAGER
    state = get_stream_state()

    if "db_manager" in state and state["db_manager"] is not None:
        return state["db_manager"]

    if _DEFAULT_DB_MANAGER is not None:
        return _DEFAULT_DB_MANAGER

    # Instantiate default DatabaseManager and run migrations
    settings = get_database_settings()
    mgr = DatabaseManager(db_path=settings.db_path)
    try:
        runner = MigrationRunner(db_manager=mgr)
        runner.apply_migrations()
    except Exception as exc:
        logger.warning("Auto-migration in get_db_manager encountered: %s", exc)

    _DEFAULT_DB_MANAGER = mgr
    state["db_manager"] = mgr
    return mgr


def set_db_manager(manager: DatabaseManager) -> None:
    """Explicitly set the active DatabaseManager singleton (useful for testing)."""
    global _DEFAULT_DB_MANAGER
    _DEFAULT_DB_MANAGER = manager
    state = get_stream_state()
    state["db_manager"] = manager
    state["db_path"] = str(manager.db_path)
