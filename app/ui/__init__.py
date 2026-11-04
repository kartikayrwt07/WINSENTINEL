"""UI application package for WinSentinel."""

from app.ui.state import get_db_manager, init_session_state, set_db_manager

__all__ = [
    "get_db_manager",
    "init_session_state",
    "set_db_manager",
]

