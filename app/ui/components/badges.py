"""HTML pill badges for severity, alert status, and event categories."""

from __future__ import annotations


def render_severity_badge(severity: str) -> str:
    """Render an HTML pill badge styled by threat severity."""
    s = (severity or "unknown").strip().lower()

    colors = {
        "critical": {"bg": "#7f1d1d", "fg": "#fecaca", "border": "#dc2626"},
        "high": {"bg": "#7c2d12", "fg": "#ffedd5", "border": "#ea580c"},
        "medium": {"bg": "#78350f", "fg": "#fef3c7", "border": "#d97706"},
        "low": {"bg": "#1e3a8a", "fg": "#dbeafe", "border": "#2563eb"},
        "informational": {"bg": "#1e293b", "fg": "#cbd5e1", "border": "#475569"},
    }

    style = colors.get(s, {"bg": "#334155", "fg": "#f8fafc", "border": "#64748b"})

    return (
        f'<span style="background-color: {style["bg"]}; color: {style["fg"]}; '
        f'border: 1px solid {style["border"]}; padding: 2px 8px; border-radius: 9999px; '
        f'font-size: 0.75rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; '
        f'display: inline-block;">{severity.upper()}</span>'
    )


def render_status_badge(status: str) -> str:
    """Render an HTML pill badge styled by alert workflow lifecycle status."""
    st = (status or "new").strip().lower()

    colors = {
        "new": {"bg": "#1e3a8a", "fg": "#93c5fd", "border": "#3b82f6"},
        "investigating": {"bg": "#581c87", "fg": "#e9d5ff", "border": "#9333ea"},
        "escalated": {"bg": "#831843", "fg": "#fbcfe8", "border": "#db2777"},
        "resolved": {"bg": "#064e3b", "fg": "#a7f3d0", "border": "#10b981"},
        "false positive": {"bg": "#1c1917", "fg": "#a8a29e", "border": "#57534e"},
        "false_positive": {"bg": "#1c1917", "fg": "#a8a29e", "border": "#57534e"},
    }

    style = colors.get(st, {"bg": "#334155", "fg": "#f8fafc", "border": "#64748b"})

    return (
        f'<span style="background-color: {style["bg"]}; color: {style["fg"]}; '
        f'border: 1px solid {style["border"]}; padding: 2px 8px; border-radius: 9999px; '
        f'font-size: 0.75rem; font-weight: 600; text-transform: capitalize; '
        f'display: inline-block;">{status.replace("_", " ").title()}</span>'
    )


def render_category_badge(category: str) -> str:
    """Render an HTML pill badge styled by telemetry event category."""
    cat = (category or "generic").strip().upper()

    colors = {
        "PROCESS": {"bg": "#0f766e", "fg": "#ccfbf1"},
        "NETWORK": {"bg": "#1d4ed8", "fg": "#dbeafe"},
        "REGISTRY": {"bg": "#b45309", "fg": "#fef3c7"},
        "FILE": {"bg": "#4338ca", "fg": "#e0e7ff"},
        "DRIVER": {"bg": "#be123c", "fg": "#ffe4e6"},
        "REMOTE_THREAD": {"bg": "#991b1b", "fg": "#fee2e2"},
        "PROCESS_ACCESS": {"bg": "#701a75", "fg": "#fae8ff"},
        "DNS": {"bg": "#0369a1", "fg": "#e0f2fe"},
        "WMI": {"bg": "#854d0e", "fg": "#fef9c3"},
        "POWERSHELL": {"bg": "#15803d", "fg": "#dcfce7"},
        "SECURITY": {"bg": "#374151", "fg": "#f3f4f6"},
    }

    style = colors.get(cat, {"bg": "#334155", "fg": "#f8fafc"})

    return (
        f'<span style="background-color: {style["bg"]}; color: {style["fg"]}; '
        f'padding: 2px 6px; border-radius: 4px; font-size: 0.70rem; font-weight: 500; '
        f'display: inline-block;">{cat}</span>'
    )
