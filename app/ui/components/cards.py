"""HTML metric and KPI cards for WinSentinel SOC dashboard."""

from __future__ import annotations


def render_metric_card(
    title: str,
    value: str | int,
    subtitle: str | None = None,
    delta: str | None = None,
    border_color: str = "#3b82f6",
) -> str:
    """Render a styled metric summary card with dark SOC aesthetics."""
    sub_html = f'<div style="font-size: 0.8rem; color: #94a3b8; margin-top: 4px;">{subtitle}</div>' if subtitle else ""
    delta_html = f'<div style="font-size: 0.75rem; color: #10b981; font-weight: 600; margin-top: 4px;">{delta}</div>' if delta else ""

    return (
        f'<div style="background: #1e293b; border-left: 4px solid {border_color}; '
        f'border-radius: 8px; padding: 16px 20px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2); '
        f'margin-bottom: 12px;">'
        f'<div style="font-size: 0.85rem; font-weight: 500; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em;">{title}</div>'
        f'<div style="font-size: 2rem; font-weight: 700; color: #f8fafc; margin-top: 6px; line-height: 1.2;">{value}</div>'
        f'{sub_html}'
        f'{delta_html}'
        f'</div>'
    )
