"""HTML table formatting utilities for WinSentinel."""

from __future__ import annotations

from typing import Any


def format_table_html(
    headers: list[str],
    rows: list[list[Any]],
    table_id: str = "soc-table",
) -> str:
    """Render a clean responsive HTML table formatted for dark SOC themes."""
    th_cells = "".join(
        f'<th style="padding: 10px 12px; text-align: left; font-size: 0.8rem; font-weight: 600; '
        f'color: #94a3b8; border-bottom: 2px solid #334155; text-transform: uppercase;">{h}</th>'
        for h in headers
    )

    tr_rows = []
    for row_idx, row in enumerate(rows):
        bg = "#1e293b" if row_idx % 2 == 0 else "#0f172a"
        td_cells = "".join(
            f'<td style="padding: 10px 12px; font-size: 0.85rem; color: #f1f5f9; '
            f'border-bottom: 1px solid #1e293b;">{cell}</td>'
            for cell in row
        )
        tr_rows.append(f'<tr style="background: {bg}; transition: background 0.15s;">{td_cells}</tr>')

    rows_html = "".join(tr_rows)

    return (
        f'<div style="overflow-x: auto; border: 1px solid #334155; border-radius: 8px; margin: 12px 0;">'
        f'<table id="{table_id}" style="width: 100%; border-collapse: collapse; background: #0f172a;">'
        f'<thead><tr style="background: #1e293b;">{th_cells}</tr></thead>'
        f'<tbody>{rows_html}</tbody>'
        f'</table>'
        f'</div>'
    )

