"""Self-contained interactive SVG visualizers for process trees and investigation timelines."""

from __future__ import annotations

from typing import Any


def render_svg_process_tree(
    nodes: list[dict[str, Any]],
    edges: list[tuple[str, str]],
    width: int = 950,
) -> str:
    """Generate a clean, responsive SVG hierarchical process execution tree.

    Args:
        nodes: List of node dicts with keys: 'id', 'label', 'pid', 'threat_level'
               ('normal', 'alert', 'suspicious'), 'command_line'.
        edges: List of directed tuples (parent_id, child_id).
        width: Canvas width in pixels.

    Returns:
        Self-contained SVG XML string.
    """
    if not nodes:
        return (
            f'<svg width="{width}" height="100" viewBox="0 0 {width} 100" xmlns="http://www.w3.org/2000/svg">'
            f'<text x="{width // 2}" y="55" fill="#94a3b8" text-anchor="middle" font-family="sans-serif" font-size="14">'
            f'No process tree data available.</text></svg>'
        )

    # Build adjacency and parent lookup
    children_map: dict[str, list[str]] = {n["id"]: [] for n in nodes}
    parent_map: dict[str, str] = {}
    for p, c in edges:
        if p in children_map and c in children_map:
            children_map[p].append(c)
            parent_map[c] = p

    # Find root nodes (no parent in nodes)
    roots = [n["id"] for n in nodes if n["id"] not in parent_map]
    if not roots:
        roots = [nodes[0]["id"]]

    # Assign depths (BFS)
    depths: dict[str, int] = {}
    queue = [(r, 0) for r in roots]
    while queue:
        curr, d = queue.pop(0)
        depths[curr] = d
        for child in children_map.get(curr, []):
            if child not in depths:
                queue.append((child, d + 1))

    # Fallback for disconnected nodes
    for n in nodes:
        if n["id"] not in depths:
            depths[n["id"]] = 0

    max_depth = max(depths.values()) if depths else 0
    levels: dict[int, list[str]] = {i: [] for i in range(max_depth + 1)}
    for nid, d in depths.items():
        levels[d].append(nid)

    # Calculate coordinates
    node_w = 220
    node_h = 75
    h_gap = 40
    v_gap = 60

    max_nodes_in_level = max(len(l) for l in levels.values()) if levels else 1
    total_w = max(width, max_nodes_in_level * (node_w + h_gap) + 80)
    total_h = (max_depth + 1) * (node_h + v_gap) + 60

    coords: dict[str, tuple[int, int]] = {}
    for d, nids in levels.items():
        y = 40 + d * (node_h + v_gap)
        level_width = len(nids) * (node_w + h_gap) - h_gap
        start_x = (total_w - level_width) // 2
        for idx, nid in enumerate(nids):
            x = start_x + idx * (node_w + h_gap)
            coords[nid] = (x, y)

    # SVG definition
    svg_parts: list[str] = [
        f'<svg width="100%" height="{total_h}" viewBox="0 0 {total_w} {total_h}" '
        f'xmlns="http://www.w3.org/2000/svg" style="background: #0f172a; border-radius: 8px; border: 1px solid #334155;">',
        '<defs>',
        '<marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '<path d="M 0 1 L 8 5 L 0 9 z" fill="#64748b" />',
        '</marker>',
        '</defs>',
    ]

    # Draw edges
    for p, c in edges:
        if p in coords and c in coords:
            px, py = coords[p]
            cx, cy = coords[c]
            start_x = px + node_w // 2
            start_y = py + node_h
            end_x = cx + node_w // 2
            end_y = cy
            mid_y = (start_y + end_y) // 2
            path_d = f"M {start_x} {start_y} C {start_x} {mid_y}, {end_x} {mid_y}, {end_x} {end_y}"
            svg_parts.append(
                f'<path d="{path_d}" stroke="#64748b" stroke-width="2" fill="none" marker-end="url(#arrow)" />'
            )

    # Draw nodes
    node_lookup = {n["id"]: n for n in nodes}
    for nid, (x, y) in coords.items():
        n = node_lookup.get(nid, {})
        label = n.get("label", "unknown")
        pid = n.get("pid", "-")
        cmd = n.get("command_line", "")
        threat = n.get("threat_level", "normal")

        if threat == "alert":
            stroke_color = "#ef4444"
            badge_bg = "#7f1d1d"
            badge_fg = "#fecaca"
            badge_text = "ALERT"
        elif threat == "suspicious":
            stroke_color = "#f59e0b"
            badge_bg = "#78350f"
            badge_fg = "#fef3c7"
            badge_text = "SUSPICIOUS"
        else:
            stroke_color = "#3b82f6"
            badge_bg = "#1e293b"
            badge_fg = "#94a3b8"
            badge_text = f"PID {pid}"

        cmd_preview = (cmd[:24] + "...") if len(cmd) > 24 else cmd

        svg_parts.append(
            f'<g id="node-{nid}">'
            f'<rect x="{x}" y="{y}" width="{node_w}" height="{node_h}" rx="8" '
            f'fill="#1e293b" stroke="{stroke_color}" stroke-width="2" />'
            f'<rect x="{x + 8}" y="{y + 8}" width="65" height="18" rx="4" fill="{badge_bg}" />'
            f'<text x="{x + 40}" y="{y + 21}" fill="{badge_fg}" font-family="sans-serif" font-size="10" font-weight="bold" text-anchor="middle">{badge_text}</text>'
            f'<text x="{x + 82}" y="{y + 22}" fill="#f8fafc" font-family="sans-serif" font-size="12" font-weight="bold">{label}</text>'
            f'<text x="{x + 10}" y="{y + 44}" fill="#94a3b8" font-family="monospace" font-size="10">{cmd_preview}</text>'
            f'<text x="{x + 10}" y="{y + 62}" fill="#64748b" font-family="sans-serif" font-size="9">PID: {pid}</text>'
            f'</g>'
        )

    svg_parts.append('</svg>')
    return "\n".join(svg_parts)


def render_svg_timeline(
    events: list[dict[str, Any]],
    width: int = 950,
) -> str:
    """Generate a clean, vertical chronological investigation timeline SVG diagram."""
    if not events:
        return (
            f'<svg width="{width}" height="100" viewBox="0 0 {width} 100" xmlns="http://www.w3.org/2000/svg">'
            f'<text x="{width // 2}" y="55" fill="#94a3b8" text-anchor="middle" font-family="sans-serif" font-size="14">'
            f'No timeline events available.</text></svg>'
        )

    row_h = 70
    total_h = len(events) * row_h + 60
    spine_x = 180

    svg_parts = [
        f'<svg width="100%" height="{total_h}" viewBox="0 0 {width} {total_h}" '
        f'xmlns="http://www.w3.org/2000/svg" style="background: #0f172a; border-radius: 8px; border: 1px solid #334155;">',
        # Vertical spine
        f'<line x1="{spine_x}" y1="30" x2="{spine_x}" y2="{total_h - 30}" stroke="#334155" stroke-width="3" />',
    ]

    for idx, ev in enumerate(events):
        y = 40 + idx * row_h
        ts = str(ev.get("timestamp", ""))[:19]
        cat = ev.get("category", "PROCESS")
        title = ev.get("title", "Event")
        is_alert = ev.get("is_alert", False)

        node_color = "#ef4444" if is_alert else "#38bdf8"
        bg_card = "#1e293b" if is_alert else "#1e293b"
        border_card = "#ef4444" if is_alert else "#334155"

        svg_parts.extend([
            # Timestamp on left
            f'<text x="{spine_x - 20}" y="{y + 12}" fill="#94a3b8" font-family="monospace" font-size="11" text-anchor="end">{ts}</text>',
            # Spine node circle
            f'<circle cx="{spine_x}" cy="{y + 8}" r="6" fill="{node_color}" stroke="#0f172a" stroke-width="2" />',
            # Content Card on right
            f'<rect x="{spine_x + 25}" y="{y - 12}" width="{width - spine_x - 50}" height="48" rx="6" fill="{bg_card}" stroke="{border_card}" stroke-width="1.5" />',
            f'<text x="{spine_x + 38}" y="{y + 10}" fill="#f8fafc" font-family="sans-serif" font-size="12" font-weight="600">{title}</text>',
            f'<text x="{spine_x + 38}" y="{y + 26}" fill="#94a3b8" font-family="sans-serif" font-size="10">{cat} | Host: {ev.get("computer", "-")}</text>',
        ])

    svg_parts.append('</svg>')
    return "\n".join(svg_parts)
