"""Process execution tree visualizer service powered by NetworkX."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import networkx as nx

from app.database.connection import DatabaseManager
from app.ui.components.visualizers import render_svg_process_tree
from app.ui.state import get_db_manager


class ProcessGraphService:
    """Builds and formats hierarchical process execution graphs for the UI."""

    def __init__(self, db_manager: DatabaseManager | None = None) -> None:
        self.db = db_manager or get_db_manager()

    def get_candidate_processes(self, computer: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve recent active processes for the process selector dropdown."""
        conditions = []
        params: list[Any] = []
        if computer:
            conditions.append("computer LIKE ?")
            params.append(f"%{computer}%")

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            query = f"""
                SELECT process_guid, process_id, image, command_line, user, computer, start_time
                FROM processes
                {where_clause}
                ORDER BY start_time DESC
                LIMIT ?;
            """
            cursor.execute(query, params + [limit])
            rows = cursor.fetchall()
            return [
                {
                    "process_guid": r[0],
                    "process_id": r[1],
                    "image": r[2],
                    "name": Path(r[2] or "unknown.exe").name,
                    "command_line": r[3],
                    "user": r[4],
                    "computer": r[5],
                    "start_time": r[6],
                }
                for r in rows
            ]

    def build_process_tree(self, process_guid: str) -> dict[str, Any]:
        """Construct full ancestor and descendant tree around a target process GUID."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            # 1. Fetch target process record
            cursor.execute("SELECT * FROM processes WHERE process_guid = ?;", (process_guid,))
            target_row = cursor.fetchone()
            if not target_row:
                return {
                    "nodes": [],
                    "edges": [],
                    "svg": render_svg_process_tree([], []),
                    "target_process": None,
                }

            col_names = [d[0] for d in cursor.description]
            target_dict = dict(zip(col_names, target_row))

            # 2. Gather alerts for alerting highlights
            cursor.execute("SELECT process_guid, severity FROM alerts WHERE process_guid IS NOT NULL;")
            alerted_guids: dict[str, str] = {r[0]: r[1].lower() for r in cursor.fetchall()}

            # 3. Build NetworkX graph of all processes on same computer
            computer = target_dict.get("computer")
            cursor.execute(
                """
                SELECT process_guid, parent_process_guid, process_id, image, command_line, user, start_time
                FROM processes
                WHERE computer = ?;
                """,
                (computer,),
            )
            all_procs = cursor.fetchall()

        G = nx.DiGraph()
        proc_data: dict[str, dict[str, Any]] = {}

        for r in all_procs:
            p_guid, parent_guid, pid, img, cmd, user, start_ts = r
            if not p_guid:
                continue

            threat = "normal"
            if p_guid in alerted_guids:
                sev = alerted_guids[p_guid]
                threat = "alert" if sev in ("critical", "high") else "suspicious"

            data = {
                "id": p_guid,
                "label": Path(img or "unknown.exe").name,
                "pid": pid,
                "image": img,
                "command_line": cmd or "",
                "user": user or "",
                "start_time": start_ts,
                "threat_level": threat,
            }
            proc_data[p_guid] = data
            G.add_node(p_guid, **data)

            if parent_guid and parent_guid != p_guid:
                G.add_edge(parent_guid, p_guid)

        # 4. Extract connected lineage (ancestors + descendants) for target_guid
        lineage_nodes: set[str] = {process_guid}
        if process_guid in G:
            # Walk ancestors
            try:
                lineage_nodes.update(nx.ancestors(G, process_guid))
            except Exception:
                pass
            # Walk descendants
            try:
                lineage_nodes.update(nx.descendants(G, process_guid))
            except Exception:
                pass

        subgraph_nodes: list[dict[str, Any]] = [
            proc_data[nid] for nid in lineage_nodes if nid in proc_data
        ]
        subgraph_edges: list[tuple[str, str]] = [
            (u, v) for u, v in G.edges() if u in lineage_nodes and v in lineage_nodes
        ]

        svg = render_svg_process_tree(subgraph_nodes, subgraph_edges)

        return {
            "nodes": subgraph_nodes,
            "edges": subgraph_edges,
            "svg": svg,
            "target_process": target_dict,
        }
