"""Core process tree graph modeling and synthetic GUID generation for WinSentinel."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

import networkx as nx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.events import EventCategory, NormalizedEvent

logger = logging.getLogger(__name__)


def generate_synthetic_guid(
    computer: str,
    process_id: int,
    timestamp: datetime,
) -> str:
    """Generate a deterministic UUID5 process GUID for events lacking native Sysmon GUIDs.

    Adheres to Decision D-01:
    UUID5(NAMESPACE_DNS, f"{computer.lower().strip()}:{pid}:{timestamp_iso}")
    Guarantees consistent, idempotent, lowercase curly-braced string GUIDs.
    """
    if timestamp.tzinfo is None:
        utc_dt = timestamp.replace(tzinfo=timezone.utc)
    else:
        utc_dt = timestamp.astimezone(timezone.utc)

    iso_str = utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
    norm_computer = computer.strip().lower()
    canonical_name = f"{norm_computer}:{process_id}:{iso_str}"

    synthetic_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, canonical_name)
    return f"{{{str(synthetic_uuid).lower()}}}"


# Alias for compatibility with research and domain references
generate_synthetic_process_guid = generate_synthetic_guid


class ProcessNode(BaseModel):
    """Strongly-typed, immutable representation of a process entity in the graph.

    Encapsulates identity invariants, parent provenance, temporal lifespans,
    and forensic anomaly flags.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    # Invariant Keys
    process_guid: str = Field(description="Primary unique invariant process GUID.")
    process_id: int = Field(description="Operating system process identifier (PID).")
    computer: str = Field(description="Hostname/computer where the process executed.")

    # Execution Metadata
    image: str = Field(description="Full path or binary name of the process image.")
    command_line: str | None = Field(default=None, description="Full process command line arguments.")
    current_directory: str | None = Field(default=None, description="Working directory of the process.")
    user: str | None = Field(default=None, description="User context under which the process ran.")
    integrity_level: str | None = Field(default=None, description="Windows token integrity level.")
    hashes: dict[str, str] = Field(default_factory=dict, description="Image cryptographic hashes.")

    # Parent Provenance
    parent_process_guid: str | None = Field(default=None, description="Invariant GUID of parent process.")
    parent_process_id: int | None = Field(default=None, description="Operating system PID of parent process.")
    parent_image: str | None = Field(default=None, description="Image path of parent process.")
    parent_command_line: str | None = Field(default=None, description="Command line of parent process.")
    parent_user: str | None = Field(default=None, description="User context of parent.")

    # Temporal Lifespan
    start_time: datetime = Field(description="Process creation timestamp (UTC).")
    end_time: datetime | None = Field(default=None, description="Process termination timestamp (UTC).")
    exit_code: int | None = Field(default=None, description="Process termination exit code.")

    # Forensic Flags
    is_synthesized: bool = Field(default=False, description="True if generated as placeholder for missing parent.")
    is_orphaned: bool = Field(default=False, description="True if root parent cannot be resolved.")
    is_anomalous: bool = Field(default=False, description="True if flagged by LineageAnomalyDetector.")
    anomaly_reasons: list[str] = Field(default_factory=list, description="Descriptions of triggered anomaly rules.")

    @field_validator("start_time", "end_time", mode="after")
    @classmethod
    def _ensure_utc(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return None
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


class ProcessTreeGraph:
    """Manages an in-memory NetworkX directed graph representing process hierarchies.

    Edges represent causal execution relationships: parent_guid -> child_guid.
    Supports multi-generational ancestry walks, generational BFS descendant
    extraction, synthetic parent placeholders, and subtree extractions.
    """

    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()
        self._nodes: dict[str, ProcessNode] = {}
        # Unresolved children waiting for their parent to be added: parent_guid -> set[child_guid]
        self._pending_children: dict[str, set[str]] = {}

    @property
    def node_count(self) -> int:
        """Total number of process nodes in the graph."""
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        """Total number of causal edges (parent -> child) in the graph."""
        return self._graph.number_of_edges()

    def add_process(self, node: ProcessNode) -> None:
        """Add or update a ProcessNode in the graph and connect causal edges."""
        guid = node.process_guid
        self._nodes[guid] = node
        self._graph.add_node(guid, **node.model_dump())

        # If parent already exists in graph, add causal edge
        if node.parent_process_guid:
            parent_guid = node.parent_process_guid
            if parent_guid in self._nodes:
                self._graph.add_edge(parent_guid, guid)
            else:
                self._pending_children.setdefault(parent_guid, set()).add(guid)

        # Check if any previously added children were waiting for this node
        if guid in self._pending_children:
            for child_guid in self._pending_children.pop(guid):
                if child_guid in self._nodes:
                    self._graph.add_edge(guid, child_guid)

    def get_node(self, guid: str) -> ProcessNode | None:
        """Retrieve a ProcessNode by its unique process_guid."""
        return self._nodes.get(guid)

    def get_parent(self, guid: str) -> ProcessNode | None:
        """Retrieve immediate parent ProcessNode or None if root/missing."""
        if guid not in self._graph:
            return None
        predecessors = list(self._graph.predecessors(guid))
        if not predecessors:
            return None
        return self._nodes.get(predecessors[0])

    def get_children(self, guid: str) -> list[ProcessNode]:
        """Retrieve all direct child ProcessNodes spawned by guid."""
        if guid not in self._graph:
            return []
        successors = list(self._graph.successors(guid))
        return [self._nodes[s] for s in successors if s in self._nodes]

    def get_ancestors_lineage(self, guid: str) -> list[ProcessNode]:
        """Return ordered ancestry chain from oldest root down to target node.

        Guarantees chronological root-to-leaf ordering: [Root, ..., Grandparent, Parent, Self].
        Protects against potential cycles via visited set.
        """
        lineage: list[ProcessNode] = []
        curr = self._nodes.get(guid)
        visited: set[str] = set()

        while curr is not None and curr.process_guid not in visited:
            visited.add(curr.process_guid)
            lineage.append(curr)
            curr = self.get_parent(curr.process_guid)

        return list(reversed(lineage))

    def get_descendants_tree(self, guid: str) -> list[ProcessNode]:
        """Return all transitive descendants spawned by guid in generational BFS order."""
        if guid not in self._graph:
            return []
        bfs_edges = nx.bfs_edges(self._graph, source=guid)
        ordered_guids = [v for _, v in bfs_edges]
        return [self._nodes[g] for g in ordered_guids if g in self._nodes]

    def get_roots(self) -> list[ProcessNode]:
        """Return all root nodes (in_degree == 0)."""
        return [
            self._nodes[n]
            for n, in_degree in self._graph.in_degree()
            if in_degree == 0 and n in self._nodes
        ]

    def get_subtree(self, root_guid: str) -> ProcessTreeGraph:
        """Extract isolated subgraph containing root_guid and all its transitive descendants."""
        sub_graph = ProcessTreeGraph()
        if root_guid not in self._nodes:
            return sub_graph

        descendant_nodes = self.get_descendants_tree(root_guid)
        sub_graph.add_process(self._nodes[root_guid])
        for desc_node in descendant_nodes:
            sub_graph.add_process(desc_node)

        return sub_graph

    def build_from_events(self, events: list[NormalizedEvent]) -> tuple[int, int]:
        """Ingest NormalizedEvent stream and construct directed process trees.

        Handles:
        - Creation events (Sysmon EID 1, Sec 4688)
        - Termination events (Sysmon EID 5)
        - Synthetic GUID generation for non-Sysmon events
        - Synthesized placeholder parent node creation (is_synthesized=True, is_orphaned=True)
        - Overwriting synthesized placeholders when genuine creation events arrive

        Returns:
            Tuple of (added_count, synthesized_count).
        """
        added_count = 0
        synthesized_count = 0

        for event in events:
            if event.event_category != EventCategory.PROCESS:
                continue

            event_id = event.event_id
            event_type = event.event_type.upper()

            # Process Creation (Sysmon EID 1, Windows Security EID 4688)
            if event_id in (1, 4688) or event_type in ("PROCESS_CREATE", "PROCESS_CREATION"):
                child_guid = event.process_guid
                if not child_guid:
                    child_guid = generate_synthetic_guid(
                        computer=event.computer,
                        process_id=event.process_id or 0,
                        timestamp=event.timestamp,
                    )

                parent_guid = event.parent_process_guid
                if not parent_guid and event.parent_process_id:
                    parent_guid = generate_synthetic_guid(
                        computer=event.computer,
                        process_id=event.parent_process_id,
                        timestamp=event.timestamp,
                    )

                # Synthesize placeholder parent if referenced but not yet observed
                if parent_guid and parent_guid not in self._nodes:
                    placeholder_parent = ProcessNode(
                        process_guid=parent_guid,
                        process_id=event.parent_process_id or 0,
                        computer=event.computer,
                        image=event.parent_image or "UNKNOWN_PARENT.EXE",
                        command_line=event.parent_command_line,
                        user=event.parent_user or event.user,
                        integrity_level=None,
                        hashes={},
                        parent_process_guid=None,
                        parent_process_id=None,
                        parent_image=None,
                        parent_command_line=None,
                        parent_user=None,
                        start_time=event.timestamp,
                        end_time=None,
                        exit_code=None,
                        is_synthesized=True,
                        is_orphaned=True,
                        is_anomalous=False,
                        anomaly_reasons=[],
                    )
                    self.add_process(placeholder_parent)
                    synthesized_count += 1

                # Construct child ProcessNode
                child_node = ProcessNode(
                    process_guid=child_guid,
                    process_id=event.process_id or 0,
                    computer=event.computer,
                    image=event.image or "UNKNOWN.EXE",
                    command_line=event.command_line,
                    current_directory=event.current_directory,
                    user=event.user,
                    integrity_level=event.integrity_level,
                    hashes=dict(event.hashes),
                    parent_process_guid=parent_guid,
                    parent_process_id=event.parent_process_id,
                    parent_image=event.parent_image,
                    parent_command_line=event.parent_command_line,
                    parent_user=event.parent_user,
                    start_time=event.timestamp,
                    end_time=None,
                    exit_code=None,
                    is_synthesized=False,
                    is_orphaned=False if parent_guid else True,
                    is_anomalous=False,
                    anomaly_reasons=[],
                )
                self.add_process(child_node)
                added_count += 1

            # Process Termination (Sysmon EID 5)
            elif event_id == 5 or event_type in ("PROCESS_TERMINATE", "PROCESS_TERMINATION"):
                proc_guid = event.process_guid
                if proc_guid and proc_guid in self._nodes:
                    existing = self._nodes[proc_guid]
                    exit_code = None
                    if event.extra_fields and "ExitCode" in event.extra_fields:
                        try:
                            exit_code = int(str(event.extra_fields["ExitCode"]), 0)
                        except (ValueError, TypeError):
                            exit_code = None
                    updated = existing.model_copy(
                        update={
                            "end_time": event.timestamp,
                            "exit_code": exit_code,
                        }
                    )
                    self.add_process(updated)

        return added_count, synthesized_count

    def to_dict(self) -> dict[str, Any]:
        """Serialize graph into standard NetworkX node-link dictionary format."""
        return nx.node_link_data(self._graph)

    def to_cytoscape(self) -> list[dict[str, Any]]:
        """Serialize graph into Cytoscape.js compatible elements list format."""
        elements: list[dict[str, Any]] = []

        for guid, node in self._nodes.items():
            elements.append(
                {
                    "data": {
                        "id": guid,
                        "label": node.image.split("\\")[-1],
                        "image": node.image,
                        "pid": node.process_id,
                        "user": node.user or "UNKNOWN",
                        "start_time": node.start_time.isoformat(),
                        "end_time": node.end_time.isoformat() if node.end_time else None,
                        "is_anomalous": node.is_anomalous,
                        "is_synthesized": node.is_synthesized,
                        "is_orphaned": node.is_orphaned,
                        "command_line": node.command_line or "",
                    }
                }
            )

        for source, target in self._graph.edges():
            elements.append(
                {
                    "data": {
                        "id": f"{source}->{target}",
                        "source": source,
                        "target": target,
                    }
                }
            )

        return elements

    def to_d3_tree(self, root_guid: str) -> dict[str, Any]:
        """Serialize a process tree hierarchy rooted at root_guid into nested D3 JSON."""
        node = self._nodes[root_guid]
        children = self.get_children(root_guid)

        return {
            "name": node.image.split("\\")[-1],
            "guid": node.process_guid,
            "pid": node.process_id,
            "command_line": node.command_line,
            "is_anomalous": node.is_anomalous,
            "is_synthesized": node.is_synthesized,
            "children": [self.to_d3_tree(child.process_guid) for child in children],
        }
