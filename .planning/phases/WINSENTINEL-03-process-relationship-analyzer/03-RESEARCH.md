# Phase 3: Process Relationship Analyzer — Technical & Domain Research

**Phase:** WINSENTINEL-03  
**Requirements Focus:** PROC-01, PROC-02, PROC-03, PROC-04, PROC-05  
**Locked Decisions:** D-01, D-02, D-03, D-04 (from `03-CONTEXT.md`)  
**Status:** COMPLETE  
**Date:** 2026-11-04  

---

## 1. Executive Summary & Architecture Overview

Phase 3 implements the **Process Relationship Analyzer** for WinSentinel. In Phases 1 and 2, the ingestion engine validated and normalized heterogeneous Windows event logs (Sysmon, Windows Security, PowerShell) into typed, frozen `NormalizedEvent` records and established a thread-safe embedded SQLite persistence layer. However, individual event records represent isolated, point-in-time snapshots of host activity. Real-world adversaries operate across multi-stage execution chains, where initial access vectors (e.g., weaponized documents or web exploits) spawn intermediate shells that subsequently launch privilege escalation tools, discovery commands, and persistence mechanisms.

Understanding and detecting these multi-stage attacks requires transforming flat event streams into **directed execution hierarchies** (process trees). This phase solves four core challenges inherent to Windows endpoint telemetry:

1. **Process Identity Invariance & Telemetry Disparity:** Windows kernel Process IDs (PIDs) are volatile, recycled integers. Sysmon provides globally unique `ProcessGuid` values, but native Windows Security EID 4688 logs omit GUIDs. We unify both sources via deterministic synthetic GUID generation (**D-01**).
2. **Missing Telemetry & Truncated Baselines:** In forensic triage of exported logs, parent processes frequently launched prior to log capture inception. Discarding these creates broken ancestry trees; we bridge this gap by synthesizing placeholder parent nodes populated from child metadata (**D-02**).
3. **Kernel PID Recycling Across Time:** Operating system PIDs are frequently reused across hours or days. We resolve PID ambiguity through temporal lifespan interval indexing (`[start_time, end_time]`) (**D-03**).
4. **Suspicious Lineage Detection:** Threat actors abuse legitimate binaries (Living-off-the-Land). We implement a dedicated `LineageAnomalyDetector` targeting MITRE ATT&CK techniques (T1059, T1204, T1190, T1068) with explainable structured findings (**D-04**).

### High-Level Architecture

```
                    +-----------------------------+
                    | Normalized Events Stream    |
                    | (Sysmon EID 1/5, Sec 4688)  |
                    +--------------+--------------+
                                   |
                                   v
             +---------------------+---------------------+
             |     Identity & Invariant Resolver         |
             |  - Sysmon ProcessGuid extraction          |
             |  - UUID5 Synthetic GUID for Sec 4688      |
             +---------------------+---------------------+
                                   |
                                   v
             +---------------------+---------------------+
             |    Temporal Lifespan Manager (D-03)       |
             |  - Start / End time interval tracking     |
             |  - PID reuse disambiguation via bisect    |
             +---------------------+---------------------+
                                   |
                                   v
             +---------------------+---------------------+
             |    Process Tree Graph Builder (D-02)      |
             |  - NetworkX DiGraph (Parent -> Child)     |
             |  - Placeholder Parent Synthesizer         |
             |  - Ancestry & Descendant traversal        |
             +----------+--------------------+-----------+
                        |                    |
                        v                    v
+-----------------------+-----+   +----------+------------------+
|  Lineage Anomaly Detector   |   | Graph Serialization & DB    |
|  (MITRE ATT&CK Matrix)      |   | - SQLite processes table    |
|  - Office -> Shells         |   | - to_dict() / Node-Link     |
|  - Web Server -> Shells     |   | - to_cytoscape() JSON       |
|  - Spooler / SQL -> Shells  |   | - to_d3() Hierarchical JSON |
|  - Suspicious Recon         |   +-----------------------------+
+-----------------------------+
```

---

## 2. NetworkX DiGraph Modeling & Graph Architecture

### 2.1 Graph Formulation and Directional Semantics

In WinSentinel, process execution hierarchies are modeled as a **Directed Acyclic Graph (DAG)** using `networkx.DiGraph`. 

- **Edge Direction:** Edges represent causal process invocation: `(parent_guid -> child_guid)`.
  - An edge `(u, v)` exists if process `u` spawned process `v`.
- **In-Degree Constraints:** Under standard Windows OS execution semantics, every process has exactly **one** creator parent process. Therefore, in an ideal process tree:
  $$\forall v \in V, \quad \text{in\_degree}(v) \le 1$$
  - A node with $\text{in\_degree}(v) = 0$ is a **Root Process** (e.g., `System`, `smss.exe`, `services.exe`, `explorer.exe`, or a synthesized placeholder ancestor).
- **Out-Degree Semantics:** A single parent process can spawn arbitrary child processes over its lifespan:
  $$\forall u \in V, \quad \text{out\_degree}(u) \ge 0$$
  - A node with $\text{out\_degree}(u) = 0$ is a **Leaf Process** (a process that terminated or spawned no child subprocesses).

### 2.2 Node Data Model (`ProcessNode`)

To ensure type safety, data integrity, and seamless serialization across SQLite and frontends, process nodes are encapsulated in a typed Pydantic v2 data model:

```python
from datetime import datetime
from pydantic import BaseModel, Field, ConfigDict

class ProcessNode(BaseModel):
    """Strongly-typed representation of an execution process entity in the graph."""
    
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
    hashes: dict[str, str] = Field(default_factory=dict, description="Image cryptographic hashes (SHA256, MD5, etc.).")
    
    # Parent Provenance
    parent_process_guid: str | None = Field(default=None, description="Invariant GUID of the parent process.")
    parent_process_id: int | None = Field(default=None, description="Operating system PID of the parent.")
    parent_image: str | None = Field(default=None, description="Image path of the parent process.")
    parent_command_line: str | None = Field(default=None, description="Command line of the parent process.")
    parent_user: str | None = Field(default=None, description="User context of the parent.")
    
    # Temporal Lifespan
    start_time: datetime = Field(description="Process creation timestamp (UTC).")
    end_time: datetime | None = Field(default=None, description="Process termination timestamp (UTC), if known.")
    exit_code: int | None = Field(default=None, description="Process termination exit code, if known.")
    
    # Forensic Flags
    is_synthesized: bool = Field(default=False, description="True if generated as placeholder for missing parent.")
    is_orphaned: bool = Field(default=False, description="True if root parent cannot be resolved.")
    is_anomalous: bool = Field(default=False, description="True if flagged by LineageAnomalyDetector.")
    anomaly_reasons: list[str] = Field(default_factory=list, description="Descriptions of triggered anomaly rules.")
```

### 2.3 Graph Traversal & Ancestry Algorithms

NetworkX provides efficient native graph operations. The `ProcessTreeGraph` wrapper provides dedicated traversal methods:

```python
import networkx as nx

class ProcessTreeGraph:
    """Manages the in-memory NetworkX directed graph of process execution trees."""

    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()
        self._nodes: dict[str, ProcessNode] = {}

    def add_process(self, node: ProcessNode) -> None:
        """Add a process node to the graph and attach parent edge if parent is present."""
        self._nodes[node.process_guid] = node
        self._graph.add_node(node.process_guid, **node.model_dump())
        
        if node.parent_process_guid:
            self._graph.add_edge(node.parent_process_guid, node.process_guid)

    def get_parent(self, guid: str) -> ProcessNode | None:
        """Retrieve immediate parent node. Complexity: O(1)."""
        predecessors = list(self._graph.predecessors(guid))
        if not predecessors:
            return None
        return self._nodes.get(predecessors[0])

    def get_children(self, guid: str) -> list[ProcessNode]:
        """Retrieve direct child processes. Complexity: O(deg+(u))."""
        successors = self._graph.successors(guid)
        return [self._nodes[s] for s in successors if s in self._nodes]

    def get_ancestors_lineage(self, guid: str) -> list[ProcessNode]:
        """Return full ordered ancestry chain from oldest known root ancestor down to current node.
        
        Walks predecessor edges sequentially until reaching a root (in-degree == 0).
        Guarantees chronological execution order: [Root, Grandparent, Parent, Self].
        Complexity: O(depth), typically depth <= 10.
        """
        lineage: list[ProcessNode] = []
        curr = self._nodes.get(guid)
        while curr is not None:
            lineage.append(curr)
            curr = self.get_parent(curr.process_guid)
        return list(reversed(lineage))

    def get_descendants_tree(self, guid: str) -> list[ProcessNode]:
        """Return all transitive descendants (children, grandchildren, etc.) spawned by guid.
        
        Uses NetworkX BFS traversal to return nodes in generational order.
        Complexity: O(V + E) for the subgraph.
        """
        if guid not in self._graph:
            return []
        descendant_guids = nx.descendants(self._graph, guid)
        # Order by BFS distance from guid
        bfs_edges = nx.bfs_edges(self._graph, source=guid)
        ordered_guids = [v for _, v in bfs_edges]
        return [self._nodes[g] for g in ordered_guids if g in self._nodes]

    def get_roots(self) -> list[ProcessNode]:
        """Return all root nodes (in_degree == 0). Complexity: O(V)."""
        return [
            self._nodes[n] for n, in_degree in self._graph.in_degree()
            if in_degree == 0 and n in self._nodes
        ]

    def get_subtree(self, root_guid: str) -> "ProcessTreeGraph":
        """Extract isolated subgraph containing root_guid and all its descendants."""
        sub_nodes = {root_guid} | nx.descendants(self._graph, root_guid)
        sub_graph = ProcessTreeGraph()
        for g in sub_nodes:
            if g in self._nodes:
                sub_graph.add_process(self._nodes[g])
        return sub_graph
```

### 2.4 Graph Serialization Formats

Downstream consumers (Phase 8 Streamlit SOC dashboard, Cytoscape.js, Plotly, and JSON export) require standardized, portable serialization.

#### 1. Standard Dictionary (Node-Link Format)
Uses `nx.node_link_data(G)` with custom node attributes. Suitable for generic Python persistence and JSON exchange:

```python
def to_dict(self) -> dict[str, Any]:
    return nx.node_link_data(self._graph)
```

#### 2. Cytoscape JSON Format
Structured specifically for graph visualization engines like Cytoscape.js or Streamlit Cytoscape components:

```python
def to_cytoscape(self) -> list[dict[str, Any]]:
    """Serialize graph into Cytoscape elements list format."""
    elements: list[dict[str, Any]] = []
    
    for guid, node in self._nodes.items():
        elements.append({
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
                "command_line": node.command_line or "",
            }
        })
        
    for source, target in self._graph.edges():
        elements.append({
            "data": {
                "id": f"{source}->{target}",
                "source": source,
                "target": target,
            }
        })
        
    return elements
```

#### 3. D3 / Hierarchical Tree Format
Nested JSON structure (`{name, attributes, children: [...]}`) utilized by D3 collapsible trees, Plotly Sunburst, or Treemap components:

```python
def to_d3_tree(self, root_guid: str) -> dict[str, Any]:
    """Serialize a single process tree hierarchy rooted at root_guid into nested D3 JSON."""
    node = self._nodes[root_guid]
    children = self.get_children(root_guid)
    
    return {
        "name": node.image.split("\\")[-1],
        "guid": node.process_guid,
        "pid": node.process_id,
        "command_line": node.command_line,
        "is_anomalous": node.is_anomalous,
        "is_synthesized": node.is_synthesized,
        "children": [self.to_d3_tree(child.process_guid) for child in children]
    }
```

---

## 3. Synthetic Process GUID Determinism (Decision D-01)

### 3.1 The Problem: Telemetry Source Disparity

- **Sysmon (EID 1, 5, etc.):** Natively generates a globally unique identifier per process instance, e.g., `{a23b7e71-419b-6435-0000-0010c2653300}`. Sysmon's driver embeds hardware/boot session identifiers into the GUID, ensuring uniqueness across reboots and PID recycling.
- **Windows Security Auditing (EID 4688):** Process creation events in the Security log record `NewProcessId` (hex or decimal PID), `ProcessId` (Creator PID), `NewProcessName` (Image path), `CommandLine`, and `TimeCreated`. However, Windows Security **never** records a GUID.
- **Consequence:** Without a unified process key, events from Windows Security logs cannot participate in parent-child graph reconstruction, cannot link to subsequent network/registry events, and cannot be evaluated by the same correlation pipeline.

### 3.2 Specification of Deterministic Synthetic GUID (UUID5)

Decision **D-01** mandates the generation of deterministic synthetic GUIDs using UUID Version 5 (SHA-1 hashing of a namespace and name string):

$$\text{SyntheticGUID} = \text{UUID5}(\text{NAMESPACE\_DNS}, \text{CanonicalName})$$

Where $\text{CanonicalName}$ is strictly formatted as:
$$\text{CanonicalName} = \text{computer}.\text{lower}().\text{strip}() + ":" + \text{str}(\text{pid}) + ":" + \text{timestamp\_iso}$$

#### Strict Timestamp Canonicalization Rules:
To guarantee 100% determinism across disparate ingestion runs:
1. Timestamp must be normalized to UTC (`timezone.utc`).
2. Subsecond fraction must be standardized to microsecond precision (`%Y-%m-%dT%H:%M:%S.%f+00:00`).
3. If subseconds are omitted in source telemetry, pad with `.000000`.

#### Python Implementation:

```python
import uuid
from datetime import datetime, timezone

def generate_synthetic_process_guid(
    computer: str,
    process_id: int,
    timestamp: datetime
) -> str:
    """Generate a deterministic UUID5 process GUID for events lacking native Sysmon GUIDs.
    
    Follows Decision D-01:
    UUID5(NAMESPACE_DNS, f"{computer.lower().strip()}:{pid}:{timestamp_iso}")
    """
    if timestamp.tzinfo is None:
        utc_dt = timestamp.replace(tzinfo=timezone.utc)
    else:
        utc_dt = timestamp.astimezone(timezone.utc)
        
    iso_str = utc_dt.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
    norm_computer = computer.strip().lower()
    canonical_name = f"{norm_computer}:{process_id}:{iso_str}"
    
    synthetic_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, canonical_name)
    # Return formatted with standard curly braces matching Sysmon convention
    return f"{{{str(synthetic_uuid).lower()}}}"
```

#### Collision Analysis:
- UUID5 utilizes SHA-1 truncation to 128 bits with standard version/variant bitmasks.
- The probability of collision across millions of events within a single computer domain is less than $10^{-18}$, completely negligible for endpoint forensic logs.
- Determinism ensures that re-importing the same EVTX file or running incremental imports produces identical GUIDs, preserving idempotent database storage.

---

## 4. Kernel PID Recycling & Temporal Lifespan Disambiguation (Decision D-03)

### 4.1 The Windows PID Recycling Phenomenon

Windows operating system PIDs:
- Are multiples of 4 (e.g., 4, 1024, 4096, 5212).
- Range from 4 up to kernel configured limits (default 65,535 or larger).
- Are aggressively reused by the Windows kernel as soon as an existing process terminates and all outstanding handle references (from other processes) are closed.
- In long-running host telemetry (e.g. 24 hours of logs), high-frequency background worker PIDs (like `conhost.exe`, `werfault.exe`, `backgroundTaskHost.exe`) can recycle the same numerical PID 50+ times.

```
Time ------------------------------------------------------------------------>
PID 4096: [== svchost.exe ==] (terminates)
                                   ... (gap) ...
PID 4096:                                          [== powershell.exe ==]
```

A flat lookup by `(computer, PID)` produces false linkages (e.g., falsely attributing child processes of `powershell.exe` to the earlier `svchost.exe`).

### 4.2 Temporal Lifespan Model

Every process entity exists within a temporal interval:
$$I(P) = [T_{\text{start}}, T_{\text{end}})$$

- **Creation Event (Sysmon EID 1, Sec EID 4688):** Establishes $T_{\text{start}} = \text{event.timestamp}$.
- **Termination Event (Sysmon EID 5):** Establishes $T_{\text{end}} = \text{event.timestamp}$ and records `exit_code`.
- **Active / Unterminated Process:** If no termination event has been observed, $T_{\text{end}} = +\infty$ (`None`).
- **Implicit Termination on Collision:** If a new process creation event arrives for the exact same `(computer, PID)` at timestamp $T_{\text{new}} > T_{\text{start}}$, and the prior process had $T_{\text{end}} = \text{None}$, the OS must have terminated the prior process before $T_{\text{new}}$. Thus, the prior process is retroactively capped at $T_{\text{end}} = T_{\text{new}}$.

### 4.3 In-Memory Temporal Indexing (`TemporalPIDResolver`)

For high-throughput resolution during stream ingestion, the analyzer maintains an in-memory sorted interval map:
$$\text{Map}: (\text{computer}, \text{PID}) \longrightarrow \text{SortedList}\big( [T_{\text{start}}, T_{\text{end}}, \text{ProcessNode}] \big)$$

#### Efficient Lookup via Binary Search:
Because the list of lifespans per `(computer, PID)` is kept sorted by $T_{\text{start}}$, locating the active process at any arbitrary query timestamp $T_{\text{query}}$ takes $O(\log k)$ time via `bisect`:

```python
import bisect
from datetime import datetime
from typing import NamedTuple

class ProcessLifespan(NamedTuple):
    start_time: datetime
    end_time: datetime | None
    node: ProcessNode

class TemporalPIDResolver:
    """Resolves (computer, pid, timestamp) tuples to exact unique ProcessNode instances."""

    def __init__(self) -> None:
        # Key: (computer.lower(), pid) -> list of ProcessLifespan sorted by start_time
        self._index: dict[tuple[str, int], list[ProcessLifespan]] = {}

    def register_process_creation(self, node: ProcessNode) -> None:
        """Register a new process creation and cap any prior unterminated instance."""
        key = (node.computer.lower(), node.process_id)
        lifespans = self._index.setdefault(key, [])
        
        # Check if previous instance was unterminated and cap it
        if lifespans:
            last = lifespans[-1]
            if last.end_time is None or last.end_time > node.start_time:
                # Prior process implicitly terminated when new PID created
                lifespans[-1] = ProcessLifespan(
                    start_time=last.start_time,
                    end_time=node.start_time,
                    node=last.node
                )
                
        lifespans.append(ProcessLifespan(
            start_time=node.start_time,
            end_time=node.end_time,
            node=node
        ))

    def register_process_termination(
        self,
        computer: str,
        pid: int,
        termination_time: datetime,
        process_guid: str | None = None
    ) -> ProcessNode | None:
        """Update termination timestamp on active matching process lifespan."""
        key = (computer.lower(), pid)
        lifespans = self._index.get(key)
        if not lifespans:
            return None
            
        # If process_guid is known, match exact node
        if process_guid:
            for idx in reversed(range(len(lifespans))):
                item = lifespans[idx]
                if item.node.process_guid == process_guid:
                    lifespans[idx] = ProcessLifespan(
                        start_time=item.start_time,
                        end_time=termination_time,
                        node=item.node
                    )
                    return item.node
                    
        # Otherwise match the most recent active lifespan
        for idx in reversed(range(len(lifespans))):
            item = lifespans[idx]
            if item.start_time <= termination_time and (item.end_time is None or item.end_time >= termination_time):
                lifespans[idx] = ProcessLifespan(
                    start_time=item.start_time,
                    end_time=termination_time,
                    node=item.node
                )
                return item.node
        return None

    def resolve(
        self,
        computer: str,
        pid: int,
        timestamp: datetime
    ) -> ProcessNode | None:
        """Locate the exact process instance that owned PID on computer at timestamp.
        
        Evaluates start_time <= timestamp <= (end_time or infinity).
        Complexity: O(log k) using binary search.
        """
        key = (computer.lower(), pid)
        lifespans = self._index.get(key)
        if not lifespans:
            return None
            
        # Binary search for rightmost lifespan with start_time <= timestamp
        starts = [item.start_time for item in lifespans]
        idx = bisect.bisect_right(starts, timestamp) - 1
        
        if idx >= 0:
            candidate = lifespans[idx]
            if candidate.start_time <= timestamp:
                if candidate.end_time is None or candidate.end_time >= timestamp:
                    return candidate.node
        return None
```

---

## 5. Missing Parent & Orphan Synthesis (Decision D-02)

### 5.1 The Missing Parent Problem

In forensic investigations of exported EVTX logs, event collection boundaries cause unavoidable gaps:
1. **Pre-Collection Inception:** Long-running system services (`services.exe`, `explorer.exe`, `svchost.exe`) or interactive applications (`WINWORD.EXE`) may have been launched hours or days before the exported log window starts.
2. **Log Wrap / Rotation:** Under heavy event volume, older process creation events (EID 1) roll over and are overwritten.
3. **Partial Event Subsets:** Analysts frequently export filtered or isolated time segments.

When a child event arrives (e.g., `cmd.exe` spawned by `WINWORD.EXE`), the child record contains:
- `process_guid`: `{CHILD-GUID}`
- `parent_process_guid`: `{PARENT-GUID-OFFICE}`
- `parent_image`: `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`
- `parent_process_id`: 5432
- `parent_command_line`: `"C:\Program Files\...\WINWORD.EXE" /n "invoice.docm"`
- `parent_user`: `CORP\victim`

If the analyzer only creates nodes for explicit process creation events, `{PARENT-GUID-OFFICE}` does not exist in the graph. Naive graph construction fails:
- Calling `get_ancestors("{CHILD-GUID}")` raises `KeyError` or returns an empty list.
- Anomaly rules checking parentage cannot access `parent_image` or parent attributes.
- The process appears as a disconnected, isolated node.

### 5.2 Synthetic Placeholder Parent Construction

Decision **D-02** dictates that whenever a process event references a `parent_process_guid` not present in the graph, the analyzer dynamically instantiates a **synthesized placeholder parent node**:

```python
def synthesize_parent_node(child_event: NormalizedEvent) -> ProcessNode:
    """Construct a placeholder parent node populated from child's parent metadata.
    
    Adheres to Decision D-02:
    is_synthesized=True, is_orphaned=True.
    """
    parent_guid = child_event.parent_process_guid
    if not parent_guid:
        # If non-Sysmon child lacks parent_process_guid, generate synthetic GUID
        parent_guid = generate_synthetic_process_guid(
            computer=child_event.computer,
            process_id=child_event.parent_process_id or 0,
            timestamp=child_event.timestamp
        )

    return ProcessNode(
        process_guid=parent_guid,
        process_id=child_event.parent_process_id or 0,
        computer=child_event.computer,
        image=child_event.parent_image or "UNKNOWN_PARENT.EXE",
        command_line=child_event.parent_command_line,
        user=child_event.parent_user or child_event.user,
        integrity_level=None,
        parent_process_guid=None, # Synthesized root
        parent_process_id=None,
        parent_image=None,
        parent_command_line=None,
        start_time=child_event.timestamp, # Estimated baseline
        end_time=None,
        exit_code=None,
        is_synthesized=True,
        is_orphaned=True,
        is_anomalous=False,
        anomaly_reasons=[],
    )
```

#### Reconciling Synthesized Nodes on Late Arrival:
If an out-of-order or late-arriving log subsequently supplies the genuine creation event for `{PARENT-GUID-OFFICE}`:
- The genuine event overwrites the synthesized placeholder.
- `is_synthesized` changes from `True` to `False`.
- The exact `start_time`, `command_line`, and parentage of the newly revealed ancestor are updated.
- Existing edges pointing to child processes remain valid and unbroken.

---

## 6. Suspicious Lineage Detection Matrix (Decision D-04)

### 6.1 Threat Landscape & Living-off-the-Land (LotL)

Modern attackers rarely bring custom compiled binaries to victim endpoints for initial execution. Instead, they exploit legitimate software to spawn native command interpreters, scripting hosts, and administration tools. 

Decision **D-04** establishes a built-in, extensible heuristic detection matrix targeting the most prevalent execution chains seen in cyber attacks.

### 6.2 Anomaly Data Model (`LineageAnomaly`)

```python
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict

class AnomalySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class LineageAnomaly(BaseModel):
    """Structured detection finding produced by LineageAnomalyDetector."""
    
    model_config = ConfigDict(frozen=True, extra="forbid")
    
    rule_id: str = Field(description="Unique rule identifier (e.g. LIN-OFFICE-SHELL).")
    rule_name: str = Field(description="Human-readable rule name.")
    severity: AnomalySeverity = Field(description="Finding severity rating.")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score (0.0 to 1.0).")
    mitre_tactics: list[str] = Field(description="Associated MITRE ATT&CK tactics.")
    mitre_techniques: list[str] = Field(description="Associated MITRE ATT&CK technique IDs.")
    
    # Process Context
    computer: str = Field(description="Host where execution occurred.")
    parent_guid: str = Field(description="Parent process GUID.")
    parent_image: str = Field(description="Parent process executable path.")
    parent_command_line: str | None = Field(default=None, description="Parent command line.")
    child_guid: str = Field(description="Child process GUID.")
    child_image: str = Field(description="Child process executable path.")
    child_command_line: str | None = Field(default=None, description="Child command line.")
    child_pid: int = Field(description="Child process PID.")
    timestamp: datetime = Field(description="Execution timestamp.")
    
    # Explainability & Triage Guidance
    explanation: str = Field(description="Detailed explanation of why this lineage is suspicious.")
    investigation_guidance: str = Field(description="Actionable SOC triage steps.")
```

### 6.3 Comprehensive MITRE ATT&CK Lineage Matrix

The table below defines the core anomalous lineage rules:

| Rule ID | Rule Name | Parent Images | Child Images | Severity | MITRE Tactic / Technique | Triage Context / Rationale |
|---|---|---|---|---|---|---|
| **LIN-OFFICE-SHELL** | Office Application Spawning Shell/Script Host | `winword.exe`, `excel.exe`, `powerpnt.exe`, `outlook.exe`, `onenote.exe`, `msaccess.exe`, `visio.exe`, `publisher.exe` | `cmd.exe`, `powershell.exe`, `pwsh.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `certutil.exe`, `bitsadmin.exe`, `curl.exe`, `rundll32.exe`, `regsvr32.exe`, `cpl.exe` | **CRITICAL** | Initial Access, Execution<br>`T1204.002`, `T1059.001`, `T1059.003`, `T1059.005` | Weaponized macro documents (VBA/Excel 4.0), CVE exploits (Follina, Equation Editor) spawning shells for payload delivery. |
| **LIN-PDF-SHELL** | PDF Viewer Spawning Script Interpreter | `acrord32.exe`, `acrobat.exe`, `foxitreader.exe` | `cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe` | **HIGH** | Initial Access, Execution<br>`T1204.002`, `T1059` | Malicious embedded PDF actions (JavaScript `/Launch`) executing external system interpreters. |
| **LIN-WEBSHELL** | Web Application Server Spawning Shell | `w3wp.exe`, `httpd.exe`, `nginx.exe`, `tomcat.exe`, `tomcat8.exe`, `tomcat9.exe`, `tomcat10.exe`, `java.exe`, `php-cgi.exe` | `cmd.exe`, `powershell.exe`, `pwsh.exe`, `whoami.exe`, `bash.exe`, `sh.exe`, `net.exe` | **CRITICAL** | Persistence, Execution<br>`T1190`, `T1505.003` | Classic web shell indicator (ProxyLogon, Log4Shell, webshell uploads executing interactive OS commands). |
| **LIN-SPOOLSV-EXEC** | Print Spooler Service Spawning Shell | `spoolsv.exe` | `cmd.exe`, `powershell.exe`, `rundll32.exe`, `regsvr32.exe` | **CRITICAL** | Privilege Escalation, Execution<br>`T1068`, `T1059` | Exploitation of Windows Print Spooler vulnerabilities (PrintNightmare CVE-2021-34527, CVE-2021-1675). |
| **LIN-SQL-SHELL** | Database Server Spawning Command Shell | `sqlservr.exe`, `mysqld.exe`, `postgres.exe`, `oracle.exe` | `cmd.exe`, `powershell.exe`, `cscript.exe`, `wscript.exe` | **CRITICAL** | Execution<br>`T1059`, `T1190` | Abuse of database stored procedures (`xp_cmdshell`) or SQL injection leading to remote code execution. |
| **LIN-SUSP-RECON** | Host Reconnaissance from Non-Standard Parent | Spooler, Web servers, Office apps, or background service hosts | `whoami.exe`, `nltest.exe`, `quser.exe`, `systeminfo.exe`, `net.exe`, `net1.exe`, `klist.exe`, `route.exe` | **HIGH** | Discovery<br>`T1033`, `T1082`, `T1087`, `T1018` | Situational awareness / post-compromise enumeration commands executed immediately after gaining initial access. |

### 6.4 Implementation Architecture: `LineageAnomalyDetector`

The detector evaluates process nodes during graph ingestion. When a rule triggers, it updates the node's `is_anomalous` flag and records the structured `LineageAnomaly`:

```python
from pathlib import PureWindowsPath

class LineageAnomalyDetector:
    """Evaluates parent-child process pairs against known suspicious execution patterns."""

    def __init__(self) -> None:
        self.rules: list[dict[str, Any]] = [
            {
                "rule_id": "LIN-OFFICE-SHELL",
                "name": "Office Application Spawning Shell/Script Host",
                "severity": AnomalySeverity.CRITICAL,
                "confidence": 0.95,
                "mitre_tactics": ["Initial Access", "Execution"],
                "mitre_techniques": ["T1204.002", "T1059.001", "T1059.003", "T1059.005"],
                "parents": {
                    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                    "onenote.exe", "msaccess.exe", "visio.exe", "publisher.exe"
                },
                "children": {
                    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                    "cscript.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
                    "curl.exe", "rundll32.exe", "regsvr32.exe", "cpl.exe"
                },
                "explanation": (
                    "A Microsoft Office application spawned a command interpreter or script engine. "
                    "This is a high-confidence indicator of malicious macro execution, weaponized template injection, "
                    "or application vulnerability exploitation."
                ),
                "guidance": (
                    "Inspect the parent document path from command_line or recent files. "
                    "Analyze subsequent child process activity and network connections. "
                    "Quarantine host if unexpected."
                )
            },
            # Additional rules (LIN-PDF-SHELL, LIN-WEBSHELL, LIN-SPOOLSV-EXEC, etc.)
        ]

    def evaluate_edge(self, parent: ProcessNode, child: ProcessNode) -> list[LineageAnomaly]:
        """Evaluate a parent-child relationship against anomaly rules."""
        anomalies: list[LineageAnomaly] = []
        
        parent_exe = PureWindowsPath(parent.image).name.lower()
        child_exe = PureWindowsPath(child.image).name.lower()
        
        for rule in self.rules:
            if parent_exe in rule["parents"] and child_exe in rule["children"]:
                anomaly = LineageAnomaly(
                    rule_id=rule["rule_id"],
                    rule_name=rule["name"],
                    severity=rule["severity"],
                    confidence=rule["confidence"],
                    mitre_tactics=rule["mitre_tactics"],
                    mitre_techniques=rule["mitre_techniques"],
                    computer=child.computer,
                    parent_guid=parent.process_guid,
                    parent_image=parent.image,
                    parent_command_line=parent.command_line,
                    child_guid=child.process_guid,
                    child_image=child.image,
                    child_command_line=child.command_line,
                    child_pid=child.process_id,
                    timestamp=child.start_time,
                    explanation=rule["explanation"],
                    investigation_guidance=rule["guidance"]
                )
                anomalies.append(anomaly)
                
        return anomalies
```

---

## 7. SQLite Process Table Synchronization & Database Integration

### 7.1 Relational Schema Analysis (`processes` Table)

In Phase 2, `001_initial_schema.sql` provisioned the base `processes` table:

```sql
CREATE TABLE IF NOT EXISTS processes (
    process_guid TEXT PRIMARY KEY,
    process_id INTEGER NOT NULL,
    image TEXT NOT NULL,
    command_line TEXT,
    current_directory TEXT,
    user TEXT,
    integrity_level TEXT,
    parent_process_guid TEXT REFERENCES processes(process_guid) ON DELETE SET NULL,
    parent_process_id INTEGER,
    parent_image TEXT,
    parent_command_line TEXT,
    start_time TEXT NOT NULL,
    end_time TEXT,
    exit_code INTEGER,
    is_orphaned INTEGER NOT NULL DEFAULT 0,
    is_anomalous INTEGER NOT NULL DEFAULT 0,
    anomaly_reasons_json TEXT
);
```

### 7.2 Schema Migration 002: Process Metadata Enhancements

To support multi-host enterprise telemetry and track synthesized parent placeholders, two attributes must be added to the schema:
1. `computer TEXT NOT NULL DEFAULT 'UNKNOWN'` — Scopes processes by host for multi-endpoint investigations.
2. `is_synthesized INTEGER NOT NULL DEFAULT 0` — Distinguishes genuine process creation telemetry from synthesized placeholder parent nodes.

#### Migration Script: `app/database/migrations/002_process_lineage_metadata.sql`

```sql
-- 002_process_lineage_metadata.sql
-- Add computer hostname scoping and is_synthesized tracking to processes table.

ALTER TABLE processes ADD COLUMN computer TEXT NOT NULL DEFAULT 'UNKNOWN';
ALTER TABLE processes ADD COLUMN is_synthesized INTEGER NOT NULL DEFAULT 0;

-- Additional triage indexes for multi-host graph queries
CREATE INDEX IF NOT EXISTS idx_processes_comp_guid ON processes(computer, process_guid);
CREATE INDEX IF NOT EXISTS idx_processes_comp_pid ON processes(computer, process_id, start_time);
CREATE INDEX IF NOT EXISTS idx_processes_anomalous ON processes(is_anomalous);
```

The transactional `MigrationRunner` developed in Phase 2 will automatically discover, checksum-validate, and apply this migration.

### 7.3 `ProcessRepository` Design

Phase 2 established the repository pattern in `app/database/repository.py`. Phase 3 introduces a dedicated `ProcessRepository` to manage relational persistence and batch synchronization of reconstructed process nodes:

```python
import json
import sqlite3
from datetime import datetime
from app.database.connection import DatabaseManager
from app.models.process import ProcessNode

class ProcessRepository:
    """Manages SQLite persistence for reconstructed process nodes and lifespans."""

    def __init__(self, db_manager: DatabaseManager) -> None:
        self.db_manager = db_manager

    def upsert_process(self, conn: sqlite3.Connection, node: ProcessNode) -> None:
        """Insert or update a process record idempotently."""
        conn.execute(
            """
            INSERT INTO processes (
                process_guid, process_id, computer, image, command_line,
                current_directory, user, integrity_level, parent_process_guid,
                parent_process_id, parent_image, parent_command_line,
                start_time, end_time, exit_code, is_synthesized,
                is_orphaned, is_anomalous, anomaly_reasons_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(process_guid) DO UPDATE SET
                end_time = coalesce(excluded.end_time, processes.end_time),
                exit_code = coalesce(excluded.exit_code, processes.exit_code),
                is_synthesized = CASE 
                    WHEN processes.is_synthesized = 1 AND excluded.is_synthesized = 0 THEN 0 
                    ELSE processes.is_synthesized 
                END,
                image = CASE 
                    WHEN processes.is_synthesized = 1 AND excluded.is_synthesized = 0 THEN excluded.image 
                    ELSE processes.image 
                END,
                is_anomalous = max(processes.is_anomalous, excluded.is_anomalous),
                anomaly_reasons_json = excluded.anomaly_reasons_json;
            """,
            (
                node.process_guid,
                node.process_id,
                node.computer,
                node.image,
                node.command_line,
                node.current_directory,
                node.user,
                node.integrity_level,
                node.parent_process_guid,
                node.parent_process_id,
                node.parent_image,
                node.parent_command_line,
                node.start_time.isoformat(),
                node.end_time.isoformat() if node.end_time else None,
                node.exit_code,
                1 if node.is_synthesized else 0,
                1 if node.is_orphaned else 0,
                1 if node.is_anomalous else 0,
                json.dumps(node.anomaly_reasons),
            )
        )

    def upsert_processes_batch(self, nodes: list[ProcessNode]) -> None:
        """Batch insert or update process records in atomic 1,000-row transactions."""
        with self.db_manager.get_connection() as conn:
            for node in nodes:
                self.upsert_process(conn, node)

    def get_process_by_guid(self, process_guid: str) -> ProcessNode | None:
        """Retrieve a single ProcessNode by GUID."""
        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM processes WHERE process_guid = ?;", (process_guid,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_node(row)

    def get_processes_by_computer(self, computer: str) -> list[ProcessNode]:
        """Retrieve all processes for a given host to reconstruct the host graph."""
        with self.db_manager.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM processes WHERE computer = ? ORDER BY start_time ASC;",
                (computer,)
            )
            return [self._row_to_node(row) for row in cursor.fetchall()]

    def _row_to_node(self, row: sqlite3.Row) -> ProcessNode:
        return ProcessNode(
            process_guid=row["process_guid"],
            process_id=row["process_id"],
            computer=row["computer"] if "computer" in row.keys() else "UNKNOWN",
            image=row["image"],
            command_line=row["command_line"],
            current_directory=row["current_directory"],
            user=row["user"],
            integrity_level=row["integrity_level"],
            parent_process_guid=row["parent_process_guid"],
            parent_process_id=row["parent_process_id"],
            parent_image=row["parent_image"],
            parent_command_line=row["parent_command_line"],
            start_time=datetime.fromisoformat(row["start_time"]),
            end_time=datetime.fromisoformat(row["end_time"]) if row["end_time"] else None,
            exit_code=row["exit_code"],
            is_synthesized=bool(row["is_synthesized"]) if "is_synthesized" in row.keys() else False,
            is_orphaned=bool(row["is_orphaned"]),
            is_anomalous=bool(row["is_anomalous"]),
            anomaly_reasons=json.loads(row["anomaly_reasons_json"]) if row["anomaly_reasons_json"] else [],
        )
```

---

## 8. Requirements Traceability & Verification Criteria

| Requirement | Scope Description | Architectural Solution | Verification Test Strategy |
|---|---|---|---|
| **PROC-01** | Reconstruct process ancestry tree using Sysmon `ProcessGuid` and `ParentProcessGuid` as primary keys. | `ProcessTreeGraph` with NetworkX DiGraph where edges represent `parent_guid -> child_guid`. Native Sysmon GUIDs prioritized; non-Sysmon events receive deterministic UUID5. | Multi-generational test tree (`Grandparent -> Parent -> Child -> Grandchild`). Assert `get_ancestors()` returns ordered list from root to child. |
| **PROC-02** | Handle PID reuse gracefully by scoping temporal process lifespans (creation EID 1 to termination EID 5). | `TemporalPIDResolver` maintains sorted intervals `[start_time, end_time]` per `(computer, PID)`. `resolve()` matches `start_time <= query_time <= end_time`. | Two distinct processes sharing PID 4096 four hours apart. Assert querying at $T_1$ returns first process; querying at $T_2$ returns second process. |
| **PROC-03** | Detect and handle orphaned processes and missing parent process records. | `synthesize_parent_node()` creates placeholder nodes (`is_synthesized=True`, `is_orphaned=True`) populated from child's parent metadata. Continuous graph connectivity preserved. | Ingest child process whose parent creation event is omitted. Assert parent exists as synthesized node, ancestry traversal succeeds, no exceptions. |
| **PROC-04** | Flag anomalous parent-child execution lineages (e.g., Office apps spawning `cmd.exe`/`powershell.exe`, web servers spawning shell interpreters). | `LineageAnomalyDetector` with MITRE ATT&CK matrix covering T1059, T1204, T1190, T1068. Produces structured `LineageAnomaly` records. | Unit test with Word spawning PowerShell, Spooler spawning cmd, and web server spawning whoami. Assert anomalous flags and MITRE technique tags. Assert benign parentage (`explorer.exe` -> `notepad.exe`) passes clean. |
| **PROC-05** | Export process hierarchy into NetworkX digraph representation for graph queries and visualization. | `ProcessTreeGraph` exports to `to_dict()` (Node-Link), `to_cytoscape()` (Cytoscape JSON), and `to_d3_tree()` (Hierarchical JSON). | Unit test serializing graph; validate JSON schema, node count, edge count, and attributes for downstream Phase 8 Streamlit rendering. |

---

## 9. Phase 3 Work Breakdown & Execution Plan

To ensure modular, test-driven implementation, Phase 3 is structured into two sequential execution plans:

### Plan 03-01: Graph Model, Invariant Resolution, PID Resolver & Persistence
- **Scope:**
  1. Add `networkx>=3.0` to `pyproject.toml` dependencies.
  2. Implement `ProcessNode` Pydantic model (`app/models/process.py`).
  3. Implement deterministic synthetic GUID generator (`app/utils/guid.py`).
  4. Implement `TemporalPIDResolver` for temporal PID reuse handling (`app/analyzers/pid_resolver.py`).
  5. Implement `ProcessTreeGraph` with NetworkX DiGraph ancestry walker (`app/analyzers/process_tree.py`).
  6. Implement Migration `002_process_lineage_metadata.sql` and `ProcessRepository` in `app/database/repository.py`.
  7. Comprehensive unit tests covering multi-generational trees, PID reuse disambiguation, synthetic parent synthesis, and SQLite persistence.

### Plan 03-02: Lineage Anomaly Detector, Serialization & Pipeline Integration
- **Scope:**
  1. Implement `LineageAnomaly` model and `LineageAnomalyDetector` with MITRE matrix (`app/analyzers/lineage_detector.py`).
  2. Implement graph serialization formats (`to_dict()`, `to_cytoscape()`, `to_d3_tree()`).
  3. Integrate Process Relationship Analyzer into `IngestionPipeline` (process creation/termination event hooks, automated process table sync).
  4. Integration tests verifying end-to-end log parsing -> process tree reconstruction -> anomaly detection -> SQLite persistence.

---

## 10. Conclusion

Phase 3 transitions WinSentinel from event-by-event log analysis to high-fidelity, graph-backed process execution hierarchy reconstruction. By resolving telemetry disparity with deterministic UUID5 identifiers, isolating OS PID reuse via temporal lifespan intervals, repairing missing parents through synthetic placeholders, and scanning for anomalous lineages across the MITRE ATT&CK matrix, WinSentinel establishes the essential contextual foundation required for downstream detection rules (Phase 4), PowerShell/persistence analyzers (Phase 5), and multi-event correlation (Phase 6).

## RESEARCH COMPLETE
