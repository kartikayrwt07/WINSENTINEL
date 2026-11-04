"""Unit tests for process tree graph model, synthetic GUID generation, and ancestry traversal."""

from __future__ import annotations

import tomllib
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.analyzers.process_analyzer import (
    ProcessNode,
    ProcessTreeGraph,
    generate_synthetic_guid,
    generate_synthetic_process_guid,
)
from app.models.events import EventCategory, NormalizedEvent


def test_pyproject_contains_networkx_dependency() -> None:
    """Verify pyproject.toml specifies networkx>=3.0 dependency."""
    pyproject_path = Path("pyproject.toml")
    assert pyproject_path.exists()
    content = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    deps = content.get("project", {}).get("dependencies", [])
    has_networkx = any("networkx" in dep for dep in deps)
    assert has_networkx, "networkx>=3.0 missing from pyproject.toml dependencies"


def test_process_node_validation_and_immutability() -> None:
    """Verify ProcessNode validates fields, sets defaults, and enforces frozen immutability."""
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    node = ProcessNode(
        process_guid="{guid-1}",
        process_id=1234,
        computer="WORKSTATION01",
        image=r"C:\Windows\System32\cmd.exe",
        start_time=t0,
    )

    assert node.process_guid == "{guid-1}"
    assert node.process_id == 1234
    assert node.computer == "WORKSTATION01"
    assert node.image == r"C:\Windows\System32\cmd.exe"
    assert node.command_line is None
    assert node.hashes == {}
    assert node.anomaly_reasons == []
    assert not node.is_synthesized
    assert not node.is_orphaned
    assert not node.is_anomalous
    assert node.start_time.tzinfo == timezone.utc

    # Verify frozen immutability
    with pytest.raises(ValidationError):
        node.is_anomalous = True  # type: ignore[misc]

    # Verify extra fields forbidden
    with pytest.raises(ValidationError):
        ProcessNode(
            process_guid="{guid-1}",
            process_id=1234,
            computer="WORKSTATION01",
            image=r"C:\Windows\System32\cmd.exe",
            start_time=t0,
            unknown_attr="invalid",  # type: ignore[call-arg]
        )


def test_generate_synthetic_guid_determinism() -> None:
    """Verify deterministic UUID5 generation using (computer, pid, timestamp)."""
    t0 = datetime(2026, 11, 4, 10, 0, 0, 123456, tzinfo=timezone.utc)
    guid1 = generate_synthetic_guid("WORKSTATION01", 4096, t0)
    guid2 = generate_synthetic_guid("workstation01  ", 4096, t0)
    assert guid1 == guid2
    assert guid1.startswith("{") and guid1.endswith("}")
    assert guid1.islower()
    assert len(guid1) == 38  # 36 uuid chars + 2 braces

    # Distinct computer produces distinct GUID
    guid_diff_comp = generate_synthetic_guid("SERVER02", 4096, t0)
    assert guid_diff_comp != guid1

    # Distinct PID produces distinct GUID
    guid_diff_pid = generate_synthetic_guid("WORKSTATION01", 5000, t0)
    assert guid_diff_pid != guid1

    # Distinct timestamp produces distinct GUID
    t1 = datetime(2026, 11, 4, 10, 0, 1, 123456, tzinfo=timezone.utc)
    guid_diff_time = generate_synthetic_guid("WORKSTATION01", 4096, t1)
    assert guid_diff_time != guid1

    # Alias check
    assert generate_synthetic_process_guid("WORKSTATION01", 4096, t0) == guid1


def test_process_tree_graph_add_and_queries() -> None:
    """Verify adding nodes, edge creation, parent and child lookups."""
    tree = ProcessTreeGraph()
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)

    parent = ProcessNode(
        process_guid="{parent-guid}",
        process_id=1000,
        computer="HOST01",
        image=r"C:\Windows\explorer.exe",
        start_time=t0,
    )
    child = ProcessNode(
        process_guid="{child-guid}",
        process_id=2000,
        computer="HOST01",
        image=r"C:\Windows\System32\cmd.exe",
        parent_process_guid="{parent-guid}",
        parent_process_id=1000,
        start_time=t0,
    )

    tree.add_process(parent)
    tree.add_process(child)

    assert tree.node_count == 2
    assert tree.edge_count == 1
    assert tree.get_node("{parent-guid}") == parent
    assert tree.get_node("{child-guid}") == child

    # Parent lookup
    assert tree.get_parent("{child-guid}") == parent
    assert tree.get_parent("{parent-guid}") is None
    assert tree.get_parent("{non-existent}") is None

    # Children lookup
    children = tree.get_children("{parent-guid}")
    assert len(children) == 1
    assert children[0] == child
    assert tree.get_children("{child-guid}") == []


def test_process_tree_out_of_order_parent_arrival() -> None:
    """Verify child added before parent properly links when parent arrives later."""
    tree = ProcessTreeGraph()
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)

    child = ProcessNode(
        process_guid="{child-guid}",
        process_id=2000,
        computer="HOST01",
        image=r"C:\Windows\System32\cmd.exe",
        parent_process_guid="{parent-guid}",
        parent_process_id=1000,
        start_time=t0,
    )
    parent = ProcessNode(
        process_guid="{parent-guid}",
        process_id=1000,
        computer="HOST01",
        image=r"C:\Windows\explorer.exe",
        start_time=t0,
    )

    # Add child first
    tree.add_process(child)
    assert tree.node_count == 1
    assert tree.edge_count == 0
    assert tree.get_parent("{child-guid}") is None

    # Add parent second
    tree.add_process(parent)
    assert tree.node_count == 2
    assert tree.edge_count == 1
    assert tree.get_parent("{child-guid}") == parent
    assert tree.get_children("{parent-guid}") == [child]


def test_process_tree_multi_generational_lineage_and_descendants() -> None:
    """Verify multi-generational ancestry walk and generational BFS descendant extraction."""
    tree = ProcessTreeGraph()
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)

    # Root -> Grandparent -> Parent -> Child -> Grandchild
    root = ProcessNode(
        process_guid="{root}",
        process_id=100,
        computer="HOST01",
        image=r"C:\Windows\System32\services.exe",
        start_time=t0,
    )
    grandparent = ProcessNode(
        process_guid="{gp}",
        process_id=200,
        computer="HOST01",
        image=r"C:\Windows\System32\svchost.exe",
        parent_process_guid="{root}",
        start_time=t0,
    )
    parent = ProcessNode(
        process_guid="{parent}",
        process_id=300,
        computer="HOST01",
        image=r"C:\Program Files\App\worker.exe",
        parent_process_guid="{gp}",
        start_time=t0,
    )
    child1 = ProcessNode(
        process_guid="{child1}",
        process_id=401,
        computer="HOST01",
        image=r"C:\Windows\System32\cmd.exe",
        parent_process_guid="{parent}",
        start_time=t0,
    )
    child2 = ProcessNode(
        process_guid="{child2}",
        process_id=402,
        computer="HOST01",
        image=r"C:\Windows\System32\powershell.exe",
        parent_process_guid="{parent}",
        start_time=t0,
    )
    grandchild = ProcessNode(
        process_guid="{gc}",
        process_id=500,
        computer="HOST01",
        image=r"C:\Windows\System32\whoami.exe",
        parent_process_guid="{child1}",
        start_time=t0,
    )

    for n in [root, grandparent, parent, child1, child2, grandchild]:
        tree.add_process(n)

    # Ancestors lineage for grandchild: [Root, Grandparent, Parent, Child1, Grandchild]
    lineage = tree.get_ancestors_lineage("{gc}")
    assert [n.process_guid for n in lineage] == ["{root}", "{gp}", "{parent}", "{child1}", "{gc}"]

    # Ancestors lineage for root: [Root]
    assert [n.process_guid for n in tree.get_ancestors_lineage("{root}")] == ["{root}"]

    # Descendants of parent in BFS order: [child1, child2, grandchild]
    descendants = tree.get_descendants_tree("{parent}")
    desc_guids = [n.process_guid for n in descendants]
    assert desc_guids == ["{child1}", "{child2}", "{gc}"]

    # Roots discovery
    roots = tree.get_roots()
    assert len(roots) == 1
    assert roots[0] == root


def test_process_tree_get_subtree() -> None:
    """Verify get_subtree extracts isolated subgraph without dangling references."""
    tree = ProcessTreeGraph()
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)

    r1 = ProcessNode(process_guid="{r1}", process_id=10, computer="H", image="r1.exe", start_time=t0)
    c1 = ProcessNode(process_guid="{c1}", process_id=20, computer="H", image="c1.exe", parent_process_guid="{r1}", start_time=t0)
    r2 = ProcessNode(process_guid="{r2}", process_id=30, computer="H", image="r2.exe", start_time=t0)

    for n in [r1, c1, r2]:
        tree.add_process(n)

    subtree = tree.get_subtree("{r1}")
    assert subtree.node_count == 2
    assert subtree.edge_count == 1
    assert subtree.get_node("{r1}") == r1
    assert subtree.get_node("{c1}") == c1
    assert subtree.get_node("{r2}") is None


def test_build_from_events_with_synthetic_guids_and_synthesized_parents() -> None:
    """Verify build_from_events handles Sysmon EID 1, Sec 4688, EID 5, and parent synthesis."""
    tree = ProcessTreeGraph()
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 4, 10, 5, 0, tzinfo=timezone.utc)

    # Event 1: Sysmon EID 1 with missing parent event
    child_event = NormalizedEvent(
        event_id=1,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="WORKSTATION01",
        timestamp=t0,
        event_category=EventCategory.PROCESS,
        event_type="PROCESS_CREATE",
        process_guid="{child-guid}",
        process_id=4000,
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        parent_process_guid="{missing-parent-guid}",
        parent_process_id=2000,
        parent_image=r"C:\Program Files\Office\winword.exe",
        parent_command_line=r'"winword.exe" invoice.docm',
        parent_user=r"CORP\victim",
        raw_payload="<xml>payload</xml>",
        event_hash="hash-child-1",
    )

    # Event 2: Non-Sysmon Security EID 4688 lacking process_guid
    sec_event = NormalizedEvent(
        event_id=4688,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        computer="WORKSTATION01",
        timestamp=t0,
        event_category=EventCategory.PROCESS,
        event_type="PROCESS_CREATE",
        process_guid=None,  # No GUID!
        process_id=5000,
        image=r"C:\Windows\System32\whoami.exe",
        parent_process_guid="{child-guid}",
        parent_process_id=4000,
        raw_payload="<xml>sec payload</xml>",
        event_hash="hash-sec-1",
    )

    # Event 3: Sysmon EID 5 Process Termination for child_event
    term_event = NormalizedEvent(
        event_id=5,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="WORKSTATION01",
        timestamp=t1,
        event_category=EventCategory.PROCESS,
        event_type="PROCESS_TERMINATE",
        process_guid="{child-guid}",
        process_id=4000,
        extra_fields={"ExitCode": "0x0"},
        raw_payload="<xml>term payload</xml>",
        event_hash="hash-term-1",
    )

    added, synthesized = tree.build_from_events([child_event, sec_event, term_event])

    # child_event added 1 child, 1 synthesized parent. sec_event added 1 child. Total added: 2, synthesized: 1
    assert added == 2
    assert synthesized == 1
    assert tree.node_count == 3  # synthesized parent, child, sec child

    # Check synthesized parent
    synth_parent = tree.get_node("{missing-parent-guid}")
    assert synth_parent is not None
    assert synth_parent.is_synthesized
    assert synth_parent.is_orphaned
    assert synth_parent.image == r"C:\Program Files\Office\winword.exe"
    assert synth_parent.user == r"CORP\victim"

    # Check child termination update
    child_node = tree.get_node("{child-guid}")
    assert child_node is not None
    assert child_node.end_time == t1
    assert child_node.exit_code == 0

    # Check sec event synthetic GUID was assigned and connected to child
    sec_node_guid = generate_synthetic_guid("WORKSTATION01", 5000, t0)
    sec_node = tree.get_node(sec_node_guid)
    assert sec_node is not None
    assert sec_node.parent_process_guid == "{child-guid}"
    assert tree.get_parent(sec_node_guid) == child_node


def test_process_tree_serialization_formats() -> None:
    """Verify to_dict, to_cytoscape, and to_d3_tree serialization."""
    tree = ProcessTreeGraph()
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    root = ProcessNode(process_guid="{root}", process_id=1, computer="H", image=r"C:\r.exe", start_time=t0)
    child = ProcessNode(process_guid="{child}", process_id=2, computer="H", image=r"C:\c.exe", parent_process_guid="{root}", start_time=t0)
    tree.add_process(root)
    tree.add_process(child)

    # 1. to_dict
    d = tree.to_dict()
    assert "nodes" in d
    assert "links" in d or "edges" in d

    # 2. to_cytoscape
    cy = tree.to_cytoscape()
    node_elements = [el for el in cy if "source" not in el["data"]]
    edge_elements = [el for el in cy if "source" in el["data"]]
    assert len(node_elements) == 2
    assert len(edge_elements) == 1
    assert edge_elements[0]["data"]["source"] == "{root}"
    assert edge_elements[0]["data"]["target"] == "{child}"

    # 3. to_d3_tree
    d3 = tree.to_d3_tree("{root}")
    assert d3["guid"] == "{root}"
    assert len(d3["children"]) == 1
    assert d3["children"][0]["guid"] == "{child}"
