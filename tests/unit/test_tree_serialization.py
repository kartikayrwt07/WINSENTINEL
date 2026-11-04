"""Unit tests for ProcessTreeGraph serialization formats: Node-Link, Cytoscape, and D3 Hierarchy."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from app.analyzers.process_analyzer import ProcessNode, ProcessTreeGraph


def _sample_graph() -> ProcessTreeGraph:
    """Helper to build a 3-generation test process tree."""
    tree = ProcessTreeGraph()
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 4, 10, 15, 0, tzinfo=timezone.utc)

    explorer = ProcessNode(
        process_guid="{guid-explorer}",
        process_id=1000,
        computer="WORKSTATION01",
        image=r"C:\Windows\explorer.exe",
        command_line="C:\\Windows\\explorer.exe",
        user=r"CORP\alice",
        start_time=t0,
    )
    word = ProcessNode(
        process_guid="{guid-word}",
        process_id=2000,
        computer="WORKSTATION01",
        image=r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
        command_line=r'"WINWORD.EXE" invoice.docx',
        user=r"CORP\alice",
        parent_process_guid="{guid-explorer}",
        parent_process_id=1000,
        parent_image=explorer.image,
        start_time=t0,
    )
    cmd = ProcessNode(
        process_guid="{guid-cmd}",
        process_id=3000,
        computer="WORKSTATION01",
        image=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c whoami",
        user=r"CORP\alice",
        parent_process_guid="{guid-word}",
        parent_process_id=2000,
        parent_image=word.image,
        start_time=t0,
        end_time=t1,
        exit_code=0,
        is_anomalous=True,
        anomaly_reasons=["[LIN-OFFICE-SHELL] Office Application Spawning Shell"],
    )

    tree.add_process(explorer)
    tree.add_process(word)
    tree.add_process(cmd)
    return tree


def test_to_dict_node_link_format():
    """Verify to_dict returns valid NetworkX node-link dictionary."""
    tree = _sample_graph()
    d = tree.to_dict()

    assert isinstance(d, dict)
    assert "nodes" in d
    assert "links" in d or "edges" in d

    link_key = "links" if "links" in d else "edges"
    assert len(d["nodes"]) == 3
    assert len(d[link_key]) == 2

    # Check node structure
    explorer_node = next(n for n in d["nodes"] if n["id"] == "{guid-explorer}")
    assert explorer_node["process_id"] == 1000
    assert explorer_node["image"] == r"C:\Windows\explorer.exe"

    # JSON roundtrip
    dumped = json.dumps(d)
    assert "{guid-explorer}" in dumped


def test_to_cytoscape_elements_format():
    """Verify to_cytoscape returns Cytoscape.js compatible node and edge elements."""
    tree = _sample_graph()
    cy = tree.to_cytoscape()

    assert isinstance(cy, list)
    nodes = [e for e in cy if "source" not in e["data"]]
    edges = [e for e in cy if "source" in e["data"]]

    assert len(nodes) == 3
    assert len(edges) == 2

    # Check node attributes
    cmd_element = next(n for n in nodes if n["data"]["id"] == "{guid-cmd}")
    assert cmd_element["data"]["label"] == "cmd.exe"
    assert cmd_element["data"]["pid"] == 3000
    assert cmd_element["data"]["is_anomalous"] is True
    assert cmd_element["data"]["user"] == r"CORP\alice"
    assert cmd_element["data"]["end_time"] is not None

    # Check edge attributes
    edge_pairs = {(e["data"]["source"], e["data"]["target"]) for e in edges}
    assert ("{guid-explorer}", "{guid-word}") in edge_pairs
    assert ("{guid-word}", "{guid-cmd}") in edge_pairs

    # JSON roundtrip
    dumped = json.dumps(cy)
    loaded = json.loads(dumped)
    assert len(loaded) == 5


def test_to_d3_tree_with_root_guid():
    """Verify to_d3_tree(root_guid) returns correct nested hierarchical JSON."""
    tree = _sample_graph()
    d3 = tree.to_d3_tree("{guid-explorer}")

    assert isinstance(d3, dict)
    assert d3["name"] == "explorer.exe"
    assert d3["guid"] == "{guid-explorer}"
    assert len(d3["children"]) == 1

    word_child = d3["children"][0]
    assert word_child["name"] == "WINWORD.EXE"
    assert word_child["guid"] == "{guid-word}"
    assert len(word_child["children"]) == 1

    cmd_child = word_child["children"][0]
    assert cmd_child["name"] == "cmd.exe"
    assert cmd_child["guid"] == "{guid-cmd}"
    assert cmd_child["is_anomalous"] is True
    assert cmd_child["children"] == []

    # JSON roundtrip
    dumped = json.dumps(d3)
    assert "explorer.exe" in dumped


def test_to_d3_tree_without_root_guid():
    """Verify to_d3_tree() with no root_guid returns list of trees for all roots."""
    tree = _sample_graph()
    # Add another distinct root
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    services = ProcessNode(
        process_guid="{guid-services}",
        process_id=600,
        computer="WORKSTATION01",
        image=r"C:\Windows\System32\services.exe",
        start_time=t0,
    )
    svchost = ProcessNode(
        process_guid="{guid-svchost}",
        process_id=800,
        computer="WORKSTATION01",
        image=r"C:\Windows\System32\svchost.exe",
        parent_process_guid="{guid-services}",
        start_time=t0,
    )
    tree.add_process(services)
    tree.add_process(svchost)

    roots_trees = tree.to_d3_tree()
    assert isinstance(roots_trees, list)
    assert len(roots_trees) == 2

    root_names = {t["name"] for t in roots_trees}
    assert "explorer.exe" in root_names
    assert "services.exe" in root_names

    dumped = json.dumps(roots_trees)
    assert "services.exe" in dumped


def test_empty_graph_and_single_node_serialization():
    """Verify serialization behavior on empty and single-node graphs."""
    empty_tree = ProcessTreeGraph()
    assert empty_tree.to_dict()["nodes"] == []
    assert empty_tree.to_cytoscape() == []
    assert empty_tree.to_d3_tree() == []
    assert empty_tree.to_d3_tree("{non-existent}") == {}

    single_tree = ProcessTreeGraph()
    single_node = ProcessNode(
        process_guid="{single}",
        process_id=1,
        computer="HOST",
        image="test.exe",
        start_time=datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc),
    )
    single_tree.add_process(single_node)

    assert len(single_tree.to_dict()["nodes"]) == 1
    cy = single_tree.to_cytoscape()
    assert len(cy) == 1
    assert cy[0]["data"]["label"] == "test.exe"

    d3 = single_tree.to_d3_tree("{single}")
    assert d3["guid"] == "{single}"
    assert d3["children"] == []

    d3_all = single_tree.to_d3_tree()
    assert isinstance(d3_all, list)
    assert len(d3_all) == 1
    assert d3_all[0]["guid"] == "{single}"


def test_d3_tree_cycle_resilience():
    """Verify to_d3_tree does not enter an infinite recursion loop if cycle exists."""
    tree = ProcessTreeGraph()
    t0 = datetime(2026, 11, 4, 10, 0, 0, tzinfo=timezone.utc)
    node1 = ProcessNode(
        process_guid="{n1}",
        process_id=1,
        computer="H",
        image="p1.exe",
        start_time=t0,
    )
    node2 = ProcessNode(
        process_guid="{n2}",
        process_id=2,
        computer="H",
        image="p2.exe",
        parent_process_guid="{n1}",
        start_time=t0,
    )
    tree.add_process(node1)
    tree.add_process(node2)

    # Intentionally add a cyclic back-edge in underlying graph
    tree._graph.add_edge("{n2}", "{n1}")

    # Must terminate without RecursionError
    d3 = tree.to_d3_tree("{n1}")
    assert d3["guid"] == "{n1}"
    assert len(d3["children"]) == 1
    assert d3["children"][0]["guid"] == "{n2}"
    # The back-link to n1 terminates as a leaf with empty children
    assert len(d3["children"][0]["children"]) == 1
    assert d3["children"][0]["children"][0]["guid"] == "{n1}"
    assert d3["children"][0]["children"][0]["children"] == []
