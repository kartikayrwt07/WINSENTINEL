"""Unit tests for Suspicious Parent-Child Lineage Anomaly Detector."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.analyzers.lineage_detector import (
    AnomalySeverity,
    LineageAnomaly,
    LineageAnomalyDetector,
    LineageRule,
)
from app.analyzers.process_analyzer import ProcessNode, ProcessTreeGraph


def _make_node(
    guid: str,
    pid: int,
    image: str,
    command_line: str = "",
    parent_guid: str | None = None,
    parent_pid: int | None = None,
    parent_image: str | None = None,
    start_time: datetime | None = None,
    computer: str = "WORKSTATION01",
) -> ProcessNode:
    """Helper to construct valid test ProcessNode."""
    return ProcessNode(
        process_guid=guid,
        process_id=pid,
        computer=computer,
        image=image,
        command_line=command_line,
        parent_process_guid=parent_guid,
        parent_process_id=parent_pid,
        parent_image=parent_image,
        start_time=start_time or datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc),
    )


def test_anomaly_severity_enum():
    """Verify AnomalySeverity contains all specified enum levels."""
    assert AnomalySeverity.CRITICAL == "CRITICAL"
    assert AnomalySeverity.HIGH == "HIGH"
    assert AnomalySeverity.MEDIUM == "MEDIUM"
    assert AnomalySeverity.LOW == "LOW"


def test_lineage_anomaly_immutability_and_validation():
    """Verify LineageAnomaly model validation and frozen immutability."""
    ts = datetime(2026, 11, 4, 12, 30, 0, tzinfo=timezone.utc)
    anomaly = LineageAnomaly(
        rule_id="LIN-OFFICE-SHELL",
        rule_name="Office Application Spawning Shell/Script Host",
        severity=AnomalySeverity.CRITICAL,
        confidence=0.95,
        mitre_tactics=["Initial Access", "Execution"],
        mitre_techniques=["T1204.002", "T1059.001"],
        computer="ENDPOINT01",
        parent_guid="{parent-guid-1111}",
        parent_image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        parent_command_line=r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" invoice.docm',
        child_guid="{child-guid-2222}",
        child_image=r"C:\Windows\System32\powershell.exe",
        child_command_line=r"powershell.exe -enc SQBFAFgA...",
        child_pid=4096,
        timestamp=ts,
        explanation="Word spawned PowerShell.",
        investigation_guidance="Inspect parent document.",
    )

    assert anomaly.severity == AnomalySeverity.CRITICAL
    assert anomaly.confidence == 0.95
    assert anomaly.child_pid == 4096

    # Verify frozen immutability
    with pytest.raises(ValidationError):
        anomaly.confidence = 0.5  # type: ignore

    # Verify extra fields forbidden
    with pytest.raises(ValidationError):
        LineageAnomaly(
            rule_id="TEST",
            rule_name="Test",
            severity=AnomalySeverity.LOW,
            confidence=0.5,
            mitre_tactics=[],
            mitre_techniques=[],
            computer="HOST",
            parent_guid="p",
            parent_image="p.exe",
            child_guid="c",
            child_image="c.exe",
            child_pid=1,
            timestamp=ts,
            explanation="exp",
            investigation_guidance="guide",
            unexpected_field="invalid",  # type: ignore
        )


def test_lin_office_shell_matrix():
    """Verify LIN-OFFICE-SHELL triggers for all office binaries spawning shell or script interpreters."""
    detector = LineageAnomalyDetector()

    office_binaries = [
        r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
        r"C:\Program Files\Microsoft Office\Office16\EXCEL.EXE",
        r"C:\Program Files\Microsoft Office\Office16\POWERPNT.EXE",
        r"C:\Program Files\Microsoft Office\Office16\OUTLOOK.EXE",
        r"C:\Program Files\Microsoft Office\Office16\ONENOTE.EXE",
        r"C:\Program Files\Microsoft Office\Office16\MSACCESS.EXE",
        r"C:\Program Files\Microsoft Office\Office16\VISIO.EXE",
        r"C:\Program Files\Microsoft Office\Office16\MSPUB.EXE",  # publisher.exe
        "publisher.exe",
    ]

    target_children = [
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\Windows\System32\wscript.exe",
        r"C:\Windows\System32\cscript.exe",
        r"C:\Windows\System32\mshta.exe",
        r"C:\Windows\System32\certutil.exe",
        r"C:\Windows\System32\bitsadmin.exe",
        r"C:\Windows\System32\curl.exe",
        r"C:\Windows\System32\rundll32.exe",
        r"C:\Windows\System32\regsvr32.exe",
        r"C:\Windows\System32\control.exe",  # cpl
        "cpl.exe",
    ]

    for office_exe in office_binaries:
        parent = _make_node(
            guid="{parent}",
            pid=1000,
            image=office_exe,
        )
        for child_exe in target_children:
            child = _make_node(
                guid="{child}",
                pid=2000,
                image=child_exe,
                parent_guid="{parent}",
                parent_pid=1000,
            )
            anomalies = detector.evaluate_edge(parent, child)
            assert len(anomalies) >= 1
            office_anomaly = next((a for a in anomalies if a.rule_id == "LIN-OFFICE-SHELL"), None)
            assert office_anomaly is not None
            assert office_anomaly.severity == AnomalySeverity.CRITICAL
            assert "T1204.002" in office_anomaly.mitre_techniques
            assert "T1059.001" in office_anomaly.mitre_techniques


def test_lin_pdf_shell_triggers():
    """Verify LIN-PDF-SHELL triggers when PDF viewers spawn script interpreters."""
    detector = LineageAnomalyDetector()

    pdf_viewers = [
        r"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe",
        r"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
        r"C:\Program Files\Foxit Software\Foxit PDF Reader\FoxitReader.exe",
    ]

    interpreters = [
        r"C:\Windows\System32\cmd.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows\System32\wscript.exe",
        r"C:\Windows\System32\cscript.exe",
        r"C:\Windows\System32\mshta.exe",
    ]

    for pdf_exe in pdf_viewers:
        parent = _make_node(guid="{p}", pid=100, image=pdf_exe)
        for interp_exe in interpreters:
            child = _make_node(guid="{c}", pid=200, image=interp_exe, parent_guid="{p}")
            anomalies = detector.evaluate_edge(parent, child)
            pdf_anomaly = next((a for a in anomalies if a.rule_id == "LIN-PDF-SHELL"), None)
            assert pdf_anomaly is not None
            assert pdf_anomaly.severity == AnomalySeverity.HIGH
            assert "T1204.002" in pdf_anomaly.mitre_techniques
            assert "T1059" in pdf_anomaly.mitre_techniques


def test_lin_webshell_triggers():
    """Verify LIN-WEBSHELL triggers when Web servers spawn command shells."""
    detector = LineageAnomalyDetector()

    web_servers = [
        r"C:\Windows\System32\inetsrv\w3wp.exe",
        r"C:\Apache24\bin\httpd.exe",
        r"C:\nginx\nginx.exe",
        r"C:\Tomcat\bin\tomcat.exe",
        r"C:\Tomcat8\bin\tomcat8.exe",
        r"C:\Tomcat9\bin\tomcat9.exe",
        r"C:\Tomcat10\bin\tomcat10.exe",
        r"C:\Program Files\Java\jdk-17\bin\java.exe",
        r"C:\PHP\php-cgi.exe",
    ]

    shells = [
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "whoami.exe",
        "bash.exe",
        "sh.exe",
        "net.exe",
    ]

    for web_exe in web_servers:
        parent = _make_node(guid="{p}", pid=111, image=web_exe)
        for shell in shells:
            child = _make_node(guid="{c}", pid=222, image=shell, parent_guid="{p}")
            anomalies = detector.evaluate_edge(parent, child)
            web_anomaly = next((a for a in anomalies if a.rule_id == "LIN-WEBSHELL"), None)
            assert web_anomaly is not None
            assert web_anomaly.severity == AnomalySeverity.CRITICAL
            assert "T1190" in web_anomaly.mitre_techniques
            assert "T1505.003" in web_anomaly.mitre_techniques


def test_lin_spoolsv_exec_triggers():
    """Verify LIN-SPOOLSV-EXEC triggers when spoolsv.exe spawns shells or execution proxies."""
    detector = LineageAnomalyDetector()

    parent = _make_node(guid="{p}", pid=500, image=r"C:\Windows\System32\spoolsv.exe")
    for child_exe in ["cmd.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe"]:
        child = _make_node(guid="{c}", pid=600, image=child_exe, parent_guid="{p}")
        anomalies = detector.evaluate_edge(parent, child)
        spool_anomaly = next((a for a in anomalies if a.rule_id == "LIN-SPOOLSV-EXEC"), None)
        assert spool_anomaly is not None
        assert spool_anomaly.severity == AnomalySeverity.CRITICAL
        assert "T1068" in spool_anomaly.mitre_techniques
        assert "T1059" in spool_anomaly.mitre_techniques


def test_lin_sql_shell_triggers():
    """Verify LIN-SQL-SHELL triggers when database processes spawn command shells."""
    detector = LineageAnomalyDetector()

    db_servers = [
        r"C:\Program Files\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQL\Binn\sqlservr.exe",
        r"C:\MySQL\bin\mysqld.exe",
        r"C:\Program Files\PostgreSQL\14\bin\postgres.exe",
        r"C:\oracle\product\19c\dbhome_1\bin\oracle.exe",
    ]

    for db_exe in db_servers:
        parent = _make_node(guid="{p}", pid=333, image=db_exe)
        for child_exe in ["cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe"]:
            child = _make_node(guid="{c}", pid=444, image=child_exe, parent_guid="{p}")
            anomalies = detector.evaluate_edge(parent, child)
            sql_anomaly = next((a for a in anomalies if a.rule_id == "LIN-SQL-SHELL"), None)
            assert sql_anomaly is not None
            assert sql_anomaly.severity == AnomalySeverity.CRITICAL
            assert "T1059" in sql_anomaly.mitre_techniques


def test_lin_susp_recon_triggers():
    """Verify LIN-SUSP-RECON triggers when non-standard parents spawn discovery utilities."""
    detector = LineageAnomalyDetector()

    recon_utils = [
        "whoami.exe",
        "nltest.exe",
        "quser.exe",
        "systeminfo.exe",
        "net.exe",
        "net1.exe",
        "klist.exe",
        "route.exe",
    ]

    parents = [
        r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
        r"C:\Windows\System32\spoolsv.exe",
        r"C:\Windows\System32\inetsrv\w3wp.exe",
        r"C:\MySQL\bin\mysqld.exe",
        r"C:\Adobe\AcroRd32.exe",
    ]

    for p_exe in parents:
        parent = _make_node(guid="{p}", pid=10, image=p_exe)
        for recon in recon_utils:
            child = _make_node(guid="{c}", pid=20, image=recon, parent_guid="{p}")
            anomalies = detector.evaluate_edge(parent, child)
            recon_anomaly = next((a for a in anomalies if a.rule_id == "LIN-SUSP-RECON"), None)
            assert recon_anomaly is not None
            assert recon_anomaly.severity == AnomalySeverity.HIGH
            assert "T1033" in recon_anomaly.mitre_techniques
            assert "T1082" in recon_anomaly.mitre_techniques


def test_benign_lineage_no_anomalies():
    """Verify normal benign parent-child lineages trigger 0 anomalies."""
    detector = LineageAnomalyDetector()

    benign_pairs = [
        (r"C:\Windows\explorer.exe", r"C:\Windows\System32\notepad.exe"),
        (r"C:\Windows\System32\services.exe", r"C:\Windows\System32\svchost.exe"),
        (r"C:\Windows\System32\svchost.exe", r"C:\Windows\System32\RuntimeBroker.exe"),
        (r"C:\Program Files\Git\cmd\git.exe", r"C:\Program Files\Git\bin\sh.exe"),
        (r"C:\Windows\explorer.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    ]

    for p_img, c_img in benign_pairs:
        p = _make_node(guid="{p}", pid=10, image=p_img)
        c = _make_node(guid="{c}", pid=20, image=c_img, parent_guid="{p}")
        anomalies = detector.evaluate_edge(p, c)
        assert len(anomalies) == 0


def test_evaluate_graph_updates_nodes_and_returns_anomalies():
    """Verify evaluate_graph tags ProcessNode in tree with is_anomalous=True and populates anomaly_reasons."""
    detector = LineageAnomalyDetector()
    tree = ProcessTreeGraph()

    word = _make_node(
        guid="{word-guid}",
        pid=1000,
        image=r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
        command_line="winword.exe test.doc",
    )
    ps = _make_node(
        guid="{ps-guid}",
        pid=2000,
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -w hidden -enc JAB...",
        parent_guid="{word-guid}",
        parent_pid=1000,
        parent_image=word.image,
    )
    whoami = _make_node(
        guid="{whoami-guid}",
        pid=3000,
        image=r"C:\Windows\System32\whoami.exe",
        command_line="whoami /priv",
        parent_guid="{word-guid}",  # Word directly spawned whoami
        parent_pid=1000,
        parent_image=word.image,
    )

    tree.add_process(word)
    tree.add_process(ps)
    tree.add_process(whoami)

    anomalies = detector.evaluate_graph(tree)
    assert len(anomalies) >= 2

    # Check that ps node was updated in the tree
    ps_updated = tree.get_node("{ps-guid}")
    assert ps_updated is not None
    assert ps_updated.is_anomalous is True
    assert any("LIN-OFFICE-SHELL" in reason for reason in ps_updated.anomaly_reasons)

    # Check that whoami node was updated
    whoami_updated = tree.get_node("{whoami-guid}")
    assert whoami_updated is not None
    assert whoami_updated.is_anomalous is True
    assert any("LIN-SUSP-RECON" in reason for reason in whoami_updated.anomaly_reasons)

    # Root word node itself is not marked anomalous as a child unless its parent was suspicious
    word_node = tree.get_node("{word-guid}")
    assert word_node is not None
    assert word_node.is_anomalous is False


def test_custom_rule_support():
    """Verify LineageAnomalyDetector supports user-defined custom rules."""
    custom = [
        {
            "rule_id": "CUSTOM-01",
            "name": "Custom Bad Parent",
            "severity": "CRITICAL",
            "confidence": 0.99,
            "mitre_tactics": ["Execution"],
            "mitre_techniques": ["T1059"],
            "parents": ["custom_parent.exe"],
            "children": ["custom_child.exe"],
            "explanation": "Custom threat indicator.",
            "guidance": "Custom triage steps.",
        }
    ]
    detector = LineageAnomalyDetector(custom_rules=custom)

    p = _make_node(guid="{p}", pid=1, image=r"C:\Tools\CUSTOM_PARENT.EXE")
    c = _make_node(guid="{c}", pid=2, image=r"C:\Tools\custom_child.exe", parent_guid="{p}")

    anomalies = detector.evaluate_edge(p, c)
    assert len(anomalies) == 1
    assert anomalies[0].rule_id == "CUSTOM-01"
    assert anomalies[0].severity == AnomalySeverity.CRITICAL
    assert anomalies[0].confidence == 0.99
