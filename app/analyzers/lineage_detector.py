"""Suspicious parent-child process lineage anomaly detector for WinSentinel."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from pathlib import PureWindowsPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.analyzers.process_analyzer import ProcessNode, ProcessTreeGraph

logger = logging.getLogger(__name__)


class AnomalySeverity(str, Enum):
    """Severity ratings for detected process lineage anomalies."""

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
    timestamp: datetime = Field(description="Execution timestamp (UTC).")

    # Explainability & Triage Guidance
    explanation: str = Field(description="Detailed explanation of why this lineage is suspicious.")
    investigation_guidance: str = Field(description="Actionable SOC triage steps.")

    @field_validator("timestamp", mode="after")
    @classmethod
    def _ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)


class LineageRule(BaseModel):
    """Definition of a parent-child execution heuristic matching rule."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    name: str
    severity: AnomalySeverity
    confidence: float = Field(ge=0.0, le=1.0)
    mitre_tactics: list[str]
    mitre_techniques: list[str]
    parents: set[str]
    children: set[str]
    explanation: str
    guidance: str


# Core suspicious parent executables across Office, PDF, Web servers, spooler, and database
_OFFICE_PARENTS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "onenote.exe", "msaccess.exe", "visio.exe", "publisher.exe", "mspub.exe",
}
_PDF_PARENTS = {"acrord32.exe", "acrobat.exe", "foxitreader.exe"}
_WEB_PARENTS = {
    "w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe",
    "tomcat8.exe", "tomcat9.exe", "tomcat10.exe", "java.exe", "php-cgi.exe",
}
_SPOOLER_PARENTS = {"spoolsv.exe"}
_SQL_PARENTS = {"sqlservr.exe", "mysqld.exe", "postgres.exe", "oracle.exe"}

_RECON_PARENTS = _OFFICE_PARENTS | _PDF_PARENTS | _WEB_PARENTS | _SPOOLER_PARENTS | _SQL_PARENTS

DEFAULT_LINEAGE_RULES: list[LineageRule] = [
    LineageRule(
        rule_id="LIN-OFFICE-SHELL",
        name="Office Application Spawning Shell/Script Host",
        severity=AnomalySeverity.CRITICAL,
        confidence=0.95,
        mitre_tactics=["Initial Access", "Execution"],
        mitre_techniques=["T1204.002", "T1059.001", "T1059.003", "T1059.005"],
        parents={p.lower() for p in _OFFICE_PARENTS},
        children={
            "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
            "cscript.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe",
            "curl.exe", "rundll32.exe", "regsvr32.exe", "cpl.exe", "control.exe",
        },
        explanation=(
            "A Microsoft Office application spawned a command interpreter or script engine. "
            "This is a high-confidence indicator of malicious macro execution, weaponized template injection, "
            "or application vulnerability exploitation."
        ),
        guidance=(
            "Inspect the parent document path from command_line or recent files. "
            "Analyze subsequent child process activity and network connections. "
            "Quarantine host if unexpected."
        ),
    ),
    LineageRule(
        rule_id="LIN-PDF-SHELL",
        name="PDF Viewer Spawning Script Interpreter",
        severity=AnomalySeverity.HIGH,
        confidence=0.90,
        mitre_tactics=["Initial Access", "Execution"],
        mitre_techniques=["T1204.002", "T1059"],
        parents={p.lower() for p in _PDF_PARENTS},
        children={
            "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
            "cscript.exe", "mshta.exe",
        },
        explanation=(
            "A PDF document viewer spawned a command interpreter or script host. "
            "Malicious embedded PDF actions (JavaScript /Launch) commonly exploit viewers to achieve initial code execution."
        ),
        guidance=(
            "Identify the PDF document opened by the user. "
            "Check for child process network activity or payload downloads."
        ),
    ),
    LineageRule(
        rule_id="LIN-WEBSHELL",
        name="Web Application Server Spawning Shell",
        severity=AnomalySeverity.CRITICAL,
        confidence=0.95,
        mitre_tactics=["Persistence", "Execution"],
        mitre_techniques=["T1190", "T1505.003"],
        parents={p.lower() for p in _WEB_PARENTS},
        children={
            "cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe",
            "bash.exe", "sh.exe", "net.exe",
        },
        explanation=(
            "A web application server or worker process spawned a shell or interactive administrative utility. "
            "This pattern strongly indicates server-side exploitation, web shell deployment, or remote command injection."
        ),
        guidance=(
            "Inspect web access logs matching the timestamp. "
            "Check file creations in web server document roots or temporary directories. "
            "Isolate affected host immediately."
        ),
    ),
    LineageRule(
        rule_id="LIN-SPOOLSV-EXEC",
        name="Print Spooler Service Spawning Shell",
        severity=AnomalySeverity.CRITICAL,
        confidence=0.95,
        mitre_tactics=["Privilege Escalation", "Execution"],
        mitre_techniques=["T1068", "T1059"],
        parents={p.lower() for p in _SPOOLER_PARENTS},
        children={
            "cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe",
            "regsvr32.exe",
        },
        explanation=(
            "Windows Print Spooler (spoolsv.exe) spawned a command shell or execution proxy. "
            "This is characteristic of PrintNightmare (CVE-2021-34527, CVE-2021-1675) or printer driver exploitation."
        ),
        guidance=(
            "Review spooler driver directory for unauthorized DLLs. "
            "Verify if Print Spooler service was recently restarted or had driver updates. "
            "Terminate rogue child processes."
        ),
    ),
    LineageRule(
        rule_id="LIN-SQL-SHELL",
        name="Database Server Spawning Command Shell",
        severity=AnomalySeverity.CRITICAL,
        confidence=0.90,
        mitre_tactics=["Execution"],
        mitre_techniques=["T1059", "T1190"],
        parents={p.lower() for p in _SQL_PARENTS},
        children={
            "cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe",
            "wscript.exe",
        },
        explanation=(
            "A database server process spawned a command shell or script host. "
            "This often indicates SQL injection exploitation or abuse of extended stored procedures (e.g. xp_cmdshell)."
        ),
        guidance=(
            "Review database query audit logs for recent xp_cmdshell executions or sysadmin privileges. "
            "Examine child process command line and connections."
        ),
    ),
    LineageRule(
        rule_id="LIN-SUSP-RECON",
        name="Host Reconnaissance from Non-Standard Parent",
        severity=AnomalySeverity.HIGH,
        confidence=0.85,
        mitre_tactics=["Discovery"],
        mitre_techniques=["T1033", "T1082", "T1087", "T1018"],
        parents={p.lower() for p in _RECON_PARENTS},
        children={
            "whoami.exe", "nltest.exe", "quser.exe", "systeminfo.exe",
            "net.exe", "net1.exe", "klist.exe", "route.exe",
        },
        explanation=(
            "A suspicious non-standard parent process (Office, Web server, Database, or Spooler) spawned a system "
            "discovery or reconnaissance utility. Adversaries execute these utilities post-exploitation for host and network situational awareness."
        ),
        guidance=(
            "Investigate preceding commands of parent process. "
            "Correlate with subsequent lateral movement or credential access."
        ),
    ),
]


class LineageAnomalyDetector:
    """Evaluates parent-child process pairs against known suspicious execution patterns."""

    def __init__(
        self,
        custom_rules: list[dict[str, Any] | LineageRule] | None = None,
    ) -> None:
        self.rules: list[LineageRule] = list(DEFAULT_LINEAGE_RULES)

        if custom_rules:
            for r in custom_rules:
                if isinstance(r, LineageRule):
                    self.rules.append(r)
                elif isinstance(r, dict):
                    # Convert dict to LineageRule, normalizing parent/children to lowercase
                    parents = {str(p).lower() for p in r.get("parents", set())}
                    children = {str(c).lower() for c in r.get("children", set())}
                    sev = r.get("severity", AnomalySeverity.MEDIUM)
                    if isinstance(sev, str):
                        sev = AnomalySeverity(sev.upper())
                    rule = LineageRule(
                        rule_id=r["rule_id"],
                        name=r.get("name", r["rule_id"]),
                        severity=sev,
                        confidence=float(r.get("confidence", 0.8)),
                        mitre_tactics=list(r.get("mitre_tactics", [])),
                        mitre_techniques=list(r.get("mitre_techniques", [])),
                        parents=parents,
                        children=children,
                        explanation=r.get("explanation", "Custom lineage anomaly rule triggered."),
                        guidance=r.get("guidance", "Investigate process relationship context."),
                    )
                    self.rules.append(rule)

    @staticmethod
    def _extract_basename(path_or_name: str | None) -> str:
        """Extract lowercase binary filename from executable path."""
        if not path_or_name:
            return ""
        # PureWindowsPath handles both Windows and POSIX path separators cleanly
        return PureWindowsPath(path_or_name).name.lower()

    def evaluate_edge(self, parent: ProcessNode, child: ProcessNode) -> list[LineageAnomaly]:
        """Evaluate a parent-child relationship against anomaly rules."""
        anomalies: list[LineageAnomaly] = []

        parent_exe = self._extract_basename(parent.image)
        child_exe = self._extract_basename(child.image)

        if not parent_exe or not child_exe:
            return anomalies

        for rule in self.rules:
            if parent_exe in rule.parents and child_exe in rule.children:
                anomaly = LineageAnomaly(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    mitre_tactics=rule.mitre_tactics,
                    mitre_techniques=rule.mitre_techniques,
                    computer=child.computer,
                    parent_guid=parent.process_guid,
                    parent_image=parent.image,
                    parent_command_line=parent.command_line,
                    child_guid=child.process_guid,
                    child_image=child.image,
                    child_command_line=child.command_line,
                    child_pid=child.process_id,
                    timestamp=child.start_time,
                    explanation=rule.explanation,
                    investigation_guidance=rule.guidance,
                )
                anomalies.append(anomaly)

        return anomalies

    # Alias for method name in requirements/prompts
    evaluate_relationship = evaluate_edge

    def evaluate_graph(self, tree: ProcessTreeGraph) -> list[LineageAnomaly]:
        """Evaluate all edges in a ProcessTreeGraph, tag anomalous nodes, and return findings."""
        if not tree._graph.edges:
            return []

        all_anomalies: list[LineageAnomaly] = []

        # Iterate over all directed edges (parent_guid, child_guid) in graph
        for parent_guid, child_guid in list(tree._graph.edges()):
            parent_node = tree.get_node(parent_guid)
            child_node = tree.get_node(child_guid)

            if parent_node is None or child_node is None:
                continue

            edge_anomalies = self.evaluate_edge(parent_node, child_node)
            if edge_anomalies:
                all_anomalies.extend(edge_anomalies)

                # Update child node with anomalous flag and reasons
                new_reasons = list(child_node.anomaly_reasons)
                for anomaly in edge_anomalies:
                    reason_entry = f"[{anomaly.rule_id}] {anomaly.rule_name}"
                    if reason_entry not in new_reasons:
                        new_reasons.append(reason_entry)

                updated_child = child_node.model_copy(
                    update={
                        "is_anomalous": True,
                        "anomaly_reasons": new_reasons,
                    }
                )
                tree.add_process(updated_child)

        return all_anomalies

    # Alias for method name in requirements/prompts
    evaluate_tree = evaluate_graph
