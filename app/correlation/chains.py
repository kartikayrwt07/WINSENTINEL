"""Declarative multi-stage attack chain definitions and stage predicates for WinSentinel.

Encapsulates 4 core enterprise intrusion chains:
1. CHAIN-PHISH-001: Malicious Document / Phishing Execution
2. CHAIN-WEBSHELL-001: Web Shell / Server Exploitation
3. CHAIN-CREDDUMP-LAT-001: Credential Dumping to Lateral Movement
4. CHAIN-LOTL-PERSIST-001: Living-off-the-Land Download to Persistence
"""

from __future__ import annotations

import ipaddress
from pathlib import PureWindowsPath
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.events import EventCategory, NormalizedEvent


# =============================================================================
# Helper Utilities & Normalizers
# =============================================================================

def _get_basename(path_or_image: str | None) -> str:
    """Extract lowercased binary filename from path."""
    if not path_or_image:
        return ""
    # Normalize slashes and extract basename
    clean = path_or_image.strip().replace("/", "\\")
    return PureWindowsPath(clean).name.lower()


def _is_private_rfc1918(ip_str: str | None) -> bool:
    """Return True if destination IP falls in RFC1918 private space and is not loopback."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_private and not ip.is_loopback
    except ValueError:
        return False


# =============================================================================
# Stage Predicate Functions
# =============================================================================

PHISHING_ROOT_BINARIES = frozenset({
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "acrobat.exe",
    "acrord32.exe",
    "eqnedt32.exe",
    "visio.exe",
    "msaccess.exe",
})

SCRIPT_INTERPRETER_BINARIES = frozenset({
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "mshta.exe",
    "cscript.exe",
    "wscript.exe",
    "certutil.exe",
    "bash.exe",
    "sh.exe",
    "wmic.exe",
    "rundll32.exe",
    "regsvr32.exe",
})

WEB_SERVER_BINARIES = frozenset({
    "w3wp.exe",
    "httpd.exe",
    "nginx.exe",
    "php-cgi.exe",
    "php.exe",
})

RECON_BINARIES = frozenset({
    "whoami.exe",
    "net.exe",
    "net1.exe",
    "nltest.exe",
    "quser.exe",
    "qwinsta.exe",
    "ipconfig.exe",
    "systeminfo.exe",
    "tasklist.exe",
    "nslookup.exe",
    "route.exe",
})

SUSPICIOUS_LSASS_ACCESS_MASKS = frozenset({
    "0x1010",
    "0x1038",
    "0x1410",
    "0x1fffff",
    "0x1000",
    "0x143a",
    "0x1438",
    "0x1f0fff",
    "0x1f1fff",
    "0x1f3fff",
})

SUSPICIOUS_FILE_EXTENSIONS = frozenset({
    ".exe",
    ".dll",
    ".vbs",
    ".ps1",
    ".bat",
    ".cmd",
    ".hta",
    ".scr",
    ".js",
    ".wsf",
})


def is_phishing_root(event: NormalizedEvent, context: dict[str, Any] | None = None) -> bool:
    """Stage predicate: Productivity software process creation."""
    base = _get_basename(event.image)
    if base in PHISHING_ROOT_BINARIES:
        return True
    return False


def is_script_interpreter(event: NormalizedEvent, context: dict[str, Any] | None = None) -> bool:
    """Stage predicate: Script or command interpreter execution."""
    base = _get_basename(event.image)
    if base in SCRIPT_INTERPRETER_BINARIES:
        return True
    return False


def is_egress_or_persistence(event: NormalizedEvent, context: dict[str, Any] | None = None) -> bool:
    """Stage predicate: Outbound non-loopback network egress, registry persistence, or scheduled task."""
    # 1. Outbound Network Connection (Sysmon EID 3)
    if event.event_id == 3 or event.event_category == EventCategory.NETWORK:
        dst = event.destination_ip
        if dst and dst != "127.0.0.1" and dst != "::1" and not dst.startswith("127."):
            return True

    # 2. Registry Persistence (Sysmon EID 12, 13, 14)
    if event.event_id in (12, 13, 14) or event.event_category == EventCategory.REGISTRY:
        target = (event.registry_target_object or "").lower()
        if any(k in target for k in (r"\run", r"\runonce", "image file execution options", "userinit", "winlogon")):
            return True

    # 3. Scheduled Task Creation (Security EID 4698) or Service Creation (4697)
    if event.event_id in (4698, 4697):
        return True

    # 4. Context alerts (e.g. from DetectionEngine or PowerShellThreatAnalyzer)
    if context and "alerts" in context:
        alerts = context["alerts"]
        for a in alerts:
            if isinstance(a, dict) and a.get("rule_id", "").startswith(("SYS-NET", "PWSH-", "PERSIST-")):
                return True

    return False


def is_web_server_root(event: NormalizedEvent, context: dict[str, Any] | None = None) -> bool:
    """Stage predicate: Web server daemon or application worker process."""
    base = _get_basename(event.image)
    if base in WEB_SERVER_BINARIES:
        return True
    if base.startswith("tomcat") and base.endswith(".exe"):
        return True
    if base == "java.exe":
        cmd = (event.command_line or "").lower()
        if any(w in cmd for w in ("tomcat", "catalina", "jetty", "weblogic", "websphere", "server", "spring-boot")):
            return True
    return False


def is_recon_command(event: NormalizedEvent, context: dict[str, Any] | None = None) -> bool:
    """Stage predicate: System and user discovery/reconnaissance utilities."""
    base = _get_basename(event.image)
    return base in RECON_BINARIES


def is_recon_or_persistence(event: NormalizedEvent, context: dict[str, Any] | None = None) -> bool:
    """Stage predicate: Reconnaissance command execution or persistence creation."""
    return is_recon_command(event, context) or is_persistence_installation(event, context)


def is_lsass_access(event: NormalizedEvent, context: dict[str, Any] | None = None) -> bool:
    """Stage predicate: Process access or thread injection targeting lsass.exe."""
    target_base = _get_basename(event.target_image)
    # Check if target is lsass.exe
    if target_base != "lsass.exe":
        # Also check target_filename or image in case field mapping varies
        if _get_basename(event.target_filename) != "lsass.exe":
            return False

    # Sysmon EID 10: ProcessAccess with suspicious granted access
    if event.event_id == 10 or event.event_category == EventCategory.PROCESS_ACCESS:
        mask = (event.granted_access or "").lower().strip()
        if mask in SUSPICIOUS_LSASS_ACCESS_MASKS:
            return True
        # Partial match if mask starts with 0x10 or 0x14 or 0x1f
        if any(mask.startswith(p) for p in ("0x101", "0x103", "0x141", "0x143", "0x1ff")):
            return True

    # Sysmon EID 8: CreateRemoteThread into lsass.exe
    if event.event_id == 8 or event.event_category == EventCategory.REMOTE_THREAD:
        return True

    return False


def is_rfc1918_egress_or_remote_exec(event: NormalizedEvent, context: dict[str, Any] | None = None) -> bool:
    """Stage predicate: Outbound connection to private RFC1918 space or remote service/task install."""
    # Outbound Network (Sysmon EID 3)
    if event.event_id == 3 or event.event_category == EventCategory.NETWORK:
        if _is_private_rfc1918(event.destination_ip):
            return True

    # Remote Service Install (Security EID 4697) or Task (4698)
    if event.event_id in (4697, 4698):
        return True

    return False


def is_lolbin_download(event: NormalizedEvent, context: dict[str, Any] | None = None) -> bool:
    """Stage predicate: Living-off-the-Land binary ingress download cradle."""
    base = _get_basename(event.image)
    cmd = (event.command_line or "").lower()

    if base == "certutil.exe":
        if "-urlcache" in cmd or "/urlcache" in cmd or "-split" in cmd or "/split" in cmd:
            return True

    if base == "bitsadmin.exe":
        if "/transfer" in cmd or "/create" in cmd or "/addfile" in cmd:
            return True

    if base in ("powershell.exe", "pwsh.exe"):
        script = (event.script_block_text or "").lower()
        combined = f"{cmd} {script}"
        if any(cradle in combined for cradle in ("downloadstring", "downloadfile", "invoke-webrequest", "iwr")):
            return True

    return False


def is_suspicious_file_drop(event: NormalizedEvent, context: dict[str, Any] | None = None) -> bool:
    """Stage predicate: File creation (Sysmon EID 11) in writable directory with executable extension."""
    if event.event_id != 11 and event.event_category != EventCategory.FILE:
        return False

    target = (event.target_filename or "").lower()
    if not target:
        return False

    # Check extension
    ext = PureWindowsPath(target).suffix.lower()
    if ext not in SUSPICIOUS_FILE_EXTENSIONS:
        return False

    # Check writable directory paths
    writable_paths = ("\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\", "\\windows\\temp\\")
    return any(p in target for p in writable_paths)


def is_persistence_installation(event: NormalizedEvent, context: dict[str, Any] | None = None) -> bool:
    """Stage predicate: Registry Run key, IFEO, Scheduled Task, or Service persistence."""
    # Sysmon EID 12, 13, 14: Registry modification
    if event.event_id in (12, 13, 14) or event.event_category == EventCategory.REGISTRY:
        target = (event.registry_target_object or "").lower()
        if any(k in target for k in (r"\run", r"\runonce", "image file execution options", "userinit", "winlogon")):
            return True

    # Security EID 4698: Scheduled Task
    if event.event_id == 4698:
        return True

    # Security EID 4697: Service Installation
    if event.event_id == 4697:
        return True

    return False


# Predicate Registry mapping predicate name strings to callables
PREDICATE_REGISTRY: dict[str, Callable[..., bool]] = {
    "is_phishing_root": is_phishing_root,
    "is_script_interpreter": is_script_interpreter,
    "is_egress_or_persistence": is_egress_or_persistence,
    "is_web_server_root": is_web_server_root,
    "is_recon_command": is_recon_command,
    "is_recon_or_persistence": is_recon_or_persistence,
    "is_lsass_access": is_lsass_access,
    "is_rfc1918_egress_or_remote_exec": is_rfc1918_egress_or_remote_exec,
    "is_lolbin_download": is_lolbin_download,
    "is_suspicious_file_drop": is_suspicious_file_drop,
    "is_persistence_installation": is_persistence_installation,
}


# =============================================================================
# Chain & Stage Definition Models
# =============================================================================

class ChainStageDefinition(BaseModel):
    """Specification for a single stage within a multi-stage attack chain."""

    model_config = ConfigDict(frozen=True)

    stage_number: int = Field(ge=1, description="Sequential stage order (1-indexed).")
    stage_name: str = Field(default="", description="Descriptive name of this attack stage.")
    name: str = Field(default="", description="Alias for stage_name.")
    tactic: str = Field(description="MITRE ATT&CK tactic (e.g. Initial Access, Execution).")
    technique: str = Field(description="MITRE ATT&CK technique (e.g. T1204.002, T1059.001).")
    requires_lineage: bool = Field(default=True, description="Whether this stage requires process tree ancestry/descendant linkage.")
    description: str = Field(description="Forensic description of what this stage identifies.")
    predicate_name: str = Field(default="", description="Name of the predicate function in PREDICATE_REGISTRY.")

    @model_validator(mode="after")
    def _sync_names(self) -> ChainStageDefinition:
        n = self.stage_name or self.name or f"Stage {self.stage_number}"
        if not self.stage_name:
            object.__setattr__(self, "stage_name", n)
        if not self.name:
            object.__setattr__(self, "name", n)
        return self

    def matches_event(self, event: NormalizedEvent, context: dict[str, Any] | None = None) -> bool:
        """Evaluate whether a NormalizedEvent satisfies this stage's predicate criteria."""
        fn = PREDICATE_REGISTRY.get(self.predicate_name)
        if fn:
            return fn(event, context)
        return False

    def matches_match(self, match: Any, context: dict[str, Any] | None = None) -> bool:
        """Evaluate whether a DetectionMatch or alert satisfies this stage."""
        if hasattr(match, "mitre_techniques") and self.technique in match.mitre_techniques:
            return True
        if hasattr(match, "mitre_tactics") and self.tactic in match.mitre_tactics:
            return True
        return False


class AttackChainDefinition(BaseModel):
    """Complete declarative definition of a multi-stage enterprise attack chain."""

    model_config = ConfigDict(frozen=True)

    chain_id: str = Field(description="Unique chain identifier (e.g. CHAIN-PHISH-001).")
    name: str = Field(description="Human-readable chain display name.")
    description: str = Field(description="Threat intelligence context and operational impact.")
    mitre_tactics: list[str] = Field(description="List of covered MITRE ATT&CK tactics.")
    mitre_techniques: list[str] = Field(description="List of covered MITRE ATT&CK techniques.")
    window_minutes: int = Field(default=30, ge=1, description="Sliding temporal correlation window in minutes.")
    stages: list[ChainStageDefinition] = Field(description="Ordered sequence of attack stages.")
    investigation_steps: list[str] = Field(default_factory=list, description="Recommended SOC triage investigation steps.")

    @field_validator("stages")
    @classmethod
    def _validate_stages(cls, v: list[ChainStageDefinition]) -> list[ChainStageDefinition]:
        if len(v) < 2:
            raise ValueError("An AttackChainDefinition requires at least 2 stages.")
        # Ensure sequential numbering
        for i, s in enumerate(v, start=1):
            if s.stage_number != i:
                raise ValueError(f"Stages must be numbered sequentially starting from 1 (got {s.stage_number} at index {i}).")
        return v


# =============================================================================
# 4 Core Predefined Attack Chains
# =============================================================================

CHAIN_PHISH = AttackChainDefinition(
    chain_id="CHAIN-PHISH-001",
    name="Malicious Document / Phishing Execution",
    description="Productivity document software spawning a script interpreter followed by network egress or persistence.",
    mitre_tactics=["Initial Access", "Execution", "Command and Control", "Persistence"],
    mitre_techniques=["T1204.002", "T1059.001", "T1105", "T1547.001"],
    window_minutes=30,
    stages=[
        ChainStageDefinition(
            stage_number=1,
            stage_name="Productivity Software Execution",
            tactic="Initial Access",
            technique="T1204.002",
            requires_lineage=True,
            description="Process creation of Microsoft Office or document viewer application.",
            predicate_name="is_phishing_root",
        ),
        ChainStageDefinition(
            stage_number=2,
            stage_name="Script or Shell Interpreter Spawn",
            tactic="Execution",
            technique="T1059.001",
            requires_lineage=True,
            description="Child process creation of PowerShell, CMD, or script interpreter under document host.",
            predicate_name="is_script_interpreter",
        ),
        ChainStageDefinition(
            stage_number=3,
            stage_name="Outbound Network Egress or Persistence",
            tactic="Command and Control",
            technique="T1105",
            requires_lineage=True,
            description="Outbound network connection or auto-start persistence created by the interpreter.",
            predicate_name="is_egress_or_persistence",
        ),
    ],
    investigation_steps=[
        "Examine the initial document name, path, and email metadata for source sender.",
        "Inspect the command-line arguments of the spawned interpreter for encoded payloads.",
        "Check outbound destination IP/domain against threat intelligence feeds and block at firewall.",
        "Isolate the endpoint to prevent further lateral movement.",
    ],
)

CHAIN_WEBSHELL = AttackChainDefinition(
    chain_id="CHAIN-WEBSHELL-001",
    name="Web Shell / Server Exploitation",
    description="Web server worker process spawning interactive shell followed by discovery reconnaissance or persistence.",
    mitre_tactics=["Initial Access", "Persistence", "Discovery", "Execution"],
    mitre_techniques=["T1190", "T1505.003", "T1082", "T1087"],
    window_minutes=30,
    stages=[
        ChainStageDefinition(
            stage_number=1,
            stage_name="Web Server Worker Execution",
            tactic="Initial Access",
            technique="T1190",
            requires_lineage=True,
            description="Web server application worker process (w3wp.exe, httpd.exe, nginx, tomcat).",
            predicate_name="is_web_server_root",
        ),
        ChainStageDefinition(
            stage_number=2,
            stage_name="Interactive Command Shell Spawn",
            tactic="Persistence",
            technique="T1505.003",
            requires_lineage=True,
            description="Child shell (cmd.exe, powershell.exe) spawned directly by the web server process.",
            predicate_name="is_script_interpreter",
        ),
        ChainStageDefinition(
            stage_number=3,
            stage_name="Reconnaissance or Persistence Creation",
            tactic="Discovery",
            technique="T1082",
            requires_lineage=True,
            description="Execution of recon utilities (whoami, net, systeminfo) or persistence drop by the shell.",
            predicate_name="is_recon_or_persistence",
        ),
    ],
    investigation_steps=[
        "Inspect web server access logs for anomalous POST requests or uploaded ASPX/PHP files.",
        "Verify web directory contents against known source code baselines to identify web shell files.",
        "Review whoami/net commands to see which accounts and group memberships the attacker discovered.",
        "Rotate server credentials and terminate rogue worker/shell processes.",
    ],
)

CHAIN_CREDDUMP_LAT = AttackChainDefinition(
    chain_id="CHAIN-CREDDUMP-LAT-001",
    name="Credential Dumping to Lateral Movement",
    description="Suspicious access or thread injection into LSASS followed by internal lateral egress or remote service creation.",
    mitre_tactics=["Credential Access", "Lateral Movement", "Execution"],
    mitre_techniques=["T1003.001", "T1021.002", "T1569.002"],
    window_minutes=30,
    stages=[
        ChainStageDefinition(
            stage_number=1,
            stage_name="LSASS Memory Access or Thread Injection",
            tactic="Credential Access",
            technique="T1003.001",
            requires_lineage=False,
            description="Process access with suspicious rights or remote thread creation targeting lsass.exe.",
            predicate_name="is_lsass_access",
        ),
        ChainStageDefinition(
            stage_number=2,
            stage_name="Lateral Internal Egress or Remote Execution",
            tactic="Lateral Movement",
            technique="T1021.002",
            requires_lineage=False,
            description="Outbound network connection to RFC1918 private address or remote service installation.",
            predicate_name="is_rfc1918_egress_or_remote_exec",
        ),
    ],
    investigation_steps=[
        "Identify the source process accessing LSASS memory and isolate the host immediately.",
        "Reset credentials for all accounts logged into this workstation/server.",
        "Audit target host on internal network for unauthorized remote access or service creation.",
    ],
)

CHAIN_LOTL_PERSIST = AttackChainDefinition(
    chain_id="CHAIN-LOTL-PERSIST-001",
    name="Living-off-the-Land Download to Persistence",
    description="Ingress tool transfer using LOLBins (certutil, bitsadmin) dropping executable in temp directories and installing persistence.",
    mitre_tactics=["Command and Control", "Persistence", "Execution"],
    mitre_techniques=["T1105", "T1547.001", "T1053.005"],
    window_minutes=30,
    stages=[
        ChainStageDefinition(
            stage_number=1,
            stage_name="LOLBin Ingress Tool Transfer",
            tactic="Command and Control",
            technique="T1105",
            requires_lineage=False,
            description="Download cradle via certutil -urlcache, bitsadmin, or PowerShell download cradle.",
            predicate_name="is_lolbin_download",
        ),
        ChainStageDefinition(
            stage_number=2,
            stage_name="Suspicious Executable File Drop",
            tactic="Execution",
            technique="T1105",
            requires_lineage=False,
            description="File creation of an executable or script in temp/writable directories.",
            predicate_name="is_suspicious_file_drop",
        ),
        ChainStageDefinition(
            stage_number=3,
            stage_name="Auto-Start Persistence Installation",
            tactic="Persistence",
            technique="T1547.001",
            requires_lineage=False,
            description="Registry Run key, IFEO, Scheduled Task, or Service auto-start persistence.",
            predicate_name="is_persistence_installation",
        ),
    ],
    investigation_steps=[
        "Acquire dropped payload from temporary directory for sandbox detonator analysis.",
        "Remove created registry Run keys, scheduled tasks, or malicious services.",
        "Identify initial download source URL and add to corporate proxy blocklists.",
    ],
)

CORE_ATTACK_CHAINS: list[AttackChainDefinition] = [
    CHAIN_PHISH,
    CHAIN_WEBSHELL,
    CHAIN_CREDDUMP_LAT,
    CHAIN_LOTL_PERSIST,
]


def get_default_attack_chains() -> list[AttackChainDefinition]:
    """Return the 4 core predefined enterprise attack chain definitions."""
    return list(CORE_ATTACK_CHAINS)
