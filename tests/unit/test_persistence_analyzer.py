"""Unit tests for WinSentinel PersistenceAnalyzer and PersistenceArtifact model.

Validates multi-source persistence correlation across:
1. Registry Auto-Runs & IFEO (Sysmon 12, 13, 14)
2. Services & Driver Loads (Security 4697, Sysmon 6)
3. Scheduled Tasks (Security 4698, Task Scheduler 106/140)
4. WMI Event Subscriptions (Sysmon 19, 20, 21)
5. Startup Folder File Drops (Sysmon 11)

Strict Invariant:
Sysmon registry modifications to Schedule\\TaskCache must NEVER generate
a SCHEDULED_TASK persistence artifact.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.analyzers.persistence_analyzer import PersistenceAnalyzer
from app.models.events import EventCategory, NormalizedEvent
from app.models.persistence import PersistenceArtifact, PersistenceType


def _make_event(
    event_id: int = 1,
    event_category: EventCategory = EventCategory.GENERIC,
    event_type: str = "GENERIC_EVENT",
    computer: str = "WIN-SERVER01",
    user: str = r"CONTOSO\Administrator",
    process_guid: str = "{12345678-ABCD-1234-ABCD-1234567890AB}",
    **kwargs,
) -> NormalizedEvent:
    """Helper to construct a valid NormalizedEvent with default fields."""
    return NormalizedEvent(
        event_id=event_id,
        record_id=kwargs.pop("record_id", 100),
        provider=kwargs.pop("provider", "Microsoft-Windows-Sysmon"),
        channel=kwargs.pop("channel", "Microsoft-Windows-Sysmon/Operational"),
        computer=computer,
        timestamp=kwargs.pop("timestamp", datetime.now(timezone.utc)),
        event_category=event_category,
        event_type=event_type,
        process_guid=process_guid,
        user=user,
        raw_payload=kwargs.pop("raw_payload", "<Event/>"),
        event_hash=kwargs.pop("event_hash", f"hash_{event_id}_{datetime.now().timestamp()}"),
        **kwargs,
    )


def test_persistence_type_enum():
    """Test 1: Verify PersistenceType enum contains all required categories."""
    expected = {
        "REGISTRY",
        "SERVICE",
        "DRIVER",
        "SCHEDULED_TASK",
        "WMI_SUBSCRIPTION",
        "STARTUP_FOLDER",
    }
    actual = {pt.value for pt in PersistenceType}
    assert actual == expected


def test_persistence_artifact_model_and_mappings():
    """Test 2: Verify PersistenceArtifact validation, to_alert_dict(), and to_evidence_dicts()."""
    ts = datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc)
    artifact = PersistenceArtifact(
        persistence_type=PersistenceType.REGISTRY,
        event_id=13,
        record_id=101,
        event_db_id=42,
        computer="ENDPOINT-01",
        timestamp_utc=ts,
        process_guid="{AAAA-BBBB-CCCC}",
        user=r"NT AUTHORITY\SYSTEM",
        target_name=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        payload=r"C:\Users\Admin\AppData\Local\Temp\evil.exe",
        severity="High",
        mitre_tactics=["TA0003 - Persistence"],
        mitre_techniques=["T1547.001 - Registry Run Keys / Startup Folder"],
        evidence_fields={"key": "Run", "action": "SetValue"},
        explanation="Suspicious Run key modified pointing to AppData/Temp",
        investigation_steps=["Check file reputation", "Inspect process lineage"],
    )

    # Test to_alert_dict()
    alert_dict = artifact.to_alert_dict()
    assert alert_dict["title"] == r"Persistence Mechanism Detected: REGISTRY (HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater)"
    assert alert_dict["severity"] == "High"
    assert alert_dict["rule_id"] == "PERS-REGISTRY-001"
    assert alert_dict["computer"] == "ENDPOINT-01"
    assert alert_dict["user"] == r"NT AUTHORITY\SYSTEM"
    assert alert_dict["status"] == "New"
    assert alert_dict["event_count"] == 1
    assert "TA0003 - Persistence" in alert_dict["mitre_tactics"]
    assert "T1547.001 - Registry Run Keys / Startup Folder" in alert_dict["mitre_techniques"]

    # Test to_evidence_dicts()
    evidence_list = artifact.to_evidence_dicts(alert_id=7)
    assert len(evidence_list) >= 3
    assert any(
        e["alert_id"] == 7
        and e["event_id"] == 42
        and e["matched_field"] == "target_name"
        and "HKLM" in e["matched_value"]
        for e in evidence_list
    )
    assert any(
        e["alert_id"] == 7
        and e["event_id"] == 42
        and e["matched_field"] == "payload"
        and "evil.exe" in e["matched_value"]
        for e in evidence_list
    )


def test_registry_run_keys_detection():
    """Test 3: Verify Registry detector flags modifications to Run, RunOnce, RunOnceEx, Explorer\\Run."""
    analyzer = PersistenceAnalyzer()

    # Standard Run key modification
    ev_run = _make_event(
        event_id=13,
        event_category=EventCategory.REGISTRY,
        registry_target_object=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\MyDaemon",
        registry_details=r"C:\Program Files\Vendor\daemon.exe",
    )
    art_run = analyzer.analyze_event(ev_run)
    assert art_run is not None
    assert art_run.persistence_type == PersistenceType.REGISTRY
    assert art_run.severity == "Medium"
    assert "T1547.001" in art_run.mitre_techniques[0]

    # RunOnce key modification with Temp payload -> High severity
    ev_runonce = _make_event(
        event_id=13,
        event_category=EventCategory.REGISTRY,
        registry_target_object=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\Dropper",
        registry_details=r"C:\Users\victim\AppData\Local\Temp\setup.exe",
    )
    art_runonce = analyzer.analyze_event(ev_runonce)
    assert art_runonce is not None
    assert art_runonce.severity == "High"

    # Policies\Explorer\Run key modification
    ev_exp_run = _make_event(
        event_id=13,
        event_category=EventCategory.REGISTRY,
        registry_target_object=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\Helper",
        registry_details=r"powershell.exe -w hidden -enc JABz...",
    )
    art_exp = analyzer.analyze_event(ev_exp_run)
    assert art_exp is not None
    assert art_exp.severity == "High"


def test_registry_ifeo_and_winlogon_hijacking():
    """Test 4: Verify Registry detector flags Winlogon and IFEO debugger hijacking with High severity."""
    analyzer = PersistenceAnalyzer()

    # IFEO Debugger hijacking (e.g. sethc.exe sticky keys backdoored to cmd.exe)
    ev_ifeo = _make_event(
        event_id=13,
        event_category=EventCategory.REGISTRY,
        registry_target_object=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger",
        registry_details=r"C:\Windows\System32\cmd.exe",
    )
    art_ifeo = analyzer.analyze_event(ev_ifeo)
    assert art_ifeo is not None
    assert art_ifeo.persistence_type == PersistenceType.REGISTRY
    assert art_ifeo.severity == "High"
    assert "T1546.012" in art_ifeo.mitre_techniques[0]
    assert "IFEO" in art_ifeo.explanation

    # Winlogon Userinit hijacking
    ev_winlogon = _make_event(
        event_id=13,
        event_category=EventCategory.REGISTRY,
        registry_target_object=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
        registry_details=r"C:\Windows\System32\userinit.exe,C:\Users\Public\backdoor.exe",
    )
    art_winlogon = analyzer.analyze_event(ev_winlogon)
    assert art_winlogon is not None
    assert art_winlogon.severity == "High"
    assert "T1547.004" in art_winlogon.mitre_techniques[0]
    assert "Winlogon" in art_winlogon.explanation


def test_service_install_escalation():
    """Test 5: Verify Security EID 4697 service installation flags, escalating if binary is suspicious."""
    analyzer = PersistenceAnalyzer()

    # Standard service install
    ev_std = _make_event(
        event_id=4697,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        event_category=EventCategory.SECURITY,
        service_name="CustomBackupAgent",
        service_file_name=r"C:\Program Files\BackupCorp\agent.exe",
    )
    art_std = analyzer.analyze_event(ev_std)
    assert art_std is not None
    assert art_std.persistence_type == PersistenceType.SERVICE
    assert art_std.severity == "Medium"
    assert art_std.target_name == "CustomBackupAgent"
    assert "T1543.003" in art_std.mitre_techniques[0]

    # Malicious service install in Temp directory with cmd/script -> High/Critical
    ev_mal = _make_event(
        event_id=4697,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        event_category=EventCategory.SECURITY,
        service_name="EvilService",
        service_file_name=r"cmd.exe /c C:\Users\AllUsers\Temp\evil.bat",
    )
    art_mal = analyzer.analyze_event(ev_mal)
    assert art_mal is not None
    assert art_mal.severity in ("High", "Critical")


def test_driver_load_detection():
    """Test 6: Verify Sysmon EID 6 driver load flags unsigned or out-of-drivers-directory drivers."""
    analyzer = PersistenceAnalyzer()

    # Unsigned driver in System32\drivers
    ev_unsigned = _make_event(
        event_id=6,
        event_category=EventCategory.DRIVER,
        target_filename=r"C:\Windows\System32\drivers\custom_rootkit.sys",
        signed="false",
        signature_status="Invalid",
    )
    art_unsigned = analyzer.analyze_event(ev_unsigned)
    assert art_unsigned is not None
    assert art_unsigned.persistence_type == PersistenceType.DRIVER
    assert art_unsigned.severity == "High"
    assert "T1068" in art_unsigned.mitre_techniques[0]

    # Driver loaded from Temp directory (suspicious location)
    ev_temp = _make_event(
        event_id=6,
        event_category=EventCategory.DRIVER,
        target_filename=r"C:\Users\Admin\AppData\Local\Temp\gdrv.sys",
        signed="true",
        signature_status="Valid",
    )
    art_temp = analyzer.analyze_event(ev_temp)
    assert art_temp is not None
    assert art_temp.severity == "High"

    # Benign, signed driver in System32\drivers -> returns None
    ev_benign = _make_event(
        event_id=6,
        event_category=EventCategory.DRIVER,
        target_filename=r"C:\Windows\System32\drivers\ntfs.sys",
        signed="true",
        signature_status="Valid",
    )
    assert analyzer.analyze_event(ev_benign) is None


def test_scheduled_task_xml_parsing():
    """Test 7: Verify Scheduled Task detector parses Security EID 4698 XML for Command and Arguments."""
    analyzer = PersistenceAnalyzer()

    task_xml = """<?xml version="1.0" encoding="UTF-16"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <RegistrationInfo>
        <Description>Periodic maintenance task</Description>
      </RegistrationInfo>
      <Actions Context="Author">
        <Exec>
          <Command>powershell.exe</Command>
          <Arguments>-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File C:\\Users\\Public\\script.ps1</Arguments>
        </Exec>
      </Actions>
    </Task>"""

    ev_task = _make_event(
        event_id=4698,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        event_category=EventCategory.SECURITY,
        task_name=r"\Microsoft\Windows\Maintenance\Updater",
        task_content=task_xml,
    )

    art = analyzer.analyze_event(ev_task)
    assert art is not None
    assert art.persistence_type == PersistenceType.SCHEDULED_TASK
    assert art.target_name == r"\Microsoft\Windows\Maintenance\Updater"
    assert "powershell.exe" in (art.payload or "")
    assert "-ExecutionPolicy Bypass" in (art.payload or "")
    assert art.severity == "High"  # powershell.exe + hidden triggers suspicious escalation
    assert "T1053.005" in art.mitre_techniques[0]


def test_task_scheduler_operational_events():
    """Test 8: Verify Scheduled Task detector flags Task Scheduler Operational events (EID 106, 140)."""
    analyzer = PersistenceAnalyzer()

    ev_106 = _make_event(
        event_id=106,
        provider="Microsoft-Windows-TaskScheduler",
        channel="Microsoft-Windows-TaskScheduler/Operational",
        event_category=EventCategory.GENERIC,
        task_name=r"\GoogleUpdateTaskMachineUA",
        command_line=r"C:\Program Files (x86)\Google\Update\GoogleUpdate.exe /ua /installsource scheduler",
    )
    art_106 = analyzer.analyze_event(ev_106)
    assert art_106 is not None
    assert art_106.persistence_type == PersistenceType.SCHEDULED_TASK
    assert art_106.severity == "Medium"
    assert art_106.target_name == r"\GoogleUpdateTaskMachineUA"


def test_strict_invariant_sysmon_registry_never_infers_scheduled_tasks():
    """Test 9: STRICT INVARIANT TEST: Verify Sysmon registry events modifying TaskCache do NOT generate task persistence."""
    analyzer = PersistenceAnalyzer()

    # Sysmon EID 12/13 modifying TaskCache
    ev_reg_task = _make_event(
        event_id=13,
        event_category=EventCategory.REGISTRY,
        registry_target_object=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MyTask\Id",
        registry_details=r"{ABCD-1234-5678}",
    )

    art = analyzer.analyze_event(ev_reg_task)
    # MUST NOT generate SCHEDULED_TASK persistence artifact!
    assert art is None, "Violated Strict Invariant: Sysmon registry event generated persistence artifact!"

    # Also test check_scheduled_task_persistence directly
    art_direct = analyzer.check_scheduled_task_persistence(ev_reg_task)
    assert art_direct is None


def test_wmi_event_subscription_detection():
    """Test 10: Verify WMI detector flags Sysmon EID 19, 20, and 21, marking EID 21 as High severity."""
    analyzer = PersistenceAnalyzer()

    # EID 19: EventFilter
    ev_19 = _make_event(
        event_id=19,
        event_category=EventCategory.WMI,
        wmi_filter="LogonWatcher",
        wmi_query="SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE TargetInstance ISA 'Win32_LogonSession'",
    )
    art_19 = analyzer.analyze_event(ev_19)
    assert art_19 is not None
    assert art_19.persistence_type == PersistenceType.WMI_SUBSCRIPTION
    assert art_19.severity == "Medium"
    assert art_19.target_name == "LogonWatcher"

    # EID 20: EventConsumer
    ev_20 = _make_event(
        event_id=20,
        event_category=EventCategory.WMI,
        wmi_consumer="CommandLineConsumer_Backdoor",
        command_line="powershell.exe -enc JABz...",
    )
    art_20 = analyzer.analyze_event(ev_20)
    assert art_20 is not None
    assert art_20.persistence_type == PersistenceType.WMI_SUBSCRIPTION
    assert art_20.severity == "Medium"
    assert art_20.target_name == "CommandLineConsumer_Backdoor"

    # EID 21: FilterToConsumerBinding (Completed persistence) -> High severity
    ev_21 = _make_event(
        event_id=21,
        event_category=EventCategory.WMI,
        wmi_filter="LogonWatcher",
        wmi_consumer="CommandLineConsumer_Backdoor",
    )
    art_21 = analyzer.analyze_event(ev_21)
    assert art_21 is not None
    assert art_21.persistence_type == PersistenceType.WMI_SUBSCRIPTION
    assert art_21.severity == "High"
    assert "T1546.003" in art_21.mitre_techniques[0]


def test_startup_folder_drop_detection():
    """Test 11: Verify Startup folder drop detector flags Sysmon EID 11 with executable/script extensions."""
    analyzer = PersistenceAnalyzer()

    # User Startup folder drop with .bat extension -> High
    ev_startup_bat = _make_event(
        event_id=11,
        event_category=EventCategory.FILE,
        target_filename=r"C:\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\launch.bat",
        image=r"C:\Windows\System32\curl.exe",
    )
    art_bat = analyzer.analyze_event(ev_startup_bat)
    assert art_bat is not None
    assert art_bat.persistence_type == PersistenceType.STARTUP_FOLDER
    assert art_bat.severity == "High"
    assert "T1547.001" in art_bat.mitre_techniques[0]

    # All Users Startup folder drop with .lnk shortcut -> High
    ev_startup_lnk = _make_event(
        event_id=11,
        event_category=EventCategory.FILE,
        target_filename=r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk",
        image=r"C:\Windows\explorer.exe",
    )
    art_lnk = analyzer.analyze_event(ev_startup_lnk)
    assert art_lnk is not None
    assert art_lnk.persistence_type == PersistenceType.STARTUP_FOLDER
    assert art_lnk.severity == "High"

    # Non-executable file drop in Startup folder (e.g. .txt log) -> returns None
    ev_startup_txt = _make_event(
        event_id=11,
        event_category=EventCategory.FILE,
        target_filename=r"C:\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\notes.txt",
    )
    assert analyzer.analyze_event(ev_startup_txt) is None


def test_benign_non_persistence_events_return_none():
    """Test 12: Verify benign events outside persistence scopes return None."""
    analyzer = PersistenceAnalyzer()

    # Benign process creation
    ev_proc = _make_event(
        event_id=1,
        event_category=EventCategory.PROCESS,
        image=r"C:\Windows\System32\notepad.exe",
        command_line="notepad.exe readme.txt",
    )
    assert analyzer.analyze_event(ev_proc) is None

    # Benign network event
    ev_net = _make_event(
        event_id=3,
        event_category=EventCategory.NETWORK,
        destination_ip="8.8.8.8",
        destination_port=53,
    )
    assert analyzer.analyze_event(ev_net) is None

    # Benign registry key not in auto-runs or IFEO
    ev_reg = _make_event(
        event_id=13,
        event_category=EventCategory.REGISTRY,
        registry_target_object=r"HKCU\Software\Microsoft\Office\16.0\Word\Options\DefaultPath",
        registry_details=r"C:\Users\victim\Documents",
    )
    assert analyzer.analyze_event(ev_reg) is None
