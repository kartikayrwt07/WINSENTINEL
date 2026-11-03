"""Pytest fixtures and configuration for WinSentinel unit tests."""

from datetime import datetime, timezone
import pytest

from app.models.events import EventCategory


@pytest.fixture
def sample_raw_xml() -> str:
    """Sample raw Windows Sysmon EID 1 Process Creation event XML."""
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System>'
        '<Provider Name="Microsoft-Windows-Sysmon" />'
        '<EventID>1</EventID>'
        '<TimeCreated SystemTime="2023-04-10T14:22:15.1234567Z" />'
        '<EventRecordID>4201</EventRecordID>'
        '<Channel>Microsoft-Windows-Sysmon/Operational</Channel>'
        '<Computer>WIN-SENTINEL-DEV</Computer>'
        '</System>'
        '<EventData>'
        '<Data Name="RuleName">-</Data>'
        '<Data Name="UtcTime">2023-04-10 14:22:15.120</Data>'
        '<Data Name="ProcessGuid">{A1B2C3D4-E5F6-7890-1234-56789ABCDEF0}</Data>'
        '<Data Name="ProcessId">4128</Data>'
        '<Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>'
        '<Data Name="CommandLine">cmd.exe /c whoami</Data>'
        '<Data Name="User">CORP\\jdoe</Data>'
        '<Data Name="Hashes">SHA256=B89D73C8B7A58E8D552309C1E14F4462615456201B4B6F71A6DBB3673F921B59,MD5=A6C11690040D9B0A3D2A7265B54BE57E</Data>'
        '</EventData>'
        '</Event>'
    )


@pytest.fixture
def sample_valid_event_dict(sample_raw_xml: str) -> dict:
    """Valid dictionary for NormalizedEvent instantiation."""
    return {
        "event_id": 1,
        "record_id": 4201,
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": "WIN-SENTINEL-DEV",
        "timestamp": datetime(2023, 4, 10, 14, 22, 15, 123456, tzinfo=timezone.utc),
        "event_category": EventCategory.PROCESS,
        "event_type": "process_create",
        "process_guid": "{A1B2C3D4-E5F6-7890-1234-56789ABCDEF0}",
        "process_id": 4128,
        "image": "C:\\Windows\\System32\\cmd.exe",
        "command_line": "cmd.exe /c whoami",
        "user": "CORP\\jdoe",
        "hashes": {
            "sha256": "b89d73c8b7a58e8d552309c1e14f4462615456201b4b6f71a6dbb3673f921b59",
            "md5": "a6c11690040d9b0a3d2a7265b54be57e",
        },
        "raw_payload": sample_raw_xml,
        "event_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "is_quarantined": False,
        "quarantine_reasons": [],
        "extra_fields": {"RuleName": "-"},
    }
