"""Integration tests for IngestionPipeline end-to-end telemetry workflow."""

import json
from pathlib import Path
import pytest

from app.ingestion.pipeline import IngestionPipeline
from app.models.events import EventCategory


@pytest.fixture
def pipeline():
    return IngestionPipeline(base_dir=Path(__file__).parent.parent.parent)


@pytest.fixture
def repo_root():
    return Path(__file__).parent.parent.parent


def test_ingest_sysmon_xml_fixtures(pipeline, repo_root):
    """Test ingestion of valid Sysmon XML sample files."""
    sample_dir = repo_root / "sample_data" / "sysmon"

    # Test EID 1
    events, stats = pipeline.ingest_file(sample_dir / "sysmon_eid1.xml")
    assert stats.parsed_events == 1
    assert stats.malformed_events == 0
    assert stats.duplicate_events == 0
    assert len(events) == 1
    ev = events[0]
    assert ev.event_id == 1
    assert ev.event_category == EventCategory.PROCESS
    assert ev.event_type == "process_create"
    assert "powershell.exe" in ev.image
    assert ev.process_id == 4104
    assert ev.parent_process_id == 2980
    assert "sha256" in ev.hashes
    assert not ev.is_quarantined

    # Test EID 3 (Network)
    events, stats = pipeline.ingest_file(sample_dir / "sysmon_eid3.xml")
    assert stats.parsed_events == 1
    assert events[0].event_category == EventCategory.NETWORK
    assert events[0].destination_ip == "198.51.100.2"
    assert events[0].destination_port == 443

    # Test EID 10 (Process Access / LSASS)
    events, stats = pipeline.ingest_file(sample_dir / "sysmon_eid10.xml")
    assert stats.parsed_events == 1
    assert events[0].event_category == EventCategory.PROCESS_ACCESS
    assert events[0].target_image == "C:\\Windows\\System32\\lsass.exe"
    assert events[0].granted_access == "0x1010"

    # Test EID 13 (Registry Run key)
    events, stats = pipeline.ingest_file(sample_dir / "sysmon_eid13.xml")
    assert stats.parsed_events == 1
    assert events[0].event_category == EventCategory.REGISTRY
    assert "SecurityUpdate" in events[0].registry_target_object
    assert events[0].registry_details == "C:\\ProgramData\\malware.exe"

    # Test EID 22 (DNS)
    events, stats = pipeline.ingest_file(sample_dir / "sysmon_eid22.xml")
    assert stats.parsed_events == 1
    assert events[0].event_category == EventCategory.DNS
    assert events[0].query_name == "evil.example.com"


def test_ingest_security_and_powershell_fixtures(pipeline, repo_root):
    """Test ingestion of Windows Security and PowerShell sample files."""
    sec_dir = repo_root / "sample_data" / "security"
    pwsh_dir = repo_root / "sample_data" / "powershell"

    # Security 4688: Process creation with hex PIDs
    events, stats = pipeline.ingest_file(sec_dir / "security_eid4688.xml")
    assert stats.parsed_events == 1
    ev = events[0]
    assert ev.event_id == 4688
    assert ev.event_category == EventCategory.SECURITY
    assert ev.process_id == 500  # 0x1f4
    assert ev.parent_process_id == 4  # 0x4
    assert ev.image == "C:\\Windows\\System32\\whoami.exe"

    # Security 4697: Service Install
    events, stats = pipeline.ingest_file(sec_dir / "security_eid4697.xml")
    assert stats.parsed_events == 1
    assert events[0].event_category == EventCategory.SECURITY
    assert events[0].service_name == "PwnService"
    assert events[0].service_file_name == "C:\\Windows\\Temp\\pwn.exe"

    # Security 4698: Scheduled Task
    events, stats = pipeline.ingest_file(sec_dir / "security_eid4698.xml")
    assert stats.parsed_events == 1
    assert events[0].event_category == EventCategory.SECURITY
    assert "PersistentBackdoor" in events[0].task_name
    assert "powershell.exe" in events[0].task_content

    # PowerShell 4104: Script Block
    events, stats = pipeline.ingest_file(pwsh_dir / "powershell_eid4104.xml")
    assert stats.parsed_events == 1
    assert events[0].event_category == EventCategory.POWERSHELL
    assert "DownloadString" in events[0].script_block_text
    assert events[0].script_block_id == "01234567-89AB-CDEF-0123-456789ABCDEF"


def test_ingestion_deduplication(pipeline, repo_root):
    """Test that importing the same file twice results in duplicate suppression."""
    sample_file = repo_root / "sample_data" / "sysmon" / "sysmon_eid7.xml"

    # First import
    events1, stats1 = pipeline.ingest_file(sample_file)
    assert stats1.parsed_events == 1
    assert stats1.duplicate_events == 0
    assert len(events1) == 1

    # Second import without reset
    events2, stats2 = pipeline.ingest_file(sample_file)
    assert stats2.parsed_events == 0
    assert stats2.duplicate_events == 1
    assert len(events2) == 0

    # After reset
    pipeline.reset_deduplication()
    events3, stats3 = pipeline.ingest_file(sample_file)
    assert stats3.parsed_events == 1
    assert stats3.duplicate_events == 0
    assert len(events3) == 1


def test_malformed_xml_handling(pipeline, repo_root):
    """Test handling of truncated XML files."""
    malformed_xml = repo_root / "sample_data" / "malformed" / "truncated_event.xml"
    events, stats = pipeline.ingest_file(malformed_xml)

    assert stats.malformed_events >= 1
    assert len(stats.quarantined_records) >= 1
    assert len(stats.error_log) >= 1


def test_missing_system_and_invalid_timestamp_quarantine(pipeline, repo_root):
    """Test partial normalization and quarantine for missing system and invalid timestamps."""
    missing_sys = repo_root / "sample_data" / "malformed" / "missing_system.xml"
    events, stats = pipeline.ingest_file(missing_sys)

    assert stats.quarantined_events == 1
    assert len(events) == 1
    assert events[0].is_quarantined is True
    assert len(events[0].quarantine_reasons) > 0
    assert len(stats.quarantined_records) == 1

    invalid_ts = repo_root / "sample_data" / "malformed" / "invalid_timestamp.json"
    events_json, stats_json = pipeline.ingest_file(invalid_ts)

    assert stats_json.quarantined_events == 1
    assert len(events_json) == 1
    assert events_json[0].is_quarantined is True
    assert any("timestamp" in r.lower() for r in events_json[0].quarantine_reasons)


def test_jsonl_ingestion(pipeline, tmp_path):
    """Test streaming and parsing of JSONL log files."""
    jsonl_file = tmp_path / "events.jsonl"
    record1 = {
        "Provider": "Microsoft-Windows-Sysmon",
        "EventID": 1,
        "TimeCreated": "2023-04-10T14:22:15Z",
        "Computer": "PC01",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "EventRecordID": 200,
        "Image": "C:\\Windows\\notepad.exe",
        "ProcessId": 1234,
    }
    record2 = {
        "Provider": "Microsoft-Windows-Security-Auditing",
        "EventID": 4688,
        "TimeCreated": "2023-04-10T14:22:16Z",
        "Computer": "PC01",
        "Channel": "Security",
        "EventRecordID": 201,
        "NewProcessName": "C:\\Windows\\calc.exe",
        "NewProcessId": "0x400",
    }
    with open(jsonl_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(record1) + "\n")
        f.write(json.dumps(record2) + "\n")

    events, stats = pipeline.ingest_file(jsonl_file, base_dir=tmp_path)
    assert stats.parsed_events == 2
    assert stats.malformed_events == 0
    assert len(events) == 2
    assert events[0].event_category == EventCategory.PROCESS
    assert events[0].image == "C:\\Windows\\notepad.exe"
    assert events[1].event_category == EventCategory.SECURITY
    assert events[1].process_id == 1024  # 0x400
