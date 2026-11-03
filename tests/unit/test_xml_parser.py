from pathlib import Path
import pytest

from app.ingestion.base import RawRecord
from app.ingestion.xml_parser import XMLParser, parse_event_xml
from app.models.stats import ImportStatistics

SAMPLE_SYSMON_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}" />
    <EventID>1</EventID>
    <Version>5</Version>
    <Level>4</Level>
    <Task>1</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-03T18:00:00.1234567Z" />
    <EventRecordID>45001</EventRecordID>
    <Correlation />
    <Execution ProcessID="2048" ThreadID="3092" />
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>DESKTOP-SENTINEL</Computer>
    <Security UserID="S-1-5-18" />
  </System>
  <EventData>
    <Data Name="RuleName">-</Data>
    <Data Name="UtcTime">2026-11-03 18:00:00.120</Data>
    <Data Name="ProcessGuid">{A1B2C3D4-0000-0000-0000-000000000000}</Data>
    <Data Name="ProcessId">4104</Data>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd.exe /c whoami</Data>
    <Data Name="CurrentDirectory">C:\\Users\\Analyst\\</Data>
    <Data Name="User">WORKGROUP\\Analyst</Data>
    <Data Name="LogonGuid">{A1B2C3D4-1111-0000-0000-000000000000}</Data>
    <Data Name="LogonId">0x3e7</Data>
    <Data Name="TerminalSessionId">1</Data>
    <Data Name="IntegrityLevel">High</Data>
    <Data Name="Hashes">SHA256=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890</Data>
    <Data Name="ParentProcessGuid">{A1B2C3D4-2222-0000-0000-000000000000}</Data>
    <Data Name="ParentProcessId">1000</Data>
    <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
    <Data Name="ParentCommandLine">explorer.exe</Data>
    <Data Name="ParentUser">WORKGROUP\\Analyst</Data>
  </EventData>
</Event>"""

SAMPLE_SECURITY_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4624</EventID>
    <TimeCreated SystemTime="2026-11-03T18:05:00.000000Z" />
    <EventRecordID>99001</EventRecordID>
    <Channel>Security</Channel>
    <Computer>DC-01.CORP.LOCAL</Computer>
    <Security />
  </System>
  <EventData>
    <TargetUserName>jdoe</TargetUserName>
    <TargetDomainName>CORP</TargetDomainName>
    <LogonType>3</LogonType>
    <IpAddress>192.168.1.50</IpAddress>
  </EventData>
</Event>"""


def test_parse_event_xml_sysmon():
    system_fields, data_fields = parse_event_xml(SAMPLE_SYSMON_XML)

    assert system_fields["Provider"] == "Microsoft-Windows-Sysmon"
    assert system_fields["ProviderGuid"] == "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"
    assert system_fields["EventID"] == "1"
    assert system_fields["EventRecordID"] == "45001"
    assert system_fields["TimeCreated"] == "2026-11-03T18:00:00.1234567Z"
    assert system_fields["Computer"] == "DESKTOP-SENTINEL"
    assert system_fields["Channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert system_fields["ProcessID"] == "2048"
    assert system_fields["UserID"] == "S-1-5-18"

    assert data_fields["Image"] == "C:\\Windows\\System32\\cmd.exe"
    assert data_fields["CommandLine"] == "cmd.exe /c whoami"
    assert "SHA256=abcdef" in data_fields["Hashes"]


def test_parse_event_xml_direct_tags():
    system_fields, data_fields = parse_event_xml(SAMPLE_SECURITY_XML)

    assert system_fields["Provider"] == "Microsoft-Windows-Security-Auditing"
    assert system_fields["EventID"] == "4624"
    assert system_fields["EventRecordID"] == "99001"
    assert system_fields["Channel"] == "Security"

    assert data_fields["TargetUserName"] == "jdoe"
    assert data_fields["TargetDomainName"] == "CORP"
    assert data_fields["LogonType"] == "3"
    assert data_fields["IpAddress"] == "192.168.1.50"


def test_xml_parser_streaming_multi_events(tmp_path: Path):
    events_xml = f"<Events>{SAMPLE_SYSMON_XML}{SAMPLE_SECURITY_XML}</Events>"
    file_path = tmp_path / "multi_events.xml"
    file_path.write_text(events_xml, encoding="utf-8")

    parser = XMLParser()
    stats = ImportStatistics()
    records = list(parser.stream_records(file_path, stats=stats))

    assert len(records) == 2
    assert records[0].record_id == 45001
    assert records[0].format == "xml"
    assert records[1].record_id == 99001
    assert records[1].format == "xml"
    assert stats.total_events == 2
    assert stats.malformed_events == 0


def test_xml_parser_single_event(tmp_path: Path):
    file_path = tmp_path / "single_event.xml"
    file_path.write_text(SAMPLE_SYSMON_XML, encoding="utf-8")

    parser = XMLParser()
    stats = ImportStatistics()
    records = list(parser.stream_records(file_path, stats=stats))

    assert len(records) == 1
    assert records[0].record_id == 45001
    assert records[0].format == "xml"
    assert stats.total_events == 1


def test_xml_parser_malformed_xml(tmp_path: Path):
    file_path = tmp_path / "corrupt.xml"
    file_path.write_text("<Events><Event><System><unclosed></Events>", encoding="utf-8")

    parser = XMLParser()
    stats = ImportStatistics()
    records = list(parser.stream_records(file_path, stats=stats))

    assert len(records) == 1
    assert records[0].metadata.get("is_corrupt") is True
    assert stats.malformed_events == 1
