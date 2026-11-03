"""Unit tests for SysmonNormalizer across all supported EventIDs."""

import pytest
from app.models.events import EventCategory
from app.normalization.sysmon import SysmonNormalizer


@pytest.fixture
def normalizer():
    return SysmonNormalizer()


def test_sysmon_eid1_process_create(normalizer):
    system_fields = {
        "Provider": "Microsoft-Windows-Sysmon",
        "EventID": "1",
        "EventRecordID": "501",
        "TimeCreated": "2023-04-10T14:22:15.1234567Z",
        "Computer": "WORKSTATION01",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
    }
    data_fields = {
        "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
        "ProcessId": "4100",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "CurrentDirectory": "C:\\Users\\admin\\",
        "User": "DOMAIN\\admin",
        "LogonGuid": "{AAAA-BBBB}",
        "LogonId": "0x3e7",
        "IntegrityLevel": "High",
        "Hashes": "SHA256=abcdef1234567890,MD5=112233445566",
        "ParentProcessGuid": "{99999999-8888-7777-6666-555555555555}",
        "ParentProcessId": "1024",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ParentCommandLine": "explorer.exe",
        "ParentUser": "DOMAIN\\admin",
    }
    raw = "<Event>sysmon_eid1</Event>"

    event = normalizer.normalize(system_fields, data_fields, raw)

    assert event.event_id == 1
    assert event.record_id == 501
    assert event.event_category == EventCategory.PROCESS
    assert event.event_type == "process_create"
    assert event.process_guid == "{11111111-2222-3333-4444-555555555555}"
    assert event.process_id == 4100
    assert event.image == "C:\\Windows\\System32\\cmd.exe"
    assert event.command_line == "cmd.exe /c whoami"
    assert event.user == "DOMAIN\\admin"
    assert event.hashes == {"sha256": "abcdef1234567890", "md5": "112233445566"}
    assert event.parent_process_guid == "{99999999-8888-7777-6666-555555555555}"
    assert event.parent_process_id == 1024
    assert event.parent_image == "C:\\Windows\\explorer.exe"
    assert event.raw_payload == raw
    assert not event.is_quarantined
    assert event.quarantine_reasons == []


def test_sysmon_eid3_network(normalizer):
    system_fields = {
        "Provider": "Microsoft-Windows-Sysmon",
        "EventID": "3",
        "TimeCreated": "2023-04-10T14:22:16Z",
        "Computer": "WORKSTATION01",
        "Channel": "Microsoft-Windows-Sysmon/Operational",
    }
    data_fields = {
        "ProcessGuid": "{1111-2222}",
        "ProcessId": "4100",
        "Image": "C:\\Windows\\System32\\curl.exe",
        "Protocol": "tcp",
        "SourceIp": "192.168.1.50",
        "SourcePort": "54321",
        "SourceHostname": "workstation01.local",
        "DestinationIp": "198.51.100.2",
        "DestinationPort": "443",
        "DestinationHostname": "api.example.com",
    }
    raw = "<Event>sysmon_eid3</Event>"

    event = normalizer.normalize(system_fields, data_fields, raw)

    assert event.event_id == 3
    assert event.event_category == EventCategory.NETWORK
    assert event.event_type == "network_connect"
    assert event.protocol == "tcp"
    assert event.source_ip == "192.168.1.50"
    assert event.source_port == 54321
    assert event.destination_ip == "198.51.100.2"
    assert event.destination_port == 443
    assert event.destination_hostname == "api.example.com"


def test_sysmon_eid6_and_eid7_drivers_and_images(normalizer):
    # EID 6: Driver Load
    sys6 = {
        "Provider": "Microsoft-Windows-Sysmon",
        "EventID": "6",
        "TimeCreated": "2023-04-10T14:22:17Z",
    }
    data6 = {
        "ImageLoaded": "C:\\Windows\\System32\\drivers\\suspicious.sys",
        "Hashes": "SHA256=111122223333",
        "Signed": "false",
        "Signature": "-",
        "SignatureStatus": "Invalid",
    }
    ev6 = normalizer.normalize(sys6, data6, "<Event>eid6</Event>")
    assert ev6.event_id == 6
    assert ev6.event_category == EventCategory.DRIVER
    assert ev6.event_type == "driver_load"
    assert ev6.image_loaded == "C:\\Windows\\System32\\drivers\\suspicious.sys"
    assert ev6.signed == "false"
    assert ev6.hashes["sha256"] == "111122223333"

    # EID 7: Image / DLL Load
    sys7 = {
        "Provider": "Microsoft-Windows-Sysmon",
        "EventID": "7",
        "TimeCreated": "2023-04-10T14:22:18Z",
    }
    data7 = {
        "ProcessGuid": "{AAAA-BBBB}",
        "ProcessId": "1234",
        "Image": "C:\\app\\test.exe",
        "ImageLoaded": "C:\\Windows\\System32\\amsi.dll",
        "Signed": "true",
        "Signature": "Microsoft Corporation",
        "SignatureStatus": "Valid",
    }
    ev7 = normalizer.normalize(sys7, data7, "<Event>eid7</Event>")
    assert ev7.event_id == 7
    assert ev7.event_category == EventCategory.IMAGE_LOAD
    assert ev7.event_type == "image_load"
    assert ev7.image_loaded == "C:\\Windows\\System32\\amsi.dll"
    assert ev7.signature == "Microsoft Corporation"


def test_sysmon_eid8_and_eid10_threads_and_access(normalizer):
    # EID 8: CreateRemoteThread
    sys8 = {
        "Provider": "Microsoft-Windows-Sysmon",
        "EventID": "8",
        "TimeCreated": "2023-04-10T14:22:19Z",
    }
    data8 = {
        "SourceProcessGuid": "{SRC-GUID}",
        "SourceProcessId": "2000",
        "SourceImage": "C:\\tools\\injector.exe",
        "TargetProcessGuid": "{TGT-GUID}",
        "TargetProcessId": "600",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
    }
    ev8 = normalizer.normalize(sys8, data8, "<Event>eid8</Event>")
    assert ev8.event_id == 8
    assert ev8.event_category == EventCategory.REMOTE_THREAD
    assert ev8.event_type == "create_remote_thread"
    assert ev8.process_guid == "{SRC-GUID}"
    assert ev8.process_id == 2000
    assert ev8.target_process_guid == "{TGT-GUID}"
    assert ev8.target_process_id == 600
    assert ev8.target_image == "C:\\Windows\\System32\\lsass.exe"

    # EID 10: Process Access
    sys10 = {
        "Provider": "Microsoft-Windows-Sysmon",
        "EventID": "10",
        "TimeCreated": "2023-04-10T14:22:20Z",
    }
    data10 = {
        "SourceProcessGUID": "{SRC-GUID-10}",
        "SourceProcessId": "2001",
        "SourceImage": "C:\\tools\\mimikatz.exe",
        "TargetProcessGUID": "{TGT-GUID-10}",
        "TargetProcessId": "600",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "GrantedAccess": "0x1010",
        "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d494",
    }
    ev10 = normalizer.normalize(sys10, data10, "<Event>eid10</Event>")
    assert ev10.event_id == 10
    assert ev10.event_category == EventCategory.PROCESS_ACCESS
    assert ev10.event_type == "process_access"
    assert ev10.granted_access == "0x1010"
    assert ev10.call_trace == "C:\\Windows\\SYSTEM32\\ntdll.dll+9d494"


def test_sysmon_registry_events(normalizer):
    for eid in (12, 13, 14):
        sys_f = {
            "Provider": "Microsoft-Windows-Sysmon",
            "EventID": str(eid),
            "TimeCreated": "2023-04-10T14:22:21Z",
        }
        data_f = {
            "EventType": "SetValue",
            "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            "Details": "C:\\ProgramData\\updater.exe",
            "ProcessId": "3344",
            "Image": "C:\\Windows\\regedit.exe",
        }
        ev = normalizer.normalize(sys_f, data_f, f"<Event>eid{eid}</Event>")
        assert ev.event_id == eid
        assert ev.event_category == EventCategory.REGISTRY
        assert ev.event_type == "registry_event"
        assert ev.registry_event_type == "SetValue"
        assert ev.registry_target_object == "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
        assert ev.registry_details == "C:\\ProgramData\\updater.exe"


def test_sysmon_wmi_and_dns(normalizer):
    # EID 19: WmiEvent (WmiEventFilter activity detected)
    sys19 = {
        "Provider": "Microsoft-Windows-Sysmon",
        "EventID": "19",
        "TimeCreated": "2023-04-10T14:22:22Z",
    }
    data19 = {
        "EventType": "WmiFilterEvent",
        "Operation": "Created",
        "Consumer": "CommandLineEventConsumer",
        "Filter": "EvilPersistenceFilter",
        "Query": "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'",
    }
    ev19 = normalizer.normalize(sys19, data19, "<Event>eid19</Event>")
    assert ev19.event_id == 19
    assert ev19.event_category == EventCategory.WMI
    assert ev19.event_type == "wmi_event"
    assert ev19.wmi_consumer == "CommandLineEventConsumer"
    assert ev19.wmi_filter == "EvilPersistenceFilter"
    assert "TargetInstance" in ev19.wmi_query

    # EID 22: DNS Query
    sys22 = {
        "Provider": "Microsoft-Windows-Sysmon",
        "EventID": "22",
        "TimeCreated": "2023-04-10T14:22:23Z",
    }
    data22 = {
        "QueryName": "malicious-c2.evil.com",
        "QueryStatus": "0",
        "QueryResults": "type: 5 c2-cname.evil.com;::ffff:198.51.100.5;",
        "ProcessId": "5500",
        "Image": "C:\\Windows\\System32\\svchost.exe",
    }
    ev22 = normalizer.normalize(sys22, data22, "<Event>eid22</Event>")
    assert ev22.event_id == 22
    assert ev22.event_category == EventCategory.DNS
    assert ev22.event_type == "dns_query"
    assert ev22.query_name == "malicious-c2.evil.com"
    assert ev22.query_status == "0"
    assert "198.51.100.5" in ev22.query_results


def test_sysmon_file_and_tampering_events(normalizer):
    # EID 11: File Create
    sys11 = {
        "Provider": "Microsoft-Windows-Sysmon",
        "EventID": "11",
        "TimeCreated": "2023-04-10T14:22:24Z",
    }
    data11 = {
        "ProcessId": "1200",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "TargetFilename": "C:\\Users\\admin\\payload.bat",
    }
    ev11 = normalizer.normalize(sys11, data11, "<Event>eid11</Event>")
    assert ev11.event_category == EventCategory.FILE
    assert ev11.event_type == "file_create"
    assert ev11.target_filename == "C:\\Users\\admin\\payload.bat"

    # EID 23: File Delete
    sys23 = {
        "Provider": "Microsoft-Windows-Sysmon",
        "EventID": "23",
        "TimeCreated": "2023-04-10T14:22:25Z",
    }
    data23 = {
        "ProcessId": "1200",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "TargetFilename": "C:\\Users\\admin\\evidence.log",
        "Hashes": "SHA256=1234abcd",
    }
    ev23 = normalizer.normalize(sys23, data23, "<Event>eid23</Event>")
    assert ev23.event_category == EventCategory.FILE
    assert ev23.event_type == "file_delete"
    assert ev23.target_filename == "C:\\Users\\admin\\evidence.log"
    assert ev23.hashes["sha256"] == "1234abcd"

    # EID 25: Process Tampering
    sys25 = {
        "Provider": "Microsoft-Windows-Sysmon",
        "EventID": "25",
        "TimeCreated": "2023-04-10T14:22:26Z",
    }
    data25 = {
        "ProcessId": "900",
        "Image": "C:\\Windows\\System32\\svchost.exe",
        "Type": "Process image change",
    }
    ev25 = normalizer.normalize(sys25, data25, "<Event>eid25</Event>")
    assert ev25.event_category == EventCategory.PROCESS
    assert ev25.event_type == "process_tampering"
    assert ev25.extra_fields.get("Type") == "Process image change"


def test_sysmon_partial_quarantine_missing_system_fields(normalizer):
    # Completely missing EventID and TimeCreated
    system_fields = {
        "Computer": "WORKSTATION01",
    }
    data_fields = {
        "Image": "C:\\Windows\\System32\\cmd.exe",
    }
    raw = "<CorruptEvent/>"

    event = normalizer.normalize(system_fields, data_fields, raw)
    assert event.is_quarantined is True
    assert len(event.quarantine_reasons) >= 2
    assert any("EventID" in r for r in event.quarantine_reasons)
    assert any("TimeCreated" in r for r in event.quarantine_reasons)
    assert event.raw_payload == raw
