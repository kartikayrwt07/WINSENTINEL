"""Sysmon event normalizer for WinSentinel."""

from __future__ import annotations

from typing import Any

from app.models.events import EventCategory, NormalizedEvent, parse_sysmon_hashes
from app.normalization.base import BaseNormalizer

# EID to (EventCategory, event_type) mapping table
SYSMON_EID_MAP: dict[int, tuple[EventCategory, str]] = {
    1: (EventCategory.PROCESS, "process_create"),
    3: (EventCategory.NETWORK, "network_connect"),
    5: (EventCategory.PROCESS, "process_terminate"),
    6: (EventCategory.DRIVER, "driver_load"),
    7: (EventCategory.IMAGE_LOAD, "image_load"),
    8: (EventCategory.REMOTE_THREAD, "create_remote_thread"),
    10: (EventCategory.PROCESS_ACCESS, "process_access"),
    11: (EventCategory.FILE, "file_create"),
    12: (EventCategory.REGISTRY, "registry_event"),
    13: (EventCategory.REGISTRY, "registry_event"),
    14: (EventCategory.REGISTRY, "registry_event"),
    19: (EventCategory.WMI, "wmi_event"),
    20: (EventCategory.WMI, "wmi_event"),
    21: (EventCategory.WMI, "wmi_event"),
    22: (EventCategory.DNS, "dns_query"),
    23: (EventCategory.FILE, "file_delete"),
    24: (EventCategory.GENERIC, "clipboard_change"),
    25: (EventCategory.PROCESS, "process_tampering"),
    26: (EventCategory.FILE, "file_delete"),
}


class SysmonNormalizer(BaseNormalizer):
    """Normalizes Microsoft-Windows-Sysmon events into NormalizedEvent structures."""

    def normalize(
        self,
        system_fields: dict[str, Any],
        data_fields: dict[str, Any],
        raw_payload: str,
    ) -> NormalizedEvent:
        """Normalize Sysmon event records."""
        system_data, is_quarantined, quarantine_reasons = self.extract_common_system(
            system_fields=system_fields,
            raw_payload=raw_payload,
        )

        event_id = system_data["event_id"]
        category, event_type = SYSMON_EID_MAP.get(
            event_id,
            (EventCategory.GENERIC, f"sysmon_{event_id}"),
        )

        # Subject process extraction (handling both ProcessGuid and SourceProcessGuid/SourceProcessGUID)
        process_guid = self.get_field_case_insensitive(
            data_fields,
            "ProcessGuid",
            "SourceProcessGuid",
            "SourceProcessGUID",
        )
        process_id = self.get_int_field_case_insensitive(
            data_fields,
            "ProcessId",
            "SourceProcessId",
        )
        image = self.get_field_case_insensitive(
            data_fields,
            "Image",
            "SourceImage",
        )
        command_line = self.get_field_case_insensitive(data_fields, "CommandLine")
        current_directory = self.get_field_case_insensitive(data_fields, "CurrentDirectory")
        user = self.get_field_case_insensitive(data_fields, "User")
        logon_guid = self.get_field_case_insensitive(data_fields, "LogonGuid")
        logon_id = self.get_field_case_insensitive(data_fields, "LogonId")
        integrity_level = self.get_field_case_insensitive(data_fields, "IntegrityLevel")

        # Hashes parsing
        hashes_raw = self.get_field_case_insensitive(data_fields, "Hashes")
        hashes = parse_sysmon_hashes(hashes_raw)

        # Parent process attributes
        parent_process_guid = self.get_field_case_insensitive(data_fields, "ParentProcessGuid")
        parent_process_id = self.get_int_field_case_insensitive(data_fields, "ParentProcessId")
        parent_image = self.get_field_case_insensitive(data_fields, "ParentImage")
        parent_command_line = self.get_field_case_insensitive(data_fields, "ParentCommandLine")
        parent_user = self.get_field_case_insensitive(data_fields, "ParentUser")

        # Target process attributes (for EID 8, 10, 25)
        target_process_guid = self.get_field_case_insensitive(
            data_fields,
            "TargetProcessGuid",
            "TargetProcessGUID",
        )
        target_process_id = self.get_int_field_case_insensitive(data_fields, "TargetProcessId")
        target_image = self.get_field_case_insensitive(data_fields, "TargetImage")
        granted_access = self.get_field_case_insensitive(data_fields, "GrantedAccess")
        call_trace = self.get_field_case_insensitive(data_fields, "CallTrace")

        # Network attributes (EID 3)
        source_ip = self.get_field_case_insensitive(data_fields, "SourceIp")
        source_port = self.get_int_field_case_insensitive(data_fields, "SourcePort")
        source_hostname = self.get_field_case_insensitive(data_fields, "SourceHostname")
        destination_ip = self.get_field_case_insensitive(data_fields, "DestinationIp")
        destination_port = self.get_int_field_case_insensitive(data_fields, "DestinationPort")
        destination_hostname = self.get_field_case_insensitive(data_fields, "DestinationHostname")
        protocol = self.get_field_case_insensitive(data_fields, "Protocol")

        # DNS attributes (EID 22)
        query_name = self.get_field_case_insensitive(data_fields, "QueryName")
        query_status = self.get_field_case_insensitive(data_fields, "QueryStatus")
        query_results = self.get_field_case_insensitive(data_fields, "QueryResults")

        # File & Driver attributes (EID 6, 7, 11, 23, 26)
        target_filename = self.get_field_case_insensitive(
            data_fields,
            "TargetFilename",
            "TargetFileName",
        )
        image_loaded = self.get_field_case_insensitive(data_fields, "ImageLoaded")
        signed = self.get_field_case_insensitive(data_fields, "Signed")
        signature = self.get_field_case_insensitive(data_fields, "Signature")
        signature_status = self.get_field_case_insensitive(data_fields, "SignatureStatus")

        # Registry attributes (EID 12, 13, 14)
        registry_event_type = self.get_field_case_insensitive(data_fields, "EventType")
        registry_target_object = self.get_field_case_insensitive(data_fields, "TargetObject")
        registry_details = self.get_field_case_insensitive(data_fields, "Details")
        registry_new_name = self.get_field_case_insensitive(data_fields, "NewName")

        # WMI attributes (EID 19, 20, 21)
        wmi_operation = self.get_field_case_insensitive(data_fields, "Operation", "EventType")
        wmi_consumer = self.get_field_case_insensitive(data_fields, "Consumer")
        wmi_filter = self.get_field_case_insensitive(data_fields, "Filter")
        wmi_query = self.get_field_case_insensitive(data_fields, "Query")

        # Collect unmapped fields into extra_fields
        mapped_keys = {
            "processguid", "sourceprocessguid", "processid", "sourceprocessid",
            "image", "sourceimage", "commandline", "currentdirectory", "user",
            "logonguid", "logonid", "integritylevel", "hashes",
            "parentprocessguid", "parentprocessid", "parentimage", "parentcommandline", "parentuser",
            "targetprocessguid", "targetprocessid", "targetimage", "grantedaccess", "calltrace",
            "sourceip", "sourceport", "sourcehostname", "destinationip", "destinationport", "destinationhostname", "protocol",
            "queryname", "querystatus", "queryresults",
            "targetfilename", "imageloaded", "signed", "signature", "signaturestatus",
            "eventtype", "targetobject", "details", "newname",
            "operation", "consumer", "filter", "query",
        }
        extra_fields: dict[str, Any] = {}
        for k, v in data_fields.items():
            if k.lower() not in mapped_keys and v:
                extra_fields[k] = v

        return NormalizedEvent(
            event_id=event_id,
            record_id=system_data["record_id"],
            provider=system_data["provider"],
            channel=system_data["channel"],
            computer=system_data["computer"],
            timestamp=system_data["timestamp"],
            event_category=category,
            event_type=event_type,
            process_guid=process_guid,
            process_id=process_id,
            image=image,
            command_line=command_line,
            current_directory=current_directory,
            user=user,
            logon_guid=logon_guid,
            logon_id=logon_id,
            integrity_level=integrity_level,
            hashes=hashes,
            parent_process_guid=parent_process_guid,
            parent_process_id=parent_process_id,
            parent_image=parent_image,
            parent_command_line=parent_command_line,
            parent_user=parent_user,
            target_process_guid=target_process_guid,
            target_process_id=target_process_id,
            target_image=target_image,
            granted_access=granted_access,
            call_trace=call_trace,
            source_ip=source_ip,
            source_port=source_port,
            source_hostname=source_hostname,
            destination_ip=destination_ip,
            destination_port=destination_port,
            destination_hostname=destination_hostname,
            protocol=protocol,
            query_name=query_name,
            query_status=query_status,
            query_results=query_results,
            target_filename=target_filename,
            image_loaded=image_loaded,
            signed=signed,
            signature=signature,
            signature_status=signature_status,
            registry_event_type=registry_event_type,
            registry_target_object=registry_target_object,
            registry_details=registry_details,
            registry_new_name=registry_new_name,
            wmi_operation=wmi_operation,
            wmi_consumer=wmi_consumer,
            wmi_filter=wmi_filter,
            wmi_query=wmi_query,
            extra_fields=extra_fields,
            raw_payload=raw_payload,
            event_hash=system_data["event_hash"],
            is_quarantined=is_quarantined,
            quarantine_reasons=quarantine_reasons,
        )
