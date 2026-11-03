"""Windows Security Auditing event normalizer for WinSentinel."""

from __future__ import annotations

from typing import Any

from app.models.events import EventCategory, NormalizedEvent
from app.normalization.base import BaseNormalizer


def parse_hex_or_dec_int(val: str | int | None) -> int | None:
    """Parse hexadecimal or decimal process and thread ID strings.

    Windows Security logs often represent PIDs in hexadecimal (e.g., '0x1f4' for 500),
    or sometimes decimal numbers. This function safely converts both forms.
    Returns None if empty, '-' or unparseable.
    """
    if val is None:
        return None
    if isinstance(val, int):
        return val

    s = str(val).strip()
    if not s or s == "-":
        return None

    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s, 10)
    except (ValueError, TypeError):
        try:
            return int(s, 16)
        except (ValueError, TypeError):
            return None


class SecurityNormalizer(BaseNormalizer):
    """Normalizes Microsoft-Windows-Security-Auditing events."""

    def normalize(
        self,
        system_fields: dict[str, Any],
        data_fields: dict[str, Any],
        raw_payload: str,
    ) -> NormalizedEvent:
        """Normalize Windows Security events (EID 4688, 4697, 4698, etc.)."""
        system_data, is_quarantined, quarantine_reasons = self.extract_common_system(
            system_fields=system_fields,
            raw_payload=raw_payload,
        )

        event_id = system_data["event_id"]
        category = EventCategory.SECURITY
        event_type = f"security_{event_id}"

        # Common Security subject fields
        user = self.get_field_case_insensitive(
            data_fields,
            "TargetUserName",
            "SubjectUserName",
            "user",
        )
        logon_id = self.get_field_case_insensitive(
            data_fields,
            "TargetLogonId",
            "SubjectLogonId",
        )

        # Attribute placeholders
        image: str | None = None
        command_line: str | None = None
        process_id: int | None = None
        parent_process_id: int | None = None
        parent_image: str | None = None
        service_name: str | None = None
        service_file_name: str | None = None
        task_name: str | None = None
        task_content: str | None = None

        if event_id == 4688:
            # Process Creation
            event_type = "process_create"
            image = self.get_field_case_insensitive(data_fields, "NewProcessName", "Image")
            command_line = self.get_field_case_insensitive(data_fields, "CommandLine")
            new_pid_raw = self.get_field_case_insensitive(data_fields, "NewProcessId")
            process_id = parse_hex_or_dec_int(new_pid_raw)
            # In EID 4688, 'ProcessId' is the creator / parent process ID
            creator_pid_raw = self.get_field_case_insensitive(data_fields, "ProcessId", "ParentProcessId")
            parent_process_id = parse_hex_or_dec_int(creator_pid_raw)
            parent_image = self.get_field_case_insensitive(data_fields, "ParentProcessName", "ParentImage")

        elif event_id == 4697:
            # A service was installed in the system
            event_type = "service_install"
            service_name = self.get_field_case_insensitive(data_fields, "ServiceName")
            service_file_name = self.get_field_case_insensitive(data_fields, "ServiceFileName")

        elif event_id == 4698:
            # A scheduled task was created
            event_type = "task_create"
            task_name = self.get_field_case_insensitive(data_fields, "TaskName")
            task_content = self.get_field_case_insensitive(data_fields, "TaskContent")

        # Collect extra fields
        mapped_keys = {
            "newprocessname", "image", "commandline", "newprocessid",
            "processid", "parentprocessid", "parentprocessname", "parentimage",
            "targetusername", "subjectusername", "targetlogonid", "subjectlogonid",
            "servicename", "servicefilename", "taskname", "taskcontent",
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
            image=image,
            command_line=command_line,
            process_id=process_id,
            user=user,
            logon_id=logon_id,
            parent_process_id=parent_process_id,
            parent_image=parent_image,
            service_name=service_name,
            service_file_name=service_file_name,
            task_name=task_name,
            task_content=task_content,
            extra_fields=extra_fields,
            raw_payload=raw_payload,
            event_hash=system_data["event_hash"],
            is_quarantined=is_quarantined,
            quarantine_reasons=quarantine_reasons,
        )
