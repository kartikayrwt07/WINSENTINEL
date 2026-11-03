"""PowerShell Operational event normalizer for WinSentinel."""

from __future__ import annotations

from typing import Any

from app.models.events import EventCategory, NormalizedEvent
from app.normalization.base import BaseNormalizer


class PowerShellNormalizer(BaseNormalizer):
    """Normalizes Microsoft-Windows-PowerShell and PowerShell events."""

    def normalize(
        self,
        system_fields: dict[str, Any],
        data_fields: dict[str, Any],
        raw_payload: str,
    ) -> NormalizedEvent:
        """Normalize PowerShell events (EID 4103 Pipeline Execution, 4104 Script Block, etc.)."""
        system_data, is_quarantined, quarantine_reasons = self.extract_common_system(
            system_fields=system_fields,
            raw_payload=raw_payload,
        )

        event_id = system_data["event_id"]
        category = EventCategory.POWERSHELL
        event_type = f"powershell_{event_id}"

        # Subject process / user
        user = self.get_field_case_insensitive(data_fields, "User", "UserId")
        process_id = self.get_int_field_case_insensitive(
            system_fields, "ProcessID", "process_id"
        ) or self.get_int_field_case_insensitive(data_fields, "ProcessId", "process_id")

        script_block_text: str | None = None
        script_block_id: str | None = None
        script_path: str | None = None

        if event_id == 4103:
            # Module / Pipeline Execution Logging
            event_type = "pipeline_execute"

        elif event_id == 4104:
            # Script Block Logging
            event_type = "script_block"
            script_block_text = self.get_field_case_insensitive(data_fields, "ScriptBlockText")
            script_block_id = self.get_field_case_insensitive(data_fields, "ScriptBlockId")
            script_path = self.get_field_case_insensitive(data_fields, "Path", "ScriptPath")

        # Collect extra fields (ContextInfo, Payload, MessageNumber, MessageTotal, etc.)
        mapped_keys = {
            "scriptblocktext", "scriptblockid", "path", "scriptpath",
            "user", "userid", "processid",
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
            user=user,
            process_id=process_id,
            script_block_text=script_block_text,
            script_block_id=script_block_id,
            script_path=script_path,
            extra_fields=extra_fields,
            raw_payload=raw_payload,
            event_hash=system_data["event_hash"],
            is_quarantined=is_quarantined,
            quarantine_reasons=quarantine_reasons,
        )
