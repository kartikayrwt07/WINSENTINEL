"""Field-matching engine with modifier pipeline and field resolution for WinSentinel.

Implements case-insensitive matching by default, string modifiers (|contains,
|startswith, |endswith, |re, |all), implicit OR for lists, Sigma PascalCase field
resolution to NormalizedEvent snake_case attributes, and ReDoS safeguards (T-04-04).
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

from app.models.detection import EvidenceItem
from app.models.events import NormalizedEvent

FIELD_ALIASES: dict[str, str] = {
    "targetobject": "registry_target_object",
    "details": "registry_details",
    "newname": "registry_new_name",
    "destinationip": "destination_ip",
    "sourceip": "source_ip",
    "imageloaded": "image_loaded",
    "parentcommandline": "parent_command_line",
    "parentimage": "parent_image",
    "parentprocessguid": "parent_process_guid",
    "parentprocessid": "parent_process_id",
    "parentuser": "parent_user",
    "targetimage": "target_image",
    "targetprocessguid": "target_process_guid",
    "targetprocessid": "target_process_id",
    "calltrace": "call_trace",
    "grantedaccess": "granted_access",
    "queryname": "query_name",
    "querystatus": "query_status",
    "queryresults": "query_results",
    "targetfilename": "target_filename",
    "hashes": "hashes",
    "commandline": "command_line",
    "image": "image",
    "currentdirectory": "current_directory",
    "processguid": "process_guid",
    "processid": "process_id",
    "user": "user",
    "computer": "computer",
    "channel": "channel",
    "provider": "provider",
    "eventid": "event_id",
    "recordid": "record_id",
    "scriptblocktext": "script_block_text",
    "scriptblockid": "script_block_id",
    "scriptpath": "script_path",
    "servicename": "service_name",
    "servicefilename": "service_file_name",
    "taskname": "task_name",
    "taskcontent": "task_content",
    "signed": "signed",
    "signature": "signature",
    "signaturestatus": "signature_status",
    "integritylevel": "integrity_level",
}


def pascal_to_snake(name: str) -> str:
    """Convert PascalCase or mixed Sigma field name to snake_case.

    Handles acronyms like DestinationIP -> destination_ip, EventID -> event_id.
    """
    s1 = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


@lru_cache(maxsize=1024)
def _compile_regex_pattern(pattern_str: str) -> re.Pattern[str]:
    """Compile and cache regular expression with case-insensitivity."""
    return re.compile(pattern_str, re.IGNORECASE)


class FieldMatcher:
    """Evaluates rule selection dictionaries against NormalizedEvent instances."""

    MAX_REGEX_LENGTH = 250

    def resolve_field_value(self, event: NormalizedEvent, raw_field: str) -> Any:
        """Resolve a Sigma or event field name to its actual value in NormalizedEvent.

        Lookup precedence:
        1. Direct attribute on NormalizedEvent (exact match)
        2. PascalCase-to-snake_case converted attribute
        3. Canonical alias mapping (e.g. TargetObject -> registry_target_object)
        4. Hash algorithm lookup in event.hashes (e.g. md5, sha256)
        5. Lookup inside event.extra_fields (direct, snake, or case-insensitive)
        6. Return None if not found or if the resolved attribute value is None.
        """
        # 1. Direct attribute match
        if hasattr(event, raw_field):
            val = getattr(event, raw_field)
            if val is not None:
                return val

        # 2. PascalCase to snake_case
        snake_name = pascal_to_snake(raw_field)
        if hasattr(event, snake_name):
            val = getattr(event, snake_name)
            if val is not None:
                return val

        # 3. Canonical aliases
        clean_alias_key = raw_field.lower().replace("_", "")
        if clean_alias_key in FIELD_ALIASES:
            alias_attr = FIELD_ALIASES[clean_alias_key]
            if hasattr(event, alias_attr):
                val = getattr(event, alias_attr)
                if val is not None:
                    return val

        # 4. Hash key lookup in event.hashes dict
        if clean_alias_key in ("md5", "sha256", "sha1", "imphash"):
            hashes_dict = getattr(event, "hashes", None)
            if isinstance(hashes_dict, dict) and clean_alias_key in hashes_dict:
                return hashes_dict[clean_alias_key]

        # 5. extra_fields dictionary
        extra = getattr(event, "extra_fields", None)
        if isinstance(extra, dict) and extra:
            if raw_field in extra and extra[raw_field] is not None:
                return extra[raw_field]
            if snake_name in extra and extra[snake_name] is not None:
                return extra[snake_name]
            raw_lower = raw_field.lower()
            for k, v in extra.items():
                if (k.lower() == raw_lower or k.lower().replace("_", "") == clean_alias_key) and v is not None:
                    return v

        return None

    def _parse_field_spec(self, field_spec: str) -> tuple[str, set[str]]:
        """Parse pipe-separated field specifiers into base field and modifier set."""
        parts = field_spec.split("|")
        base_field = parts[0].strip()
        modifiers = {p.strip().lower() for p in parts[1:] if p.strip()}
        return base_field, modifiers

    def _match_single_value(self, actual_val: Any, pattern: Any, modifiers: set[str]) -> bool:
        """Evaluate a single actual value against a pattern using the modifier pipeline."""
        if actual_val is None:
            return False

        # Regular expression matching (T-04-04 ReDoS safeguard)
        if "re" in modifiers:
            pattern_str = str(pattern)
            if len(pattern_str) > self.MAX_REGEX_LENGTH:
                raise ValueError(
                    f"Regex pattern exceeds maximum allowed length of {self.MAX_REGEX_LENGTH} characters: "
                    f"'{pattern_str[:30]}...'"
                )
            regex = _compile_regex_pattern(pattern_str)
            if isinstance(actual_val, dict):
                return any(bool(regex.search(str(v))) for v in actual_val.values())
            return bool(regex.search(str(actual_val)))

        # String prefix match
        if "startswith" in modifiers:
            return str(actual_val).lower().startswith(str(pattern).lower())

        # String suffix match
        if "endswith" in modifiers:
            return str(actual_val).lower().endswith(str(pattern).lower())

        # Substring inclusion
        if "contains" in modifiers:
            pattern_str = str(pattern).lower()
            if isinstance(actual_val, dict):
                return any(pattern_str in str(v).lower() for v in actual_val.values()) or pattern_str in str(actual_val).lower()
            return pattern_str in str(actual_val).lower()

        # Default: exact equality (case-insensitive for strings, exact for numbers/booleans)
        if isinstance(actual_val, bool) and isinstance(pattern, bool):
            return actual_val is pattern

        if isinstance(actual_val, (int, float)) and isinstance(pattern, (int, float)):
            return actual_val == pattern

        if isinstance(actual_val, (int, float)) and isinstance(pattern, str):
            try:
                num = float(pattern) if "." in pattern else int(pattern)
                return actual_val == num
            except ValueError:
                pass
        elif isinstance(pattern, (int, float)) and isinstance(actual_val, str):
            try:
                num = float(actual_val) if "." in actual_val else int(actual_val)
                return num == pattern
            except ValueError:
                pass

        if isinstance(actual_val, dict):
            pat_str = str(pattern).lower()
            return any(pat_str == str(v).lower() for v in actual_val.values())

        return str(actual_val).lower() == str(pattern).lower()

    def match_selection(
        self,
        event: NormalizedEvent,
        selection_dict: dict[str, Any],
    ) -> tuple[bool, list[EvidenceItem]]:
        """Evaluate a selection dictionary against an event.

        All field criteria in selection_dict must match (logical AND).
        Returns:
            Tuple of (matched_bool, list_of_evidence_items).
        """
        if not selection_dict:
            return False, []

        evidence_items: list[EvidenceItem] = []

        for field_spec, pattern_val in selection_dict.items():
            base_field, modifiers = self._parse_field_spec(field_spec)
            actual_value = self.resolve_field_value(event, base_field)

            if actual_value is None:
                return False, []

            mod_label = "|".join(sorted(modifiers)) if modifiers else "exact"

            if isinstance(pattern_val, (list, tuple, set)):
                if "all" in modifiers:
                    # All patterns must match the actual value
                    for pat in pattern_val:
                        if not self._match_single_value(actual_value, pat, modifiers):
                            return False, []
                        evidence_items.append(
                            EvidenceItem(
                                field=base_field,
                                actual_value=actual_value,
                                matched_pattern=pat,
                                modifier=mod_label,
                            )
                        )
                else:
                    # Implicit OR: any matching pattern satisfies this field
                    matched_patterns = [
                        pat for pat in pattern_val if self._match_single_value(actual_value, pat, modifiers)
                    ]
                    if not matched_patterns:
                        return False, []
                    for mp in matched_patterns:
                        evidence_items.append(
                            EvidenceItem(
                                field=base_field,
                                actual_value=actual_value,
                                matched_pattern=mp,
                                modifier=mod_label,
                            )
                        )
            else:
                # Single scalar pattern
                if not self._match_single_value(actual_value, pattern_val, modifiers):
                    return False, []
                evidence_items.append(
                    EvidenceItem(
                        field=base_field,
                        actual_value=actual_value,
                        matched_pattern=pattern_val,
                        modifier=mod_label,
                    )
                )

        return True, evidence_items
