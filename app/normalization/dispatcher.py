"""Normalizer registry and dynamic dispatcher for WinSentinel."""

from __future__ import annotations

import logging
from typing import Any

from app.models.events import EventCategory, NormalizedEvent
from app.normalization.base import BaseNormalizer
from app.normalization.powershell import PowerShellNormalizer
from app.normalization.security import SecurityNormalizer
from app.normalization.sysmon import SysmonNormalizer

logger = logging.getLogger(__name__)


class GenericNormalizer(BaseNormalizer):
    """Fallback normalizer for unmapped or generic event log providers."""

    def normalize(
        self,
        system_fields: dict[str, Any],
        data_fields: dict[str, Any],
        raw_payload: str,
    ) -> NormalizedEvent:
        """Normalize generic event payload into NormalizedEvent contract."""
        system_data, is_quarantined, quarantine_reasons = self.extract_common_system(
            system_fields=system_fields,
            raw_payload=raw_payload,
        )

        event_id = system_data["event_id"]
        extra_fields: dict[str, Any] = dict(data_fields) if data_fields else {}

        return NormalizedEvent(
            event_id=event_id,
            record_id=system_data["record_id"],
            provider=system_data["provider"],
            channel=system_data["channel"],
            computer=system_data["computer"],
            timestamp=system_data["timestamp"],
            event_category=EventCategory.GENERIC,
            event_type=f"event_{event_id}",
            extra_fields=extra_fields,
            raw_payload=raw_payload,
            event_hash=system_data["event_hash"],
            is_quarantined=is_quarantined,
            quarantine_reasons=quarantine_reasons,
        )


class NormalizerDispatcher:
    """Routes raw event dictionaries to specialized provider normalizers."""

    def __init__(self) -> None:
        self._generic = GenericNormalizer()
        self._registry: dict[str, BaseNormalizer] = {}

        # Register default normalizers
        sysmon_norm = SysmonNormalizer()
        security_norm = SecurityNormalizer()
        pwsh_norm = PowerShellNormalizer()

        self.register("microsoft-windows-sysmon", sysmon_norm)
        self.register("sysmon", sysmon_norm)

        self.register("microsoft-windows-security-auditing", security_norm)
        self.register("security", security_norm)

        self.register("microsoft-windows-powershell", pwsh_norm)
        self.register("powershell", pwsh_norm)

    def register(self, provider: str, normalizer: BaseNormalizer) -> None:
        """Register a normalizer instance for a provider name."""
        self._registry[provider.strip().lower()] = normalizer

    def dispatch(
        self,
        system_fields: dict[str, Any],
        data_fields: dict[str, Any],
        raw_payload: str,
    ) -> NormalizedEvent:
        """Dispatch event fields to the appropriate normalizer based on Provider."""
        provider = (
            system_fields.get("Provider")
            or system_fields.get("ProviderName")
            or system_fields.get("provider")
            or ""
        )
        provider_clean = str(provider).strip().lower()

        normalizer = self._registry.get(provider_clean)
        if not normalizer:
            # Fuzzy substring fallback
            if "sysmon" in provider_clean:
                normalizer = self._registry.get("microsoft-windows-sysmon")
            elif "security-auditing" in provider_clean or "security" in provider_clean:
                normalizer = self._registry.get("microsoft-windows-security-auditing")
            elif "powershell" in provider_clean:
                normalizer = self._registry.get("microsoft-windows-powershell")

        if not normalizer:
            normalizer = self._generic

        return normalizer.normalize(
            system_fields=system_fields,
            data_fields=data_fields,
            raw_payload=raw_payload,
        )
