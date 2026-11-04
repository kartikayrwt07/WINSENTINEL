"""Multi-Source Persistence Threat Analyzer for WinSentinel.

Detects host persistence mechanisms across 5 distinct telemetry channels:
1. Registry Auto-Runs & IFEO (Sysmon EID 12, 13, 14)
2. Services & Driver Loads (Security EID 4697, Sysmon EID 6)
3. Scheduled Tasks (Authoritative Security EID 4698 XML & Task Scheduler EID 106, 140)
4. WMI Event Subscriptions (Sysmon EID 19, 20, 21)
5. Startup Folder File Drops (Sysmon EID 11)

Strict Invariant: Scheduled tasks are NEVER inferred purely from Sysmon registry modifications.
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

from app.models.events import EventCategory, NormalizedEvent
from app.models.persistence import PersistenceArtifact, PersistenceType

logger = logging.getLogger(__name__)


class PersistenceAnalyzer:
    """Correlates telemetry events to uncover adversary persistence techniques."""

    # Monitored registry persistence key fragments (lowercase)
    RUN_KEYS = (
        r"\currentversion\run",
        r"\currentversion\runonce",
        r"\currentversion\runonceex",
        r"\policies\explorer\run",
    )
    WINLOGON_KEYS = (
        r"\winlogon\userinit",
        r"\winlogon\shell",
    )
    APPINIT_KEYS = (
        r"\currentversion\windows\appinit_dlls",
    )
    SILENT_PROCESS_EXIT_KEYS = (
        r"\currentversion\silentprocessexit",
    )

    # Suspicious file paths & script/LOLBAS binaries for payload escalation
    SUSPICIOUS_PATHS = (
        "\\temp\\",
        "\\tmp\\",
        "\\users\\",
        "\\appdata\\",
        "\\programdata\\",
    )
    SUSPICIOUS_EXTENSIONS = (
        ".vbs",
        ".ps1",
        ".bat",
        ".cmd",
        ".js",
        ".wsf",
    )
    LOLBAS_BINARIES = (
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "cscript.exe",
        "wscript.exe",
        "certutil.exe",
        "bitsadmin.exe",
    )

    # Startup folder extensions
    STARTUP_EXTENSIONS = (
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".vbs",
        ".js",
        ".wsf",
        ".ps1",
        ".lnk",
    )

    def _parse_task_xml(self, task_content: str) -> tuple[str | None, str | None]:
        """Safely parse Task Definition XML without external entity resolution."""
        if not task_content or not task_content.strip():
            return None, None

        try:
            # Defensively configure XMLParser with zero entity resolution to mitigate XXE
            parser = ET.XMLParser()
            try:
                parser.entity = {}
            except Exception:
                pass

            root = ET.fromstring(task_content.strip(), parser=parser)
            cmd: str | None = None
            args: str | None = None

            # Traverse regardless of XML namespace
            for elem in root.iter():
                tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                tag_lower = tag.lower()
                if tag_lower == "command" and elem.text and not cmd:
                    cmd = elem.text.strip()
                elif tag_lower == "arguments" and elem.text and not args:
                    args = elem.text.strip()

            return cmd, args
        except Exception as err:
            logger.debug("Failed to parse task XML: %s", err)
            return None, None

    def check_registry_persistence(
        self,
        event: NormalizedEvent,
        event_db_id: int | None = None,
    ) -> PersistenceArtifact | None:
        """Inspect Sysmon Registry events (EID 12, 13, 14) for persistence modifications."""
        target = event.registry_target_object
        if not target:
            return None

        target_lower = target.lower()

        # Strict project invariant: Sysmon registry events modifying TaskCache or Tree\Tasks
        # must NEVER generate scheduled task persistence or false alarms.
        if "schedule\\taskcache" in target_lower or "microsoft\\windows\\tasks" in target_lower:
            return None

        payload = event.registry_details or event.registry_new_name or event.command_line
        payload_lower = (payload or "").lower()

        # 1. Image File Execution Options (IFEO) Debugger Hijacking
        if r"\image file execution options" in target_lower and r"\debugger" in target_lower:
            return PersistenceArtifact(
                persistence_type=PersistenceType.REGISTRY,
                event_id=event.event_id,
                record_id=event.record_id,
                event_db_id=event_db_id,
                computer=event.computer,
                timestamp_utc=event.timestamp,
                process_guid=event.process_guid,
                user=event.user,
                target_name=target,
                payload=payload,
                severity="High",
                mitre_tactics=["TA0003 - Persistence", "TA0004 - Privilege Escalation"],
                mitre_techniques=["T1546.012 - Image File Execution Options Injection"],
                evidence_fields={
                    "registry_target_object": target,
                    "registry_details": payload,
                    "registry_event_type": event.registry_event_type,
                },
                explanation=f"Image File Execution Options (IFEO) debugger hijacking detected on {target}",
                investigation_steps=[
                    f"Examine the debugger payload specified in {target}.",
                    "Determine whether the associated process is an accessibility binary (e.g., sethc.exe, utilman.exe).",
                    "Verify the parent process and user credentials that modified the IFEO registry key.",
                ],
            )

        # 2. Winlogon (Userinit / Shell) Hijacking
        if any(wk in target_lower for wk in self.WINLOGON_KEYS):
            return PersistenceArtifact(
                persistence_type=PersistenceType.REGISTRY,
                event_id=event.event_id,
                record_id=event.record_id,
                event_db_id=event_db_id,
                computer=event.computer,
                timestamp_utc=event.timestamp,
                process_guid=event.process_guid,
                user=event.user,
                target_name=target,
                payload=payload,
                severity="High",
                mitre_tactics=["TA0003 - Persistence", "TA0004 - Privilege Escalation"],
                mitre_techniques=["T1547.004 - Winlogon Helper DLL"],
                evidence_fields={
                    "registry_target_object": target,
                    "registry_details": payload,
                    "registry_event_type": event.registry_event_type,
                },
                explanation=f"Winlogon persistence mechanism modified: {target}",
                investigation_steps=[
                    f"Check whether the Winlogon payload points to non-standard binaries outside C:\\Windows\\System32.",
                    "Review user logon events around the time of registry modification.",
                    "Inspect disk image for dropped helper DLLs or executables.",
                ],
            )

        # 3. AppInit_DLLs Injection
        if any(ak in target_lower for ak in self.APPINIT_KEYS):
            return PersistenceArtifact(
                persistence_type=PersistenceType.REGISTRY,
                event_id=event.event_id,
                record_id=event.record_id,
                event_db_id=event_db_id,
                computer=event.computer,
                timestamp_utc=event.timestamp,
                process_guid=event.process_guid,
                user=event.user,
                target_name=target,
                payload=payload,
                severity="High",
                mitre_tactics=["TA0003 - Persistence", "TA0004 - Privilege Escalation"],
                mitre_techniques=["T1546.010 - AppInit DLLs"],
                evidence_fields={
                    "registry_target_object": target,
                    "registry_details": payload,
                    "registry_event_type": event.registry_event_type,
                },
                explanation=f"AppInit_DLLs persistence modification detected: {target}",
                investigation_steps=[
                    "Examine the DLL path referenced in AppInit_DLLs for digital signature and reputation.",
                    "Determine if Secure Boot is enabled (AppInit_DLLs is disabled by default under Secure Boot).",
                ],
            )

        # 4. Standard Run / RunOnce / RunOnceEx / Explorer\Run Keys
        if any(rk in target_lower for rk in self.RUN_KEYS):
            # Check for suspicious payload characteristics (Temp, Users, AppData, script, LOLBAS)
            is_suspicious_payload = (
                any(p in payload_lower for p in self.SUSPICIOUS_PATHS)
                or any(payload_lower.endswith(ext) or (ext + " ") in payload_lower for ext in self.SUSPICIOUS_EXTENSIONS)
                or any(bin_name in payload_lower for bin_name in self.LOLBAS_BINARIES)
            )

            severity = "High" if is_suspicious_payload else "Medium"
            explanation = (
                f"Suspicious Auto-Run registry key modified pointing to script, temp/user path, or LOLBAS: {target}"
                if is_suspicious_payload
                else f"Auto-Run registry key modified: {target}"
            )

            return PersistenceArtifact(
                persistence_type=PersistenceType.REGISTRY,
                event_id=event.event_id,
                record_id=event.record_id,
                event_db_id=event_db_id,
                computer=event.computer,
                timestamp_utc=event.timestamp,
                process_guid=event.process_guid,
                user=event.user,
                target_name=target,
                payload=payload,
                severity=severity,
                mitre_tactics=["TA0003 - Persistence"],
                mitre_techniques=["T1547.001 - Registry Run Keys / Startup Folder"],
                evidence_fields={
                    "registry_target_object": target,
                    "registry_details": payload,
                    "registry_event_type": event.registry_event_type,
                },
                explanation=explanation,
                investigation_steps=[
                    f"Verify whether the binary at '{payload}' is known and authorized enterprise software.",
                    "Inspect the file hashes and digital signature of the referenced binary.",
                    "Review network connections initiated by the process post-reboot.",
                ],
            )

        return None

    def check_service_driver_persistence(
        self,
        event: NormalizedEvent,
        event_db_id: int | None = None,
    ) -> PersistenceArtifact | None:
        """Inspect Security EID 4697 (service installed) and Sysmon EID 6 (driver loaded)."""
        # 1. Windows Service Installation (Security EID 4697 or Service Category)
        if event.event_id == 4697 or (
            event.event_category == EventCategory.SECURITY
            and event.service_name is not None
        ) or (event.service_name is not None and event.service_file_name is not None):
            service_name = event.service_name or "UnknownService"
            service_file = event.service_file_name or event.command_line or "UnknownBinary"
            service_file_lower = service_file.lower()

            # Check if binary executes out of user profiles, temp, or uses script interpreters
            is_suspicious_path = any(p in service_file_lower for p in self.SUSPICIOUS_PATHS)
            is_script_or_lolbas = (
                any(service_file_lower.endswith(ext) or (ext + " ") in service_file_lower for ext in self.SUSPICIOUS_EXTENSIONS)
                or any(bin_name in service_file_lower for bin_name in self.LOLBAS_BINARIES)
            )

            if is_suspicious_path and is_script_or_lolbas:
                severity = "Critical"
            elif is_suspicious_path or is_script_or_lolbas:
                severity = "High"
            else:
                severity = "Medium"

            return PersistenceArtifact(
                persistence_type=PersistenceType.SERVICE,
                event_id=event.event_id,
                record_id=event.record_id,
                event_db_id=event_db_id,
                computer=event.computer,
                timestamp_utc=event.timestamp,
                process_guid=event.process_guid,
                user=event.user,
                target_name=service_name,
                payload=service_file,
                severity=severity,
                mitre_tactics=["TA0003 - Persistence", "TA0004 - Privilege Escalation"],
                mitre_techniques=["T1543.003 - Windows Service"],
                evidence_fields={
                    "service_name": service_name,
                    "service_file_name": service_file,
                },
                explanation=(
                    f"New Windows service installed ('{service_name}') executing suspicious binary: {service_file}"
                    if severity in ("High", "Critical")
                    else f"New Windows service installed: '{service_name}' ({service_file})"
                ),
                investigation_steps=[
                    f"Verify whether service '{service_name}' was installed as part of an authorized software update.",
                    f"Inspect the binary located at '{service_file}' for signature and reputation.",
                    "Check the service account context (LocalSystem, NetworkService, LocalService).",
                ],
            )

        # 2. Kernel Driver Load (Sysmon EID 6)
        if event.event_id == 6 or event.event_category == EventCategory.DRIVER:
            driver_path = event.target_filename or event.image_loaded or "UnknownDriver"
            driver_lower = driver_path.lower()

            signed_str = (event.signed or "").strip().lower()
            sig_status = (event.signature_status or "").strip().lower()

            is_unsigned = signed_str == "false" or (bool(sig_status) and sig_status != "valid")
            is_non_driver_path = not (
                "\\system32\\drivers\\" in driver_lower
                or "\\system32\\drivers" in driver_lower
                or "\\syswow64\\drivers" in driver_lower
            )

            if is_unsigned or is_non_driver_path:
                return PersistenceArtifact(
                    persistence_type=PersistenceType.DRIVER,
                    event_id=event.event_id,
                    record_id=event.record_id,
                    event_db_id=event_db_id,
                    computer=event.computer,
                    timestamp_utc=event.timestamp,
                    process_guid=event.process_guid,
                    user=event.user,
                    target_name=driver_path,
                    payload=driver_path,
                    severity="High",
                    mitre_tactics=["TA0003 - Persistence", "TA0004 - Privilege Escalation"],
                    mitre_techniques=[
                        "T1068 - Exploitation for Privilege Escalation",
                        "T1543.003 - Windows Service",
                    ],
                    evidence_fields={
                        "driver_path": driver_path,
                        "signed": event.signed,
                        "signature_status": event.signature_status,
                        "hashes": event.hashes,
                    },
                    explanation=f"Suspicious or unsigned kernel driver loaded: {driver_path}",
                    investigation_steps=[
                        f"Verify driver certificate and signature status: signed={event.signed}, status={event.signature_status}.",
                        "Compute driver file hash and compare against known Bring Your Own Vulnerable Driver (BYOVD) catalogs.",
                        "Inspect calling process and account that initiated driver load.",
                    ],
                )

        return None

    def check_scheduled_task_persistence(
        self,
        event: NormalizedEvent,
        event_db_id: int | None = None,
    ) -> PersistenceArtifact | None:
        """Inspect authoritative Scheduled Task telemetry (Security 4698, Task Scheduler 106/140).

        STRICT PROJECT INVARIANT:
        Modifications to registry keys (Schedule\\TaskCache) alone are NEVER classified
        as scheduled task persistence.
        """
        # Strict Invariant: Exclude registry events
        if event.event_id in (12, 13, 14) or event.event_category == EventCategory.REGISTRY:
            return None

        # Authoritative sources only
        is_security_4698 = event.event_id == 4698
        is_task_scheduler_op = event.event_id in (106, 140) and (
            "taskscheduler" in (event.provider or "").lower()
            or "taskscheduler" in (event.channel or "").lower()
        )

        if not (is_security_4698 or is_task_scheduler_op or bool(event.task_content)):
            return None

        task_name = event.task_name or "ScheduledTask"
        cmd, args = self._parse_task_xml(event.task_content) if event.task_content else (None, None)

        if cmd or args:
            payload = f"{cmd} {args}".strip() if (cmd and args) else (cmd or args or "")
        else:
            payload = event.command_line or ""

        payload_lower = (payload or "").lower()

        is_suspicious_payload = (
            any(bin_name in payload_lower for bin_name in self.LOLBAS_BINARIES)
            or any(p in payload_lower for p in self.SUSPICIOUS_PATHS)
            or any(payload_lower.endswith(ext) or (ext + " ") in payload_lower for ext in self.SUSPICIOUS_EXTENSIONS)
        )

        severity = "High" if is_suspicious_payload else "Medium"
        explanation = (
            f"Scheduled task created with suspicious execution payload ('{task_name}'): {payload}"
            if is_suspicious_payload and payload
            else f"Scheduled task created or modified: '{task_name}'"
        )

        evidence_fields: dict[str, Any] = {"task_name": task_name}
        if cmd:
            evidence_fields["command"] = cmd
        if args:
            evidence_fields["arguments"] = args
        if event.task_content:
            evidence_fields["task_content"] = event.task_content[:500]

        return PersistenceArtifact(
            persistence_type=PersistenceType.SCHEDULED_TASK,
            event_id=event.event_id,
            record_id=event.record_id,
            event_db_id=event_db_id,
            computer=event.computer,
            timestamp_utc=event.timestamp,
            process_guid=event.process_guid,
            user=event.user,
            target_name=task_name,
            payload=payload if payload else None,
            severity=severity,
            mitre_tactics=["TA0003 - Persistence", "TA0002 - Execution"],
            mitre_techniques=["T1053.005 - Scheduled Task"],
            evidence_fields=evidence_fields,
            explanation=explanation,
            investigation_steps=[
                f"Inspect task definition and triggers for scheduled task '{task_name}'.",
                "Verify whether the user account registering the task had proper change management authorization.",
                f"Examine executable or script '{payload}' for persistence persistence hooks or external network activity.",
            ],
        )

    def check_wmi_persistence(
        self,
        event: NormalizedEvent,
        event_db_id: int | None = None,
    ) -> PersistenceArtifact | None:
        """Inspect Sysmon WMI events: EID 19 (Filter), EID 20 (Consumer), EID 21 (Binding)."""
        is_wmi = event.event_id in (19, 20, 21) or event.event_category == EventCategory.WMI
        if not is_wmi:
            return None

        # EID 21: FilterToConsumerBinding (Completed WMI Persistence)
        if event.event_id == 21 or (event.wmi_consumer and event.wmi_filter):
            consumer_name = event.wmi_consumer or "UnknownConsumer"
            filter_name = event.wmi_filter or "UnknownFilter"
            target = f"Binding: {filter_name} -> {consumer_name}"
            payload = f"Filter={filter_name}; Consumer={consumer_name}"

            return PersistenceArtifact(
                persistence_type=PersistenceType.WMI_SUBSCRIPTION,
                event_id=event.event_id,
                record_id=event.record_id,
                event_db_id=event_db_id,
                computer=event.computer,
                timestamp_utc=event.timestamp,
                process_guid=event.process_guid,
                user=event.user,
                target_name=target,
                payload=payload,
                severity="High",
                mitre_tactics=["TA0003 - Persistence"],
                mitre_techniques=["T1546.003 - Windows Management Instrumentation Event Subscription"],
                evidence_fields={
                    "wmi_operation": event.wmi_operation or "FilterToConsumerBindingCreated",
                    "wmi_consumer": consumer_name,
                    "wmi_filter": filter_name,
                },
                explanation=f"Persistent WMI FilterToConsumerBinding created linking filter '{filter_name}' to consumer '{consumer_name}'",
                investigation_steps=[
                    f"Query root\\subscription namespace for consumer '{consumer_name}' and filter '{filter_name}'.",
                    "Determine whether the consumer executes arbitrary command lines or VBScript / JScript.",
                    "Review processes running under WmiPrvSE.exe shortly after trigger conditions are met.",
                ],
            )

        # EID 20: EventConsumer Creation
        if event.event_id == 20 or event.wmi_consumer:
            consumer_name = event.wmi_consumer or "UnknownConsumer"
            payload = event.wmi_query or event.command_line

            return PersistenceArtifact(
                persistence_type=PersistenceType.WMI_SUBSCRIPTION,
                event_id=event.event_id,
                record_id=event.record_id,
                event_db_id=event_db_id,
                computer=event.computer,
                timestamp_utc=event.timestamp,
                process_guid=event.process_guid,
                user=event.user,
                target_name=consumer_name,
                payload=payload,
                severity="Medium",
                mitre_tactics=["TA0003 - Persistence"],
                mitre_techniques=["T1546.003 - Windows Management Instrumentation Event Subscription"],
                evidence_fields={
                    "wmi_operation": event.wmi_operation or "EventConsumerCreated",
                    "wmi_consumer": consumer_name,
                },
                explanation=f"WMI EventConsumer created: '{consumer_name}'",
                investigation_steps=[
                    f"Examine consumer payload command line or script for '{consumer_name}'.",
                    "Monitor for subsequent FilterToConsumerBinding events.",
                ],
            )

        # EID 19: EventFilter Creation
        if event.event_id == 19 or event.wmi_filter:
            filter_name = event.wmi_filter or "UnknownFilter"
            query = event.wmi_query or ""

            return PersistenceArtifact(
                persistence_type=PersistenceType.WMI_SUBSCRIPTION,
                event_id=event.event_id,
                record_id=event.record_id,
                event_db_id=event_db_id,
                computer=event.computer,
                timestamp_utc=event.timestamp,
                process_guid=event.process_guid,
                user=event.user,
                target_name=filter_name,
                payload=query,
                severity="Medium",
                mitre_tactics=["TA0003 - Persistence"],
                mitre_techniques=["T1546.003 - Windows Management Instrumentation Event Subscription"],
                evidence_fields={
                    "wmi_operation": event.wmi_operation or "EventFilterCreated",
                    "wmi_filter": filter_name,
                    "wmi_query": query,
                },
                explanation=f"WMI EventFilter created: '{filter_name}' querying: {query}",
                investigation_steps=[
                    f"Review WQL query for filter '{filter_name}'.",
                    "Check if the query matches logon, timer, or hardware state triggers.",
                ],
            )

        return None

    def check_startup_folder_persistence(
        self,
        event: NormalizedEvent,
        event_db_id: int | None = None,
    ) -> PersistenceArtifact | None:
        """Inspect Sysmon EID 11 (File creation) targeting user or system Startup folders."""
        if not (event.event_id == 11 or event.event_category == EventCategory.FILE):
            return None

        target_file = event.target_filename
        if not target_file:
            return None

        target_lower = target_file.lower()

        # Check for presence in Start Menu\Programs\Startup\
        in_startup = (
            r"\start menu\programs\startup" in target_lower
            or r"\programs\startup" in target_lower
        )
        if not in_startup:
            return None

        # Check for suspicious extensions (.exe, .dll, .bat, .cmd, .vbs, .js, .wsf, .ps1, .lnk)
        has_suspicious_ext = any(target_lower.endswith(ext) for ext in self.STARTUP_EXTENSIONS)
        if not has_suspicious_ext:
            return None

        return PersistenceArtifact(
            persistence_type=PersistenceType.STARTUP_FOLDER,
            event_id=event.event_id,
            record_id=event.record_id,
            event_db_id=event_db_id,
            computer=event.computer,
            timestamp_utc=event.timestamp,
            process_guid=event.process_guid,
            user=event.user,
            target_name=target_file,
            payload=target_file,
            severity="High",
            mitre_tactics=["TA0003 - Persistence"],
            mitre_techniques=["T1547.001 - Registry Run Keys / Startup Folder"],
            evidence_fields={
                "target_filename": target_file,
                "process_image": event.image,
            },
            explanation=f"Executable or script dropped into Windows Startup folder: {target_file}",
            investigation_steps=[
                f"Verify the authenticity and digital signature of '{target_file}'.",
                "Identify the process that dropped the startup file using process GUID.",
                "Remove the unauthorized shortcut or binary to prevent execution on next user logon.",
            ],
        )

    def analyze_event(
        self,
        event: NormalizedEvent,
        event_db_id: int | None = None,
    ) -> PersistenceArtifact | None:
        """Evaluate a NormalizedEvent across all 5 persistence detectors."""
        # 1. Registry (Sysmon EID 12, 13, 14)
        if event.event_id in (12, 13, 14) or event.event_category == EventCategory.REGISTRY:
            return self.check_registry_persistence(event, event_db_id=event_db_id)

        # 2. Services & Drivers (Security 4697, Sysmon 6)
        if (
            event.event_id in (6, 4697)
            or event.event_category in (EventCategory.DRIVER, EventCategory.SECURITY)
            or (event.service_name is not None and event.service_file_name is not None)
        ):
            res = self.check_service_driver_persistence(event, event_db_id=event_db_id)
            if res:
                return res

        # 3. Scheduled Tasks (Security 4698, Task Scheduler 106/140)
        if (
            event.event_id in (4698, 106, 140)
            or bool(event.task_content)
        ):
            res = self.check_scheduled_task_persistence(event, event_db_id=event_db_id)
            if res:
                return res

        # 4. WMI Subscriptions (Sysmon 19, 20, 21)
        if (
            event.event_id in (19, 20, 21)
            or event.event_category == EventCategory.WMI
        ):
            return self.check_wmi_persistence(event, event_db_id=event_db_id)

        # 5. Startup Folder File Drops (Sysmon 11)
        if event.event_id == 11 or event.event_category == EventCategory.FILE:
            return self.check_startup_folder_persistence(event, event_db_id=event_db_id)

        # Fallback inspection for cross-category events with populated indicators
        if event.registry_target_object:
            res = self.check_registry_persistence(event, event_db_id=event_db_id)
            if res:
                return res

        if event.service_name:
            res = self.check_service_driver_persistence(event, event_db_id=event_db_id)
            if res:
                return res

        if event.task_name or event.task_content:
            res = self.check_scheduled_task_persistence(event, event_db_id=event_db_id)
            if res:
                return res

        if event.wmi_consumer or event.wmi_filter:
            res = self.check_wmi_persistence(event, event_db_id=event_db_id)
            if res:
                return res

        if event.target_filename and "startup" in (event.target_filename or "").lower():
            res = self.check_startup_folder_persistence(event, event_db_id=event_db_id)
            if res:
                return res

        return None
