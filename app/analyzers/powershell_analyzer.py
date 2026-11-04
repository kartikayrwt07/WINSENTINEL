"""PowerShell Threat Analyzer for WinSentinel.

Provides multi-pattern threat detection and composite risk scoring (0-100)
for PowerShell process creation and script block logs. Incorporates safe
de-obfuscation, benign administrative baseline offsets, and active threat
safety overrides.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from app.analyzers.powershell_deobfuscator import (
    DeobfuscationResult,
    PowerShellDeobfuscator,
)
from app.models.events import EventCategory, NormalizedEvent
from app.models.powershell import PowerShellAnalysisResult


class PowerShellThreatAnalyzer:
    """Evaluates PowerShell telemetry using weighted heuristics and composite risk scoring."""

    # Download cradles (+40 weight)
    CRADLE_PATTERNS = [
        re.compile(r"Net\.WebClient", re.IGNORECASE),
        re.compile(r"\bDownloadString\b", re.IGNORECASE),
        re.compile(r"\bDownloadFile\b", re.IGNORECASE),
        re.compile(r"\bDownloadData\b", re.IGNORECASE),
        re.compile(r"\bInvoke-WebRequest\b", re.IGNORECASE),
        re.compile(r"\biwr\b", re.IGNORECASE),
        re.compile(r"\bStart-BitsTransfer\b", re.IGNORECASE),
        re.compile(r"\bInvoke-RestMethod\b", re.IGNORECASE),
        re.compile(r"\birm\b", re.IGNORECASE),
        re.compile(r"Net\.Sockets\.TcpClient", re.IGNORECASE),
    ]

    # Execution policy bypass flags (+20 weight)
    BYPASS_PATTERNS = [
        re.compile(r"-(?:ep|executionpolicy)\s+(?:bypass|unrestricted)\b", re.IGNORECASE),
        re.compile(r"-(?:nop|noprofile)\b", re.IGNORECASE),
    ]

    # Hidden and non-interactive windows (+20 weight)
    HIDDEN_WINDOW_PATTERNS = [
        re.compile(r"-(?:w|windowstyle)\s+(?:hidden|1)\b", re.IGNORECASE),
        re.compile(r"-(?:noni|noninteractive)\b", re.IGNORECASE),
    ]

    # Suspicious native memory and injection APIs (+30 weight)
    SUSPICIOUS_API_PATTERNS = [
        re.compile(r"\bVirtualAlloc\b", re.IGNORECASE),
        re.compile(r"\bVirtualProtect\b", re.IGNORECASE),
        re.compile(r"\bWriteProcessMemory\b", re.IGNORECASE),
        re.compile(r"\bCreateThread\b", re.IGNORECASE),
        re.compile(r"\bRtlMoveMemory\b", re.IGNORECASE),
        re.compile(r"\bGetProcAddress\b", re.IGNORECASE),
        re.compile(r"\bLoadLibrary\b", re.IGNORECASE),
        re.compile(r"\bQueueUserAPC\b", re.IGNORECASE),
        re.compile(r"\bMapViewOfFile\b", re.IGNORECASE),
    ]

    # Obfuscation syntax constructs (+15 weight)
    OBFUSCATION_PATTERNS = [
        re.compile(r"\[char\[\]\]", re.IGNORECASE),
        re.compile(r"\[(?:System\.)?Convert\]::FromBase64String", re.IGNORECASE),
        re.compile(r"-join\b", re.IGNORECASE),
    ]

    # Benign administrative query cmdlets (-30 offset)
    BENIGN_QUERY_PATTERNS = [
        re.compile(
            r"\bGet-(?:Process|Service|WmiObject|CimInstance|ItemProperty|WinEvent|ChildItem)\b",
            re.IGNORECASE,
        ),
    ]

    # Benign maintenance and management scripts (-30 offset)
    BENIGN_ADMIN_PATTERNS = [
        re.compile(r"\$PSScriptRoot\b", re.IGNORECASE),
        re.compile(r"\bDefender\b", re.IGNORECASE),
        re.compile(r"\bIntune\b", re.IGNORECASE),
        re.compile(r"\bCCM\b", re.IGNORECASE),
    ]

    def __init__(self) -> None:
        self.deobfuscator = PowerShellDeobfuscator()

    def analyze_text(
        self,
        text: str,
        event_id: int = 1,
        computer: str = "UNKNOWN",
        timestamp_utc: datetime | None = None,
        process_guid: str | None = None,
        user: str | None = None,
        record_id: int | None = None,
        event_db_id: int | None = None,
    ) -> PowerShellAnalysisResult:
        """Analyze PowerShell text/script block and compute composite risk score."""
        ts = timestamp_utc or datetime.now(timezone.utc)
        deob_res: DeobfuscationResult = self.deobfuscator.deobfuscate(text)

        # Inspect both raw, normalized, and decoded payload
        inspection_targets = [text, deob_res.normalized_text]
        if deob_res.decoded_text:
            inspection_targets.append(deob_res.decoded_text)

        combined_text = "\n".join(inspection_targets)

        indicators: list[str] = []
        matched_patterns: dict[str, list[str]] = {}
        raw_score = 0

        # 1. Base64 Payload (+30)
        if deob_res.has_base64 and deob_res.extracted_base64:
            indicators.append("Base64Payload")
            matched_patterns["Base64Payload"] = [f"-enc {deob_res.extracted_base64[:40]}..."]
            raw_score += 30

        # 2. Download Cradle (+40)
        cradle_matches: list[str] = []
        for pat in self.CRADLE_PATTERNS:
            found = pat.findall(combined_text)
            if found:
                cradle_matches.extend(found[:3])
        if cradle_matches:
            indicators.append("DownloadCradle")
            matched_patterns["DownloadCradle"] = list(dict.fromkeys(cradle_matches))
            raw_score += 40

        # 3. Execution Policy Bypass (+20)
        bypass_matches: list[str] = []
        for pat in self.BYPASS_PATTERNS:
            found = pat.findall(combined_text)
            if found:
                bypass_matches.extend(found[:3])
        if bypass_matches:
            indicators.append("ExecutionPolicyBypass")
            matched_patterns["ExecutionPolicyBypass"] = list(dict.fromkeys(bypass_matches))
            raw_score += 20

        # 4. Hidden / Non-Interactive Window (+20)
        hidden_matches: list[str] = []
        for pat in self.HIDDEN_WINDOW_PATTERNS:
            found = pat.findall(combined_text)
            if found:
                hidden_matches.extend(found[:3])
        if hidden_matches:
            indicators.append("HiddenWindow")
            matched_patterns["HiddenWindow"] = list(dict.fromkeys(hidden_matches))
            raw_score += 20

        # 5. Suspicious Native APIs (+30)
        api_matches: list[str] = []
        for pat in self.SUSPICIOUS_API_PATTERNS:
            found = pat.findall(combined_text)
            if found:
                api_matches.extend(found[:3])
        if api_matches:
            indicators.append("SuspiciousNativeApi")
            matched_patterns["SuspiciousNativeApi"] = list(dict.fromkeys(api_matches))
            raw_score += 30

        # 6. Obfuscation Techniques (+15)
        obfuscation_matches: list[str] = []
        if deob_res.has_backticks and (text.count("`") > 3 or (deob_res.decoded_text and deob_res.decoded_text.count("`") > 3)):
            obfuscation_matches.append("ExcessiveBackticks")
        if deob_res.has_concatenation:
            obfuscation_matches.append("StringConcatenation")
        if deob_res.has_format_operator:
            obfuscation_matches.append("FormatOperator")
        for pat in self.OBFUSCATION_PATTERNS:
            found = pat.findall(combined_text)
            if found:
                obfuscation_matches.extend(found[:3])

        if obfuscation_matches:
            indicators.append("ObfuscationTechniques")
            matched_patterns["ObfuscationTechniques"] = list(dict.fromkeys(obfuscation_matches))
            raw_score += 15

        # 7. Benign Administrative Baseline (-30) & Safety Override
        benign_matches: list[str] = []
        for pat in self.BENIGN_QUERY_PATTERNS + self.BENIGN_ADMIN_PATTERNS:
            found = pat.findall(combined_text)
            if found:
                benign_matches.extend(found[:3])

        if benign_matches:
            # Active Threat Safety Override (D-02):
            # If download cradle (+40) or suspicious native API (+30) is present,
            # nullify the benign administrative reduction to prevent evasion.
            has_active_threat = ("DownloadCradle" in indicators) or ("SuspiciousNativeApi" in indicators)
            if not has_active_threat:
                indicators.append("BenignAdministrativeOffset")
                matched_patterns["BenignAdministrativeOffset"] = list(dict.fromkeys(benign_matches))
                raw_score -= 30

        # Clamping
        final_score = max(0, min(100, raw_score))

        # Severity mapping
        if final_score >= 85:
            severity = "Critical"
        elif final_score >= 60:
            severity = "High"
        elif final_score >= 30:
            severity = "Medium"
        else:
            severity = "Informational"

        # MITRE ATT&CK Mappings
        mitre_tactics: list[str] = ["Execution"]
        mitre_techniques: list[str] = ["T1059.001"]

        if "Base64Payload" in indicators or "ObfuscationTechniques" in indicators:
            if "Defense Evasion" not in mitre_tactics:
                mitre_tactics.append("Defense Evasion")
            mitre_techniques.append("T1027")

        if "DownloadCradle" in indicators:
            if "Command and Control" not in mitre_tactics:
                mitre_tactics.append("Command and Control")
            mitre_techniques.append("T1105")

        if "ExecutionPolicyBypass" in indicators:
            if "Defense Evasion" not in mitre_tactics:
                mitre_tactics.append("Defense Evasion")
            mitre_techniques.append("T1562.001")

        if "HiddenWindow" in indicators:
            if "Defense Evasion" not in mitre_tactics:
                mitre_tactics.append("Defense Evasion")
            mitre_techniques.append("T1564.003")

        if "SuspiciousNativeApi" in indicators:
            for tac in ("Defense Evasion", "Privilege Escalation"):
                if tac not in mitre_tactics:
                    mitre_tactics.append(tac)
            mitre_techniques.append("T1055")

        # Stable deduplication
        mitre_tactics = list(dict.fromkeys(mitre_tactics))
        mitre_techniques = list(dict.fromkeys(mitre_techniques))

        # Investigation checklist
        investigation_steps: list[str] = [
            "Inspect the full parent-child process tree to identify the invoking application and session.",
        ]
        if "Base64Payload" in indicators or "ObfuscationTechniques" in indicators:
            investigation_steps.append(
                "Review de-obfuscated script content and decoded payload for secondary droppers or execution stages."
            )
        if "DownloadCradle" in indicators:
            investigation_steps.append(
                "Correlate network connection logs (Sysmon EID 3) and DNS queries (Sysmon EID 22) for C2 destination IP/domain."
            )
        if "SuspiciousNativeApi" in indicators:
            investigation_steps.append(
                "Investigate process access (Sysmon EID 10) and remote thread creation (Sysmon EID 8) for memory injection."
            )
        if "ExecutionPolicyBypass" in indicators:
            investigation_steps.append(
                "Verify whether execution policy bypass was initiated by an authorized administrator or an automated task."
            )
        if "HiddenWindow" in indicators:
            investigation_steps.append(
                "Determine if hidden window execution was intended to conceal unauthorized activity from the console."
            )

        return PowerShellAnalysisResult(
            event_id=event_id,
            record_id=record_id,
            event_db_id=event_db_id,
            computer=computer,
            timestamp_utc=ts,
            process_guid=process_guid,
            user=user,
            raw_command=text,
            decoded_command=deob_res.decoded_text,
            deobfuscated_command=deob_res.normalized_text,
            risk_score=final_score,
            severity=severity,
            indicators=indicators,
            matched_patterns=matched_patterns,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            investigation_steps=investigation_steps,
        )

    def analyze_event(
        self,
        event: NormalizedEvent,
        event_db_id: int | None = None,
    ) -> PowerShellAnalysisResult | None:
        """Evaluate a NormalizedEvent for PowerShell activity and return analysis result."""
        # 1. PowerShell ScriptBlock Logging (EID 4104, 4103)
        if event.event_id in (4103, 4104) or event.event_category == EventCategory.POWERSHELL:
            candidate = event.script_block_text or event.command_line
            if not candidate:
                return None
            return self.analyze_text(
                candidate,
                event_id=event.event_id,
                computer=event.computer,
                timestamp_utc=event.timestamp,
                process_guid=event.process_guid,
                user=event.user,
                record_id=event.record_id,
                event_db_id=event_db_id,
            )

        # 2. Process Creation (Sysmon EID 1, Security EID 4688)
        if event.event_id in (1, 4688) or event.event_category == EventCategory.PROCESS:
            img = (event.image or "").lower()
            cmd = (event.command_line or "").lower()
            is_pwsh_image = any(x in img for x in ("powershell.exe", "pwsh.exe", "powershell_ise.exe"))
            is_pwsh_cmd = any(x in cmd for x in ("powershell", "pwsh"))
            if is_pwsh_image or is_pwsh_cmd:
                candidate = event.command_line or event.script_block_text
                if not candidate:
                    return None
                return self.analyze_text(
                    candidate,
                    event_id=event.event_id,
                    computer=event.computer,
                    timestamp_utc=event.timestamp,
                    process_guid=event.process_guid,
                    user=event.user,
                    record_id=event.record_id,
                    event_db_id=event_db_id,
                )

        # 3. Fallback: check if script_block_text is populated on any other event
        if event.script_block_text:
            return self.analyze_text(
                event.script_block_text,
                event_id=event.event_id,
                computer=event.computer,
                timestamp_utc=event.timestamp,
                process_guid=event.process_guid,
                user=event.user,
                record_id=event.record_id,
                event_db_id=event_db_id,
            )

        return None
