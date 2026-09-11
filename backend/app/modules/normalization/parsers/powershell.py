import re
from typing import Dict, Any
from app.modules.normalization.parsers.base import BaseParser

# Patterns that indicate suspicious PowerShell usage
_ENCODED_CMD_PATTERN = re.compile(r"-[Ee]n[Cc](?:odedCommand)?", re.IGNORECASE)
_DOWNLOAD_PATTERN = re.compile(
    r"(IEX|Invoke-Expression|WebClient|DownloadString|DownloadFile|Net\.WebClient|curl|wget)",
    re.IGNORECASE,
)
_BYPASS_PATTERN = re.compile(
    r"(-[Ee]xecution[Pp]olicy\s+(?:Bypass|Unrestricted)|bypass)",
    re.IGNORECASE,
)
_SUSPICIOUS_CMDLETS = re.compile(
    r"(Invoke-Mimikatz|Invoke-ReflectivePEInjection|Add-MpPreference|Set-MpPreference|"
    r"Invoke-BloodHound|Get-NetDomain|Get-DomainUser|Invoke-Shellcode)",
    re.IGNORECASE,
)


def _classify_ps_severity(script_text: str) -> str:
    if _SUSPICIOUS_CMDLETS.search(script_text):
        return "CRITICAL"
    if _ENCODED_CMD_PATTERN.search(script_text) or _DOWNLOAD_PATTERN.search(script_text):
        return "HIGH"
    if _BYPASS_PATTERN.search(script_text):
        return "MEDIUM"
    return "LOW"


class PowerShellParser(BaseParser):
    """
    Parser for PowerShell Script Block Logging telemetry (Event ID 4104)
    and generic PowerShell execution log formats.
    All original field values are preserved in raw_data.
    """

    source_name = "powershell"

    def parse(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        script_text = (
            raw.get("ScriptBlockText")
            or raw.get("CommandLine")
            or raw.get("script_text")
            or ""
        )
        command_name = raw.get("CommandName") or raw.get("command_name") or "powershell"
        host = raw.get("Computer") or raw.get("host") or raw.get("MachineName")
        user = raw.get("UserId") or raw.get("user") or raw.get("SubjectUserName")

        severity = _classify_ps_severity(script_text)
        is_encoded = bool(_ENCODED_CMD_PATTERN.search(script_text))

        # Event type classification
        event_type = "powershell_script_execution"
        if is_encoded:
            event_type = "powershell_encoded_command"
        elif _DOWNLOAD_PATTERN.search(script_text):
            event_type = "powershell_download_cradle"

        action = "ENCODED" if is_encoded else "EXECUTED"

        return {
            "timestamp": self._parse_timestamp(raw.get("TimeCreated") or raw.get("timestamp")),
            "source": self.source_name,
            "host": host,
            "user": user,
            "event_type": event_type,
            "severity": severity,
            "attack_stage": "Execution",
            "attack_id": raw.get("attack_id"),
            "detection_state": "DETECTED",
            "investigation_state": "UNINVESTIGATED",
            "confidence": 0.0,
            "action": action,
            "raw_data": raw,
        }
