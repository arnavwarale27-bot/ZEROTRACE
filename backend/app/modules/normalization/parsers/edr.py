import re
from typing import Dict, Any
from app.modules.normalization.parsers.base import BaseParser

_CRITICAL_EDR_INDICATORS = re.compile(
    r"(lsass|mimikatz|sekurlsa|procdump|reflective|token::privobj|vault::cred)",
    re.IGNORECASE,
)
_PERSISTENCE_REGISTRY = re.compile(
    r"(CurrentVersion\\Run|CurrentVersion\\RunOnce|Services\\|Winlogon)",
    re.IGNORECASE,
)


class EDRParser(BaseParser):
    """
    Parser for EDR (Endpoint Detection & Response) telemetry (CrowdStrike, Defender, SentinelOne).
    Handles process execution, file integrity, registry modification, and memory dump alerts.
    All original field values are preserved in raw_data.
    """

    source_name = "edr"

    def parse(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        raw_event_type = (
            raw.get("event_type")
            or raw.get("eventType")
            or raw.get("action")
            or "edr_alert"
        )
        process_name = raw.get("process_name") or raw.get("Image") or raw.get("process") or ""
        cmdline = raw.get("command_line") or raw.get("CommandLine") or ""
        target_path = raw.get("file_path") or raw.get("TargetFilename") or raw.get("TargetObject") or ""

        combined_text = f"{process_name} {cmdline} {target_path}"

        severity = raw.get("severity") or "MEDIUM"
        event_type = f"edr_{str(raw_event_type).lower()}"
        attack_stage = "Execution"

        if _CRITICAL_EDR_INDICATORS.search(combined_text):
            severity = "CRITICAL"
            event_type = "edr_credential_dumping"
            attack_stage = "Credential Access"
        elif _PERSISTENCE_REGISTRY.search(target_path):
            severity = "HIGH"
            event_type = "edr_persistence_registry_modification"
            attack_stage = "Persistence"
        elif "tamper" in combined_text.lower() or "disable" in combined_text.lower():
            severity = "HIGH"
            event_type = "edr_tampering_attempt"
            attack_stage = "Defense Evasion"

        host = raw.get("ComputerName") or raw.get("host") or raw.get("agent_id") or raw.get("hostname")
        user = raw.get("AccountName") or raw.get("user") or raw.get("username")

        return {
            "timestamp": self._parse_timestamp(
                raw.get("TimeCreated") or raw.get("timestamp") or raw.get("EventTime")
            ),
            "source": self.source_name,
            "host": host,
            "user": user,
            "event_type": event_type,
            "severity": str(severity).upper(),
            "attack_stage": attack_stage,
            "attack_id": raw.get("attack_id"),
            "detection_state": "DETECTED",
            "investigation_state": "UNINVESTIGATED",
            "confidence": float(raw.get("confidence", 0.0)),
            "action": raw.get("action") or "ALERT",
            "raw_data": raw,
        }
