from typing import Dict, Any
from app.modules.normalization.parsers.base import BaseParser


class GenericParser(BaseParser):
    """
    Fallback parser for arbitrary or unknown security log sources.
    Safely extracts common telemetry fields if present and defaults missing fields gracefully.
    All original field values are preserved in raw_data.
    """

    source_name = "generic"

    def parse(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        source = str(raw.get("source") or raw.get("log_source") or "generic")
        host = raw.get("host") or raw.get("hostname") or raw.get("Computer") or raw.get("ip")
        user = raw.get("user") or raw.get("username") or raw.get("account")
        event_type = str(raw.get("event_type") or raw.get("action") or raw.get("type") or "generic_security_event")
        severity = str(raw.get("severity") or raw.get("level") or "INFO").upper()

        if severity not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            severity = "INFO"

        return {
            "timestamp": self._parse_timestamp(
                raw.get("timestamp") or raw.get("time") or raw.get("TimeCreated")
            ),
            "source": source,
            "host": host,
            "user": user,
            "event_type": event_type,
            "severity": severity,
            "attack_stage": raw.get("attack_stage"),
            "attack_id": raw.get("attack_id"),
            "detection_state": raw.get("detection_state", "DETECTED"),
            "investigation_state": raw.get("investigation_state", "UNINVESTIGATED"),
            "confidence": float(raw.get("confidence", 0.0)),
            "action": raw.get("action"),
            "raw_data": raw,
        }
