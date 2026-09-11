from typing import Dict, Any
from app.modules.normalization.parsers.base import BaseParser

_SUSPICIOUS_C2_PORTS = {4444, 8443, 1337, 6667, 31337, 8081, 9001}


class NetworkParser(BaseParser):
    """
    Parser for Network Connection & Firewall logs (Palo Alto, Cisco ASA, Zeek Conn, Sysmon Event ID 3).
    Extracts src/dest IPs, ports, protocols, and network actions.
    All original field values are preserved in raw_data.
    """

    source_name = "network"

    def parse(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        src_ip = (
            raw.get("SourceIp")
            or raw.get("src_ip")
            or raw.get("source_ip")
            or raw.get("src")
        )
        dest_ip = (
            raw.get("DestinationIp")
            or raw.get("dest_ip")
            or raw.get("destination_ip")
            or raw.get("dst")
        )
        dest_port = raw.get("DestinationPort") or raw.get("dest_port") or raw.get("dst_port")
        action_raw = str(raw.get("action") or raw.get("Action") or "ALLOW").upper()

        dest_port_int = int(dest_port) if dest_port is not None and str(dest_port).isdigit() else None

        severity = "INFO"
        event_type = "network_connection"
        attack_stage = "Initial Access"

        if action_raw in ("DENY", "DROP", "REJECT", "BLOCKED"):
            event_type = "network_connection_blocked"
            severity = "LOW"
        elif dest_port_int in _SUSPICIOUS_C2_PORTS:
            event_type = "network_suspicious_c2_connection"
            severity = "HIGH"
            attack_stage = "Command and Control"

        host = src_ip or raw.get("host") or raw.get("Computer")
        user = raw.get("user") or raw.get("User")

        return {
            "timestamp": self._parse_timestamp(
                raw.get("TimeCreated") or raw.get("timestamp") or raw.get("time")
            ),
            "source": self.source_name,
            "host": host,
            "user": user,
            "event_type": event_type,
            "severity": severity,
            "attack_stage": attack_stage,
            "attack_id": raw.get("attack_id"),
            "detection_state": "DETECTED",
            "investigation_state": "UNINVESTIGATED",
            "confidence": 0.0,
            "action": action_raw,
            "raw_data": raw,
        }
