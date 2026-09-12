import re
from typing import Dict, Any
from app.modules.normalization.parsers.base import BaseParser

_SUSPICIOUS_TLDS = (".xyz", ".top", ".kim", ".work", ".click", ".buzz", ".cc", ".tk")
_HEX_OR_B64_SUBDOMAIN = re.compile(r"([a-zA-Z0-9+/=]{16,}\.)")


class DNSParser(BaseParser):
    """
    Parser for DNS query and response logs (bind, Windows DNS, Sysmon Event ID 22, Zeek DNS).
    Extracts domains, query types, resolved IPs, and detects potential DNS tunneling / DGA.
    All original field values are preserved in raw_data.
    """

    source_name = "dns"

    def parse(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        domain = (
            raw.get("QueryName")
            or raw.get("query_domain")
            or raw.get("domain")
            or raw.get("query")
            or ""
        )
        query_type = raw.get("QueryType") or raw.get("query_type") or "A"
        client_ip = (
            raw.get("ClientIP")
            or raw.get("SourceIp")
            or raw.get("src_ip")
            or raw.get("host")
        )
        response_code = raw.get("ResponseCode") or raw.get("rcode") or "NOERROR"

        # Determine severity and event_type
        severity = "INFO"
        event_type = "dns_query"

        domain_str = str(domain).lower()
        subdomains = domain_str.split(".")
        has_tunneling_subdomain = any(len(sub) >= 40 for sub in subdomains[:-2])

        if any(domain_str.endswith(tld) for tld in _SUSPICIOUS_TLDS):
            severity = "MEDIUM"
            event_type = "dns_suspicious_tld"

        if has_tunneling_subdomain or _HEX_OR_B64_SUBDOMAIN.search(domain_str):
            severity = "HIGH"
            event_type = "dns_potential_tunneling"

        if str(query_type).upper() == "TXT" and severity in ("MEDIUM", "HIGH"):
            event_type = "dns_txt_exfiltration"
            severity = "HIGH"

        attack_stage = "Command and Control" if severity in ("MEDIUM", "HIGH", "CRITICAL") else "Reconnaissance"

        return {
            "timestamp": self._parse_timestamp(
                raw.get("TimeCreated") or raw.get("timestamp") or raw.get("time")
            ),
            "source": self.source_name,
            "host": client_ip,
            "user": raw.get("user") or raw.get("UserId"),
            "event_type": event_type,
            "severity": severity,
            "attack_stage": attack_stage,
            "attack_id": raw.get("attack_id"),
            "detection_state": "DETECTED",
            "investigation_state": "UNINVESTIGATED",
            "confidence": 0.0,
            "action": f"QUERY_{query_type}",
            "raw_data": raw,
        }
