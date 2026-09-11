import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from app.models.schemas import IOC
from app.modules.enrichment.adapters.base import BaseThreatIntelAdapter

_SUSPICIOUS_TLDS = {".xyz", ".top", ".kim", ".work", ".click", ".buzz", ".cc", ".tk"}
_TRUSTED_DOMAINS = {"microsoft.com", "google.com", "windowsupdate.com", "internal", "corp.internal", "local"}
_MALICIOUS_TOOLS = {"mimikatz.exe", "procdump.exe", "sekurlsa.dll", "bloodhound.exe"}
_LOLBINS = {"powershell.exe", "cmd.exe", "certutil.exe", "mshta.exe", "wscript.exe", "cscript.exe"}


class LocalRuleEnricher(BaseThreatIntelAdapter):
    """
    Local heuristic threat enrichment adapter.
    Performs deterministic RFC IP classification, TLD analysis, and LOLBin identification
    without relying on external network dependencies.
    """

    @property
    def provider_name(self) -> str:
        return "local_rules"

    def enrich(self, ioc: IOC) -> Optional[Dict[str, Any]]:
        val = ioc.value.strip().lower()
        ioc_type = ioc.type.lower()

        reputation = "unknown"
        status = "enriched"
        confidence = 0.5
        tags: List[str] = []
        details: Dict[str, Any] = {}

        now = datetime.now(timezone.utc).isoformat()

        # 1. IP Address Enrichment
        if ioc_type == "ip":
            try:
                ip = ipaddress.ip_address(val)
                if ip.is_private:
                    reputation = "benign"
                    confidence = 0.9
                    tags.extend(["internal_network", "rfc1918_private"])
                    details["network_scope"] = "private"
                elif ip.is_loopback or ip.is_reserved:
                    reputation = "benign"
                    confidence = 0.95
                    tags.append("loopback_or_reserved")
                    details["network_scope"] = "loopback"
                else:
                    reputation = "unknown"
                    confidence = 0.5
                    tags.append("public_routable")
                    details["network_scope"] = "public"
            except ValueError:
                status = "unknown"

        # 2. Domain Name Enrichment
        elif ioc_type == "domain":
            if any(val.endswith(tld) for tld in _SUSPICIOUS_TLDS):
                reputation = "suspicious"
                confidence = 0.75
                tags.append("suspicious_tld")
                details["tld_risk"] = "high"
            elif any(val.endswith(td) for td in _TRUSTED_DOMAINS):
                reputation = "benign"
                confidence = 0.85
                tags.append("trusted_domain")
                details["domain_category"] = "trusted_vendor"
            else:
                reputation = "unknown"
                tags.append("standard_domain")

        # 3. Process Binary Enrichment
        elif ioc_type == "process":
            proc_clean = val.split("\\")[-1].split("/")[-1].lower()
            if proc_clean in _MALICIOUS_TOOLS:
                reputation = "malicious"
                confidence = 0.95
                tags.extend(["credential_dumping_tool", "offensive_utility"])
                details["binary_class"] = "threat_tool"
            elif proc_clean in _LOLBINS:
                reputation = "suspicious"
                confidence = 0.65
                tags.extend(["lolbin", "system_shell"])
                details["binary_class"] = "living_off_the_land"
            else:
                reputation = "unknown"
                tags.append("standard_process")

        # 4. Hash Enrichment
        elif ioc_type in ("sha256", "md5", "sha1"):
            tags.append(f"{ioc_type}_checksum")
            reputation = "unknown"
            details["hash_algorithm"] = ioc_type.upper()

        # 5. User/Host Enrichment
        elif ioc_type in ("username", "hostname"):
            tags.append(f"entity_{ioc_type}")
            reputation = "unknown"

        return {
            "status": status,
            "reputation": reputation,
            "confidence": confidence,
            "tags": tags,
            "provider": self.provider_name,
            "enriched_at": now,
            "details": details,
        }
