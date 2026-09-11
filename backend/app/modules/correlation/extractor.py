import re
from typing import Dict, Set, Any
from app.models.schemas import SecurityEvent

_GENERIC_USERS = {"system", "-", "", "n/a", "none", "unknown", "local service", "network service"}
_GENERIC_HOSTS = {"unknown", "-", "", "n/a", "localhost"}
_GENERIC_IPS = {"127.0.0.1", "0.0.0.0", "::1", "-", "", "none"}

_IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")


class EntityExtractor:
    """
    Extracts core security entities (hosts, users, IPs, processes, IOCs)
    from normalized SecurityEvent objects for graph correlation.
    """

    @staticmethod
    def extract_entities(event: SecurityEvent) -> Dict[str, Set[str]]:
        entities: Dict[str, Set[str]] = {
            "host": set(),
            "user": set(),
            "ip": set(),
            "process": set(),
            "ioc": set(),
        }

        # 1. Host entity
        if event.host:
            host_val = str(event.host).strip().lower()
            if host_val not in _GENERIC_HOSTS:
                entities["host"].add(host_val)
                # If host string is an IP address, add to IP entity as well
                if _IP_REGEX.fullmatch(host_val) and host_val not in _GENERIC_IPS:
                    entities["ip"].add(host_val)

        # 2. User entity
        if event.user:
            user_val = str(event.user).strip().lower()
            # Strip domain prefix if present (e.g. CORP\jsmith -> jsmith)
            clean_user = user_val.split("\\")[-1].split("@")[0]
            if clean_user and clean_user not in _GENERIC_USERS:
                entities["user"].add(clean_user)

        # 3. IP entities from raw_data
        raw = event.raw_data or {}
        for ip_field in ("ClientIP", "SourceIp", "DestinationIp", "src_ip", "dst_ip", "ip"):
            ip_val = str(raw.get(ip_field, "")).strip().lower()
            if ip_val and ip_val not in _GENERIC_IPS and _IP_REGEX.fullmatch(ip_val):
                entities["ip"].add(ip_val)

        # 4. Process entity
        process_val = (
            raw.get("process_name")
            or raw.get("Image")
            or raw.get("process")
            or raw.get("TargetFilename")
        )
        if process_val:
            proc_clean = str(process_val).strip().split("\\")[-1].split("/")[-1].lower()
            if proc_clean and proc_clean not in ("-", "n/a", "none"):
                entities["process"].add(proc_clean)

        # 5. IOC entities (domain, query, hash, registry key)
        for ioc_field in ("QueryName", "query_domain", "domain", "file_hash", "SHA256", "MD5", "TargetObject"):
            ioc_val = str(raw.get(ioc_field, "")).strip().lower()
            if ioc_val and ioc_val not in ("-", "n/a", "none"):
                entities["ioc"].add(ioc_val)

        return entities
