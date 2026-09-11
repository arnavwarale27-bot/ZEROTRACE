from typing import Dict, Type
from app.modules.normalization.parsers.base import BaseParser, generate_event_id
from app.modules.normalization.parsers.windows_security import WindowsSecurityParser
from app.modules.normalization.parsers.powershell import PowerShellParser
from app.modules.normalization.parsers.dns import DNSParser
from app.modules.normalization.parsers.network import NetworkParser
from app.modules.normalization.parsers.edr import EDRParser
from app.modules.normalization.parsers.generic import GenericParser

_PARSER_REGISTRY: Dict[str, Type[BaseParser]] = {
    "windows_security": WindowsSecurityParser,
    "powershell": PowerShellParser,
    "dns": DNSParser,
    "network": NetworkParser,
    "edr": EDRParser,
}

# Alias lookup mapping
_SOURCE_ALIASES: Dict[str, str] = {
    "winsec": "windows_security",
    "windows": "windows_security",
    "windows_event_log": "windows_security",
    "ps": "powershell",
    "powershell_script": "powershell",
    "bind": "dns",
    "zeek_dns": "dns",
    "dns_log": "dns",
    "firewall": "network",
    "netflow": "network",
    "conn": "network",
    "zeek_conn": "network",
    "crowdstrike": "edr",
    "defender": "edr",
    "sentinelone": "edr",
    "edr_alert": "edr",
}


def get_parser(source: str) -> BaseParser:
    """
    Lookup and return appropriate source parser instance.
    Supports aliases and falls back to GenericParser if source is unrecognized.
    """
    key = (source or "").lower().strip()
    canonical = _SOURCE_ALIASES.get(key, key)
    parser_cls = _PARSER_REGISTRY.get(canonical, GenericParser)
    return parser_cls()


__all__ = [
    "BaseParser",
    "generate_event_id",
    "WindowsSecurityParser",
    "PowerShellParser",
    "DNSParser",
    "NetworkParser",
    "EDRParser",
    "GenericParser",
    "get_parser",
]
