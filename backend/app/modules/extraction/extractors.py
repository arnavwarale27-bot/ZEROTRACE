import re
import ipaddress
from typing import List, Dict, Set, Any, Tuple
from app.models.schemas import SecurityEvent

_MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_REGEX = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")

_IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_DOMAIN_REGEX = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,24})\b"
)
_URL_REGEX = re.compile(
    r"https?://(?:[a-zA-Z0-9$-_@.&+!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
)

_IGNORED_EXTENSIONS = {".exe", ".dll", ".ps1", ".bat", ".sh", ".py", ".sys", ".txt", ".log", ".json"}
_GENERIC_HOSTS = {"unknown", "-", "", "n/a", "localhost", "none"}
_GENERIC_USERS = {"system", "-", "", "n/a", "none", "unknown", "local service", "network service"}


def is_valid_ip(val: str) -> bool:
    """Validates if string is a valid IPv4 or IPv6 address excluding broadcast/loopback."""
    try:
        ip = ipaddress.ip_address(val.strip())
        if ip.is_loopback or ip.is_unspecified:
            return False
        return True
    except ValueError:
        return False


def extract_ips(event: SecurityEvent) -> Set[str]:
    """Extract all valid IP addresses from event host and raw payload."""
    ips: Set[str] = set()

    # Check host field
    if event.host and is_valid_ip(event.host):
        ips.add(event.host.strip())

    # Check raw_data fields
    raw = event.raw_data or {}
    for key in ("ClientIP", "SourceIp", "DestinationIp", "src_ip", "dst_ip", "ip", "src", "dst"):
        val = str(raw.get(key, "")).strip()
        if val and is_valid_ip(val):
            ips.add(val)

    # Search embedded IPs in text payloads (command_line, ScriptBlockText)
    for text_key in ("command_line", "CommandLine", "ScriptBlockText"):
        text = str(raw.get(text_key, ""))
        for match in _IPV4_REGEX.findall(text):
            if is_valid_ip(match):
                ips.add(match)

    return ips


def extract_domains(event: SecurityEvent) -> Set[str]:
    """Extract domain names from DNS queries, URLs, and event payload."""
    domains: Set[str] = set()
    raw = event.raw_data or {}

    # 1. Direct DNS Query fields
    for field in ("QueryName", "query_domain", "domain", "query"):
        val = str(raw.get(field, "")).strip().lower().rstrip(".")
        if val and _DOMAIN_REGEX.fullmatch(val) and not is_valid_ip(val):
            domains.add(val)

    # 2. Extract from embedded URLs in script/command lines
    for text_key in ("ScriptBlockText", "command_line", "CommandLine", "url", "Url"):
        text = str(raw.get(text_key, ""))
        for url in _URL_REGEX.findall(text):
            # Extract domain part from URL
            domain_match = re.search(r"https?://([^/:\s]+)", url)
            if domain_match:
                d = domain_match.group(1).lower().strip().rstrip(".")
                if _DOMAIN_REGEX.fullmatch(d) and not is_valid_ip(d):
                    domains.add(d)

    # Filter out domains ending with file extensions
    valid_domains = {
        d for d in domains if not any(d.endswith(ext) for ext in _IGNORED_EXTENSIONS)
    }
    return valid_domains


def extract_hashes(event: SecurityEvent) -> Set[Tuple[str, str]]:
    """Extract file hashes from event payload. Returns set of (hash_type, hash_value)."""
    hashes: Set[Tuple[str, str]] = set()
    raw = event.raw_data or {}

    # Check explicit fields
    for field, htype in [
        ("SHA256", "sha256"),
        ("sha256", "sha256"),
        ("file_hash", "sha256"),
        ("MD5", "md5"),
        ("md5", "md5"),
        ("SHA1", "sha1"),
        ("sha1", "sha1"),
    ]:
        val = str(raw.get(field, "")).strip().lower()
        if val:
            if len(val) == 64 and _SHA256_REGEX.fullmatch(val):
                hashes.add(("sha256", val))
            elif len(val) == 32 and _MD5_REGEX.fullmatch(val):
                hashes.add(("md5", val))
            elif len(val) == 40 and _SHA1_REGEX.fullmatch(val):
                hashes.add(("sha1", val))

    # Search in command line / file path
    for text_key in ("command_line", "CommandLine", "ScriptBlockText"):
        text = str(raw.get(text_key, ""))
        for sha in _SHA256_REGEX.findall(text):
            hashes.add(("sha256", sha.lower()))
        for md5 in _MD5_REGEX.findall(text):
            hashes.add(("md5", md5.lower()))

    return hashes


def extract_usernames(event: SecurityEvent) -> Set[str]:
    """Extract non-generic usernames from event identity fields."""
    users: Set[str] = set()

    raw = event.raw_data or {}
    candidates = [
        event.user,
        raw.get("TargetUserName"),
        raw.get("SubjectUserName"),
        raw.get("AccountName"),
        raw.get("UserId"),
        raw.get("user"),
        raw.get("username"),
    ]

    for user in candidates:
        if user:
            u = str(user).strip()
            # Strip domain prefixes like CORP\user or user@domain.com
            clean_u = u.split("\\")[-1].split("@")[0].strip()
            if clean_u and clean_u.lower() not in _GENERIC_USERS:
                users.add(clean_u)

    return users


def extract_hostnames(event: SecurityEvent) -> Set[str]:
    """Extract machine hostnames from event asset fields."""
    hosts: Set[str] = set()

    raw = event.raw_data or {}
    candidates = [
        event.host,
        raw.get("Computer"),
        raw.get("ComputerName"),
        raw.get("WorkstationName"),
        raw.get("hostname"),
    ]

    for host in candidates:
        if host:
            h = str(host).strip()
            if h and h.lower() not in _GENERIC_HOSTS and not is_valid_ip(h):
                hosts.add(h)

    return hosts


def extract_processes(event: SecurityEvent) -> Set[str]:
    """Extract executable process names from process, image, or command lines."""
    processes: Set[str] = set()
    raw = event.raw_data or {}

    candidates = [
        raw.get("process_name"),
        raw.get("Image"),
        raw.get("process"),
        raw.get("TargetFilename"),
        raw.get("TargetObject"),
    ]

    for proc in candidates:
        if proc:
            p_str = str(proc).strip().replace("/", "\\").split("\\")[-1].lower()
            if p_str and p_str.endswith(".exe"):
                processes.add(p_str)

    # Check command line for process names
    for text_key in ("command_line", "CommandLine", "ScriptBlockText"):
        text = str(raw.get(text_key, "")).lower()
        for match in re.findall(r"\b([a-zA-Z0-9_\-\.]+\.exe)\b", text):
            processes.add(match)

    return processes
