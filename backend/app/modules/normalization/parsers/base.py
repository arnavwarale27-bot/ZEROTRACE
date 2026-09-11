from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, Any
import hashlib
import uuid


def generate_event_id(source: str, raw_data: Dict[str, Any]) -> str:
    """
    Generate a deterministic event_id using UUID5 derived from source + stable raw content hash.
    Same raw input always produces the same event_id, enabling future deduplication in Phase 3.
    """
    content = f"{source}:{str(sorted(raw_data.items()))}"
    namespace = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # RFC 4122 URL namespace
    return f"evt-{str(uuid.uuid5(namespace, content))}"


class BaseParser(ABC):
    """
    Abstract base parser defining the contract for all source-specific log parsers.
    Each parser is responsible for extracting normalized SecurityEvent fields
    from a source-specific raw log dictionary.
    Raw data is ALWAYS preserved in raw_data — no information is discarded.
    """

    # The canonical source name this parser handles (used by ParserRegistry)
    source_name: str = "unknown"

    @abstractmethod
    def parse(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse source-specific raw log into a dict of SecurityEvent fields.
        Must include raw_data = raw (full original payload preserved).
        Must NOT include event_id or latency (set by the normalization service).
        Returns a dict ready to be passed into SecurityEvent(**dict).
        """
        ...

    def _safe_get(self, d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
        """Safely traverse nested dict or return default."""
        for key in keys:
            if isinstance(d, dict):
                d = d.get(key, default)
            else:
                return default
        return d

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _parse_timestamp(self, value: Any) -> datetime:
        """Parse a timestamp string or return current UTC time if unparseable."""
        if isinstance(value, datetime):
            return value
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        if isinstance(value, str):
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
            ):
                try:
                    dt = datetime.strptime(value, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt
                except ValueError:
                    continue
        return self._now()
