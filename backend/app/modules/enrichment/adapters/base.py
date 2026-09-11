from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from app.models.schemas import IOC


class BaseThreatIntelAdapter(ABC):
    """
    Abstract interface for Threat Intelligence Enrichment Adapters.
    Decouples enrichment providers (local heuristics, VirusTotal, AbuseIPDB, OTX)
    from business domain logic.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name identifier of the enrichment provider."""
        ...

    @abstractmethod
    def enrich(self, ioc: IOC) -> Optional[Dict[str, Any]]:
        """
        Enriches an IOC with context data.

        Returns:
            Dictionary containing enrichment fields:
            - status: "enriched" | "unavailable" | "unknown"
            - reputation: "malicious" | "suspicious" | "benign" | "unknown"
            - confidence: float (0.0 to 1.0)
            - tags: List[str]
            - details: Dict[str, Any]
        """
        ...
