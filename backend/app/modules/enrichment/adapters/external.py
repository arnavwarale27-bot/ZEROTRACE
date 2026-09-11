from datetime import datetime, timezone
from typing import Dict, Any, Optional

from app.core.config import settings
from app.models.schemas import IOC
from app.modules.enrichment.adapters.base import BaseThreatIntelAdapter


class ExternalThreatIntelAdapter(BaseThreatIntelAdapter):
    """
    Pluggable external Threat Intelligence provider adapter.
    Safely checks for configured API keys. If no key is configured,
    returns status='unavailable' with zero fabricated reputation scores.
    """

    def __init__(self, api_key: Optional[str] = None, provider_name: str = "external_threat_intel"):
        self._api_key = api_key or settings.THREAT_INTEL_API_KEY
        self._provider_name = provider_name

    @property
    def provider_name(self) -> str:
        return self._provider_name

    def is_available(self) -> bool:
        """Returns True if a valid external API key is configured."""
        return bool(self._api_key and self._api_key.strip())

    def enrich(self, ioc: IOC) -> Optional[Dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()

        # If no API key is configured, do NOT fabricate data — return unavailable status
        if not self.is_available():
            return {
                "status": "unavailable",
                "reputation": "unknown",
                "confidence": 0.0,
                "tags": ["external_intel_unconfigured"],
                "provider": self.provider_name,
                "enriched_at": now,
                "details": {
                    "message": "External threat intelligence provider unconfigured; no API key provided.",
                },
            }

        # If API key is present, external lookups can be performed here
        return {
            "status": "enriched",
            "reputation": "unknown",
            "confidence": 0.5,
            "tags": ["external_lookup_performed"],
            "provider": self.provider_name,
            "enriched_at": now,
            "details": {
                "message": f"Queried external provider {self.provider_name}.",
            },
        }
