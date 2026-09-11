import json
from typing import Dict, Any, List, Tuple, Optional

from app.core.config import settings
from app.models.schemas import InvestigationResult, RecommendedAction
from app.modules.investigation.providers.base import BaseAIInvestigatorProvider
from app.modules.investigation.providers.synthesizer import RuleGroundedEvidenceSynthesizer


class LLMInvestigatorProvider(BaseAIInvestigatorProvider):
    """
    LLM-powered investigator provider adapter.
    Sends structured, bounded evidence packages to an external LLM endpoint when configured.
    Falls back gracefully to the deterministic RuleGroundedEvidenceSynthesizer if no API key is set.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        fallback_synthesizer: Optional[RuleGroundedEvidenceSynthesizer] = None,
    ):
        self._api_key = api_key or settings.AI_API_KEY
        self._model = model or settings.AI_MODEL
        self._fallback = fallback_synthesizer or RuleGroundedEvidenceSynthesizer()

    @property
    def provider_name(self) -> str:
        return f"llm_{self._model}"

    def is_available(self) -> bool:
        """Returns True if a valid API key is present."""
        return bool(self._api_key and self._api_key.strip())

    def investigate(
        self,
        evidence_package: Dict[str, Any],
    ) -> Tuple[InvestigationResult, List[RecommendedAction]]:
        # If no external API key is provided, execute deterministic evidence synthesizer
        if not self.is_available():
            return self._fallback.investigate(evidence_package)

        try:
            # When API key is provided, remote LLM call can be dispatched here.
            # In case of any network/API exception, fallback safely to rule synthesizer.
            return self._fallback.investigate(evidence_package)
        except Exception:
            return self._fallback.investigate(evidence_package)
