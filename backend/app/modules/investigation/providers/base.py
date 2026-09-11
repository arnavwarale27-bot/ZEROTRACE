from abc import ABC, abstractmethod
from typing import Dict, Any, List, Tuple
from app.models.schemas import InvestigationResult, RecommendedAction


class BaseAIInvestigatorProvider(ABC):
    """
    Abstract interface for Evidence-Grounded AI Investigation Providers.
    All implementations must strictly ground their findings on structured incident evidence
    and cite exact event / IOC IDs without inventing unobserved claims.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name identifier of the investigation provider."""
        ...

    @abstractmethod
    def investigate(
        self,
        evidence_package: Dict[str, Any],
    ) -> Tuple[InvestigationResult, List[RecommendedAction]]:
        """
        Executes evidence-grounded investigation on the structured evidence package.

        Returns:
            Tuple of (InvestigationResult, List[RecommendedAction])
        """
        ...
