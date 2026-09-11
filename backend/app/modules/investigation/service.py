from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.schemas import (
    Incident,
    InvestigationResult,
    RecommendedAction,
    Evidence,
)
from app.models.domain import (
    InvestigationResultModel,
    RecommendedActionModel,
    EvidenceModel,
)
from app.modules.investigation.evidence_builder import (
    StructuredEvidenceBuilder,
    _evidence_model_to_schema,
)
from app.modules.investigation.providers.base import BaseAIInvestigatorProvider
from app.modules.investigation.providers.synthesizer import RuleGroundedEvidenceSynthesizer
from app.modules.investigation.providers.llm import LLMInvestigatorProvider
from app.db.repository import (
    incident_repo,
    investigation_repo,
    action_repo,
    evidence_repo,
)


def _inv_model_to_schema(model: InvestigationResultModel) -> InvestigationResult:
    ts = model.created_at
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return InvestigationResult(
        id=model.id,
        incident_id=model.incident_id,
        summary=model.summary,
        mitre_techniques=model.mitre_techniques or [],
        evidence_ids=model.evidence_ids or [],
        confidence_score=model.confidence_score,
        status=model.status,
        created_at=ts,
    )


def _action_model_to_schema(model: RecommendedActionModel) -> RecommendedAction:
    return RecommendedAction(
        id=model.id,
        incident_id=model.incident_id,
        action_type=model.action_type,
        description=model.description,
        priority=model.priority,
        automated=model.automated,
        status=model.status,
    )


class EvidenceGroundedAIInvestigationService:
    """
    Evidence-Grounded AI Investigation Service.
    Coordinates evidence aggregation, deterministic or LLM-powered investigation synthesis,
    and recommended remediation actions grounded strictly on real telemetry evidence.
    """

    def __init__(
        self,
        evidence_builder: Optional[StructuredEvidenceBuilder] = None,
        provider: Optional[BaseAIInvestigatorProvider] = None,
    ):
        self.evidence_builder = evidence_builder or StructuredEvidenceBuilder()
        self.provider = provider or LLMInvestigatorProvider()

    def investigate_incident(
        self,
        db: Session,
        incident_id: str,
    ) -> Dict[str, Any]:
        """
        Executes an end-to-end evidence-grounded AI investigation for an incident.
        """
        db_inc = incident_repo.get_by_id(db, incident_id)
        if not db_inc:
            raise ValueError(f"Incident with ID '{incident_id}' not found.")

        # 1. Build structured evidence package
        evidence_pkg = self.evidence_builder.build_evidence_package(db, incident_id)

        # 2. Run investigation provider
        inv_result, actions = self.provider.investigate(evidence_pkg)

        # 3. Persist Investigation Result & Actions
        saved_inv_model = investigation_repo.save(db, inv_result)
        saved_actions: List[RecommendedAction] = []
        for act in actions:
            saved_act_model = action_repo.save(db, act)
            saved_actions.append(_action_model_to_schema(saved_act_model))

        # 4. Update incident status
        db_inc.status = "INVESTIGATED"
        db_inc.updated_at = datetime.now(timezone.utc)
        db.commit()

        return {
            "incident_id": incident_id,
            "investigation": _inv_model_to_schema(saved_inv_model),
            "recommended_actions": saved_actions,
            "evidence_package": evidence_pkg,
        }

    def get_investigation(
        self,
        db: Session,
        incident_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieves existing investigation findings, evidence records, and actions for an incident.
        """
        inv_model = investigation_repo.get_by_incident_id(db, incident_id)
        if not inv_model:
            return None

        inv_schema = _inv_model_to_schema(inv_model)
        evidence_models = evidence_repo.get_by_incident_id(db, incident_id)
        action_models = action_repo.get_by_incident_id(db, incident_id)

        return {
            "incident_id": incident_id,
            "investigation": inv_schema,
            "evidence_items": [_evidence_model_to_schema(e) for e in evidence_models],
            "recommended_actions": [_action_model_to_schema(a) for a in action_models],
        }
