from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.schemas import TimelineEvent, MitreTechnique, InvestigationResult, RecommendedAction
from app.modules.timeline.service import AttackTimelineService
from app.modules.mitre.service import MitreMappingService
from app.modules.investigation.service import EvidenceGroundedAIInvestigationService

router = APIRouter(prefix="/incidents", tags=["Attack Intelligence & AI Investigation"])

timeline_service = AttackTimelineService()
mitre_service = MitreMappingService()
investigation_service = EvidenceGroundedAIInvestigationService()


@router.get(
    "/{incident_id}/timeline",
    response_model=List[TimelineEvent],
    summary="Get Incident Attack Timeline",
    description="Retrieve chronologically reconstructed attack progression for an incident backed by verified database security events.",
)
def get_incident_timeline(
    incident_id: str,
    db: Session = Depends(get_db),
) -> List[TimelineEvent]:
    timeline = timeline_service.get_timeline(db, incident_id)
    if not timeline:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No timeline events found for Incident '{incident_id}'.",
        )
    return timeline


@router.get(
    "/{incident_id}/mitre",
    summary="Get Incident MITRE ATT&CK Technique Mappings",
    description="Retrieve mapped MITRE ATT&CK techniques for an incident, indicating supporting event IDs and evidence nature (observed vs inferred).",
)
def get_incident_mitre_mappings(
    incident_id: str,
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    mappings = mitre_service.map_incident_techniques(db, incident_id)
    return mappings


@router.post(
    "/{incident_id}/investigate",
    summary="Generate Evidence-Grounded AI Investigation",
    description="Executes automated evidence packaging and AI investigation synthesis for an incident, generating root cause analysis, MITRE linkages, and prioritized response actions.",
)
def generate_investigation(
    incident_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    try:
        return investigation_service.investigate_incident(db, incident_id)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(val_err),
        ) from val_err
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Investigation failed: {str(exc)}",
        ) from exc


@router.get(
    "/{incident_id}/investigation",
    summary="Get AI Investigation Findings",
    description="Retrieve existing AI investigation findings, structured evidence artifacts, and recommended response actions for an incident.",
)
def get_investigation_result(
    incident_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    result = investigation_service.get_investigation(db, incident_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation result for Incident '{incident_id}' has not been generated yet.",
        )
    return result
