from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.schemas import Incident, SecurityEvent
from app.modules.correlation.service import EventCorrelationService

router = APIRouter(prefix="/incidents", tags=["Incidents"])
correlation_service = EventCorrelationService()


@router.get(
    "",
    response_model=List[Incident],
    summary="List Incidents",
    description="Retrieve paginated list of created security incidents with optional status and severity filtering.",
)
def list_incidents(
    status: Optional[str] = Query(None, description="Filter by status (OPEN, IN_PROGRESS, CLOSED, RESOLVED)"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL, INFO)"),
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=500, description="Pagination limit"),
    db: Session = Depends(get_db),
) -> List[Incident]:
    return correlation_service.list_incidents(
        db, status=status, severity=severity, skip=skip, limit=limit
    )


@router.get(
    "/{incident_id}",
    summary="Get Incident with Associated Events",
    description="Retrieve a single security incident by ID along with all associated normalized SecurityEvent objects.",
)
def get_incident_with_events(
    incident_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    res = correlation_service.get_incident_with_events(db, incident_id)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found.",
        )
    return res
