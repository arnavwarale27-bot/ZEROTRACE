from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.modules.correlation.config import CorrelationConfig
from app.modules.correlation.service import EventCorrelationService

router = APIRouter(prefix="/correlation", tags=["Correlation"])
correlation_service = EventCorrelationService()


@router.post(
    "/run",
    status_code=status.HTTP_200_OK,
    summary="Run Event Correlation & Deduplication Engine",
    description="Analyzes stored SecurityEvent records, performs deduplication, clusters related events into Incidents using entity pivots, and persists created Incidents.",
)
def run_correlation(
    time_window_minutes: int = Query(
        30, ge=1, le=1440, description="Correlation time window delta in minutes"
    ),
    min_events: int = Query(
        2, ge=1, description="Minimum number of related events required to create an incident"
    ),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    config = CorrelationConfig(
        time_window_minutes=time_window_minutes,
        min_events_for_incident=min_events,
    )
    return correlation_service.run_correlation(db, config=config)
