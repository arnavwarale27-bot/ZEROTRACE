from typing import Dict, List, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.schemas import SecurityEvent
from app.modules.ingestion.service import LogIngestionService

router = APIRouter(prefix="/events", tags=["Events"])
ingestion_service = LogIngestionService()


@router.post(
    "/ingest",
    response_model=SecurityEvent,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest Single Raw Security Event",
    description="Accepts a raw security log payload, normalizes it into canonical SecurityEvent schema, and persists it.",
)
def ingest_single_event(
    raw_log: Dict[str, Any],
    source: Optional[str] = Query(None, description="Optional override for event log source"),
    db: Session = Depends(get_db),
) -> SecurityEvent:
    try:
        return ingestion_service.ingest_event(db, raw_log, source_override=source)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid event payload: {str(val_err)}",
        ) from val_err
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to ingest event: {str(exc)}",
        ) from exc


@router.post(
    "/ingest/batch",
    status_code=status.HTTP_200_OK,
    summary="Ingest Batch of Raw Security Events",
    description="Accepts an array of raw log payloads, normalizes and persists each item, returning batch results and any errors.",
)
def ingest_batch_events(
    raw_logs: List[Dict[str, Any]],
    source: Optional[str] = Query(None, description="Optional override for all events in batch"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    if not isinstance(raw_logs, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch ingestion payload must be a JSON array of event objects.",
        )
    return ingestion_service.ingest_batch(db, raw_logs, source_override=source)


@router.get(
    "",
    response_model=List[SecurityEvent],
    summary="List Stored Security Events",
    description="Retrieve paginated list of normalized security events with optional filtering by source, severity, and event_type.",
)
def list_events(
    source: Optional[str] = Query(None, description="Filter by source name (partial match)"),
    severity: Optional[str] = Query(None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL, INFO)"),
    event_type: Optional[str] = Query(None, description="Filter by event_type (partial match)"),
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=500, description="Pagination page limit"),
    db: Session = Depends(get_db),
) -> List[SecurityEvent]:
    return ingestion_service.list_events(
        db,
        source=source,
        severity=severity,
        event_type=event_type,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/{event_id}",
    response_model=SecurityEvent,
    summary="Get Security Event by Event ID",
    description="Retrieve a single normalized security event by its unique event_id.",
)
def get_event_by_id(
    event_id: str,
    db: Session = Depends(get_db),
) -> SecurityEvent:
    event = ingestion_service.get_event_by_id(db, event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event with event_id '{event_id}' not found.",
        )
    return event
