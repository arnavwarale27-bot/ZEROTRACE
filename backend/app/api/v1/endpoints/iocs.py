from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.schemas import IOC, SecurityEvent
from app.modules.extraction.service import EntityIOCExtractionService
from app.modules.enrichment.service import ThreatIntelEnrichmentService

router = APIRouter(prefix="/iocs", tags=["IOCs & Threat Intel"])
extraction_service = EntityIOCExtractionService()
enrichment_service = ThreatIntelEnrichmentService()


@router.post(
    "/extract",
    status_code=status.HTTP_200_OK,
    summary="Extract IOCs from Stored Security Events",
    description="Parses stored SecurityEvent records, extracts IP addresses, domain names, hashes, usernames, hostnames, and process names, linking them back to source events without duplicates.",
)
def extract_iocs(
    event_id: Optional[str] = Query(None, description="Optional specific event ID to extract IOCs from"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    event_ids = [event_id] if event_id else None
    return extraction_service.extract_and_store_from_events(db, event_ids=event_ids)


@router.get(
    "",
    response_model=List[IOC],
    summary="List Extracted IOCs",
    description="Retrieve paginated list of extracted IOC entities with optional type and tag filtering.",
)
def list_iocs(
    type: Optional[str] = Query(None, description="Filter by indicator type (ip, domain, sha256, md5, username, hostname, process)"),
    tag: Optional[str] = Query(None, description="Filter by tag (e.g. source:powershell, lolbin, internal_network)"),
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=500, description="Pagination limit"),
    db: Session = Depends(get_db),
) -> List[IOC]:
    return extraction_service.list_iocs(db, ioc_type=type, tag=tag, skip=skip, limit=limit)


@router.get(
    "/{ioc_id}",
    summary="Get IOC by ID with Related Events",
    description="Retrieve a single IOC record by ID along with all associated SecurityEvent records linked to it.",
)
def get_ioc_with_events(
    ioc_id: str,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    res = extraction_service.get_ioc_with_events(db, ioc_id)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IOC with ID '{ioc_id}' not found.",
        )
    return res


@router.post(
    "/{ioc_id}/enrich",
    response_model=IOC,
    summary="Enrich Specific IOC",
    description="Trigger local rule classification and external threat intelligence lookup on a specific IOC.",
)
def enrich_single_ioc(
    ioc_id: str,
    db: Session = Depends(get_db),
) -> IOC:
    enriched = enrichment_service.enrich_ioc(db, ioc_id)
    if not enriched:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IOC with ID '{ioc_id}' not found for enrichment.",
        )
    return enriched


@router.post(
    "/enrich/batch",
    status_code=status.HTTP_200_OK,
    summary="Enrich All Stored IOCs",
    description="Batch runs threat intelligence enrichment across all stored IOC entities.",
)
def enrich_all_iocs(
    limit: int = Query(500, ge=1, le=2000, description="Max IOCs to enrich"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    return enrichment_service.enrich_all(db, limit=limit)
