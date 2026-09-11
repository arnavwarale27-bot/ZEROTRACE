from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.schemas import SecurityEvent
from app.modules.normalization.service import LogNormalizationService
from app.db.repository import security_event_repo, SecurityEventRepository


class LogIngestionService:
    """
    Log Ingestion Service.
    Coordinates receiving raw JSON security log payloads, passing them to the
    normalization layer, and persisting normalized SecurityEvent entities to the database.
    """

    def __init__(
        self,
        normalization_service: Optional[LogNormalizationService] = None,
        repository: Optional[SecurityEventRepository] = None,
    ):
        self.normalization_service = normalization_service or LogNormalizationService()
        self.repo = repository or security_event_repo

    def ingest_event(
        self,
        db: Session,
        raw_log: Dict[str, Any],
        source_override: Optional[str] = None,
    ) -> SecurityEvent:
        """
        Ingest a single raw security event payload.
        Normalizes the payload into a SecurityEvent and stores it in the database.
        """
        normalized_event = self.normalization_service.normalize(
            raw_log, source_override=source_override
        )
        self.repo.save(db, normalized_event)
        return normalized_event

    def ingest_batch(
        self,
        db: Session,
        raw_logs: List[Dict[str, Any]],
        source_override: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Ingest a batch of raw security events.
        Processes events atomically per-item, recording partial successes and detailed errors.
        """
        ingested_events: List[SecurityEvent] = []
        errors: List[Dict[str, Any]] = []

        for idx, raw_item in enumerate(raw_logs):
            try:
                event = self.ingest_event(db, raw_item, source_override=source_override)
                ingested_events.append(event)
            except Exception as exc:
                errors.append(
                    {
                        "index": idx,
                        "error": str(exc),
                        "raw_log": raw_item if isinstance(raw_item, dict) else str(raw_item),
                    }
                )

        return {
            "total": len(raw_logs),
            "ingested_count": len(ingested_events),
            "failed_count": len(errors),
            "events": ingested_events,
            "errors": errors,
        }

    def get_event_by_id(self, db: Session, event_id: str) -> Optional[SecurityEvent]:
        """Fetch a single normalized SecurityEvent by event_id."""
        db_obj = self.repo.get_by_event_id(db, event_id)
        if not db_obj:
            return None
        return SecurityEvent.model_validate(db_obj, from_attributes=True)

    def list_events(
        self,
        db: Session,
        *,
        source: Optional[str] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[SecurityEvent]:
        """List stored SecurityEvents with optional filtering and pagination."""
        db_objs = self.repo.list_events(
            db,
            source=source,
            severity=severity,
            event_type=event_type,
            skip=skip,
            limit=limit,
        )
        return [SecurityEvent.model_validate(obj, from_attributes=True) for obj in db_objs]
