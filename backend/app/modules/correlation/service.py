from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.schemas import SecurityEvent, Incident
from app.modules.correlation.config import CorrelationConfig
from app.modules.correlation.deduplicator import EventDeduplicator
from app.modules.correlation.engine import CorrelationEngine
from app.db.repository import security_event_repo, incident_repo


class EventCorrelationService:
    """
    Service layer orchestrating event correlation, duplicate detection,
    and incident clustering over stored SecurityEvents.
    """

    def run_correlation(
        self,
        db: Session,
        config: Optional[CorrelationConfig] = None,
    ) -> Dict[str, Any]:
        """
        Runs deduplication and correlation clustering over stored database events.
        Persists duplicate metadata and created Incidents in the database.
        """
        cfg = config or CorrelationConfig()

        # 1. Fetch stored security events
        db_events = security_event_repo.list_events(db, limit=2000)
        events = [SecurityEvent.model_validate(e, from_attributes=True) for e in db_events]

        if not events:
            return {
                "events_processed": 0,
                "duplicates_found": 0,
                "incidents_created": 0,
                "incidents": [],
                "duplicate_events": [],
            }

        # 2. Run deduplication
        dedup = EventDeduplicator(cfg)
        primary_events, duplicate_events = dedup.process_duplicates(events)

        # Persist duplicate detection states
        for dup in duplicate_events:
            security_event_repo.save(db, dup)

        # 3. Run Correlation Graph Clustering
        engine = CorrelationEngine(cfg)
        incidents = engine.cluster_events(primary_events)

        # 4. Persist Incidents and update event investigation states
        persisted_incidents: List[Incident] = []
        for inc in incidents:
            incident_repo.save(db, inc)
            persisted_incidents.append(inc)

            # Update associated events investigation_state to IN_PROGRESS
            for event_id in inc.event_ids:
                event_model = security_event_repo.get_by_event_id(db, event_id)
                if event_model and event_model.investigation_state == "UNINVESTIGATED":
                    event_model.investigation_state = "IN_PROGRESS"
                    db.commit()

        return {
            "events_processed": len(events),
            "duplicates_found": len(duplicate_events),
            "incidents_created": len(persisted_incidents),
            "incidents": persisted_incidents,
            "duplicate_events": duplicate_events,
        }

    def list_incidents(
        self,
        db: Session,
        *,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Incident]:
        """Lists incidents with optional status and severity filtering."""
        db_incidents = incident_repo.list_incidents(
            db, status=status, severity=severity, skip=skip, limit=limit
        )
        return [Incident.model_validate(inc, from_attributes=True) for inc in db_incidents]

    def get_incident_with_events(
        self, db: Session, incident_id: str
    ) -> Optional[Dict[str, Any]]:
        """Retrieves an Incident by ID along with its associated SecurityEvent records."""
        db_inc = incident_repo.get_by_id(db, incident_id)
        if not db_inc:
            return None

        incident = Incident.model_validate(db_inc, from_attributes=True)

        events: List[SecurityEvent] = []
        for e_id in incident.event_ids:
            db_evt = security_event_repo.get_by_event_id(db, e_id)
            if db_evt:
                events.append(SecurityEvent.model_validate(db_evt, from_attributes=True))

        return {
            "incident": incident,
            "events": events,
        }
