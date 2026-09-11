from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import uuid
from sqlalchemy.orm import Session

from app.models.schemas import Incident, SecurityEvent, IOC, TimelineEvent, Evidence
from app.models.domain import EvidenceModel
from app.modules.timeline.service import AttackTimelineService
from app.modules.mitre.service import MitreMappingService
from app.modules.extraction.service import EntityIOCExtractionService, _model_to_schema
from app.db.repository import incident_repo, security_event_repo, ioc_repo, evidence_repo


def _evidence_model_to_schema(model: EvidenceModel) -> Evidence:
    ts = model.collected_at
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return Evidence(
        id=model.id,
        incident_id=model.incident_id,
        source=model.source,
        data_type=model.data_type,
        content=model.content or {},
        relevance_score=model.relevance_score,
        collected_at=ts,
    )


class StructuredEvidenceBuilder:
    """
    Constructs a structured, bounded evidence package for an incident
    without exposing the entire raw database to the AI investigation layer.
    """

    def __init__(
        self,
        timeline_service: Optional[AttackTimelineService] = None,
        mitre_service: Optional[MitreMappingService] = None,
        extraction_service: Optional[EntityIOCExtractionService] = None,
    ):
        self.timeline_service = timeline_service or AttackTimelineService()
        self.mitre_service = mitre_service or MitreMappingService()
        self.extraction_service = extraction_service or EntityIOCExtractionService()

    def build_evidence_package(
        self,
        db: Session,
        incident_id: str,
    ) -> Dict[str, Any]:
        """
        Gathers timeline, MITRE techniques, IOCs, and asset contexts into a structured package.
        Persists formal Evidence records to the database.
        """
        db_inc = incident_repo.get_by_id(db, incident_id)
        if not db_inc:
            raise ValueError(f"Incident '{incident_id}' not found.")

        incident = Incident.model_validate(db_inc, from_attributes=True)

        # 1. Timeline Milestones
        timeline_items = self.timeline_service.build_timeline(db, incident_id)

        # 2. MITRE Technique Mappings
        mitre_mappings = self.mitre_service.map_incident_techniques(db, incident_id)

        # 3. Linked Security Events
        events: List[SecurityEvent] = []
        for eid in incident.event_ids:
            db_evt = security_event_repo.get_by_event_id(db, eid)
            if db_evt:
                events.append(SecurityEvent.model_validate(db_evt, from_attributes=True))

        # 4. Extract and Enrich Associated IOCs
        all_iocs = self.extraction_service.extract_and_store_from_events(db, incident.event_ids)
        incident_iocs = all_iocs.get("iocs", [])

        # 5. Persist formal Evidence records
        now = datetime.now(timezone.utc)
        evidence_records: List[Evidence] = []

        # Evidence Item 1: Telemetry Timeline
        ev1_id = f"ev-{str(uuid.uuid5(uuid.NAMESPACE_URL, f'{incident_id}:timeline'))[:8]}"
        ev1 = Evidence(
            id=ev1_id,
            incident_id=incident_id,
            source="timeline_reconstruction",
            data_type="log_excerpt",
            content={
                "milestones_count": len(timeline_items),
                "events": [t.model_dump(mode="json") for t in timeline_items],
            },
            relevance_score=0.95,
            collected_at=now,
        )
        evidence_repo.save(db, ev1)
        evidence_records.append(ev1)

        # Evidence Item 2: MITRE Behavioral Matrix
        ev2_id = f"ev-{str(uuid.uuid5(uuid.NAMESPACE_URL, f'{incident_id}:mitre'))[:8]}"
        ev2 = Evidence(
            id=ev2_id,
            incident_id=incident_id,
            source="mitre_mapping",
            data_type="artifact",
            content={"techniques": mitre_mappings},
            relevance_score=0.90,
            collected_at=now,
        )
        evidence_repo.save(db, ev2)
        evidence_records.append(ev2)

        # Evidence Item 3: Indicator Entities
        ev3_id = f"ev-{str(uuid.uuid5(uuid.NAMESPACE_URL, f'{incident_id}:iocs'))[:8]}"
        ev3 = Evidence(
            id=ev3_id,
            incident_id=incident_id,
            source="ioc_extractor",
            data_type="artifact",
            content={"iocs": [i.model_dump(mode="json") for i in incident_iocs]},
            relevance_score=0.85,
            collected_at=now,
        )
        evidence_repo.save(db, ev3)
        evidence_records.append(ev3)

        return {
            "incident": incident.model_dump(mode="json"),
            "timeline": [t.model_dump(mode="json") for t in timeline_items],
            "mitre_techniques": mitre_mappings,
            "iocs": [i.model_dump(mode="json") for i in incident_iocs],
            "events_count": len(events),
            "evidence_items": [e.model_dump(mode="json") for e in evidence_records],
        }
