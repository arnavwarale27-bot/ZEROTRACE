from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set
import uuid
from sqlalchemy.orm import Session

from app.models.schemas import SecurityEvent, IOC
from app.models.domain import IOCModel
from app.modules.extraction.extractors import (
    extract_ips,
    extract_domains,
    extract_hashes,
    extract_usernames,
    extract_hostnames,
    extract_processes,
)
from app.db.repository import ioc_repo, security_event_repo


def generate_ioc_id(ioc_type: str, value: str) -> str:
    """Deterministic UUID5 ID based on indicator type and lowercase normalized value."""
    key = f"{ioc_type.lower()}:{value.strip().lower()}"
    return f"ioc-{str(uuid.uuid5(uuid.NAMESPACE_URL, key))[:8]}"


def _model_to_schema(model: IOCModel) -> IOC:
    """Converts SQLAlchemy IOCModel to Pydantic IOC schema."""
    return IOC(
        id=model.id,
        type=model.type,
        value=model.value,
        first_seen=model.first_seen if model.first_seen.tzinfo else model.first_seen.replace(tzinfo=timezone.utc),
        last_seen=model.last_seen if model.last_seen.tzinfo else model.last_seen.replace(tzinfo=timezone.utc),
        confidence_score=model.confidence_score,
        tags=model.tags or [],
        metadata=model.metadata_json or {},
    )


class EntityIOCExtractionService:
    """
    Service responsible for extracting Indicators of Compromise (IOCs)
    and security entities from normalized SecurityEvent data and persisting
    deduplicated records linked to source events.
    """

    def extract_iocs_from_event(self, event: SecurityEvent) -> List[IOC]:
        """
        Extracts all candidate IOC entities from a single SecurityEvent.
        Returns deduplicated list of IOC objects linked to the event.
        """
        extracted_map: Dict[Tuple[str, str], IOC] = {}

        event_ts = event.timestamp
        if event_ts.tzinfo is None:
            event_ts = event_ts.replace(tzinfo=timezone.utc)

        # 1. IP Addresses
        for ip_val in extract_ips(event):
            ioc_id = generate_ioc_id("ip", ip_val)
            extracted_map[("ip", ip_val)] = IOC(
                id=ioc_id,
                type="ip",
                value=ip_val,
                first_seen=event_ts,
                last_seen=event_ts,
                confidence_score=event.confidence,
                tags=[f"source:{event.source}"],
                metadata={"related_event_ids": [event.event_id]},
            )

        # 2. Domain Names
        for domain_val in extract_domains(event):
            ioc_id = generate_ioc_id("domain", domain_val)
            extracted_map[("domain", domain_val)] = IOC(
                id=ioc_id,
                type="domain",
                value=domain_val,
                first_seen=event_ts,
                last_seen=event_ts,
                confidence_score=event.confidence,
                tags=[f"source:{event.source}"],
                metadata={"related_event_ids": [event.event_id]},
            )

        # 3. File Hashes
        for hash_type, hash_val in extract_hashes(event):
            ioc_id = generate_ioc_id(hash_type, hash_val)
            extracted_map[(hash_type, hash_val)] = IOC(
                id=ioc_id,
                type=hash_type,
                value=hash_val,
                first_seen=event_ts,
                last_seen=event_ts,
                confidence_score=event.confidence,
                tags=[f"source:{event.source}"],
                metadata={"related_event_ids": [event.event_id]},
            )

        # 4. Usernames
        for user_val in extract_usernames(event):
            ioc_id = generate_ioc_id("username", user_val)
            extracted_map[("username", user_val)] = IOC(
                id=ioc_id,
                type="username",
                value=user_val,
                first_seen=event_ts,
                last_seen=event_ts,
                confidence_score=event.confidence,
                tags=[f"source:{event.source}"],
                metadata={"related_event_ids": [event.event_id]},
            )

        # 5. Hostnames
        for host_val in extract_hostnames(event):
            ioc_id = generate_ioc_id("hostname", host_val)
            extracted_map[("hostname", host_val)] = IOC(
                id=ioc_id,
                type="hostname",
                value=host_val,
                first_seen=event_ts,
                last_seen=event_ts,
                confidence_score=event.confidence,
                tags=[f"source:{event.source}"],
                metadata={"related_event_ids": [event.event_id]},
            )

        # 6. Process Names
        for proc_val in extract_processes(event):
            ioc_id = generate_ioc_id("process", proc_val)
            extracted_map[("process", proc_val)] = IOC(
                id=ioc_id,
                type="process",
                value=proc_val,
                first_seen=event_ts,
                last_seen=event_ts,
                confidence_score=event.confidence,
                tags=[f"source:{event.source}"],
                metadata={"related_event_ids": [event.event_id]},
            )

        return list(extracted_map.values())

    def extract_and_store_from_events(
        self,
        db: Session,
        event_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Extracts IOCs from stored events in the database and persists them.
        Updates existing IOCs by merging event references and timestamps without duplicating records.
        """
        # Fetch target events
        if event_ids:
            events_models = [
                security_event_repo.get_by_event_id(db, eid)
                for eid in event_ids
                if security_event_repo.get_by_event_id(db, eid)
            ]
        else:
            events_models = security_event_repo.list_events(db, limit=2000)

        events = [SecurityEvent.model_validate(em, from_attributes=True) for em in events_models]

        total_extracted = 0
        stored_iocs: List[IOC] = []

        for event in events:
            event_iocs = self.extract_iocs_from_event(event)
            total_extracted += len(event_iocs)

            for ioc in event_iocs:
                # Check if IOC already exists in DB
                existing_model = ioc_repo.get_by_id(db, ioc.id)
                if existing_model:
                    existing_ioc = _model_to_schema(existing_model)

                    # Merge related_event_ids
                    existing_event_ids = set(existing_ioc.metadata.get("related_event_ids", []))
                    existing_event_ids.add(event.event_id)
                    existing_ioc.metadata["related_event_ids"] = list(existing_event_ids)

                    # Update timestamps
                    if ioc.last_seen > existing_ioc.last_seen:
                        existing_ioc.last_seen = ioc.last_seen
                    if ioc.first_seen < existing_ioc.first_seen:
                        existing_ioc.first_seen = ioc.first_seen

                    # Merge tags
                    merged_tags = list(set(existing_ioc.tags + ioc.tags))
                    existing_ioc.tags = merged_tags

                    persisted = ioc_repo.save(db, existing_ioc)
                    stored_iocs.append(_model_to_schema(persisted))
                else:
                    persisted = ioc_repo.save(db, ioc)
                    stored_iocs.append(_model_to_schema(persisted))

        # Deduplicate return list by ID
        unique_iocs_by_id = {ioc.id: ioc for ioc in stored_iocs}

        return {
            "events_scanned": len(events),
            "total_extracted": total_extracted,
            "unique_iocs_stored": len(unique_iocs_by_id),
            "iocs": list(unique_iocs_by_id.values()),
        }

    def list_iocs(
        self,
        db: Session,
        *,
        ioc_type: Optional[str] = None,
        tag: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[IOC]:
        """List stored IOC entities with optional type/tag filtering."""
        models = ioc_repo.list_iocs(db, ioc_type=ioc_type, tag=tag, skip=skip, limit=limit)
        return [_model_to_schema(m) for m in models]

    def get_ioc_with_events(
        self,
        db: Session,
        ioc_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a specific IOC and all associated SecurityEvent records."""
        model = ioc_repo.get_by_id(db, ioc_id)
        if not model:
            return None

        ioc = _model_to_schema(model)
        related_ids = ioc.metadata.get("related_event_ids", [])

        events: List[SecurityEvent] = []
        for eid in related_ids:
            evt_model = security_event_repo.get_by_event_id(db, eid)
            if evt_model:
                events.append(SecurityEvent.model_validate(evt_model, from_attributes=True))

        return {
            "ioc": ioc,
            "events": events,
        }
