from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import uuid
from sqlalchemy.orm import Session

from app.models.schemas import TimelineEvent, SecurityEvent, Incident
from app.models.domain import TimelineEventModel
from app.db.repository import incident_repo, security_event_repo, timeline_repo


def _model_to_schema(model: TimelineEventModel) -> TimelineEvent:
    ts = model.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return TimelineEvent(
        id=model.id,
        incident_id=model.incident_id,
        timestamp=ts,
        title=model.title,
        description=model.description,
        event_type=model.event_type,
        source_event_id=model.source_event_id,
        sequence=model.sequence,
    )


class AttackTimelineService:
    """
    Attack Timeline Construction Service.
    Reconstructs chronological attack progressions from real database SecurityEvents
    linked to an Incident, distinguishing observed telemetry milestones from inferred stages.
    """

    def build_timeline(
        self,
        db: Session,
        incident_id: str,
    ) -> List[TimelineEvent]:
        """
        Reconstructs and persists chronological TimelineEvent milestones for an Incident.
        """
        db_inc = incident_repo.get_by_id(db, incident_id)
        if not db_inc:
            return []

        # 1. Fetch real constituent SecurityEvents
        events: List[SecurityEvent] = []
        for eid in db_inc.event_ids or []:
            db_evt = security_event_repo.get_by_event_id(db, eid)
            if db_evt:
                events.append(SecurityEvent.model_validate(db_evt, from_attributes=True))

        if not events:
            return []

        # 2. Sort chronologically by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        timeline_items: List[TimelineEvent] = []

        for seq, evt in enumerate(sorted_events):
            raw = evt.raw_data or {}

            # Extract actor/asset context
            host_str = evt.host or raw.get("Computer") or raw.get("ClientIP") or "Unknown Host"
            user_str = evt.user or raw.get("AccountName") or raw.get("TargetUserName") or "System/Unspecified"
            proc_str = raw.get("process_name") or raw.get("Image") or raw.get("CommandLine") or ""
            ip_str = raw.get("DestinationIp") or raw.get("SourceIp") or raw.get("ClientIP") or ""
            domain_str = raw.get("QueryName") or raw.get("domain") or ""

            # Build title
            title = f"[{evt.source.upper()}] {evt.event_type.replace('_', ' ').title()}"
            if host_str != "Unknown Host":
                title += f" on {host_str}"

            # Build narrative details
            details_parts = [
                f"Observed event of type '{evt.event_type}' reported by {evt.source} telemetry.",
                f"Asset: {host_str} | Actor: {user_str} | Severity: {evt.severity}.",
            ]
            if proc_str:
                details_parts.append(f"Process / Command: {proc_str}.")
            if ip_str:
                details_parts.append(f"Network Endpoint: {ip_str}.")
            if domain_str:
                details_parts.append(f"Target Domain: {domain_str}.")
            if evt.action:
                details_parts.append(f"Action Taken: {evt.action}.")
            if evt.attack_stage:
                details_parts.append(f"Cyber Kill Chain Stage: {evt.attack_stage}.")

            # Deterministic timeline ID
            key = f"{incident_id}:{evt.event_id}:{seq}"
            tl_id = f"tl-{str(uuid.uuid5(uuid.NAMESPACE_URL, key))[:8]}"

            evt_ts = evt.timestamp
            if evt_ts.tzinfo is None:
                evt_ts = evt_ts.replace(tzinfo=timezone.utc)

            tl_event = TimelineEvent(
                id=tl_id,
                incident_id=incident_id,
                timestamp=evt_ts,
                title=title,
                description=" ".join(details_parts),
                event_type=evt.event_type,
                source_event_id=evt.event_id,
                sequence=seq,
            )

            # Persist to database
            saved_model = timeline_repo.save(db, tl_event)
            timeline_items.append(_model_to_schema(saved_model))

        return timeline_items

    def get_timeline(
        self,
        db: Session,
        incident_id: str,
    ) -> List[TimelineEvent]:
        """
        Retrieves existing timeline for an incident, generating it if not yet present.
        """
        existing = timeline_repo.get_by_incident_id(db, incident_id)
        if existing:
            return [_model_to_schema(m) for m in existing]
        return self.build_timeline(db, incident_id)
