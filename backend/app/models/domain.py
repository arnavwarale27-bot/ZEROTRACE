from datetime import datetime
from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, JSON, Text, ForeignKey
from app.db.base import Base


class SecurityEventModel(Base):
    """SQLAlchemy ORM table for Security Events."""
    __tablename__ = "security_events"

    event_id = Column(String, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    source = Column(String, index=True)
    host = Column(String, nullable=True, index=True)
    user = Column(String, nullable=True, index=True)
    event_type = Column(String, index=True)
    severity = Column(String, default="MEDIUM")
    attack_stage = Column(String, nullable=True)
    attack_id = Column(String, nullable=True)
    detection_state = Column(String, default="DETECTED")
    investigation_state = Column(String, default="UNINVESTIGATED")
    confidence = Column(Float, default=0.0)
    latency = Column(Float, nullable=True)
    action = Column(String, nullable=True)
    raw_data = Column(JSON, default=dict)


class IOCModel(Base):
    """SQLAlchemy ORM table for Indicators of Compromise."""
    __tablename__ = "iocs"

    id = Column(String, primary_key=True, index=True)
    type = Column(String, index=True)
    value = Column(String, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    confidence_score = Column(Float, default=0.0)
    tags = Column(JSON, default=list)
    metadata_json = Column(JSON, default=dict)


class IncidentModel(Base):
    """SQLAlchemy ORM table for Security Incidents."""
    __tablename__ = "incidents"

    id = Column(String, primary_primary=True, index=True) if False else Column(String, primary_key=True, index=True)
    title = Column(String)
    description = Column(Text, nullable=True)
    severity = Column(String, default="MEDIUM")
    status = Column(String, default="OPEN")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    event_ids = Column(JSON, default=list)
    ioc_ids = Column(JSON, default=list)


class EvidenceModel(Base):
    """SQLAlchemy ORM table for Evidence Items."""
    __tablename__ = "evidence"

    id = Column(String, primary_key=True, index=True)
    incident_id = Column(String, index=True)
    source = Column(String)
    data_type = Column(String)
    content = Column(JSON, default=dict)
    relevance_score = Column(Float, default=0.0)
    collected_at = Column(DateTime, default=datetime.utcnow)


class TimelineEventModel(Base):
    """SQLAlchemy ORM table for Timeline Events."""
    __tablename__ = "timeline_events"

    id = Column(String, primary_key=True, index=True)
    incident_id = Column(String, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    title = Column(String)
    description = Column(Text)
    event_type = Column(String)
    source_event_id = Column(String, nullable=True)
    sequence = Column(Integer, default=0)


class MitreTechniqueModel(Base):
    """SQLAlchemy ORM table for MITRE ATT&CK Techniques."""
    __tablename__ = "mitre_techniques"

    technique_id = Column(String, primary_key=True, index=True)
    name = Column(String)
    tactic = Column(String, index=True)
    description = Column(Text)
    url = Column(String, nullable=True)


class InvestigationResultModel(Base):
    """SQLAlchemy ORM table for AI Investigation Results."""
    __tablename__ = "investigation_results"

    id = Column(String, primary_key=True, index=True)
    incident_id = Column(String, index=True)
    summary = Column(Text)
    mitre_techniques = Column(JSON, default=list)
    evidence_ids = Column(JSON, default=list)
    confidence_score = Column(Float, default=0.0)
    status = Column(String, default="COMPLETED")
    created_at = Column(DateTime, default=datetime.utcnow)


class RecommendedActionModel(Base):
    """SQLAlchemy ORM table for Recommended Actions."""
    __tablename__ = "recommended_actions"

    id = Column(String, primary_key=True, index=True)
    incident_id = Column(String, index=True)
    action_type = Column(String)
    description = Column(Text)
    priority = Column(String, default="HIGH")
    automated = Column(Boolean, default=False)
    status = Column(String, default="PENDING")
