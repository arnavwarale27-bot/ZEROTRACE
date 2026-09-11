from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, ConfigDict, Field


class SecurityEvent(BaseModel):
    """
    Core Normalized Security Event Schema.
    Must contain all mandatory fields and preserve raw event data in raw_data.
    """
    event_id: str = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(..., description="ISO 8601 timestamp of event occurrence")
    source: str = Field(..., description="Log source name (e.g. Sysmon, CloudTrail, AuthLog)")
    host: Optional[str] = Field(None, description="Hostname or IP of affected asset")
    user: Optional[str] = Field(None, description="Username or service account identity")
    event_type: str = Field(..., description="Categorized event type (e.g. process_creation, authentication)")
    severity: str = Field("MEDIUM", description="Event severity (LOW, MEDIUM, HIGH, CRITICAL, INFO)")
    attack_stage: Optional[str] = Field(None, description="Cyber Kill Chain or MITRE ATT&CK stage")
    attack_id: Optional[str] = Field(None, description="Associated Attack campaign or alert ID")
    detection_state: str = Field("DETECTED", description="Detection status (e.g. DETECTED, SUPPRESSED, RAW)")
    investigation_state: str = Field("UNINVESTIGATED", description="Investigation lifecycle status")
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="Detection confidence score between 0.0 and 1.0")
    latency: Optional[float] = Field(None, description="Ingestion/processing latency in milliseconds")
    action: Optional[str] = Field(None, description="Action taken (e.g. ALLOWED, BLOCKED, QUARANTINED)")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Preserved unparsed raw log payload")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "event_id": "evt-12345678",
                "timestamp": "2026-09-12T00:00:00Z",
                "source": "CrowdStrike",
                "host": "sec-workstation-01",
                "user": "admin",
                "event_type": "process_creation",
                "severity": "HIGH",
                "attack_stage": "Execution",
                "attack_id": "T1059.001",
                "detection_state": "DETECTED",
                "investigation_state": "UNINVESTIGATED",
                "confidence": 0.85,
                "latency": 120.5,
                "action": "BLOCKED",
                "raw_data": {"ProcessName": "powershell.exe", "CommandLine": "powershell -enc ..."}
            }
        }
    )


class IOC(BaseModel):
    """Indicator of Compromise entity schema."""
    id: str = Field(..., description="Unique IOC identifier")
    type: str = Field(..., description="IOC Type: ip, domain, sha256, md5, url, email")
    value: str = Field(..., description="IOC indicator value string")
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    confidence_score: float = Field(0.0, ge=0.0, le=1.0)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Incident(BaseModel):
    """Security Incident entity schema."""
    id: str = Field(..., description="Unique Incident identifier")
    title: str = Field(..., description="Short descriptive title of incident")
    description: Optional[str] = Field(None, description="Detailed incident narrative summary")
    severity: str = Field("MEDIUM", description="Overall incident severity")
    status: str = Field("OPEN", description="Lifecycle status: OPEN, IN_PROGRESS, CLOSED, RESOLVED")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_ids: List[str] = Field(default_factory=list, description="Associated security event IDs")
    ioc_ids: List[str] = Field(default_factory=list, description="Associated IOC IDs")


class Evidence(BaseModel):
    """Evidence grounded item supporting incident investigation."""
    id: str = Field(..., description="Unique evidence item identifier")
    incident_id: str = Field(..., description="Parent incident identifier")
    source: str = Field(..., description="Source system or collector providing evidence")
    data_type: str = Field(..., description="Data type: log_excerpt, network_pcap, memory_dump, artifact")
    content: Dict[str, Any] = Field(default_factory=dict, description="Structured evidence details")
    relevance_score: float = Field(0.0, ge=0.0, le=1.0, description="Relevance score to incident context")
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))



class TimelineEvent(BaseModel):
    """Attack timeline sequence entry schema."""
    id: str = Field(..., description="Unique timeline entry identifier")
    incident_id: str = Field(..., description="Parent incident identifier")
    timestamp: datetime = Field(..., description="Timestamp of timeline event")
    title: str = Field(..., description="Summary title of timeline milestone")
    description: str = Field(..., description="Detailed description of activity")
    event_type: str = Field(..., description="Event classification tag")
    source_event_id: Optional[str] = Field(None, description="Linked raw SecurityEvent ID if applicable")
    sequence: int = Field(0, description="Sequential index order in attack timeline")


class MitreTechnique(BaseModel):
    """MITRE ATT&CK Framework technique mapping schema."""
    technique_id: str = Field(..., description="MITRE Technique ID (e.g. T1059.001)")
    name: str = Field(..., description="MITRE Technique Name (e.g. PowerShell)")
    tactic: str = Field(..., description="MITRE Tactic stage (e.g. Execution)")
    description: str = Field(..., description="Technique description overview")
    url: Optional[str] = Field(None, description="Link to MITRE ATT&CK reference page")


class InvestigationResult(BaseModel):
    """Structured AI/SOC Investigation Output schema."""
    id: str = Field(..., description="Unique investigation result identifier")
    incident_id: str = Field(..., description="Associated incident identifier")
    summary: str = Field(..., description="Factual investigation summary synthesis")
    mitre_techniques: List[str] = Field(default_factory=list, description="Mapped MITRE technique IDs")
    evidence_ids: List[str] = Field(default_factory=list, description="Referenced evidence item IDs")
    confidence_score: float = Field(0.0, ge=0.0, le=1.0, description="Overall investigation confidence rating")
    status: str = Field("COMPLETED", description="Investigation execution status")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))



class RecommendedAction(BaseModel):
    """Remediation and Response action recommendation schema."""
    id: str = Field(..., description="Unique action recommendation identifier")
    incident_id: str = Field(..., description="Associated incident identifier")
    action_type: str = Field(..., description="Type of action: isolate_host, revoke_credentials, block_ip")
    description: str = Field(..., description="Clear instruction detailing recommended response")
    priority: str = Field("HIGH", description="Action priority rating: LOW, MEDIUM, HIGH, CRITICAL")
    automated: bool = Field(False, description="Whether action can be automatically dispatched")
    status: str = Field("PENDING", description="Action status: PENDING, EXECUTED, SKIPPED")


class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str
    version: str
    app: str
