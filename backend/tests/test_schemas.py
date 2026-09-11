from datetime import datetime, timezone
import pytest
from app.models.schemas import (
    SecurityEvent,
    IOC,
    Incident,
    Evidence,
    TimelineEvent,
    MitreTechnique,
    InvestigationResult,
    RecommendedAction,
)


def test_security_event_schema_required_fields():
    """Verify SecurityEvent schema validates all mandatory fields including raw_data."""
    event_data = {
        "event_id": "evt-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "Sysmon",
        "host": "srv-dc01",
        "user": "NT AUTHORITY\\SYSTEM",
        "event_type": "process_creation",
        "severity": "HIGH",
        "attack_stage": "Execution",
        "attack_id": "T1059.001",
        "detection_state": "DETECTED",
        "investigation_state": "UNINVESTIGATED",
        "confidence": 0.9,
        "latency": 45.2,
        "action": "ALLOWED",
        "raw_data": {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami"}
    }


    event = SecurityEvent(**event_data)
    assert event.event_id == "evt-001"
    assert event.source == "Sysmon"
    assert event.severity == "HIGH"
    assert event.confidence == 0.9
    assert event.raw_data["Image"] == "C:\\Windows\\System32\\cmd.exe"


def test_ioc_schema():
    ioc = IOC(
        id="ioc-101",
        type="ip",
        value="192.168.1.100",
        confidence_score=0.8,
        tags=["suspicious", "c2"]
    )
    assert ioc.id == "ioc-101"
    assert ioc.type == "ip"
    assert ioc.value == "192.168.1.100"


def test_incident_schema():
    incident = Incident(
        id="inc-500",
        title="Suspicious Process Execution",
        severity="HIGH",
        status="OPEN",
        event_ids=["evt-001"],
        ioc_ids=["ioc-101"]
    )
    assert incident.id == "inc-500"
    assert len(incident.event_ids) == 1


def test_evidence_schema():
    evidence = Evidence(
        id="ev-01",
        incident_id="inc-500",
        source="Host Telemetry",
        data_type="log_excerpt",
        content={"cmd": "whoami"},
        relevance_score=0.95
    )
    assert evidence.id == "ev-01"
    assert evidence.relevance_score == 0.95


def test_timeline_event_schema():
    timeline = TimelineEvent(
        id="tl-01",
        incident_id="inc-500",
        timestamp=datetime.now(timezone.utc),
        title="Command shell launched",
        description="Process cmd.exe spawned by unknown parent process",
        event_type="execution",
        source_event_id="evt-001",
        sequence=1
    )
    assert timeline.sequence == 1



def test_mitre_technique_schema():
    technique = MitreTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        tactic="Execution",
        description="Command and Scripting Interpreter: PowerShell",
        url="https://attack.mitre.org/techniques/T1059/001/"
    )
    assert technique.technique_id == "T1059.001"


def test_investigation_result_schema():
    inv = InvestigationResult(
        id="inv-01",
        incident_id="inc-500",
        summary="Verified suspicious execution of cmd.exe",
        mitre_techniques=["T1059.001"],
        evidence_ids=["ev-01"],
        confidence_score=0.88,
        status="COMPLETED"
    )
    assert inv.confidence_score == 0.88


def test_recommended_action_schema():
    action = RecommendedAction(
        id="act-01",
        incident_id="inc-500",
        action_type="isolate_host",
        description="Isolate srv-dc01 from corporate network pool",
        priority="CRITICAL",
        automated=False,
        status="PENDING"
    )
    assert action.action_type == "isolate_host"
    assert action.automated is False
