from datetime import datetime, timezone, timedelta
import pytest

from app.models.schemas import SecurityEvent, Incident
from app.modules.correlation.config import CorrelationConfig
from app.modules.correlation.extractor import EntityExtractor
from app.modules.correlation.deduplicator import EventDeduplicator
from app.modules.correlation.engine import CorrelationEngine
from app.modules.correlation.service import EventCorrelationService
from app.modules.ingestion.service import LogIngestionService


def test_entity_extractor():
    event = SecurityEvent(
        event_id="evt-1",
        timestamp=datetime.now(timezone.utc),
        source="powershell",
        host="FINANCE-PC01",
        user="CORP\\jsmith",
        event_type="powershell_encoded_command",
        severity="HIGH",
        raw_data={
            "ClientIP": "10.0.1.50",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "QueryName": "malicious-c2.xyz",
        },
    )
    entities = EntityExtractor.extract_entities(event)
    assert "finance-pc01" in entities["host"]
    assert "jsmith" in entities["user"]
    assert "10.0.1.50" in entities["ip"]
    assert "powershell.exe" in entities["process"]
    assert "malicious-c2.xyz" in entities["ioc"]


def test_duplicate_detection():
    now = datetime.now(timezone.utc)
    raw = {"source": "windows_security", "EventID": 4624, "Computer": "DC01", "TargetUserName": "admin"}

    e1 = SecurityEvent(
        event_id="evt-101",
        timestamp=now,
        source="windows_security",
        host="DC01",
        user="admin",
        event_type="authentication_success",
        severity="INFO",
        raw_data=raw,
    )
    e2 = SecurityEvent(
        event_id="evt-102",
        timestamp=now + timedelta(seconds=30),  # Within 120s duplicate window
        source="windows_security",
        host="DC01",
        user="admin",
        event_type="authentication_success",
        severity="INFO",
        raw_data=raw,
    )

    dedup = EventDeduplicator()
    primary, duplicates = dedup.process_duplicates([e1, e2])

    assert len(primary) == 1
    assert len(duplicates) == 1
    assert duplicates[0].detection_state == "DUPLICATE"
    assert duplicates[0].raw_data.get("duplicate_of") == "evt-101"


def test_events_belonging_to_same_incident():
    now = datetime.now(timezone.utc)
    # Event 1: PowerShell script on host DC01
    e1 = SecurityEvent(
        event_id="evt-201",
        timestamp=now,
        source="powershell",
        host="DC01",
        user="admin",
        event_type="powershell_encoded_command",
        severity="HIGH",
        attack_stage="Execution",
        raw_data={"ScriptBlockText": "powershell.exe -Enc ABC..."},
    )
    # Event 2: EDR LSASS Dump on same host DC01 within 10 minutes
    e2 = SecurityEvent(
        event_id="evt-202",
        timestamp=now + timedelta(minutes=10),
        source="edr",
        host="DC01",
        user="SYSTEM",
        event_type="edr_credential_dumping",
        severity="CRITICAL",
        attack_stage="Credential Access",
        raw_data={"process_name": "procdump.exe"},
    )

    engine = CorrelationEngine(CorrelationConfig(time_window_minutes=30))
    incidents = engine.cluster_events([e1, e2])

    assert len(incidents) == 1
    inc = incidents[0]
    assert "DC01" in inc.title
    assert inc.severity == "CRITICAL"  # Escalated due to multi-stage & CRITICAL event
    assert "evt-201" in inc.event_ids
    assert "evt-202" in inc.event_ids


def test_unrelated_events_remain_separate():
    now = datetime.now(timezone.utc)
    # Event on HOST-A
    e1 = SecurityEvent(
        event_id="evt-301",
        timestamp=now,
        source="network",
        host="10.0.1.10",
        user="userA",
        event_type="network_connection_blocked",
        severity="LOW",
        raw_data={"SourceIp": "10.0.1.10"},
    )
    # Unrelated Event on HOST-B at different time
    e2 = SecurityEvent(
        event_id="evt-302",
        timestamp=now + timedelta(hours=5),
        source="dns",
        host="10.0.9.99",
        user="userB",
        event_type="dns_query",
        severity="INFO",
        raw_data={"QueryName": "google.com"},
    )

    engine = CorrelationEngine(CorrelationConfig(time_window_minutes=30, min_events_for_incident=2, critical_event_standalone_incident=False))
    incidents = engine.cluster_events([e1, e2])

    assert len(incidents) == 0  # Neither event forms a 2-event cluster or standalone critical event


def test_time_window_behavior():
    now = datetime.now(timezone.utc)
    e1 = SecurityEvent(
        event_id="evt-401",
        timestamp=now,
        source="edr",
        host="SERVER-X",
        user="userX",
        event_type="edr_alert",
        severity="HIGH",
        raw_data={"process": "cmd.exe"},
    )
    # Event on SAME host but outside 30-minute correlation time window (45 mins later)
    e2 = SecurityEvent(
        event_id="evt-402",
        timestamp=now + timedelta(minutes=45),
        source="edr",
        host="SERVER-X",
        user="userX",
        event_type="edr_alert",
        severity="HIGH",
        raw_data={"process": "net.exe"},
    )

    engine = CorrelationEngine(CorrelationConfig(time_window_minutes=30, min_events_for_incident=2))
    incidents = engine.cluster_events([e1, e2])

    # Should not link e1 and e2 together because they exceed 30 minutes window
    for inc in incidents:
        assert not ("evt-401" in inc.event_ids and "evt-402" in inc.event_ids)


def test_service_run_correlation(db):
    ingest_svc = LogIngestionService()
    corr_svc = EventCorrelationService()

    now_str = "2026-09-12T00:00:00Z"
    now_str2 = "2026-09-12T00:00:10Z"
    logs = [
        # Event 1
        {"source": "powershell", "EventID": 4104, "TimeCreated": now_str, "Computer": "HOST-TEST", "UserId": "user1", "ScriptBlockText": "Invoke-Mimikatz"},
        # Event 2 (Duplicate of Event 1 within 60s, 10s later)
        {"source": "powershell", "EventID": 4104, "TimeCreated": now_str2, "Computer": "HOST-TEST", "UserId": "user1", "ScriptBlockText": "Invoke-Mimikatz"},
        # Event 3 (Correlated event on HOST-TEST)
        {"source": "edr", "EventTime": now_str, "ComputerName": "HOST-TEST", "AccountName": "user1", "event_type": "LSASSDump", "process_name": "procdump.exe"},
    ]

    ingest_svc.ingest_batch(db, logs)

    result = corr_svc.run_correlation(db, config=CorrelationConfig(time_window_minutes=30))
    assert result["events_processed"] == 3
    assert result["duplicates_found"] == 1
    assert result["incidents_created"] >= 1


def test_api_correlation_and_incidents(client):
    # Ingest 2 related events via API
    e1 = {"source": "network", "SourceIp": "10.0.5.5", "DestinationPort": 4444, "action": "ALLOW", "TimeCreated": "2026-09-12T01:00:00Z"}
    e2 = {"source": "edr", "ComputerName": "10.0.5.5", "event_type": "LSASSDump", "process_name": "procdump.exe", "TimeCreated": "2026-09-12T01:05:00Z"}

    client.post("/api/v1/events/ingest/batch", json=[e1, e2])

    # Run correlation via POST /api/v1/correlation/run
    res_corr = client.post("/api/v1/correlation/run?time_window_minutes=60")
    assert res_corr.status_code == 200
    corr_data = res_corr.json()
    assert corr_data["incidents_created"] >= 1

    # List incidents via GET /api/v1/incidents
    res_inc = client.get("/api/v1/incidents")
    assert res_inc.status_code == 200
    inc_list = res_inc.json()
    assert len(inc_list) >= 1

    inc_id = inc_list[0]["id"]

    # Get incident details with linked events via GET /api/v1/incidents/{inc_id}
    res_single = client.get(f"/api/v1/incidents/{inc_id}")
    assert res_single.status_code == 200
    single_data = res_single.json()
    assert "incident" in single_data
    assert "events" in single_data
    assert len(single_data["events"]) >= 1
