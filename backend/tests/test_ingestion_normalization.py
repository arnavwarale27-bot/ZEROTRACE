import pytest
from app.models.schemas import SecurityEvent
from app.modules.normalization.parsers import (
    WindowsSecurityParser,
    PowerShellParser,
    DNSParser,
    NetworkParser,
    EDRParser,
    GenericParser,
    generate_event_id,
    get_parser,
)
from app.modules.normalization.service import LogNormalizationService
from app.modules.ingestion.service import LogIngestionService


def test_windows_security_parser_auth_success():
    parser = WindowsSecurityParser()
    raw = {
        "EventID": 4624,
        "TimeCreated": "2026-09-12T00:00:00Z",
        "Computer": "DC01.corp.internal",
        "TargetUserName": "admin_svc",
        "LogonType": 3,
    }
    parsed = parser.parse(raw)
    assert parsed["event_type"] == "authentication_success"
    assert parsed["severity"] == "INFO"
    assert parsed["host"] == "DC01.corp.internal"
    assert parsed["user"] == "admin_svc"
    assert parsed["action"] == "Network"
    assert parsed["attack_stage"] == "Credential Access"
    assert parsed["raw_data"] == raw


def test_windows_security_parser_auth_failure():
    parser = WindowsSecurityParser()
    raw = {
        "EventID": 4625,
        "TimeCreated": "2026-09-12T00:00:00Z",
        "Computer": "WORKSTATION-01",
        "TargetUserName": "Administrator",
    }
    parsed = parser.parse(raw)
    assert parsed["event_type"] == "authentication_failure"
    assert parsed["severity"] == "HIGH"


def test_powershell_parser_encoded_command():
    parser = PowerShellParser()
    raw = {
        "EventID": 4104,
        "TimeCreated": "2026-09-12T00:00:00Z",
        "Computer": "FINANCE-PC",
        "UserId": "CORP\\user1",
        "ScriptBlockText": "powershell.exe -EncodedCommand SQBFAFgA",
    }
    parsed = parser.parse(raw)
    assert parsed["event_type"] == "powershell_encoded_command"
    assert parsed["severity"] == "HIGH"
    assert parsed["action"] == "ENCODED"
    assert parsed["attack_stage"] == "Execution"


def test_powershell_parser_mimikatz():
    parser = PowerShellParser()
    raw = {
        "EventID": 4104,
        "TimeCreated": "2026-09-12T00:00:00Z",
        "ScriptBlockText": "Invoke-Mimikatz -DumpCreds",
    }
    parsed = parser.parse(raw)
    assert parsed["severity"] == "CRITICAL"


def test_dns_parser_tunneling():
    parser = DNSParser()
    raw = {
        "TimeCreated": "2026-09-12T00:00:00Z",
        "ClientIP": "10.0.1.50",
        "QueryName": "a1b2c3d4e5f6g7h8i9j0.c2server.xyz",
        "QueryType": "TXT",
    }
    parsed = parser.parse(raw)
    assert parsed["event_type"] == "dns_txt_exfiltration"
    assert parsed["severity"] == "HIGH"
    assert parsed["attack_stage"] == "Command and Control"


def test_network_parser_c2_connection():
    parser = NetworkParser()
    raw = {
        "TimeCreated": "2026-09-12T00:00:00Z",
        "SourceIp": "10.0.1.50",
        "DestinationIp": "198.51.100.1",
        "DestinationPort": 4444,
        "action": "ALLOW",
    }
    parsed = parser.parse(raw)
    assert parsed["event_type"] == "network_suspicious_c2_connection"
    assert parsed["severity"] == "HIGH"
    assert parsed["attack_stage"] == "Command and Control"


def test_edr_parser_lsass_dump():
    parser = EDRParser()
    raw = {
        "TimeCreated": "2026-09-12T00:00:00Z",
        "ComputerName": "SERVER-01",
        "AccountName": "SYSTEM",
        "event_type": "LSASSDump",
        "process_name": "procdump.exe",
        "command_line": "procdump.exe -ma lsass.exe",
    }
    parsed = parser.parse(raw)
    assert parsed["event_type"] == "edr_credential_dumping"
    assert parsed["severity"] == "CRITICAL"
    assert parsed["attack_stage"] == "Credential Access"


def test_generic_parser_fallback():
    parser = get_parser("unknown_source")
    assert isinstance(parser, GenericParser)
    raw = {
        "source": "custom_app",
        "timestamp": "2026-09-12T00:00:00Z",
        "host": "app-server",
        "severity": "HIGH",
        "event_type": "custom_alert",
    }
    parsed = parser.parse(raw)
    assert parsed["source"] == "custom_app"
    assert parsed["severity"] == "HIGH"


def test_deterministic_event_id():
    raw = {"source": "windows_security", "EventID": 4624, "Computer": "PC01"}
    id1 = generate_event_id("windows_security", raw)
    id2 = generate_event_id("windows_security", raw)
    assert id1 == id2
    assert id1.startswith("evt-")


def test_raw_data_preservation():
    service = LogNormalizationService()
    raw = {"source": "dns", "QueryName": "example.com", "custom_meta": {"nested": "value"}}
    event = service.normalize(raw)
    assert event.raw_data == raw
    assert event.raw_data["custom_meta"]["nested"] == "value"


def test_normalization_service_invalid_input():
    service = LogNormalizationService()
    with pytest.raises(ValueError, match="Input raw_log must be a JSON dictionary"):
        service.normalize("not_a_dict")


def test_ingestion_service_single_event(db):
    service = LogIngestionService()
    raw = {
        "source": "windows_security",
        "EventID": 4624,
        "TimeCreated": "2026-09-12T00:00:00Z",
        "Computer": "DC01",
        "TargetUserName": "jdoe",
    }
    event = service.ingest_event(db, raw)
    assert isinstance(event, SecurityEvent)
    assert event.event_type == "authentication_success"

    # Verify persisted in database
    retrieved = service.get_event_by_id(db, event.event_id)
    assert retrieved is not None
    assert retrieved.user == "jdoe"


def test_ingestion_service_batch_with_errors(db):
    service = LogIngestionService()
    batch = [
        {"source": "dns", "QueryName": "valid.com", "TimeCreated": "2026-09-12T00:00:00Z"},
        "invalid_non_dict_payload",
        {"source": "edr", "event_type": "FileCreate", "TimeCreated": "2026-09-12T00:00:00Z"},
    ]
    result = service.ingest_batch(db, batch)
    assert result["total"] == 3
    assert result["ingested_count"] == 2
    assert result["failed_count"] == 1
    assert len(result["errors"]) == 1
    assert result["errors"][0]["index"] == 1


def test_api_ingest_single_and_query(client):
    payload = {
        "source": "powershell",
        "EventID": 4104,
        "TimeCreated": "2026-09-12T00:00:00Z",
        "Computer": "PC-TEST",
        "ScriptBlockText": "Get-Process",
    }
    # Test POST /api/v1/events/ingest
    response = client.post("/api/v1/events/ingest", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["event_type"] == "powershell_script_execution"
    assert data["host"] == "PC-TEST"
    assert "event_id" in data

    event_id = data["event_id"]

    # Test GET /api/v1/events/{event_id}
    response_get = client.get(f"/api/v1/events/{event_id}")
    assert response_get.status_code == 200
    assert response_get.json()["event_id"] == event_id

    # Test GET /api/v1/events (list)
    response_list = client.get("/api/v1/events?source=powershell")
    assert response_list.status_code == 200
    events_list = response_list.json()
    assert len(events_list) == 1
    assert events_list[0]["event_id"] == event_id


def test_api_ingest_batch(client):
    batch_payload = [
        {"source": "network", "SourceIp": "10.0.0.1", "DestinationPort": 80, "action": "ALLOW"},
        {"source": "network", "SourceIp": "10.0.0.2", "DestinationPort": 4444, "action": "ALLOW"},
    ]
    response = client.post("/api/v1/events/ingest/batch", json=batch_payload)
    assert response.status_code == 200
    res_data = response.json()
    assert res_data["total"] == 2
    assert res_data["ingested_count"] == 2
    assert res_data["failed_count"] == 0
