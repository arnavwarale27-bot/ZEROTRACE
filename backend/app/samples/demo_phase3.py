import json
from datetime import datetime, timezone
from app.core.database import SessionLocal, init_db
from app.modules.ingestion.service import LogIngestionService
from app.modules.correlation.service import EventCorrelationService
from app.modules.correlation.config import CorrelationConfig


def run_phase3_demo():
    print("=" * 80)
    print("PHASE 3 — CORRELATION & INCIDENT CLUSTERING DEMO")
    print("=" * 80)

    init_db()
    db = SessionLocal()
    try:
        ingest_svc = LogIngestionService()
        corr_svc = EventCorrelationService()

        # 1. Input Events (including duplicate and multi-source correlated events)
        sample_input_logs = [
            {
                "source": "windows_security",
                "EventID": 4624,
                "TimeCreated": "2026-09-12T01:00:00Z",
                "Computer": "SEC-HOST-01",
                "TargetUserName": "admin_user",
                "LogonType": 3,
            },
            {
                "source": "powershell",
                "EventID": 4104,
                "TimeCreated": "2026-09-12T01:05:00Z",
                "Computer": "SEC-HOST-01",
                "UserId": "admin_user",
                "ScriptBlockText": "powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA...",
                "attack_id": "T1059.001",
            },
            # Near-duplicate PowerShell log (same host, user, command 15s later)
            {
                "source": "powershell",
                "EventID": 4104,
                "TimeCreated": "2026-09-12T01:05:15Z",
                "Computer": "SEC-HOST-01",
                "UserId": "admin_user",
                "ScriptBlockText": "powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA...",
                "attack_id": "T1059.001",
            },
            {
                "source": "network",
                "TimeCreated": "2026-09-12T01:10:00Z",
                "SourceIp": "10.0.4.15",
                "Computer": "SEC-HOST-01",
                "DestinationIp": "185.220.101.5",
                "DestinationPort": 4444,
                "action": "ALLOW",
                "attack_id": "T1071.001",
            },
            {
                "source": "edr",
                "TimeCreated": "2026-09-12T01:15:00Z",
                "ComputerName": "SEC-HOST-01",
                "AccountName": "admin_user",
                "event_type": "LSASSDump",
                "process_name": "procdump.exe",
                "command_line": "procdump.exe -ma lsass.exe",
                "confidence": 0.95,
                "attack_id": "T1003.001",
            },
            # Unrelated isolated event on distinct host
            {
                "source": "dns",
                "TimeCreated": "2026-09-12T01:20:00Z",
                "ClientIP": "192.168.99.99",
                "QueryName": "normal-update.com",
                "QueryType": "A",
            },
        ]

        print("\n1. INPUT EVENTS (6 raw log payloads across 5 sources):")
        for idx, log in enumerate(sample_input_logs, 1):
            print(f"   [{idx}] Source: {log['source']} | Computer/Host: {log.get('Computer') or log.get('ComputerName') or log.get('ClientIP')} | Event: {log.get('event_type') or log.get('EventID')}")

        # Ingest events into database
        ingest_res = ingest_svc.ingest_batch(db, sample_input_logs)
        print(f"\n   Ingested: {ingest_res['ingested_count']}/{ingest_res['total']} events into DB.")

        # 2. Correlation Engine Execution
        print("\n2. RUNNING CORRELATION ENGINE (Time Window = 60 mins)...")
        result = corr_svc.run_correlation(db, config=CorrelationConfig(time_window_minutes=60))

        print("\n3. CORRELATION RESULT SUMMARY:")
        print(f"   - Total Events Processed: {result['events_processed']}")
        print(f"   - Duplicates Identified:  {result['duplicates_found']}")
        print(f"   - Incidents Created:      {result['incidents_created']}")

        # 4. Duplicate Handling
        print("\n4. DUPLICATE HANDLING DETAILS:")
        if result["duplicate_events"]:
            for dup in result["duplicate_events"]:
                print(f"   - Event ID: {dup.event_id}")
                print(f"     Status: {dup.detection_state}")
                print(f"     Primary Reference: duplicate_of = {dup.raw_data.get('duplicate_of')}")
                print(f"     Original Payload Preserved: {dup.raw_data.get('source')} ({dup.timestamp})")

        # 5. Created Incidents & Associated Events
        print("\n5. CREATED INCIDENTS & LINKED SECURITY EVENTS:")
        for inc in result["incidents"]:
            print(f"\n   --------------------------------------------------")
            print(f"   Incident ID:  {inc.id}")
            print(f"   Title:        {inc.title}")
            print(f"   Severity:     {inc.severity}")
            print(f"   Status:       {inc.status}")
            print(f"   Linked Event IDs ({len(inc.event_ids)} events):")
            
            # Fetch linked events
            inc_detail = corr_svc.get_incident_with_events(db, inc.id)
            if inc_detail:
                for evt in inc_detail["events"]:
                    print(f"     * [{evt.event_id}] {evt.timestamp.isoformat()} | {evt.source} | {evt.event_type} | Severity: {evt.severity} | Stage: {evt.attack_stage}")
            print(f"   --------------------------------------------------")

    finally:
        db.close()


if __name__ == "__main__":
    run_phase3_demo()
