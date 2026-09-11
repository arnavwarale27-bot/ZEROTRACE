from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
import uuid

from app.models.schemas import InvestigationResult, RecommendedAction
from app.modules.investigation.providers.base import BaseAIInvestigatorProvider


class RuleGroundedEvidenceSynthesizer(BaseAIInvestigatorProvider):
    """
    Deterministic, evidence-grounded AI investigation synthesizer.
    Analyzes verified chronological milestones, MITRE mappings, and extracted IOCs,
    strictly citing real event IDs and asserting 'Insufficient evidence' when data is lacking.
    """

    @property
    def provider_name(self) -> str:
        return "rule_grounded_evidence_synthesizer"

    def investigate(
        self,
        evidence_package: Dict[str, Any],
    ) -> Tuple[InvestigationResult, List[RecommendedAction]]:
        incident = evidence_package["incident"]
        incident_id = incident["id"]
        timeline = evidence_package.get("timeline", [])
        mitre_techniques = evidence_package.get("mitre_techniques", [])
        iocs = evidence_package.get("iocs", [])
        evidence_items = evidence_package.get("evidence_items", [])

        now = datetime.now(timezone.utc)
        inv_id = f"inv-{str(uuid.uuid5(uuid.NAMESPACE_URL, f'{incident_id}:investigation'))[:8]}"
        evidence_ids = [e["id"] for e in evidence_items]
        tech_ids = [t["technique_id"] for t in mitre_techniques]

        # Check for insufficient evidence
        if len(timeline) == 0:
            summary = (
                f"Insufficient evidence for incident {incident_id}. "
                "No supporting security telemetry events are available to reconstruct an attack progression."
            )
            return (
                InvestigationResult(
                    id=inv_id,
                    incident_id=incident_id,
                    summary=summary,
                    mitre_techniques=[],
                    evidence_ids=evidence_ids,
                    confidence_score=0.1,
                    status="COMPLETED",
                    created_at=now,
                ),
                [],
            )

        # Extract context
        hosts = {t.get("title", "").split("on ")[-1] for t in timeline if "on " in t.get("title", "")}
        primary_host = next(iter(hosts)) if hosts else "Unknown Host"

        extracted_ips = [i["value"] for i in iocs if i["type"] == "ip"]
        extracted_domains = [i["value"] for i in iocs if i["type"] == "domain"]
        extracted_users = [i["value"] for i in iocs if i["type"] == "username"]
        extracted_procs = [i["value"] for i in iocs if i["type"] == "process"]

        # Build chronological attack reconstruction citing real event IDs
        narrative_points: List[str] = []
        for item in timeline:
            evt_id = item.get("source_event_id")
            evt_type = item.get("event_type")
            title = item.get("title")
            narrative_points.append(f"[{evt_id}] {title}: {evt_type}")

        # Synthesize Root Cause Narrative
        findings_sections: List[str] = [
            f"### Incident Summary",
            f"Security incident {incident_id} involves {len(timeline)} correlated event(s) targeting asset `{primary_host}` with overall severity rating `{incident['severity']}`.",
            "",
            f"### Chronological Attack Progression (Grounded in Verified Telemetry)",
        ]

        for item in timeline:
            evt_id = item.get("source_event_id")
            findings_sections.append(f"- **Event `[{evt_id}]`** ({item.get('timestamp')}): {item.get('description')}")

        findings_sections.extend([
            "",
            f"### MITRE ATT&CK Framework Mapping",
        ])

        if mitre_techniques:
            for t in mitre_techniques:
                events_citation = ", ".join([f"`[{eid}]`" for eid in t.get("supporting_event_ids", [])])
                findings_sections.append(
                    f"- **{t['technique_id']} - {t['name']}** (Tactic: *{t['tactic']}* | Nature: *{t['evidence_nature'].upper()}*): "
                    f"Supported by event(s) {events_citation}."
                )
        else:
            findings_sections.append("- No definitive MITRE ATT&CK techniques observed in current telemetry.")

        findings_sections.extend([
            "",
            f"### Extracted Indicators & Entity Context",
            f"- **Target Assets / Hostnames**: {', '.join(hosts) if hosts else 'None'}",
            f"- **Involved Identities / Users**: {', '.join(extracted_users) if extracted_users else 'None specified'}",
            f"- **Observed Processes**: {', '.join(extracted_procs) if extracted_procs else 'None'}",
            f"- **External Network Endpoints / C2**: {', '.join(extracted_ips + extracted_domains) if (extracted_ips or extracted_domains) else 'None detected'}",
            "",
            f"### Uncertainty & Missing Evidence",
        ])

        if not extracted_domains and not extracted_ips:
            findings_sections.append("- External network command and control infrastructure was unobserved in current telemetry window.")
        else:
            findings_sections.append("- Full lateral movement blast radius outside monitored host telemetry remains unobserved.")

        summary_text = "\n".join(findings_sections)

        # Calculate Confidence Score based on severity & MITRE depth
        confidence = 0.80
        if len(mitre_techniques) >= 2:
            confidence = 0.92
        elif incident["severity"] in ("CRITICAL", "HIGH"):
            confidence = 0.85

        # Generate Prioritized Response Recommendations
        actions: List[RecommendedAction] = []

        # Action 1: Host Isolation
        if primary_host and primary_host != "Unknown Host":
            actions.append(
                RecommendedAction(
                    id=f"act-{str(uuid.uuid5(uuid.NAMESPACE_URL, f'{incident_id}:isolate:{primary_host}'))[:8]}",
                    incident_id=incident_id,
                    action_type="isolate_host",
                    description=f"Isolate compromised workstation/host '{primary_host}' from the internal corporate network to halt potential lateral movement.",
                    priority="CRITICAL" if incident["severity"] == "CRITICAL" else "HIGH",
                    automated=False,
                    status="PENDING",
                )
            )

        # Action 2: Credential Revocation
        for u in extracted_users:
            actions.append(
                RecommendedAction(
                    id=f"act-{str(uuid.uuid5(uuid.NAMESPACE_URL, f'{incident_id}:revoke:{u}'))[:8]}",
                    incident_id=incident_id,
                    action_type="revoke_credentials",
                    description=f"Force password reset and terminate active Kerberos/OAuth sessions for user account '{u}'.",
                    priority="HIGH",
                    automated=False,
                    status="PENDING",
                )
            )

        # Action 3: Perimeter Firewall Blocking for External C2
        for bad_ip in extracted_ips:
            if not bad_ip.startswith("10.") and not bad_ip.startswith("192.168."):
                actions.append(
                    RecommendedAction(
                        id=f"act-{str(uuid.uuid5(uuid.NAMESPACE_URL, f'{incident_id}:block:{bad_ip}'))[:8]}",
                        incident_id=incident_id,
                        action_type="block_ip",
                        description=f"Deploy perimeter firewall drop rule for external C2 IP endpoint '{bad_ip}'.",
                        priority="HIGH",
                        automated=True,
                        status="PENDING",
                    )
                )

        for bad_domain in extracted_domains:
            actions.append(
                RecommendedAction(
                    id=f"act-{str(uuid.uuid5(uuid.NAMESPACE_URL, f'{incident_id}:block_domain:{bad_domain}'))[:8]}",
                    incident_id=incident_id,
                    action_type="block_domain",
                    description=f"Add malicious domain '{bad_domain}' to DNS sinkhole and perimeter web proxy blocklist.",
                    priority="HIGH",
                    automated=True,
                    status="PENDING",
                )
            )

        # Fallback Action if no specific entities
        if not actions:
            actions.append(
                RecommendedAction(
                    id=f"act-{str(uuid.uuid5(uuid.NAMESPACE_URL, f'{incident_id}:monitor'))[:8]}",
                    incident_id=incident_id,
                    action_type="enhanced_monitoring",
                    description="Enable enhanced telemetry auditing on affected assets to capture additional behavioral indicators.",
                    priority="MEDIUM",
                    automated=False,
                    status="PENDING",
                )
            )

        investigation_result = InvestigationResult(
            id=inv_id,
            incident_id=incident_id,
            summary=summary_text,
            mitre_techniques=tech_ids,
            evidence_ids=evidence_ids,
            confidence_score=confidence,
            status="COMPLETED",
            created_at=now,
        )

        return investigation_result, actions
