from typing import List, Dict, Any, Optional, Set
from sqlalchemy.orm import Session

from app.models.schemas import SecurityEvent, MitreTechnique, Incident
from app.models.domain import MitreTechniqueModel
from app.modules.mitre.knowledgebase import MITRE_KNOWLEDGEBASE
from app.db.repository import mitre_repo, incident_repo, security_event_repo


def _model_to_schema(model: MitreTechniqueModel) -> MitreTechnique:
    return MitreTechnique(
        technique_id=model.technique_id,
        name=model.name,
        tactic=model.tactic,
        description=model.description,
        url=model.url,
    )


class MitreMappingService:
    """
    MITRE ATT&CK Mapping Service.
    Maps observed security telemetry to standard MITRE ATT&CK techniques,
    distinguishing direct observed attack IDs from inferred behavioral patterns.
    """

    def map_event_to_techniques(self, event: SecurityEvent) -> List[Dict[str, Any]]:
        """
        Maps a single SecurityEvent to applicable MITRE techniques.
        Returns list of dicts with technique schema + supporting evidence metadata.
        """
        mapped_dict: Dict[str, Dict[str, Any]] = {}

        raw = event.raw_data or {}
        raw_text = (
            str(raw.get("CommandLine", ""))
            + " "
            + str(raw.get("command_line", ""))
            + " "
            + str(raw.get("ScriptBlockText", ""))
            + " "
            + str(raw.get("process_name", ""))
            + " "
            + str(raw.get("TargetObject", ""))
        ).lower()

        # 1. Observed Mapping from direct attack_id in telemetry
        if event.attack_id:
            tid = event.attack_id.strip()
            if tid in MITRE_KNOWLEDGEBASE:
                kb_entry = MITRE_KNOWLEDGEBASE[tid]
                mapped_dict[tid] = {
                    "technique": MitreTechnique(
                        technique_id=tid,
                        name=kb_entry["name"],
                        tactic=kb_entry["tactic"],
                        description=kb_entry["description"],
                        url=kb_entry["url"],
                    ),
                    "evidence_nature": "observed",
                    "supporting_event_ids": [event.event_id],
                }

        # 2. Inferred Behavioral Mapping
        # PowerShell / Command Execution
        if "powershell" in event.source.lower() or "powershell" in event.event_type.lower() or "powershell.exe" in raw_text:
            if "T1059.001" not in mapped_dict and "T1059.001" in MITRE_KNOWLEDGEBASE:
                mapped_dict["T1059.001"] = {
                    "technique": MitreTechnique(technique_id="T1059.001", **MITRE_KNOWLEDGEBASE["T1059.001"]),
                    "evidence_nature": "observed" if event.attack_id == "T1059.001" else "inferred",
                    "supporting_event_ids": [event.event_id],
                }
            if "encodedcommand" in raw_text or "-enc" in raw_text:
                if "T1027" not in mapped_dict:
                    mapped_dict["T1027"] = {
                        "technique": MitreTechnique(technique_id="T1027", **MITRE_KNOWLEDGEBASE["T1027"]),
                        "evidence_nature": "inferred",
                        "supporting_event_ids": [event.event_id],
                    }

        # LSASS / Credential Dumping
        if (
            "lsass" in raw_text
            or "procdump" in raw_text
            or "mimikatz" in raw_text
            or "sekurlsa" in raw_text
            or event.event_type == "edr_credential_dumping"
        ):
            if "T1003.001" in MITRE_KNOWLEDGEBASE:
                nature = "observed" if event.attack_id == "T1003.001" else "inferred"
                mapped_dict["T1003.001"] = {
                    "technique": MitreTechnique(technique_id="T1003.001", **MITRE_KNOWLEDGEBASE["T1003.001"]),
                    "evidence_nature": nature,
                    "supporting_event_ids": [event.event_id],
                }

        # DNS Tunneling / Exfiltration
        if "dns_txt_exfiltration" in event.event_type or "dns_potential_tunneling" in event.event_type:
            if "T1071.004" in MITRE_KNOWLEDGEBASE:
                mapped_dict["T1071.004"] = {
                    "technique": MitreTechnique(technique_id="T1071.004", **MITRE_KNOWLEDGEBASE["T1071.004"]),
                    "evidence_nature": "inferred",
                    "supporting_event_ids": [event.event_id],
                }
            if "T1572" in MITRE_KNOWLEDGEBASE:
                mapped_dict["T1572"] = {
                    "technique": MitreTechnique(technique_id="T1572", **MITRE_KNOWLEDGEBASE["T1572"]),
                    "evidence_nature": "inferred",
                    "supporting_event_ids": [event.event_id],
                }

        # Network C2 Web Protocols
        if "c2" in event.event_type or "4444" in raw_text:
            if "T1071.001" in MITRE_KNOWLEDGEBASE and "T1071.001" not in mapped_dict:
                nature = "observed" if event.attack_id == "T1071.001" else "inferred"
                mapped_dict["T1071.001"] = {
                    "technique": MitreTechnique(technique_id="T1071.001", **MITRE_KNOWLEDGEBASE["T1071.001"]),
                    "evidence_nature": nature,
                    "supporting_event_ids": [event.event_id],
                }

        # Registry Persistence
        if "registry" in event.event_type.lower() or "currentversion\\run" in raw_text:
            if "T1547.001" in MITRE_KNOWLEDGEBASE:
                nature = "observed" if event.attack_id == "T1547.001" else "inferred"
                mapped_dict["T1547.001"] = {
                    "technique": MitreTechnique(technique_id="T1547.001", **MITRE_KNOWLEDGEBASE["T1547.001"]),
                    "evidence_nature": nature,
                    "supporting_event_ids": [event.event_id],
                }

        # System Binary Proxy Execution (Rundll32, etc.)
        if "rundll32" in raw_text:
            if "T1218" in MITRE_KNOWLEDGEBASE:
                nature = "observed" if event.attack_id == "T1218" else "inferred"
                mapped_dict["T1218"] = {
                    "technique": MitreTechnique(technique_id="T1218", **MITRE_KNOWLEDGEBASE["T1218"]),
                    "evidence_nature": nature,
                    "supporting_event_ids": [event.event_id],
                }

        return list(mapped_dict.values())

    def map_incident_techniques(
        self,
        db: Session,
        incident_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Maps all events belonging to an incident to MITRE ATT&CK techniques.
        Aggregates supporting event IDs per technique and persists to database.
        """
        db_inc = incident_repo.get_by_id(db, incident_id)
        if not db_inc:
            return []

        events: List[SecurityEvent] = []
        for eid in db_inc.event_ids or []:
            db_evt = security_event_repo.get_by_event_id(db, eid)
            if db_evt:
                events.append(SecurityEvent.model_validate(db_evt, from_attributes=True))

        combined_mappings: Dict[str, Dict[str, Any]] = {}

        for evt in events:
            evt_mappings = self.map_event_to_techniques(evt)
            for m in evt_mappings:
                tech: MitreTechnique = m["technique"]
                tid = tech.technique_id
                nature = m["evidence_nature"]

                if tid not in combined_mappings:
                    combined_mappings[tid] = {
                        "technique": tech,
                        "evidence_nature": nature,
                        "supporting_event_ids": set(m["supporting_event_ids"]),
                    }
                    # Persist technique definition to database
                    mitre_repo.save(db, tech)
                else:
                    # If any event observed it explicitly, promote nature to observed
                    if nature == "observed":
                        combined_mappings[tid]["evidence_nature"] = "observed"
                    combined_mappings[tid]["supporting_event_ids"].update(m["supporting_event_ids"])

        # Format output list with serializable supporting event lists
        results: List[Dict[str, Any]] = []
        for tid, data in combined_mappings.items():
            results.append({
                "technique_id": data["technique"].technique_id,
                "name": data["technique"].name,
                "tactic": data["technique"].tactic,
                "description": data["technique"].description,
                "url": data["technique"].url,
                "evidence_nature": data["evidence_nature"],
                "supporting_event_ids": sorted(list(data["supporting_event_ids"])),
            })

        return results
