from typing import Dict, Any
from app.modules.normalization.parsers.base import BaseParser

# Windows Security Event ID → event_type mapping
_EVENT_ID_TYPE_MAP: Dict[int, str] = {
    4624: "authentication_success",
    4625: "authentication_failure",
    4648: "authentication_explicit_credential",
    4688: "process_creation",
    4689: "process_termination",
    4697: "service_installation",
    4698: "scheduled_task_created",
    4699: "scheduled_task_deleted",
    4702: "scheduled_task_modified",
    4720: "user_account_created",
    4726: "user_account_deleted",
    4728: "group_member_added",
    4732: "group_member_added",
    4756: "group_member_added",
    4768: "kerberos_tgt_request",
    4769: "kerberos_service_ticket_request",
    4771: "kerberos_preauth_failure",
    4776: "credential_validation",
}

# Windows Security Event ID → severity
_EVENT_ID_SEVERITY_MAP: Dict[int, str] = {
    4624: "INFO",
    4625: "HIGH",
    4648: "MEDIUM",
    4688: "MEDIUM",
    4697: "HIGH",
    4698: "HIGH",
    4720: "HIGH",
    4726: "MEDIUM",
    4768: "LOW",
    4769: "LOW",
    4771: "HIGH",
    4776: "MEDIUM",
}

# Logon types per Microsoft documentation
_LOGON_TYPE_MAP: Dict[int, str] = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}


class WindowsSecurityParser(BaseParser):
    """
    Parser for Windows Security Event Log telemetry.
    Handles EventID-based authentication, process creation, and account management events.
    All original field values are preserved in raw_data.
    """

    source_name = "windows_security"

    def parse(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        event_id_int = int(raw.get("EventID", 0))
        event_type = _EVENT_ID_TYPE_MAP.get(event_id_int, "windows_security_event")
        severity = _EVENT_ID_SEVERITY_MAP.get(event_id_int, "MEDIUM")

        # Extract subject (actor) identity
        user = (
            raw.get("SubjectUserName")
            or raw.get("TargetUserName")
            or raw.get("user")
        )
        # Strip system accounts from user field
        if user and user.strip() in ("-", "", "SYSTEM"):
            user = None

        host = raw.get("Computer") or raw.get("WorkstationName") or raw.get("host")

        # Determine action from logon type if applicable
        logon_type_int = raw.get("LogonType")
        action = None
        if logon_type_int is not None:
            action = _LOGON_TYPE_MAP.get(int(logon_type_int))

        # Process creation events carry command line
        if event_id_int == 4688:
            action = "PROCESS_CREATED"

        # Attack stage hints
        attack_stage = None
        if event_id_int in (4688, 4697, 4698, 4699, 4702):
            attack_stage = "Execution"
        elif event_id_int in (4624, 4625, 4648, 4768, 4769, 4771, 4776):
            attack_stage = "Credential Access"
        elif event_id_int in (4720, 4726, 4728, 4732, 4756):
            attack_stage = "Persistence"

        return {
            "timestamp": self._parse_timestamp(raw.get("TimeCreated") or raw.get("timestamp")),
            "source": self.source_name,
            "host": host,
            "user": user,
            "event_type": event_type,
            "severity": severity,
            "attack_stage": attack_stage,
            "attack_id": raw.get("attack_id"),
            "detection_state": "DETECTED",
            "investigation_state": "UNINVESTIGATED",
            "confidence": 0.0,
            "action": action,
            "raw_data": raw,
        }
