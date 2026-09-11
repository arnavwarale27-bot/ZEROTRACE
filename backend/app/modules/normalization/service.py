from datetime import datetime, timezone
from typing import Dict, Any, Optional
from pydantic import ValidationError

from app.models.schemas import SecurityEvent
from app.modules.normalization.parsers import get_parser, generate_event_id


class LogNormalizationService:
    """
    Log Normalization Service.
    Transforms raw security logs from various sources into unified SecurityEvent Pydantic models.
    Preserves original raw data completely in `raw_data`.
    Generates deterministic event_ids and calculates processing latency.
    """

    def normalize(self, raw_log: Dict[str, Any], source_override: Optional[str] = None) -> SecurityEvent:
        """
        Normalize raw log record into SecurityEvent schema.

        Args:
            raw_log: Raw dictionary representation of security log.
            source_override: Optional source identifier overriding raw_log fields.

        Returns:
            Validated SecurityEvent model.

        Raises:
            ValueError: If required fields are missing or validation fails.
        """
        if not isinstance(raw_log, dict):
            raise ValueError("Input raw_log must be a JSON dictionary.")

        # Determine source
        source = (
            source_override
            or raw_log.get("source")
            or raw_log.get("log_source")
            or raw_log.get("Source")
            or raw_log.get("Provider_Name")
            or "generic"
        )

        parser = get_parser(str(source))
        fields = parser.parse(raw_log)

        # Set source to canonical parser source_name if generic source string was passed
        if fields.get("source") == "generic" and source != "generic":
            fields["source"] = str(source)

        # Generate event_id if not present
        if not fields.get("event_id"):
            provided_id = raw_log.get("event_id") or raw_log.get("EventID")
            if provided_id and isinstance(provided_id, str) and provided_id.startswith("evt-"):
                fields["event_id"] = provided_id
            else:
                fields["event_id"] = generate_event_id(fields["source"], raw_log)

        # Calculate latency in ms
        now = datetime.now(timezone.utc)
        evt_ts = fields.get("timestamp")
        if isinstance(evt_ts, datetime):
            if evt_ts.tzinfo is None:
                evt_ts = evt_ts.replace(tzinfo=timezone.utc)
            latency_ms = (now - evt_ts).total_seconds() * 1000.0
            fields["latency"] = max(0.0, round(latency_ms, 2))
        else:
            fields["latency"] = 0.0

        # Validate against SecurityEvent schema
        try:
            return SecurityEvent(**fields)
        except ValidationError as e:
            raise ValueError(f"Normalization failed validation: {e}") from e
