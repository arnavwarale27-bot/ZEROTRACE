from typing import List, Tuple, Dict, Any, Set
from app.models.schemas import SecurityEvent
from app.modules.correlation.config import CorrelationConfig


class EventDeduplicator:
    """
    Identifies duplicate and near-duplicate security events.
    Does NOT delete any records — marks duplicate events with detection_state = "DUPLICATE"
    and attaches duplicate_of reference to primary event_id in raw_data.
    """

    def __init__(self, config: CorrelationConfig = None):
        self.config = config or CorrelationConfig()

    def process_duplicates(self, events: List[SecurityEvent]) -> Tuple[List[SecurityEvent], List[SecurityEvent]]:
        """
        Processes a list of SecurityEvents.

        Returns:
            Tuple of (primary_events, duplicate_events_with_updated_metadata)
        """
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        primary_events: List[SecurityEvent] = []
        duplicate_events: List[SecurityEvent] = []
        seen_duplicates: Set[str] = set()

        for i, event in enumerate(sorted_events):
            if event.event_id in seen_duplicates:
                continue

            is_dup = False
            for prev_event in primary_events:
                if self._are_duplicates(prev_event, event):
                    is_dup = True
                    seen_duplicates.add(event.event_id)
                    # Update detection state & reference primary event ID
                    event.detection_state = "DUPLICATE"
                    updated_raw = dict(event.raw_data or {})
                    updated_raw["duplicate_of"] = prev_event.event_id
                    event.raw_data = updated_raw
                    duplicate_events.append(event)
                    break

            if not is_dup:
                primary_events.append(event)

        return primary_events, duplicate_events

    def _are_duplicates(self, e1: SecurityEvent, e2: SecurityEvent) -> bool:
        """Determines if e2 is a duplicate of e1."""
        time_delta = abs((e1.timestamp - e2.timestamp).total_seconds())
        if time_delta > self.config.duplicate_window_seconds:
            return False

        if e1.source != e2.source or e1.event_type != e2.event_type:
            return False

        if (e1.host or "").lower() != (e2.host or "").lower():
            return False

        if (e1.user or "").lower() != (e2.user or "").lower():
            return False

        # Check payload payload matching
        raw1 = e1.raw_data or {}
        raw2 = e2.raw_data or {}

        cmd1 = (raw1.get("ScriptBlockText") or raw1.get("command_line") or raw1.get("CommandLine") or raw1.get("QueryName") or "")
        cmd2 = (raw2.get("ScriptBlockText") or raw2.get("command_line") or raw2.get("CommandLine") or raw2.get("QueryName") or "")

        if cmd1 and cmd2 and str(cmd1).strip() == str(cmd2).strip():
            return True

        # If EventID and Computer match within threshold
        if raw1.get("EventID") and raw1.get("EventID") == raw2.get("EventID"):
            return True

        return False
