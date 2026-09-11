from datetime import datetime, timezone
from typing import List, Dict, Set, Any, Tuple
import uuid

from app.models.schemas import SecurityEvent, Incident
from app.modules.correlation.config import CorrelationConfig
from app.modules.correlation.extractor import EntityExtractor


_SEVERITY_HIERARCHY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_RANK_TO_SEVERITY = {0: "INFO", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


class CorrelationEngine:
    """
    Correlation Engine that groups related SecurityEvents into Incident clusters
    using connected components analysis over time proximity and shared entity pivots.
    Deterministic severity calculation and incident title/narrative generation.
    """

    def __init__(self, config: CorrelationConfig = None):
        self.config = config or CorrelationConfig()

    def cluster_events(self, events: List[SecurityEvent]) -> List[Incident]:
        """
        Main entry point to perform event correlation and return created Incident models.
        """
        # Filter out suppressed or duplicate events from forming new clusters
        valid_events = [e for e in events if e.detection_state != "DUPLICATE"]
        if not valid_events:
            return []

        # 1. Extract entities for all events
        event_entities: Dict[str, Dict[str, Set[str]]] = {
            e.event_id: EntityExtractor.extract_entities(e) for e in valid_events
        }

        event_map: Dict[str, SecurityEvent] = {e.event_id: e for e in valid_events}

        # 2. Build adjacency list graph
        adj: Dict[str, Set[str]] = {e.event_id: set() for e in valid_events}

        time_window_sec = self.config.time_window_minutes * 60.0

        n = len(valid_events)
        for i in range(n):
            e1 = valid_events[i]
            ents1 = event_entities[e1.event_id]

            for j in range(i + 1, n):
                e2 = valid_events[j]
                ents2 = event_entities[e2.event_id]

                # Check time proximity
                time_delta = abs((e1.timestamp - e2.timestamp).total_seconds())
                if time_delta > time_window_sec:
                    continue

                # Check shared pivot entity
                shared_pivot = self._find_shared_pivot(ents1, ents2)
                if shared_pivot:
                    adj[e1.event_id].add(e2.event_id)
                    adj[e2.event_id].add(e1.event_id)

        # 3. Find connected components (clusters)
        visited: Set[str] = set()
        clusters: List[List[SecurityEvent]] = []

        for e_id in adj:
            if e_id not in visited:
                component: List[SecurityEvent] = []
                queue = [e_id]
                visited.add(e_id)

                while queue:
                    curr = queue.pop(0)
                    component.append(event_map[curr])

                    for neighbor in adj[curr]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)

                clusters.append(component)

        # 4. Form Incidents from clusters
        incidents: List[Incident] = []
        for cluster in clusters:
            if self._should_form_incident(cluster):
                incident = self._create_incident_from_cluster(cluster)
                incidents.append(incident)

        return incidents

    def _find_shared_pivot(
        self, ents1: Dict[str, Set[str]], ents2: Dict[str, Set[str]]
    ) -> bool:
        """Returns True if ents1 and ents2 share at least 1 entity pivot key."""
        for key in self.config.pivot_keys:
            s1 = ents1.get(key, set())
            s2 = ents2.get(key, set())
            if s1 and s2 and not s1.isdisjoint(s2):
                return True
        return False

    def _should_form_incident(self, cluster: List[SecurityEvent]) -> bool:
        """Determines if a cluster of events meets criteria for Incident creation."""
        if len(cluster) >= self.config.min_events_for_incident:
            return True

        if self.config.critical_event_standalone_incident:
            for event in cluster:
                if str(event.severity).upper() in ("CRITICAL", "HIGH"):
                    return True
        return False

    def _create_incident_from_cluster(self, cluster: List[SecurityEvent]) -> Incident:
        """Builds an Incident model from a correlated cluster of events."""
        sorted_cluster = sorted(cluster, key=lambda e: e.timestamp)
        event_ids = [e.event_id for e in sorted_cluster]

        # Calculate Incident Severity
        max_rank = 0
        attack_stages: Set[str] = set()
        hosts: Set[str] = set()
        users: Set[str] = set()
        event_types: Set[str] = set()

        for event in sorted_cluster:
            rank = _SEVERITY_HIERARCHY.get(str(event.severity).upper(), 1)
            if rank > max_rank:
                max_rank = rank

            if event.attack_stage:
                attack_stages.add(event.attack_stage)
            if event.host:
                hosts.add(event.host)
            if event.user:
                users.add(event.user)
            event_types.add(event.event_type)

        # Escalate severity to CRITICAL if multiple attack kill chain stages are present
        if len(attack_stages) >= 2 and max_rank >= 3:
            max_rank = 4  # CRITICAL

        incident_severity = _RANK_TO_SEVERITY.get(max_rank, "MEDIUM")

        # Generate Title & Description
        primary_host = next(iter(hosts)) if hosts else "Unknown Host"
        primary_user = f" (User: {next(iter(users))})" if users else ""
        types_summary = ", ".join(list(event_types)[:3])

        title = f"Security Incident on {primary_host}{primary_user}: {types_summary}"

        description_lines = [
            f"Correlated incident involving {len(cluster)} security event(s) on host {primary_host}.",
            f"Event Types: {', '.join(event_types)}.",
            f"Attack Stages Detected: {', '.join(attack_stages) if attack_stages else 'N/A'}.",
            f"Earliest Event: {sorted_cluster[0].timestamp.isoformat()}.",
            f"Latest Event: {sorted_cluster[-1].timestamp.isoformat()}.",
        ]

        # Use deterministic UUID based on sorted event IDs so re-runs yield consistent incident IDs
        content_hash = f"incident:{','.join(sorted(event_ids))}"
        inc_id = f"inc-{str(uuid.uuid5(uuid.NAMESPACE_URL, content_hash))[:8]}"

        now = datetime.now(timezone.utc)

        return Incident(
            id=inc_id,
            title=title,
            description="\n".join(description_lines),
            severity=incident_severity,
            status="OPEN",
            created_at=now,
            updated_at=now,
            event_ids=event_ids,
            ioc_ids=[],
        )
