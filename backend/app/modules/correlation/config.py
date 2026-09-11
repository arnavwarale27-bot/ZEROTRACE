from typing import List
from pydantic import BaseModel, Field


class CorrelationConfig(BaseModel):
    """
    Configuration options for Event Correlation and Incident Clustering Engine.
    All parameters are configurable per-run or system-wide.
    """

    time_window_minutes: int = Field(
        30, ge=1, le=1440, description="Max time delta in minutes between correlated events"
    )
    duplicate_window_seconds: float = Field(
        120.0, ge=1.0, description="Max time delta in seconds to consider events near-duplicates"
    )
    min_events_for_incident: int = Field(
        2, ge=1, description="Minimum number of related events required to create an incident"
    )
    critical_event_standalone_incident: bool = Field(
        True, description="Allow a single CRITICAL or HIGH severity event to form an incident"
    )
    pivot_keys: List[str] = Field(
        default_factory=lambda: ["host", "user", "ip", "process", "ioc"],
        description="Entities used to establish relationship edges between security events",
    )
