from typing import Dict, Any


class AnalystDashboardService:
    """
    Analyst Dashboard Aggregation Component Interface.
    Aggregates SOC metrics, active incident queues, and system telemetry feeds.
    To be implemented in subsequent project phases.
    """

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Fetch high-level SOC dashboard metrics."""
        raise NotImplementedError("Analyst Dashboard module will be implemented in Phase 2.")
