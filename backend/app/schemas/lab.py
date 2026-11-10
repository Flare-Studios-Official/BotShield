"""Detection Lab Simulation Schemas."""

from typing import List
from pydantic import BaseModel, Field


class LabScenarioStartRequest(BaseModel):
    """Command to execute a controlled demonstration scenario."""
    scenario: str = Field(
        ...,
        description="Scenario type: 'normal_browser', 'automated_scraper', 'burst_bot', 'endpoint_enumeration', 'rate_limit_offender'"
    )
    request_count: int = Field(default=25, ge=1, le=100, description="Total requests to generate")
    interval_ms: int = Field(default=50, ge=0, le=1000, description="Inter-request interval in milliseconds")


class LabSimulationStatus(BaseModel):
    """Status report of lab simulation."""
    is_running: bool
    active_scenario: str
    completed_requests: int
    target_requests: int
    simulated_ip: str
    latest_score: int
    triggered_rules: List[str]
