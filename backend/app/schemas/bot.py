"""Bot Detection and Telemetry Schemas."""

from datetime import datetime
from typing import Dict, List, Optional
import ipaddress
from pydantic import BaseModel, Field, field_validator


class BotEventCreate(BaseModel):
    """Payload to record an HTTP request event."""
    source_ip: str = Field(..., max_length=64, description="IPv4 or IPv6 source address")
    http_method: str = Field("GET", max_length=12)
    path: str = Field("/", max_length=2048)
    user_agent: str = Field("", max_length=1024)
    response_status: int = Field(200, ge=100, le=599)
    duration_ms: float = Field(0.0, ge=0.0, le=300000.0)
    session_id: str = Field("", max_length=128)
    is_lab_traffic: bool = False
    lab_scenario: str = Field("", max_length=64)

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        clean = v.strip()
        try:
            ipaddress.ip_address(clean)
        except ValueError:
            raise ValueError(f"'{clean}' is not a valid IPv4 or IPv6 address.")
        return clean


class BotEventSchema(BaseModel):
    """Individual telemetry event schema."""
    id: str
    timestamp: datetime
    source_ip: str
    http_method: str
    path: str
    user_agent: str
    response_status: int
    duration_ms: float
    session_id: str
    is_lab_traffic: bool
    lab_scenario: str


class TriggeredRuleSchema(BaseModel):
    """Rule trigger detail in risk evaluation."""
    rule_id: str
    rule_name: str
    points_awarded: int
    threshold: float
    observed_value: float
    explanation: str


class BotDetectionResultSchema(BaseModel):
    """Complete detection evaluation for an IP address."""
    id: str
    source_ip: str
    risk_score: int
    risk_level: str  # low, moderate, high, critical
    window_start: datetime
    window_end: datetime
    total_requests: int
    status_404_count: int
    unique_paths_count: int
    triggered_rules: List[TriggeredRuleSchema]
    evidence: List[Dict[str, str]]
    reviewed: bool
    reviewed_by: Optional[str] = None
    review_notes: Optional[str] = None
    is_false_positive: bool = False
    created_at: datetime


class DetectionRuleSchema(BaseModel):
    """Detection rule definition and weights."""
    id: str
    name: str
    description: str
    weight: int
    threshold_value: float
    enabled: bool
    updated_at: datetime


class DetectionRuleUpdate(BaseModel):
    """Payload to adjust rule weights and thresholds."""
    weight: Optional[int] = Field(None, ge=0, le=100)
    threshold_value: Optional[float] = Field(None, ge=0.0)
    enabled: Optional[bool] = None


class ReviewDetectionRequest(BaseModel):
    """Payload for human analyst false-positive review."""
    reviewed_by: str = Field(..., min_length=2)
    review_notes: str = Field(..., min_length=5)
    is_false_positive: bool = False


class BotDashboardSummary(BaseModel):
    """Aggregated detection metrics for the SOC dashboard."""
    total_events: int
    unique_ips: int
    requests_last_minute: int
    critical_detections_count: int
    high_detections_count: int
    moderate_detections_count: int
    low_detections_count: int
    top_probed_paths: List[Dict[str, int]]
    traffic_velocity_series: List[Dict[str, str | int]]
    risk_tier_distribution: Dict[str, int]
