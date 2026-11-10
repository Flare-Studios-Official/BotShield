"""Bot Detection and Telemetry Schemas."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class BotEventCreate(BaseModel):
    """Payload to record an HTTP request event."""
    source_ip: str
    http_method: str = "GET"
    path: str = "/"
    user_agent: str = ""
    response_status: int = 200
    duration_ms: float = 0.0
    session_id: str = ""
    is_lab_traffic: bool = False
    lab_scenario: str = ""


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
    evidence: List[str]
    reviewed: bool
    reviewed_by: str
    review_notes: str
    is_false_positive: bool
    created_at: datetime


class TopSuspiciousIP(BaseModel):
    """Summary of a suspicious IP."""
    source_ip: str
    risk_score: int
    risk_level: str
    request_count: int
    last_seen: datetime
    top_trigger: str


class PathCount(BaseModel):
    """Path frequency item."""
    path: str
    count: int


class StatusDistribution(BaseModel):
    """HTTP status code count."""
    status_code: int
    count: int


class BotDashboardSummary(BaseModel):
    """Aggregated dashboard telemetry metrics."""
    total_events: int
    unique_ips: int
    suspicious_count: int
    requests_per_minute: float
    risk_distribution: Dict[str, int]
    top_suspicious_ips: List[TopSuspiciousIP]
    top_paths: List[PathCount]
    status_distribution: List[StatusDistribution]
    recent_detections: List[BotDetectionResultSchema]


class DetectionRuleSchema(BaseModel):
    """Detection rule configuration item."""
    id: str
    name: str
    description: str
    weight: int
    threshold_value: float
    enabled: bool
    updated_at: datetime


class DetectionRuleUpdate(BaseModel):
    """Rule update payload."""
    weight: Optional[int] = None
    threshold_value: Optional[float] = None
    enabled: Optional[bool] = None


class ReviewDetectionRequest(BaseModel):
    """Analyst review request."""
    reviewed_by: str = Field(..., description="Analyst username or identifier")
    review_notes: str = Field(..., description="Explanation of analysis or false positive rationale")
    is_false_positive: bool = False
