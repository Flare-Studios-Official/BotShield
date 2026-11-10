"""Website Security Scanner Pydantic Schemas."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field


class WebsiteScanRequest(BaseModel):
    """Scan request payload."""
    target_url: str = Field(..., description="Target URL (e.g. https://example.com) to analyze.")


class WebsiteFindingSchema(BaseModel):
    """Individual security finding detail."""
    id: str
    category: str
    name: str
    severity: str  # info, low, medium, high
    observed_value: str
    description: str
    implication: str
    recommendation: str
    confidence: str  # confirmed, observed, possible


class RedirectHopSchema(BaseModel):
    """Hop in a redirect chain."""
    step: int
    url: str
    status_code: int
    resolved_ip: str


class WebsiteScanResponse(BaseModel):
    """Full structured report for a website scan."""
    id: str
    target_url: str
    final_url: str
    resolved_ip: str
    status_code: int
    response_time_ms: float
    https_enforced: bool
    tls_version: str
    tls_cert_issuer: str
    tls_cert_expiry: str
    content_type: str
    content_length: int
    server_header: str
    redirect_count: int
    redirect_chain: List[RedirectHopSchema]
    security_score: int
    findings: List[WebsiteFindingSchema]
    created_at: datetime
    disclaimer: str = (
        "This is an automated, non-invasive passive security inspection based on public HTTP "
        "headers and metadata. It does not constitute a comprehensive penetration test or audit."
    )


class WebsiteScanSummary(BaseModel):
    """Brief summary for scan list views."""
    id: str
    target_url: str
    status_code: int
    security_score: int
    finding_count: int
    created_at: datetime
