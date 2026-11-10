"""Proxy Intelligence Schemas."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class ProxyTestRequest(BaseModel):
    """Proxy diagnostic request."""
    proxy_url: str = Field(..., description="Proxy endpoint URL (e.g. http://12.34.56.78:8080 or socks5://...)")
    target_url: Optional[str] = Field(None, description="Optional public target destination to test egress")


class ProxyTestResponse(BaseModel):
    """Proxy diagnostic test response."""
    id: str
    proxy_scheme: str
    proxy_host: str
    proxy_port: int
    target_tested: str
    success: bool
    latency_ms: float
    egress_ip: str
    egress_classification: str
    error_message: str
    created_at: datetime
    disclaimer: str = (
        "This tool is strictly intended for diagnostic auditing of user-authorized proxy servers. "
        "It does not perform proxy rotation, identity masking, or security circumvention."
    )
