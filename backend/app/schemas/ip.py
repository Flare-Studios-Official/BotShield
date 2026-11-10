"""IP Intelligence Pydantic Schemas."""

from datetime import datetime
from typing import Any, Dict, List
from pydantic import BaseModel, Field


class IPAnalysisRequest(BaseModel):
    """IP intelligence lookup request."""
    ip_address: str = Field(..., description="IPv4 or IPv6 address to analyze.")


class ThreatSignalSchema(BaseModel):
    """Individual threat or classification signal."""
    category: str
    indicator: str
    severity: str  # low, medium, high, info
    confidence: str  # confirmed, observed, heuristic
    source: str
    details: str


class IPAnalysisResponse(BaseModel):
    """Full IP intelligence report."""
    id: str
    ip_address: str
    ip_version: int
    is_routable: bool
    classification: str
    asn: str
    as_org: str
    reverse_dns: str
    country_code: str
    country_name: str
    city: str
    is_datacenter: bool
    is_vpn: bool
    is_proxy: bool
    is_tor: bool
    reputation_score: int
    threat_level: str
    provider_sources: Dict[str, Any]
    signals: List[ThreatSignalSchema]
    created_at: datetime
    disclaimer: str = (
        "IP intelligence is heuristic and contextual. Classification as datacenter, VPN, or proxy "
        "does not by itself prove malicious intent."
    )
