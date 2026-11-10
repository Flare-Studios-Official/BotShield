"""BotShield Database Models

Defines persistent SQLite entities for scans, findings, intelligence,
telemetry events, detection rules, proxy diagnostics, and reports.
"""

import uuid
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.database import Base, utc_now


def generate_uuid() -> str:
    return str(uuid.uuid4())


class WebsiteScan(Base):
    """Represents a passive security scan of a public website."""
    __tablename__ = "website_scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    target_url = Column(String(2048), nullable=False, index=True)
    final_url = Column(String(2048), nullable=False)
    resolved_ip = Column(String(45), nullable=False)
    status_code = Column(Integer, nullable=False)
    response_time_ms = Column(Float, nullable=False)
    https_enforced = Column(Boolean, default=False)
    tls_version = Column(String(32), default="")
    tls_cert_issuer = Column(String(256), default="")
    tls_cert_expiry = Column(String(64), default="")
    content_type = Column(String(128), default="")
    content_length = Column(Integer, default=0)
    server_header = Column(String(128), default="")
    redirect_count = Column(Integer, default=0)
    redirect_chain_json = Column(Text, default="[]")
    security_score = Column(Integer, default=0)
    created_at = Column(DateTime, default=utc_now, index=True)

    findings = relationship("WebsiteFinding", back_populates="scan", cascade="all, delete-orphan")


class WebsiteFinding(Base):
    """An individual security finding (header, robots, ratelimit, bot defense)."""
    __tablename__ = "website_findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("website_scans.id"), nullable=False, index=True)
    category = Column(String(32), nullable=False)  # header, robots, ratelimit, bot_defense, tls
    name = Column(String(128), nullable=False)
    severity = Column(String(16), nullable=False)  # info, low, medium, high
    observed_value = Column(Text, default="")
    description = Column(Text, nullable=False)
    implication = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)
    confidence = Column(String(16), default="confirmed")  # confirmed, observed, possible

    scan = relationship("WebsiteScan", back_populates="findings")


class IPAnalysisRecord(Base):
    """Represents an IP intelligence lookup and risk assessment."""
    __tablename__ = "ip_analyses"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    ip_address = Column(String(45), nullable=False, index=True)
    ip_version = Column(Integer, nullable=False)  # 4 or 6
    is_routable = Column(Boolean, default=True)
    classification = Column(String(32), nullable=False)  # public, private, loopback, reserved
    asn = Column(String(64), default="Unknown")
    as_org = Column(String(256), default="Unknown")
    reverse_dns = Column(String(256), default="")
    country_code = Column(String(8), default="")
    country_name = Column(String(64), default="")
    city = Column(String(64), default="")
    is_datacenter = Column(Boolean, default=False)
    is_vpn = Column(Boolean, default=False)
    is_proxy = Column(Boolean, default=False)
    is_tor = Column(Boolean, default=False)
    reputation_score = Column(Integer, default=0)  # 0 (clean) to 100 (high risk)
    threat_level = Column(String(16), default="low")  # low, moderate, high, critical
    provider_sources_json = Column(Text, default="{}")
    signals_json = Column(Text, default="[]")
    created_at = Column(DateTime, default=utc_now, index=True)


class BotEvent(Base):
    """Telemetry record for an inbound HTTP request."""
    __tablename__ = "bot_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=utc_now, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    http_method = Column(String(10), nullable=False)
    path = Column(String(1024), nullable=False, index=True)
    user_agent = Column(String(512), default="")
    response_status = Column(Integer, nullable=False, index=True)
    duration_ms = Column(Float, default=0.0)
    session_id = Column(String(64), default="", index=True)
    is_lab_traffic = Column(Boolean, default=False, index=True)
    lab_scenario = Column(String(32), default="")

    __table_args__ = (
        Index("idx_botevent_ip_ts", "source_ip", "timestamp"),
    )


class BotDetectionResult(Base):
    """Behavioral analysis snapshot for a source IP over a sliding window."""
    __tablename__ = "bot_detections"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    source_ip = Column(String(45), nullable=False, index=True)
    risk_score = Column(Integer, nullable=False)  # 0-100
    risk_level = Column(String(16), nullable=False)  # low, moderate, high, critical
    window_start = Column(DateTime, nullable=False)
    window_end = Column(DateTime, nullable=False)
    total_requests = Column(Integer, nullable=False)
    status_404_count = Column(Integer, default=0)
    unique_paths_count = Column(Integer, default=0)
    triggered_rules_json = Column(Text, default="[]")
    evidence_json = Column(Text, default="[]")
    reviewed = Column(Boolean, default=False)
    reviewed_by = Column(String(64), default="")
    review_notes = Column(Text, default="")
    is_false_positive = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utc_now, index=True)


class DetectionRuleConfig(Base):
    """Configurable scoring weight and thresholds for detection rules."""
    __tablename__ = "detection_rules"

    id = Column(String(64), primary_key=True)
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=False)
    weight = Column(Integer, nullable=False)
    threshold_value = Column(Float, nullable=False)
    enabled = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=utc_now)


class ProxyTestRecord(Base):
    """Diagnostic audit record for an authorized proxy endpoint."""
    __tablename__ = "proxy_tests"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    proxy_scheme = Column(String(16), nullable=False)  # http, https, socks5
    proxy_host = Column(String(256), nullable=False)
    proxy_port = Column(Integer, nullable=False)
    target_tested = Column(String(1024), nullable=False)
    success = Column(Boolean, default=False)
    latency_ms = Column(Float, default=0.0)
    egress_ip = Column(String(45), default="")
    egress_classification = Column(String(64), default="")
    error_message = Column(Text, default="")
    created_at = Column(DateTime, default=utc_now, index=True)
