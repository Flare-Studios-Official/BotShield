"""Database models exports."""

from app.models.schema_models import (
    Base,
    WebsiteScan,
    WebsiteFinding,
    IPAnalysisRecord,
    BotEvent,
    BotDetectionResult,
    DetectionRuleConfig,
    ProxyTestRecord,
)

__all__ = [
    "Base",
    "WebsiteScan",
    "WebsiteFinding",
    "IPAnalysisRecord",
    "BotEvent",
    "BotDetectionResult",
    "DetectionRuleConfig",
    "ProxyTestRecord",
]
