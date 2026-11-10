"""BotShield Configuration Module

Provides centralized settings with environment variable support,
secure defaults, and strict validation for defensive operations.
"""

import os
from pathlib import Path
from typing import List
from pydantic import BaseModel, Field

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
    HAS_SETTINGS = True
except ImportError:
    HAS_SETTINGS = False
    BaseSettings = BaseModel  # type: ignore
    SettingsConfigDict = dict  # type: ignore


class Settings(BaseSettings):
    """Application runtime settings for BotShield."""

    app_name: str = "BotShield"
    app_version: str = "1.0.0"
    app_description: str = "Website Security, Bot Detection, IP Intelligence & Proxy Analysis Platform"
    environment: str = os.getenv("BOTSHIELD_ENV", "development")
    debug: bool = os.getenv("BOTSHIELD_DEBUG", "false").lower() in ("true", "1", "yes")

    # Host & Port
    api_host: str = os.getenv("BOTSHIELD_HOST", "127.0.0.1")
    api_port: int = int(os.getenv("BOTSHIELD_PORT", "8000"))
    cors_origins: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    # Database
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./botshield.db")

    # SSRF & Outbound Safety Guardrails
    allowed_schemes: List[str] = ["http", "https"]
    max_redirects: int = 5
    http_timeout_seconds: float = 8.0
    max_response_body_bytes: int = 2 * 1024 * 1024  # 2 MB limit
    disallow_private_networks: bool = True

    # Bot Detection Engine Heuristics & Sliding Windows
    telemetry_window_seconds: int = 300  # 5-minute sliding window
    burst_window_seconds: int = 10  # 10-second burst window
    burst_threshold_count: int = 15  # requests within burst window
    high_frequency_threshold: int = 50  # requests within 5-minute window
    probing_404_threshold: int = 5  # distinct 404s
    path_enumeration_threshold: int = 10  # distinct probed endpoints
    rate_limit_violation_threshold: int = 3

    # Default Rule Weights (Max: 100)
    weight_high_frequency: int = 25
    weight_burst_velocity: int = 20
    weight_endpoint_probing: int = 20
    weight_excessive_404s: int = 15
    weight_automation_user_agent: int = 10
    weight_rate_limit_violations: int = 20
    weight_rapid_sequence: int = 10

    # Risk Tier Boundaries
    risk_low_max: int = 24
    risk_moderate_max: int = 49
    risk_high_max: int = 74
    # 75-100 is Critical

    # External Intelligence (Optional - zero hard dependencies)
    abuseipdb_api_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
    ipinfo_token: str = os.getenv("IPINFO_TOKEN", "")
    enable_external_intelligence: bool = True

    # Storage paths
    reports_dir: Path = Path("./reports")


settings = Settings()
