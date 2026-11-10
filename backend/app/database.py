"""BotShield Database Core

Configures SQLite SQLAlchemy session, Declarative Base, and schema initializer.
"""

from datetime import datetime, timezone
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    echo=settings.debug,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency for database session lifecycles."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def utc_now() -> datetime:
    """Returns current UTC timestamp with timezone awareness."""
    return datetime.now(timezone.utc)


def init_db():
    """Initializes database schema and default rule configurations."""
    from app.models.schema_models import DetectionRuleConfig
    Base.metadata.create_all(bind=engine)

    # Seed default detection rules if table is empty
    db = SessionLocal()
    try:
        existing = db.query(DetectionRuleConfig).first()
        if not existing:
            default_rules = [
                DetectionRuleConfig(
                    id="HIGH_FREQUENCY",
                    name="High Request Frequency",
                    description="Excessive request volume from a single IP within a 5-minute sliding window.",
                    weight=settings.weight_high_frequency,
                    threshold_value=float(settings.high_frequency_threshold),
                    enabled=True
                ),
                DetectionRuleConfig(
                    id="BURST_VELOCITY",
                    name="Short-Window Burst Velocity",
                    description="Rapid cluster of requests exceeding human navigation speed within 10 seconds.",
                    weight=settings.weight_burst_velocity,
                    threshold_value=float(settings.burst_threshold_count),
                    enabled=True
                ),
                DetectionRuleConfig(
                    id="ENDPOINT_PROBING",
                    name="Path & Endpoint Enumeration",
                    description="Client systematically scanning many distinct paths or common administrative probes.",
                    weight=settings.weight_endpoint_probing,
                    threshold_value=float(settings.path_enumeration_threshold),
                    enabled=True
                ),
                DetectionRuleConfig(
                    id="EXCESSIVE_404S",
                    name="Repeated 404 Probing",
                    description="High volume of HTTP 404 Not Found responses indicating aggressive scanning.",
                    weight=settings.weight_excessive_404s,
                    threshold_value=float(settings.probing_404_threshold),
                    enabled=True
                ),
                DetectionRuleConfig(
                    id="AUTOMATION_USER_AGENT",
                    name="Automation User-Agent Indicator",
                    description="Presence of known scraping frameworks, headless libraries, or empty User-Agent headers.",
                    weight=settings.weight_automation_user_agent,
                    threshold_value=1.0,
                    enabled=True
                ),
                DetectionRuleConfig(
                    id="RATE_LIMIT_VIOLATIONS",
                    name="Rate Limit Violations",
                    description="Continued requests despite receiving HTTP 429 Too Many Requests status codes.",
                    weight=settings.weight_rate_limit_violations,
                    threshold_value=float(settings.rate_limit_violation_threshold),
                    enabled=True
                ),
                DetectionRuleConfig(
                    id="RAPID_SEQUENCE",
                    name="Unnatural Inter-Request Timing",
                    description="Requests with deterministic, sub-100ms intervals characteristic of programmatic scripts.",
                    weight=settings.weight_rapid_sequence,
                    threshold_value=0.15,
                    enabled=True
                ),
            ]
            db.add_all(default_rules)
            db.commit()
    finally:
        db.close()
