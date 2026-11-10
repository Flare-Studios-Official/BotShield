"""Tests for behavioral bot detection, telemetry ingestion, and scoring."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models.schema_models import DetectionRuleConfig
from app.schemas.bot import BotEventCreate
from app.services.bot_detector import evaluate_ip_behavior, record_bot_event
from app.services.traffic_simulator import run_lab_scenario


@pytest.fixture
def test_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    # Seed default rules
    rules = [
        DetectionRuleConfig(id="HIGH_FREQUENCY", name="High Frequency", description="", weight=25, threshold_value=20.0, enabled=True),
        DetectionRuleConfig(id="BURST_VELOCITY", name="Burst Velocity", description="", weight=20, threshold_value=10.0, enabled=True),
        DetectionRuleConfig(id="ENDPOINT_PROBING", name="Endpoint Probing", description="", weight=20, threshold_value=5.0, enabled=True),
        DetectionRuleConfig(id="EXCESSIVE_404S", name="Excessive 404s", description="", weight=15, threshold_value=4.0, enabled=True),
        DetectionRuleConfig(id="AUTOMATION_USER_AGENT", name="Automation UA", description="", weight=10, threshold_value=1.0, enabled=True),
        DetectionRuleConfig(id="RATE_LIMIT_VIOLATIONS", name="Rate Limit Violations", description="", weight=20, threshold_value=3.0, enabled=True),
        DetectionRuleConfig(id="RAPID_SEQUENCE", name="Rapid Sequence", description="", weight=10, threshold_value=0.15, enabled=True),
    ]
    db.add_all(rules)
    db.commit()

    yield db
    db.close()


def test_empty_ip_evaluation(test_db):
    """An IP with zero recorded events scores 0 with Low risk."""
    res = evaluate_ip_behavior("198.51.100.1", db=test_db)
    assert res.risk_score == 0
    assert res.risk_level == "low"
    assert len(res.triggered_rules) == 0


def test_high_frequency_trigger(test_db):
    """High volume triggers HIGH_FREQUENCY rule."""
    test_ip = "198.51.100.5"
    for i in range(25):
        record_bot_event(
            BotEventCreate(
                source_ip=test_ip,
                http_method="GET",
                path=f"/page/{i}",
                user_agent="Mozilla/5.0",
                response_status=200,
            ),
            db=test_db
        )

    res = evaluate_ip_behavior(test_ip, db=test_db)
    triggered_ids = [r.rule_id for r in res.triggered_rules]
    assert "HIGH_FREQUENCY" in triggered_ids
    assert res.risk_score >= 25


def test_lab_scenario_automated_scraper(test_db):
    """Controlled simulation of scraper triggers automation UA and frequency."""
    sim_result = run_lab_scenario(
        scenario="automated_scraper",
        request_count=30,
        interval_ms=10,
        db=test_db
    )
    assert sim_result["events_generated"] == 30
    assert sim_result["risk_score"] > 0
    assert any("Frequency" in r or "User-Agent" in r for r in sim_result["triggered_rules"])
