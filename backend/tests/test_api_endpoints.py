"""Integration tests for BotShield FastAPI endpoints."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app
from app.models.schema_models import DetectionRuleConfig

# Use StaticPool so the in-memory SQLite database persists across test connections
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
Base.metadata.create_all(bind=test_engine)

# Seed rules into test engine
db = TestingSessionLocal()
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
db.close()


def override_get_db():
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def test_health_check_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["app"] == "BotShield"


def test_ssrf_protection_on_scan_endpoint():
    """Attempting to scan localhost or loopback should return 400 Bad Request."""
    response = client.post("/api/websites/scan", json={"target_url": "http://localhost:8000"})
    assert response.status_code == 400
    assert "SSRF" in response.json()["detail"] or "Loopback" in response.json()["detail"]


def test_ip_analysis_private_endpoint():
    """Private IP is safely analyzed without error."""
    response = client.post("/api/ips/analyze", json={"ip_address": "10.0.0.1"})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "private"
    assert data["is_routable"] is False


def test_bot_telemetry_and_summary_endpoint():
    """Ingesting an event and retrieving summary statistics."""
    payload = {
        "source_ip": "198.51.100.77",
        "http_method": "GET",
        "path": "/api/test",
        "user_agent": "Mozilla/5.0 TestClient",
        "response_status": 200,
        "duration_ms": 15.0,
    }
    post_resp = client.post("/api/bots/events", json=payload)
    assert post_resp.status_code == 200
    event_data = post_resp.json()
    assert event_data["source_ip"] == "198.51.100.77"

    # Retrieve summary
    summary_resp = client.get("/api/bots/summary")
    assert summary_resp.status_code == 200
    summary = summary_resp.json()
    assert summary["total_events"] >= 1


def test_detection_rules_list():
    response = client.get("/api/bots/rules")
    assert response.status_code == 200
    rules_data = response.json()
    assert len(rules_data) >= 7


def test_lab_simulation_and_reset():
    """Run a lab scenario and clear demonstration data."""
    run_resp = client.post("/api/lab/run", json={"scenario": "normal_browser", "request_count": 5})
    assert run_resp.status_code == 200
    res_data = run_resp.json()
    assert res_data["scenario"] == "normal_browser"

    reset_resp = client.post("/api/lab/reset")
    assert reset_resp.status_code == 200
    assert reset_resp.json()["status"] == "success"
