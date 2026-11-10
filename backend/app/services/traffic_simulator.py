"""BotShield Local Detection Lab Traffic Simulator

Generates isolated, reproducible traffic patterns strictly against local
demonstration endpoints to benchmark behavioral detection rules.
"""

import random
import time
from typing import Any, Dict, List
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal, utc_now
from app.models.schema_models import BotEvent
from app.schemas.bot import BotDetectionResultSchema, BotEventCreate
from app.services.bot_detector import evaluate_ip_behavior, record_bot_event

# Deterministic simulated IP addresses for lab testing
LAB_IPS = {
    "normal_browser": "198.51.100.10",       # TEST-NET-2
    "automated_scraper": "198.51.100.20",
    "burst_bot": "198.51.100.30",
    "endpoint_enumeration": "198.51.100.40",
    "rate_limit_offender": "198.51.100.50",
}

NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

NORMAL_PATHS = [
    "/", "/about", "/pricing", "/features", "/docs", "/contact", "/blog", "/blog/security-tips"
]

ENUMERATION_PATHS = [
    "/wp-login.php", "/wp-admin", "/admin", "/.env", "/config.json", "/phpmyadmin",
    "/actuator/env", "/.git/config", "/api/v1/users", "/server-status", "/backup.zip",
    "/v2/_catalog", "/aws/credentials", "/.aws/config", "/id_rsa", "/debug/vars"
]


def run_lab_scenario(
    scenario: str,
    request_count: int = 25,
    interval_ms: int = 50,
    db: Session = None
) -> Dict[str, Any]:
    """Executes a controlled simulation and returns generated telemetry and detection evaluation."""
    close_db = False
    if db is None:
        db = SessionLocal()
        close_db = True

    try:
        source_ip = LAB_IPS.get(scenario, "198.51.100.99")
        events_created: List[BotEvent] = []

        if scenario == "normal_browser":
            # Normal browser behavior: realistic intervals, standard headers, mostly 200 OK
            ua = random.choice(NORMAL_USER_AGENTS)
            for i in range(min(request_count, 15)):
                path = random.choice(NORMAL_PATHS)
                ev = record_bot_event(
                    BotEventCreate(
                        source_ip=source_ip,
                        http_method="GET",
                        path=path,
                        user_agent=ua,
                        response_status=200,
                        duration_ms=round(random.uniform(45.0, 150.0), 2),
                        session_id="lab-session-normal-101",
                        is_lab_traffic=True,
                        lab_scenario="normal_browser",
                    ),
                    db=db
                )
                events_created.append(ev)

        elif scenario == "automated_scraper":
            # Scraper using automation UA, high velocity, programmatic intervals
            ua = "python-requests/2.31.0"
            for i in range(request_count):
                path = f"/api/products?page={i + 1}"
                ev = record_bot_event(
                    BotEventCreate(
                        source_ip=source_ip,
                        http_method="GET",
                        path=path,
                        user_agent=ua,
                        response_status=200,
                        duration_ms=round(random.uniform(10.0, 35.0), 2),
                        session_id="",
                        is_lab_traffic=True,
                        lab_scenario="automated_scraper",
                    ),
                    db=db
                )
                events_created.append(ev)

        elif scenario == "burst_bot":
            # High burst: rapid cluster within sub-second intervals
            ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeadlessChrome/120.0"
            for i in range(max(request_count, 20)):
                path = "/checkout/voucher" if i % 2 == 0 else "/api/inventory"
                ev = record_bot_event(
                    BotEventCreate(
                        source_ip=source_ip,
                        http_method="POST" if i % 2 == 0 else "GET",
                        path=path,
                        user_agent=ua,
                        response_status=200 if i < 15 else 429,
                        duration_ms=round(random.uniform(5.0, 20.0), 2),
                        session_id="burst-session-99",
                        is_lab_traffic=True,
                        lab_scenario="burst_bot",
                    ),
                    db=db
                )
                events_created.append(ev)

        elif scenario == "endpoint_enumeration":
            # Scanner: many sensitive paths, mostly 404 responses
            ua = "sqlmap/1.7#stable"
            for i in range(request_count):
                path = ENUMERATION_PATHS[i % len(ENUMERATION_PATHS)]
                status = 404 if i % 5 != 0 else 403
                ev = record_bot_event(
                    BotEventCreate(
                        source_ip=source_ip,
                        http_method="GET",
                        path=path,
                        user_agent=ua,
                        response_status=status,
                        duration_ms=round(random.uniform(15.0, 40.0), 2),
                        session_id="",
                        is_lab_traffic=True,
                        lab_scenario="endpoint_enumeration",
                    ),
                    db=db
                )
                events_created.append(ev)

        elif scenario == "rate_limit_offender":
            # Offender continues hammering endpoint despite receiving 429 status codes
            ua = "Go-http-client/1.1"
            for i in range(request_count):
                status = 200 if i < 5 else 429
                ev = record_bot_event(
                    BotEventCreate(
                        source_ip=source_ip,
                        http_method="POST",
                        path="/api/login",
                        user_agent=ua,
                        response_status=status,
                        duration_ms=round(random.uniform(8.0, 25.0), 2),
                        session_id="",
                        is_lab_traffic=True,
                        lab_scenario="rate_limit_offender",
                    ),
                    db=db
                )
                events_created.append(ev)

        # Run behavioral evaluation on the simulated IP
        evaluation: BotDetectionResultSchema = evaluate_ip_behavior(
            source_ip=source_ip,
            db=db,
            window_seconds=settings.telemetry_window_seconds
        )

        return {
            "scenario": scenario,
            "simulated_ip": source_ip,
            "events_generated": len(events_created),
            "risk_score": evaluation.risk_score,
            "risk_level": evaluation.risk_level,
            "triggered_rules": [r.rule_name for r in evaluation.triggered_rules],
            "evaluation": evaluation.model_dump(),
        }

    finally:
        if close_db:
            db.close()


def reset_lab_events(db: Session) -> int:
    """Removes only lab-generated demonstration telemetry, preserving real production data."""
    deleted_count = db.query(BotEvent).filter(BotEvent.is_lab_traffic == True).delete()
    db.commit()
    return deleted_count
